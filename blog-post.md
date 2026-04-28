# I Built a DDoS Detection Tool From Scratch — Here's How It Works

If someone sent thousands of fake requests to your website every second, how would you stop them?

I was tasked with building an anomaly detection engine — a tool that watches web traffic in real time, learns what "normal" looks like, and automatically blocks attackers. No third-party security libraries allowed. Just Python, some math, and Linux networking.

---

## What It Does and Why It Matters

I'm protecting a Nextcloud cloud storage platform sitting behind an Nginx reverse proxy. Nginx logs every request in JSON format. My Python daemon reads these logs in real time and does four things: watches every HTTP request, learns normal traffic patterns over time, detects anomalies using statistics, and blocks attackers via iptables while alerting the team on Slack.

> **[IMAGE: Upload docs/architecture.png here — the architecture diagram showing the full system flow]**

---

## How the Sliding Window Works

To measure "how many requests are happening right now," I use a sliding window built on Python's `collections.deque` (a double-ended queue).

Every time a request comes in, I append its timestamp to the right side of the deque. Then I check the left side — if those timestamps are older than 60 seconds, I pop them off. What remains is exactly how many requests happened in the last minute.

```python
from collections import deque
import time

window = deque()

def on_new_request():
    now = time.time()
    window.append(now)
    while window[0] < now - 60:
        window.popleft()
    rate = len(window) / 60
```

Deques make this O(1) — adding and removing from either end takes constant time, so it stays fast even under heavy load.

I maintain a global window for all traffic, plus a per-IP dictionary of individual windows. This lets me detect both server-wide floods and single-IP attacks.

---

## How the Baseline Learns From Traffic

Is 50 requests per second a lot? Depends on your server. My baseline manager calculates the mean and standard deviation of traffic every 60 seconds using a 30-minute rolling window.

It's also time-aware — traffic at 3 AM differs from 3 PM, so it keeps per-hour statistics. And it enforces floor values (mean ≥ 1.0, stddev ≥ 0.5) to prevent false alarms during quiet periods. Without these floors, a server with zero traffic would flag any single request as an anomaly.

---

## How the Detection Logic Makes a Decision

An IP gets flagged if either of two conditions fires:

**Z-score > 3.0** — the rate is more than 3 standard deviations above the mean, putting it in the top 0.1% of expected behavior.

**Rate > 5x the mean** — a simple multiplier catch for when standard deviation is unusually high.

If an IP generates excessive 4xx/5xx errors, thresholds tighten automatically to catch credential stuffing attacks.

---

## How iptables Blocks an IP

When the detector flags an IP, I add a kernel-level firewall rule:

```bash
iptables -I DOCKER-USER -s 203.0.113.42 -j DROP
```

This silently discards all packets from that IP — no response, no connection, nothing. It's instant and happens at the kernel level.

Bans follow a tiered schedule: 10 min → 30 min → 2 hours → permanent. Every ban and unban sends a Slack alert with the IP, trigger condition, rate, and duration.

> **[IMAGE: Upload screenshots/Iptables-banned.png here — terminal showing the iptables DROP rule]**

---

## The Result

I simulated an attack with Apache Benchmark, firing 500 requests from 50 concurrent connections:

```bash
ab -n 500 -c 50 http://localhost/
```

Within seconds, the detector flagged the traffic with a z-score of 3.03, banned the source IP, fired a Slack alert, and displayed the ban on the live dashboard. After 10 minutes, the auto-unbanner lifted the ban and sent a confirmation to Slack.

> **[IMAGE: Upload screenshots/Ban-slack.png here — the dashboard showing the banned IP with countdown timer]**

> **[IMAGE: Upload screenshots/Unban-slack.png here — Slack showing ban, unban, and global alert notifications]**

---

## Links

- **GitHub**: [github.com/Rexien/anomalydetection](https://github.com/Rexien/anomalydetection)
- **Live Dashboard**: [zamistage3.duckdns.org](http://zamistage3.duckdns.org)
- **Nextcloud**: [92.4.137.99](http://92.4.137.99)
