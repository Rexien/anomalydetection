I Built a DDoS Detection Tool From Scratch — Here's How It Works

If someone sent thousands of fake requests to your website every second, how would you stop them?

I was tasked with building an anomaly detection engine — a tool that watches web traffic in real time, learns what "normal" looks like, and automatically blocks attackers. No third-party security libraries allowed. Just Python, some math, and Linux networking.


What It Does and Why It Matters

I'm protecting a Nextcloud cloud storage platform sitting behind an Nginx reverse proxy. Nginx logs every request in JSON format. My Python daemon reads these logs in real time and does four things: watches every HTTP request, learns normal traffic patterns over time, detects anomalies using statistics, and blocks attackers via iptables while alerting the team on Slack.

[ADD ARCHITECTURE DIAGRAM IMAGE HERE]


How the Sliding Window Works

To measure "how many requests are happening right now," I use a sliding window built on Python's collections.deque (a double-ended queue).

The concept is simple: every time a request comes in, I append its timestamp to the right side of the deque. Then I check the left side — if those timestamps are older than 60 seconds, I pop them off. What remains is exactly how many requests happened in the last minute. The current rate is just len(window) / 60.

Deques make this O(1) — adding and removing from either end takes constant time, so it stays fast even under heavy load.

I maintain a global window for all traffic, plus a per-IP dictionary of individual windows. This lets me detect both server-wide floods and single-IP attacks.


How the Baseline Learns From Traffic

Is 50 requests per second a lot? Depends on your server. My baseline manager calculates the mean and standard deviation of traffic every 60 seconds using a 30-minute rolling window.

It's also time-aware — traffic at 3 AM differs from 3 PM, so it keeps per-hour statistics and prefers the current hour's data when it has enough samples.

And it enforces floor values (mean of at least 1.0, standard deviation of at least 0.5) to prevent false alarms during quiet periods. Without these floors, a server with zero traffic would flag any single request as an anomaly.


How the Detection Logic Makes a Decision

An IP gets flagged if either of two conditions fires.

Z-score greater than 3.0 — the request rate is more than 3 standard deviations above the mean. Statistically, that puts it in the top 0.1% of expected behavior. The formula is (current_rate minus mean) divided by stddev.

Rate greater than 5 times the mean — a simple multiplier catch for cases where the standard deviation is unusually high.

If an IP generates excessive 4xx/5xx errors (like failed login attempts), thresholds tighten automatically to catch credential stuffing attacks that would slip under normal thresholds.


How iptables Blocks an IP

When the detector flags an IP, I add a kernel-level firewall rule using iptables. The command inserts a DROP rule into the DOCKER-USER chain for that specific source IP. This silently discards all packets from the attacker at the kernel level — no response, no connection, nothing. It's instant and uses almost no resources.

To unban, I simply delete the rule. Bans follow a tiered schedule: first offense is 10 minutes, second is 30 minutes, third is 2 hours, and after that it's permanent. Every ban and unban sends a Slack alert with the IP address, trigger condition, current rate, baseline comparison, and ban duration.


The Result

I simulated an attack with Apache Benchmark, firing 500 requests from 50 concurrent connections. Within seconds, the detector flagged the traffic with a z-score of 3.03 (just above the 3.0 threshold), banned the source IP, fired a Slack alert with full context, and displayed the ban on the live dashboard with a countdown timer. After 10 minutes, the auto-unbanner lifted the ban and sent a confirmation to Slack. The full detection-to-ban-to-unban cycle worked exactly as designed.

[ADD DASHBOARD SCREENSHOT HERE]
[ADD SLACK NOTIFICATIONS SCREENSHOT HERE]


Links

GitHub: https://github.com/Rexien/anomalydetection
Live Dashboard: http://zamistage3.duckdns.org
Nextcloud: http://92.4.137.99
