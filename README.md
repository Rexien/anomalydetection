# HNG Anomaly Detection Engine — DDoS Detection Tool

A real-time anomaly detection daemon that monitors HTTP traffic to a Nextcloud instance, learns normal traffic patterns using a rolling baseline, and automatically blocks abusive IPs via iptables.

## 🔗 Live Links

| Resource | URL |
|----------|-----|
| **Metrics Dashboard** | `https://YOUR_DOMAIN` |
| **Server IP** | `YOUR_SERVER_IP` |
| **Blog Post** | `YOUR_BLOG_URL` |

---

## Language Choice: Python

Python was chosen for:
- **Rapid prototyping** — the sliding-window and baseline math is natural in Python.
- **`collections.deque`** — built-in, O(1) append/popleft data structure perfect for sliding windows.
- **FastAPI** — lightweight async web framework for the dashboard with zero boilerplate.
- **`psutil`** — cross-platform system metrics for the dashboard.
- **Readability** — code is easy to audit during live interviews.

---

## Architecture

```
Internet → Nginx (JSON access logs) → Nextcloud
                  │
                  ▼
            HNG-nginx-logs (Docker volume)
                  │
                  ▼
        ┌─────────────────────────────────────────────────┐
        │            Anomaly Detection Daemon             │
        │                                                 │
        │  monitor.py ──→ detector.py ──→ blocker.py      │
        │       │              │              │            │
        │       ▼              ▼              ▼            │
        │  baseline.py    notifier.py    unbanner.py       │
        │                                                 │
        │  dashboard.py (FastAPI on :8080)                 │
        └─────────────────────────────────────────────────┘
```

---

## How the Sliding Window Works

Two `collections.deque` instances track request timestamps over a **60-second window**:

1. **Global window** — one deque holding timestamps of ALL requests.
2. **Per-IP windows** — a `dict[str, deque]` mapping each source IP to its own deque.

### Eviction Logic
On every incoming request:
1. Append the current timestamp to both the global deque and the IP-specific deque.
2. Calculate `cutoff = now - 60`.
3. Pop entries from the **left** of each deque while `deque[0] < cutoff`.
4. The **length** of the deque divided by 60 gives the current rate in req/s.

```python
# Pseudocode
global_window.append(now)
while global_window[0] < now - 60:
    global_window.popleft()
rate = len(global_window) / 60
```

This is O(1) amortized per request (each entry is appended once and popped once).

---

## How the Baseline Works

| Parameter | Value |
|-----------|-------|
| Window size | 30 minutes |
| Recalculation interval | Every 60 seconds |
| Per-second granularity | Yes |
| Hour-slot preference | Current hour if ≥ 300 samples |
| Floor values | mean ≥ 1.0, stddev ≥ 0.5 |

### Rolling Window
- A deque stores `(second_timestamp, count)` tuples.
- Entries older than 30 minutes are evicted on each recalculation.
- **Gaps are filled with zeros** — seconds with no requests count as 0 to avoid inflated means.

### Per-Hour Slots
- Statistics are stored per-hour for temporal awareness.
- If the current hour has ≥ 300 seconds of data, its mean/stddev is preferred.
- This allows the baseline to adapt to time-of-day traffic patterns.

### Detection Decision
An IP or global rate is flagged anomalous if **either** condition fires:
- **Z-score** `> 3.0` → `(rate - mean) / stddev > 3.0`
- **Rate multiplier** → `rate > 5 × mean`

If an IP's 4xx/5xx error rate exceeds 3× the baseline error rate, thresholds are automatically tightened (z-score threshold reduced to 1.5, multiplier to 2×).

---

## Setup Instructions (Fresh VPS)

### Prerequisites
- Ubuntu 22.04+ VPS (min 2 vCPU, 2 GB RAM)
- Domain/subdomain pointed to the VPS IP
- Slack webhook URL

### Step-by-step

```bash
# 1. SSH into your VPS
ssh root@YOUR_SERVER_IP

# 2. Install Docker & Docker Compose
curl -fsSL https://get.docker.com | sh
apt install -y docker-compose-plugin

# 3. Clone the repo
git clone https://github.com/YOUR_USERNAME/YOUR_REPO.git
cd YOUR_REPO

# 4. Update config
# Edit detector/config.yaml — set your Slack webhook URL
# Edit nginx/nginx.conf — replace YOUR_DOMAIN with your actual domain

# 5. Start the stack
docker compose up -d --build

# 6. Verify
# Nextcloud: http://YOUR_SERVER_IP
# Dashboard: http://YOUR_DOMAIN:8080 (or via Nginx proxy)

# 7. Check logs
docker compose logs -f detector
```

### Optional: Caddy for HTTPS on the dashboard
```bash
apt install -y caddy
cat > /etc/caddy/Caddyfile << EOF
YOUR_DOMAIN {
    reverse_proxy localhost:8080
}
EOF
systemctl restart caddy
```

---

## Repository Structure

```
detector/
  main.py           # Daemon entry point
  monitor.py        # Log tailing and parsing
  baseline.py       # Rolling baseline computation
  detector.py       # Sliding window + anomaly detection
  blocker.py        # iptables ban management
  unbanner.py       # Auto-unban scheduler
  notifier.py       # Slack webhook alerts
  dashboard.py      # Live metrics web UI
  config.yaml       # All configurable thresholds
  requirements.txt  # Python dependencies
  Dockerfile        # Container image for the detector
nginx/
  nginx.conf        # Nginx reverse proxy with JSON logging
docs/
  architecture.png  # Architecture diagram
screenshots/
  Tool-running.png
  Ban-slack.png
  Unban-slack.png
  Global-alert-slack.png
  Iptables-banned.png
  Audit-log.png
  Baseline-graph.png
docker-compose.yml  # Full stack orchestration
README.md           # This file
```

---

## GitHub Repo

🔗 `https://github.com/YOUR_USERNAME/YOUR_REPO`

---

## Blog Post

🔗 `YOUR_BLOG_URL`
