#!/usr/bin/env python3
"""
Anomaly Detection Engine — Main Entry Point
=============================================
Coordinates all modules: log monitoring, baseline computation,
anomaly detection, IP blocking, auto-unbanning, Slack notifications,
and the live metrics dashboard.

This daemon runs continuously alongside Nextcloud, monitoring HTTP
traffic via Nginx access logs and responding to anomalies in real time.
"""

import os
import sys
import time
import yaml
import signal
import threading
from datetime import datetime

from monitor import LogMonitor
from baseline import BaselineManager
from detector import AnomalyDetector
from blocker import IPBlocker
from unbanner import AutoUnbanner
from notifier import SlackNotifier
from dashboard import DashboardServer

# ── Global state ────────────────────────────────────────────────
START_TIME = time.time()
AUDIT_LOG_PATH = "/var/log/detector/audit.log"


def load_config(path="config.yaml") -> dict:
    """Load configuration from YAML file."""
    with open(path, 'r') as f:
        return yaml.safe_load(f)


def audit_log(message: str):
    """
    Write a structured audit log entry.
    Format: [timestamp] ACTION ip | condition | rate | baseline | duration
    """
    timestamp = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")
    entry = f"[{timestamp}] {message}\n"

    try:
        os.makedirs(os.path.dirname(AUDIT_LOG_PATH), exist_ok=True)
        with open(AUDIT_LOG_PATH, 'a') as f:
            f.write(entry)
    except Exception as e:
        print(f"[audit] Error writing log: {e}", file=sys.stderr)

    # Also print to stdout for container logging
    print(f"[AUDIT] {entry.strip()}")


def main():
    global AUDIT_LOG_PATH

    print("=" * 60)
    print("  🛡️  HNG Anomaly Detection Engine v1.0")
    print("  Starting up...")
    print("=" * 60)

    # Load configuration
    config = load_config()
    AUDIT_LOG_PATH = config.get('audit_log_path', AUDIT_LOG_PATH)

    print(f"[main] Config loaded.")
    print(f"[main]   Log path     : {config['log_path']}")
    print(f"[main]   Slack webhook : {'configured' if config.get('slack_webhook_url') else 'NOT SET'}")
    print(f"[main]   Dashboard    : http://0.0.0.0:{config.get('dashboard_port', 8080)}")

    # ── Initialize modules ──────────────────────────────────────
    notifier = SlackNotifier(config.get('slack_webhook_url', ''))

    blocker = IPBlocker(
        whitelist=config.get('whitelist', []),
        audit_logger=audit_log
    )

    baseline = BaselineManager(
        window_minutes=config['thresholds']['baseline_window_minutes'],
        recalc_interval=config['thresholds']['baseline_recalc_seconds'],
        audit_logger=audit_log
    )

    unbanner = AutoUnbanner(
        blocker=blocker,
        notifier=notifier,
        audit_logger=audit_log
    )

    anomaly_detector = AnomalyDetector(
        config=config,
        baseline=baseline,
        blocker=blocker,
        notifier=notifier,
        audit_logger=audit_log
    )

    monitor = LogMonitor(
        log_path=config['log_path'],
        callback=anomaly_detector.process_request
    )

    dashboard = DashboardServer(
        port=config.get('dashboard_port', 8080),
        detector=anomaly_detector,
        baseline=baseline,
        blocker=blocker,
        start_time=START_TIME
    )

    # ── Start all modules ───────────────────────────────────────
    print("[main] Starting baseline manager...")
    baseline.start()

    print("[main] Starting auto-unbanner...")
    unbanner.start()

    print("[main] Starting log monitor...")
    monitor.start()

    print("[main] Starting dashboard server...")
    dash_thread = threading.Thread(target=dashboard.run, daemon=True)
    dash_thread.start()

    print("[main] ✅ All modules started. Monitoring traffic...")

    # Send startup notification to Slack
    notifier.send_startup_alert()

    # ── Graceful shutdown ───────────────────────────────────────
    def shutdown(sig, frame):
        print("\n[main] Shutting down gracefully...")
        monitor.stop()
        baseline.stop()
        unbanner.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    # ── Keep main thread alive ──────────────────────────────────
    while True:
        time.sleep(1)


if __name__ == "__main__":
    main()
