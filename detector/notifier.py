#!/usr/bin/env python3
"""
Slack Notifier Module
======================
Sends structured alerts to a configured Slack webhook URL.

Alert types:
  - IP ban notification (per-IP anomaly)
  - IP unban notification
  - Global traffic anomaly alert
  - Startup notification
"""

import time
import requests
import threading


class SlackNotifier:
    """
    Sends notifications to Slack via an Incoming Webhook.

    Parameters
    ----------
    webhook_url : str
        The Slack Incoming Webhook URL.
    """

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def _send(self, payload: dict):
        """
        Send a payload to Slack in a background thread
        so it doesn't block the detection hot path.
        """
        if not self.webhook_url:
            print("[notifier] No Slack webhook configured, skipping alert")
            return

        def _post():
            try:
                resp = requests.post(
                    self.webhook_url, json=payload, timeout=10
                )
                if resp.status_code != 200:
                    print(f"[notifier] Slack returned {resp.status_code}: {resp.text}")
            except Exception as e:
                print(f"[notifier] Slack error: {e}")

        threading.Thread(target=_post, daemon=True).start()

    def send_ban_alert(self, ip: str, condition: str, rate: float,
                       baseline: float, duration):
        """Send a ban notification to Slack."""
        dur_str = f"{duration}s ({self._human_duration(duration)})" if duration else "PERMANENT"
        ts = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())

        self._send({
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "🚨 IP BANNED"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*IP:*\n`{ip}`"},
                        {"type": "mrkdwn", "text": f"*Condition:*\n{condition}"},
                        {"type": "mrkdwn", "text": f"*Current Rate:*\n{rate:.2f} req/s"},
                        {"type": "mrkdwn", "text": f"*Baseline Mean:*\n{baseline:.2f} req/s"},
                        {"type": "mrkdwn", "text": f"*Ban Duration:*\n{dur_str}"},
                        {"type": "mrkdwn", "text": f"*Timestamp:*\n{ts}"},
                    ]
                }
            ]
        })

    def send_unban_alert(self, ip: str, duration_str: str, condition: str):
        """Send an unban notification to Slack."""
        ts = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())

        self._send({
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "✅ IP UNBANNED"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*IP:*\n`{ip}`"},
                        {"type": "mrkdwn", "text": f"*Previous Condition:*\n{condition}"},
                        {"type": "mrkdwn", "text": f"*Ban Duration Was:*\n{duration_str}"},
                        {"type": "mrkdwn", "text": f"*Timestamp:*\n{ts}"},
                    ]
                }
            ]
        })

    def send_global_alert(self, condition: str, rate: float, baseline: float):
        """Send a global traffic anomaly alert (no ban)."""
        ts = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())

        self._send({
            "blocks": [
                {
                    "type": "header",
                    "text": {"type": "plain_text", "text": "⚠️ GLOBAL TRAFFIC ANOMALY"}
                },
                {
                    "type": "section",
                    "fields": [
                        {"type": "mrkdwn", "text": f"*Condition:*\n{condition}"},
                        {"type": "mrkdwn", "text": f"*Global Rate:*\n{rate:.2f} req/s"},
                        {"type": "mrkdwn", "text": f"*Baseline Mean:*\n{baseline:.2f} req/s"},
                        {"type": "mrkdwn", "text": f"*Timestamp:*\n{ts}"},
                    ]
                },
                {
                    "type": "context",
                    "elements": [
                        {"type": "mrkdwn", "text": "_No IP banned — global traffic spike detected._"}
                    ]
                }
            ]
        })

    def send_startup_alert(self):
        """Send a startup notification."""
        ts = time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime())
        self._send({
            "text": f"🟢 *Anomaly Detection Engine Started*\nTimestamp: {ts}\nMonitoring traffic..."
        })

    @staticmethod
    def _human_duration(seconds):
        if seconds is None:
            return "permanent"
        if seconds >= 3600:
            return f"{seconds // 3600}h"
        if seconds >= 60:
            return f"{seconds // 60}m"
        return f"{seconds}s"
