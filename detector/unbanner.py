#!/usr/bin/env python3
"""
Auto-Unbanner Module
=====================
Periodically checks banned IPs and releases bans on a backoff schedule:
  - 1st offense: 10 minutes
  - 2nd offense: 30 minutes
  - 3rd offense: 2 hours
  - 4th+ offense: permanent (never unbanned)

Sends Slack notification and writes audit log on every unban.
"""

import time
import threading


class AutoUnbanner:
    """
    Manages automatic unbanning of IPs after their ban duration expires.

    Parameters
    ----------
    blocker : IPBlocker
        Reference to the IP blocking module.
    notifier : SlackNotifier
        Reference to the Slack notification module.
    audit_logger : callable
        Function to write structured audit log entries.
    """

    def __init__(self, blocker, notifier, audit_logger=None):
        self.blocker = blocker
        self.notifier = notifier
        self.audit_log = audit_logger or (lambda msg: None)
        self._running = False

    def start(self):
        """Start the periodic unban-check thread."""
        self._running = True
        t = threading.Thread(target=self._check_loop, daemon=True)
        t.start()

    def stop(self):
        self._running = False

    def _check_loop(self):
        """Check for expired bans every 10 seconds."""
        while self._running:
            time.sleep(10)
            try:
                self._process_unbans()
            except Exception as e:
                print(f"[unbanner] Error: {e}")

    def _process_unbans(self):
        """
        Find all bans whose duration has elapsed and unban them.
        Permanent bans (duration=None) are never released.
        """
        now = time.time()
        expired = self.blocker.get_expired_bans(now)

        for ip, info in expired:
            duration = info.get('duration')
            condition = info.get('condition', 'unknown')
            rate = info.get('rate', 0)
            baseline = info.get('baseline', 0)

            # Unban the IP (removes iptables rule)
            self.blocker.unban(ip)

            # Format duration for display
            dur_str = self._format_duration(duration)

            # Send Slack notification
            self.notifier.send_unban_alert(ip, dur_str, condition)

            # Write audit log
            self.audit_log(
                f"UNBAN {ip} | {condition} | {rate:.2f} | {baseline:.2f} | {dur_str}"
            )

    @staticmethod
    def _format_duration(seconds):
        """Convert seconds to human-readable duration string."""
        if seconds is None:
            return "permanent"
        if seconds >= 3600:
            return f"{seconds // 3600}h"
        if seconds >= 60:
            return f"{seconds // 60}m"
        return f"{seconds}s"
