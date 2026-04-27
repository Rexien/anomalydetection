#!/usr/bin/env python3
"""
Anomaly Detector Module
========================
Core detection engine using two deque-based sliding windows (per-IP
and global) over the last 60 seconds. No rate-limiting libraries.

Detection logic:
  1. Compute current rate from the sliding window length / 60.
  2. Compare against the rolling baseline (mean + stddev).
  3. Flag as anomalous if z-score > 3.0 OR rate > 5x baseline mean.
  4. If an IP has elevated 4xx/5xx errors (3x baseline), tighten
     its thresholds automatically.
  5. Per-IP anomaly → ban + Slack alert.
  6. Global anomaly → Slack alert only.
"""

import time
import threading
from collections import deque


class AnomalyDetector:
    """
    Sliding-window anomaly detector.

    Parameters
    ----------
    config : dict
        Loaded config.yaml as a dictionary.
    baseline : BaselineManager
        Reference to the rolling baseline module.
    blocker : IPBlocker
        Reference to the iptables blocking module.
    notifier : SlackNotifier
        Reference to the Slack notification module.
    audit_logger : callable
        Function to write structured audit log entries.
    """

    def __init__(self, config, baseline, blocker, notifier, audit_logger):
        self.config = config
        self.baseline = baseline
        self.blocker = blocker
        self.notifier = notifier
        self.audit_log = audit_logger

        thresholds = config['thresholds']
        self.window_seconds = thresholds['sliding_window_seconds']

        # ── Global sliding window ─────────────────────────────
        # Deque of timestamps (floats) for all requests in last 60s
        self.global_window = deque()

        # ── Per-IP sliding windows ────────────────────────────
        # ip_str -> deque of timestamps
        self.ip_windows = {}

        # ── Per-IP error windows (4xx/5xx) ────────────────────
        self.ip_error_windows = {}

        # ── Ban offense counter (for escalating durations) ────
        self.ban_counts = {}

        # ── Metrics (read by dashboard) ───────────────────────
        self.global_rate = 0.0
        self.ip_rates = {}
        self.top_ips = []
        self.total_requests = 0

        # ── Cooldown for global alerts (max 1 per 60s) ────────
        self._last_global_alert = 0

        self._lock = threading.Lock()

    def process_request(self, entry: dict):
        """
        Process a single parsed log entry. Called by LogMonitor.

        This is the hot path — every request flows through here.
        Steps:
          1. Record timestamp in global + per-IP deque windows.
          2. Evict entries older than sliding_window_seconds.
          3. Update rate metrics.
          4. Feed the baseline recorder.
          5. Check for per-IP and global anomalies.
        """
        now = time.time()
        ip = entry['source_ip']
        status = entry['status']
        is_error = status >= 400

        with self._lock:
            self.total_requests += 1

            # ── Step 1: Append to sliding windows ──────────────
            self.global_window.append(now)

            if ip not in self.ip_windows:
                self.ip_windows[ip] = deque()
            self.ip_windows[ip].append(now)

            if is_error:
                if ip not in self.ip_error_windows:
                    self.ip_error_windows[ip] = deque()
                self.ip_error_windows[ip].append(now)

            # ── Step 2: Evict stale entries ────────────────────
            cutoff = now - self.window_seconds
            self._evict(self.global_window, cutoff)

            for _ip in list(self.ip_windows.keys()):
                self._evict(self.ip_windows[_ip], cutoff)
                if not self.ip_windows[_ip]:
                    del self.ip_windows[_ip]

            for _ip in list(self.ip_error_windows.keys()):
                self._evict(self.ip_error_windows[_ip], cutoff)
                if not self.ip_error_windows[_ip]:
                    del self.ip_error_windows[_ip]

            # ── Step 3: Compute current rates ──────────────────
            self.global_rate = len(self.global_window) / self.window_seconds
            ip_rate = len(self.ip_windows.get(ip, deque())) / self.window_seconds
            self.ip_rates[ip] = ip_rate

            # Top 10 IPs by rate
            self.top_ips = sorted(
                self.ip_rates.items(), key=lambda x: x[1], reverse=True
            )[:10]

            ip_error_count = len(self.ip_error_windows.get(ip, deque()))

        # ── Step 4: Feed the baseline ──────────────────────────
        self.baseline.record_request(now, is_error)

        # ── Step 5: Check anomalies ────────────────────────────
        self._check_ip_anomaly(ip, ip_rate, ip_error_count)
        self._check_global_anomaly()

    @staticmethod
    def _evict(window: deque, cutoff: float):
        """
        Remove all entries from the left of the deque that are
        older than `cutoff`. O(k) where k = number of evicted items.
        """
        while window and window[0] < cutoff:
            window.popleft()

    def _check_ip_anomaly(self, ip: str, ip_rate: float, ip_error_count: int):
        """
        Check if a single IP's request rate is anomalous.

        Uses z-score and rate-multiplier thresholds from config.
        Tightens thresholds if the IP has an elevated error rate.
        """
        # Skip already-banned or whitelisted IPs
        if self.blocker.is_banned(ip):
            return
        if ip in self.config.get('whitelist', []):
            return

        mean = self.baseline.effective_mean
        stddev = self.baseline.effective_stddev

        # ── Load thresholds ────────────────────────────────────
        zscore_threshold = self.config['thresholds']['zscore']
        rate_multiplier = self.config['thresholds']['rate_multiplier']

        # ── Error surge: tighten thresholds ────────────────────
        # If this IP's error rate > 3x the baseline error rate,
        # reduce the thresholds so it gets caught faster.
        ip_error_rate = ip_error_count / self.window_seconds
        error_surge_mult = self.config['thresholds']['error_surge_multiplier']

        if ip_error_rate > self.baseline.error_rate_mean * error_surge_mult:
            zscore_threshold = max(zscore_threshold * 0.6, 1.5)
            rate_multiplier = max(rate_multiplier * 0.6, 2.0)

        # ── Z-score calculation ────────────────────────────────
        if stddev > 0:
            zscore = (ip_rate - mean) / stddev
        else:
            zscore = 0.0 if ip_rate <= mean else float('inf')

        # ── Anomaly check: z-score OR rate multiplier ──────────
        zscore_fired = zscore > zscore_threshold
        multiplier_fired = ip_rate > mean * rate_multiplier

        if (zscore_fired or multiplier_fired) and ip_rate > mean:
            # Determine which condition triggered
            if zscore_fired:
                condition = f"zscore={zscore:.2f}>{zscore_threshold}"
            else:
                condition = f"rate={ip_rate:.2f}>{rate_multiplier}x_mean({mean:.2f})"

            # Escalating ban duration
            ban_count = self.ban_counts.get(ip, 0) + 1
            self.ban_counts[ip] = ban_count

            durations = self.config['ban_durations']
            if ban_count <= len(durations):
                duration = durations[ban_count - 1]
            else:
                duration = None  # Permanent

            dur_str = f"{duration}s" if duration else "permanent"

            # Execute ban
            self.blocker.ban(ip, duration, condition, ip_rate, mean)
            self.notifier.send_ban_alert(ip, condition, ip_rate, mean, duration)
            self.audit_log(
                f"BAN {ip} | {condition} | {ip_rate:.2f} | {mean:.2f} | {dur_str}"
            )

    def _check_global_anomaly(self):
        """
        Check if the overall global request rate is anomalous.
        Global anomaly → Slack alert only (no ban).
        Rate-limited to one alert per 60 seconds.
        """
        now = time.time()
        if now - self._last_global_alert < 60:
            return

        mean = self.baseline.effective_mean
        stddev = self.baseline.effective_stddev
        global_rate = self.global_rate

        zscore_threshold = self.config['thresholds']['zscore']
        rate_multiplier = self.config['thresholds']['rate_multiplier']

        if stddev > 0:
            zscore = (global_rate - mean) / stddev
        else:
            zscore = 0.0 if global_rate <= mean else float('inf')

        zscore_fired = zscore > zscore_threshold
        multiplier_fired = global_rate > mean * rate_multiplier

        if (zscore_fired or multiplier_fired) and global_rate > mean:
            self._last_global_alert = now

            if zscore_fired:
                condition = f"global_zscore={zscore:.2f}>{zscore_threshold}"
            else:
                condition = f"global_rate={global_rate:.2f}>{rate_multiplier}x_mean({mean:.2f})"

            self.notifier.send_global_alert(condition, global_rate, mean)
            self.audit_log(
                f"GLOBAL_ALERT - | {condition} | {global_rate:.2f} | {mean:.2f} | -"
            )
