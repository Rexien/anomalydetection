#!/usr/bin/env python3
"""
Rolling Baseline Module
========================
Computes mean and standard deviation from a rolling 30-minute window
of per-second request counts. Recalculated every 60 seconds.

Key design decisions:
  - Uses a deque of (second_timestamp, count) tuples for the rolling window.
  - Fills gaps with zeros for seconds that had no requests, so the
    mean/stddev accurately reflects quiet periods.
  - Maintains per-hour slots so the current hour's baseline is preferred
    when it has enough data (>= 300 seconds of observations).
  - Floor values prevent the baseline from ever being zero, which would
    break z-score calculations and cause false positives on idle servers.
"""

import time
import math
import threading
from collections import deque


class BaselineManager:
    """
    Manages a rolling baseline of per-second request counts.

    Parameters
    ----------
    window_minutes : int
        Size of the rolling window in minutes (default: 30).
    recalc_interval : int
        How often to recalculate the baseline, in seconds (default: 60).
    audit_logger : callable
        Function to write audit log entries.
    """

    def __init__(self, window_minutes=30, recalc_interval=60, audit_logger=None):
        self.window_minutes = window_minutes
        self.recalc_interval = recalc_interval
        self.audit_logger = audit_logger or (lambda msg: None)

        # ── Per-second request counts ───────────────────────────────
        # Deque of (second_timestamp, request_count) tuples.
        # Only seconds with at least one request are stored; gaps are
        # filled with zeros during recalculation.
        self._counts = deque()
        self._error_counts = deque()  # Same structure for 4xx/5xx
        self._lock = threading.Lock()

        # ── Per-hour slots ──────────────────────────────────────────
        # hour_key -> {'mean': float, 'stddev': float, 'samples': int}
        self._hourly_slots = {}

        # ── Effective baseline (thread-safe reads) ──────────────────
        self.effective_mean = 1.0      # Floor: never below 1.0
        self.effective_stddev = 0.5    # Floor: never below 0.5
        self.error_rate_mean = 0.1     # Floor: never below 0.1

        # ── History for dashboard graphing ──────────────────────────
        # Stores last 720 recalculation snapshots (~12 hours)
        self.history = deque(maxlen=720)

        self._running = False

    def start(self):
        """Start the periodic recalculation thread."""
        self._running = True
        t = threading.Thread(target=self._recalc_loop, daemon=True)
        t.start()

    def stop(self):
        self._running = False

    def record_request(self, timestamp: float, is_error: bool = False):
        """
        Record a single request at the given timestamp.
        Called by the detector for every parsed log line.

        The per-second count for that timestamp's second is incremented.
        """
        sec = int(timestamp)

        with self._lock:
            # Update request counts
            if self._counts and self._counts[-1][0] == sec:
                self._counts[-1] = (sec, self._counts[-1][1] + 1)
            else:
                self._counts.append((sec, 1))

            # Update error counts
            if is_error:
                if self._error_counts and self._error_counts[-1][0] == sec:
                    self._error_counts[-1] = (sec, self._error_counts[-1][1] + 1)
                else:
                    self._error_counts.append((sec, 1))

    def _recalc_loop(self):
        """Periodically recalculate the baseline."""
        while self._running:
            time.sleep(self.recalc_interval)
            try:
                self._recalculate()
            except Exception as e:
                print(f"[baseline] Recalculation error: {e}")

    def _recalculate(self):
        """
        Recompute effective_mean and effective_stddev from the rolling window.

        Steps:
          1. Evict entries older than `window_minutes` from the deques.
          2. Build a full per-second count array, filling zeros for gaps.
          3. Compute mean and stddev of the full array.
          4. Update the current hour's slot.
          5. Prefer the current hour's stats if it has >= 300 samples.
          6. Apply floor values to prevent division-by-zero in z-scores.
        """
        now = time.time()
        cutoff = now - (self.window_minutes * 60)
        current_hour = int(now // 3600)

        with self._lock:
            # ── Step 1: Evict old entries ───────────────────────────
            while self._counts and self._counts[0][0] < cutoff:
                self._counts.popleft()
            while self._error_counts and self._error_counts[0][0] < cutoff:
                self._error_counts.popleft()

            # ── Step 2: Build full per-second array with zero-fill ──
            if self._counts:
                first_sec = self._counts[0][0]
                last_sec = self._counts[-1][0]
                total_seconds = max(last_sec - first_sec + 1, 1)

                count_map = {}
                for sec, cnt in self._counts:
                    count_map[sec] = cnt

                full_counts = [
                    count_map.get(first_sec + i, 0)
                    for i in range(total_seconds)
                ]
            else:
                full_counts = [0]

            # ── Step 3: Compute mean and stddev ─────────────────────
            n = len(full_counts)
            mean = sum(full_counts) / n
            variance = sum((x - mean) ** 2 for x in full_counts) / n
            stddev = math.sqrt(variance)

            # Error rate mean
            error_map = {}
            for sec, cnt in self._error_counts:
                error_map[sec] = cnt
            error_total = sum(error_map.values())
            error_mean = error_total / max(n, 1)

            # ── Step 4: Update hourly slot ──────────────────────────
            self._hourly_slots[current_hour] = {
                'mean': mean,
                'stddev': stddev,
                'samples': n,
            }

            # ── Step 5: Prefer current hour if enough data ──────────
            slot = self._hourly_slots.get(current_hour, {})
            if slot.get('samples', 0) >= 300:
                raw_mean = slot['mean']
                raw_stddev = slot['stddev']
            else:
                raw_mean = mean
                raw_stddev = stddev

            # ── Step 6: Apply floor values ──────────────────────────
            self.effective_mean = max(raw_mean, 1.0)
            self.effective_stddev = max(raw_stddev, 0.5)
            self.error_rate_mean = max(error_mean, 0.1)

            # ── Record history snapshot for graphing ────────────────
            self.history.append({
                'timestamp': now,
                'effective_mean': self.effective_mean,
                'effective_stddev': self.effective_stddev,
                'error_rate_mean': self.error_rate_mean,
                'hour_slot': current_hour,
                'samples': n,
            })

            # ── Cleanup old hourly slots (keep 24h) ────────────────
            stale = [h for h in self._hourly_slots if h < current_hour - 24]
            for h in stale:
                del self._hourly_slots[h]

        # ── Audit log ───────────────────────────────────────────────
        self.audit_logger(
            f"BASELINE_RECALC - | samples={n} | "
            f"mean={self.effective_mean:.2f} stddev={self.effective_stddev:.2f} | "
            f"{self.effective_mean:.2f} | -"
        )
        print(
            f"[baseline] Recalculated: mean={self.effective_mean:.2f}, "
            f"stddev={self.effective_stddev:.2f}, samples={n}, hour={current_hour}"
        )
