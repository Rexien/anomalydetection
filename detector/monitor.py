#!/usr/bin/env python3
"""
Log Monitor Module
==================
Continuously tails the Nginx JSON access log file line by line.
Parses each JSON entry and feeds it to the detector via a callback.
Implements tail-follow behaviour (like `tail -f`): starts at the end
of the file and reads only new lines as they are appended.
"""

import json
import time
import os
import threading
import sys


class LogMonitor:
    """
    Watches the Nginx access log and parses incoming JSON lines.

    Parameters
    ----------
    log_path : str
        Absolute path to the Nginx JSON access log.
    callback : callable
        Function to call with each parsed log entry dict.
    """

    def __init__(self, log_path: str, callback):
        self.log_path = log_path
        self.callback = callback
        self._running = False
        self._thread = None
        self._lines_processed = 0

    @property
    def lines_processed(self):
        return self._lines_processed

    def start(self):
        """Start tailing the log in a background thread."""
        self._running = True
        self._thread = threading.Thread(target=self._tail_loop, daemon=True)
        self._thread.start()

    def stop(self):
        """Signal the monitor to stop."""
        self._running = False

    def _tail_loop(self):
        """
        Core tail-follow loop.
        - Waits for the log file to appear.
        - Seeks to end of file on first open.
        - Reads new lines as they are appended.
        - Handles log rotation by detecting file truncation / inode change.
        """
        while self._running:
            try:
                # Wait for log file to exist
                if not os.path.exists(self.log_path):
                    print(f"[monitor] Waiting for log file: {self.log_path}")
                    time.sleep(2)
                    continue

                inode = os.stat(self.log_path).st_ino

                with open(self.log_path, 'r') as f:
                    # Start at end of file (tail behaviour)
                    f.seek(0, 2)
                    print(f"[monitor] Tailing {self.log_path} (inode={inode})")

                    while self._running:
                        line = f.readline()

                        if not line:
                            # No new data — short sleep to avoid busy-waiting
                            time.sleep(0.1)

                            # Check for log rotation (file replaced)
                            try:
                                current_inode = os.stat(self.log_path).st_ino
                                if current_inode != inode:
                                    print("[monitor] Log file rotated, reopening...")
                                    break
                            except FileNotFoundError:
                                print("[monitor] Log file disappeared, waiting...")
                                break
                            continue

                        line = line.strip()
                        if not line:
                            continue

                        self._parse_and_dispatch(line)

            except Exception as e:
                print(f"[monitor] Error: {e}", file=sys.stderr)
                time.sleep(2)

    def _parse_and_dispatch(self, line: str):
        """
        Parse a single JSON log line and dispatch to the callback.

        Expected JSON fields:
          source_ip, timestamp, method, path, status, response_size
        """
        try:
            entry = json.loads(line)
            parsed = {
                'source_ip': str(entry.get('source_ip', '')).strip(),
                'timestamp': str(entry.get('timestamp', '')),
                'method': str(entry.get('method', '')),
                'path': str(entry.get('path', '')),
                'status': int(entry.get('status', 0)),
                'response_size': int(entry.get('response_size', 0)),
            }

            # Skip entries with empty IP
            if not parsed['source_ip']:
                return

            self._lines_processed += 1
            self.callback(parsed)

        except json.JSONDecodeError:
            # Skip malformed lines silently
            pass
        except (ValueError, TypeError) as e:
            print(f"[monitor] Parse error: {e} — line: {line[:100]}")
