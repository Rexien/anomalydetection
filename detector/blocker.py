#!/usr/bin/env python3
"""
IP Blocker Module
==================
Manages iptables DROP rules for banned IPs.
Executes blocking commands within 10 seconds of detection.
Uses DOCKER-USER chain (preferred) with INPUT chain fallback.
"""

import subprocess
import threading
import time


class IPBlocker:
    """
    Manages iptables rules for banning/unbanning IPs.

    Parameters
    ----------
    whitelist : list
        IPs that must never be banned.
    audit_logger : callable
        Function to write structured audit log entries.
    """

    def __init__(self, whitelist=None, audit_logger=None):
        self.whitelist = whitelist or []
        self.audit_logger = audit_logger or (lambda msg: None)

        # ip -> {ban_time, duration, condition, rate, baseline, unban_time}
        self.banned_ips = {}
        self._lock = threading.Lock()

        # Determine which iptables chain to use
        self._chain = self._detect_chain()
        print(f"[blocker] Using iptables chain: {self._chain}")

    def _detect_chain(self) -> str:
        """Check if DOCKER-USER chain exists; fall back to INPUT."""
        try:
            result = subprocess.run(
                ['iptables', '-L', 'DOCKER-USER', '-n'],
                capture_output=True, timeout=5
            )
            if result.returncode == 0:
                return 'DOCKER-USER'
        except Exception:
            pass
        return 'INPUT'

    def is_banned(self, ip: str) -> bool:
        with self._lock:
            return ip in self.banned_ips

    def get_banned_list(self) -> dict:
        """Return a copy of banned IPs dict (for dashboard)."""
        with self._lock:
            return dict(self.banned_ips)

    def ban(self, ip: str, duration, condition: str, rate: float, baseline: float):
        """
        Ban an IP by adding an iptables DROP rule.

        Parameters
        ----------
        ip : str
            The IP address to block.
        duration : int or None
            Ban duration in seconds. None = permanent.
        condition : str
            The condition that triggered the ban.
        rate : float
            The IP's request rate at time of detection.
        baseline : float
            The baseline mean at time of detection.
        """
        if ip in self.whitelist:
            return
        if self.is_banned(ip):
            return

        now = time.time()
        with self._lock:
            self.banned_ips[ip] = {
                'ban_time': now,
                'duration': duration,
                'condition': condition,
                'rate': rate,
                'baseline': baseline,
                'unban_time': now + duration if duration else None,
            }

        # Execute iptables DROP rule
        self._add_rule(ip)
        dur_str = f"{duration}s" if duration else "permanent"
        print(f"[blocker] BANNED {ip} for {dur_str} — {condition}")

    def unban(self, ip: str):
        """Remove an IP's iptables DROP rule and clear from banned list."""
        with self._lock:
            if ip in self.banned_ips:
                del self.banned_ips[ip]

        self._remove_rule(ip)
        print(f"[blocker] UNBANNED {ip}")

    def _add_rule(self, ip: str):
        """Insert an iptables DROP rule for the given IP."""
        try:
            subprocess.run(
                ['iptables', '-I', self._chain, '-s', ip, '-j', 'DROP'],
                check=True, capture_output=True, timeout=10
            )
        except subprocess.CalledProcessError as e:
            print(f"[blocker] iptables add failed ({self._chain}): {e.stderr}")
            # Fallback to INPUT if DOCKER-USER failed
            if self._chain != 'INPUT':
                try:
                    subprocess.run(
                        ['iptables', '-I', 'INPUT', '-s', ip, '-j', 'DROP'],
                        check=True, capture_output=True, timeout=10
                    )
                except Exception as e2:
                    print(f"[blocker] iptables INPUT fallback failed: {e2}")
        except Exception as e:
            print(f"[blocker] iptables error: {e}")

    def _remove_rule(self, ip: str):
        """Delete the iptables DROP rule for the given IP."""
        for chain in [self._chain, 'INPUT']:
            try:
                subprocess.run(
                    ['iptables', '-D', chain, '-s', ip, '-j', 'DROP'],
                    capture_output=True, timeout=10
                )
            except Exception:
                pass

    def get_expired_bans(self, now: float) -> list:
        """Return list of (ip, info) tuples for bans that have expired."""
        with self._lock:
            expired = []
            for ip, info in self.banned_ips.items():
                if info['unban_time'] is not None and now >= info['unban_time']:
                    expired.append((ip, dict(info)))
            return expired
