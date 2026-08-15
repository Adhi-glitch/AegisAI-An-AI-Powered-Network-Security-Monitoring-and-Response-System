"""
Response engine: maps confidence tiers to actions (log, rate_limit, block).
Defaults to dry-run. Includes whitelist and auto-unblock timeout logic.
"""
from typing import Dict, Any
import time
from threading import Lock, Thread
from config import get_config

cfg = get_config()
TIERS = cfg.confidence_tiers

class ResponseEngine:
    def __init__(self, dry_run: bool = True, unblock_after_seconds: int = 300):
        self.dry_run = dry_run
        self.unblock_after_seconds = unblock_after_seconds
        self.whitelist = set()
        self.blocked = {}  # ip -> unblock_time
        self.lock = Lock()

    def classify_confidence(self, confidence: float) -> str:
        for tier_name, rng in TIERS.items():
            low, high = rng
            if low <= confidence <= high:
                return tier_name
        return "Low"

    def decide_action(self, confidence: float) -> str:
        tier = self.classify_confidence(confidence)
        if tier == "High":
            return "block"
        if tier == "Medium":
            return "rate_limit"
        return "log"

    def apply_action(self, ip: str, action: str) -> Dict[str, Any]:
        if ip in self.whitelist:
            return {"status": "whitelisted", "ip": ip}

        if action == "block":
            return self._block(ip)
        if action == "rate_limit":
            return self._rate_limit(ip)
        return self._log(ip)

    def _log(self, ip: str):
        # simple logging action
        return {"status": "logged", "ip": ip}

    def _rate_limit(self, ip: str):
        # TODO: integrate with traffic control / firewall
        if self.dry_run:
            return {"status": "dry_run_rate_limited", "ip": ip}
        return {"status": "rate_limited", "ip": ip}

    def _block(self, ip: str):
        with self.lock:
            unblock_time = time.time() + self.unblock_after_seconds
            self.blocked[ip] = unblock_time
        # TODO: implement actual firewall command (iptables/netsh); keep dry_run safe
        if self.dry_run:
            return {"status": "dry_run_blocked", "ip": ip, "unblock_at": unblock_time}
        return {"status": "blocked", "ip": ip, "unblock_at": unblock_time}

    def manual_unblock(self, ip: str) -> Dict[str, Any]:
        with self.lock:
            if ip in self.blocked:
                del self.blocked[ip]
                # TODO: remove firewall rule
                return {"status": "unblocked", "ip": ip}
            return {"status": "not_blocked", "ip": ip}

    def _reaper(self):
        while True:
            now = time.time()
            with self.lock:
                expired = [ip for ip, t in self.blocked.items() if t <= now]
                for ip in expired:
                    del self.blocked[ip]
                    # TODO: remove firewall rule (if not dry_run)
            time.sleep(5)

    def start_reaper(self):
        if getattr(self, "_reaper_started", False):
            return
        self._reaper_started = True
        t = Thread(target=self._reaper, daemon=True)
        t.start()


# default instance
engine = ResponseEngine()
