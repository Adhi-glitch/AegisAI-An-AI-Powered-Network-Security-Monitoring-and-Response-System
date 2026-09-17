"""
Response engine: maps confidence tiers to actions (log, rate_limit, block).
Defaults to dry-run. Includes whitelist and auto-unblock timeout logic.
"""
import time
from threading import Lock
from typing import Any, Dict

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
            now = time.time()
            self._prune_expired_locked(now)
            unblock_time = now + self.unblock_after_seconds
            self.blocked[ip] = unblock_time
        # TODO: implement actual firewall command (iptables/netsh); keep dry_run safe
        if self.dry_run:
            return {"status": "dry_run_blocked", "ip": ip, "unblock_at": unblock_time}
        return {"status": "blocked", "ip": ip, "unblock_at": unblock_time}

    def manual_unblock(self, ip: str) -> Dict[str, Any]:
        with self.lock:
            self._prune_expired_locked()
            if ip in self.blocked:
                del self.blocked[ip]
                # TODO: remove firewall rule
                return {"status": "unblocked", "ip": ip}
            return {"status": "not_blocked", "ip": ip}

    def _prune_expired_locked(self, now: float | None = None):
        now = time.time() if now is None else now
        expired = [ip for ip, unblock_time in self.blocked.items() if unblock_time <= now]
        for ip in expired:
            del self.blocked[ip]


# default instance
engine = ResponseEngine()
