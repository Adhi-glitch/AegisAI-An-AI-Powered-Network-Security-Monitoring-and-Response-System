"""Response execution with a pure policy decision layer and dry-run safety."""
import time
from collections import deque
from threading import Lock
from typing import Any, Dict

from config import get_config
from .policy_engine import PolicyDecision, evaluate_policy
from .adapters import FirewallAdapter, default_adapter

cfg = get_config()
TIERS = cfg.confidence_tiers

class ResponseEngine:
    def __init__(
        self,
        dry_run: bool = True,
        unblock_after_seconds: int = 300,
        adapter: FirewallAdapter | None = None,
        allowlist: set[str] | None = None,
        max_actions_per_minute: int = 60,
        max_audit_records: int = 10_000,
    ):
        self.dry_run = dry_run
        self.unblock_after_seconds = unblock_after_seconds
        self.whitelist = set(allowlist or set())
        self.blocked = {}  # ip -> unblock_time
        self.audit_log: deque[Dict[str, Any]] = deque(
            maxlen=max(1, int(max_audit_records))
        )
        self.audit_lock = Lock()
        self.action_timestamps: list[float] = []
        self.max_actions_per_minute = max_actions_per_minute
        self.adapter = adapter or default_adapter()
        self.lock = Lock()

    def classify_confidence(self, confidence: float) -> str:
        for tier_name, rng in TIERS.items():
            low, high = rng
            if low <= confidence <= high:
                return tier_name
        return "Low"

    def decide_action(
        self,
        confidence: float,
        attack_type: str | None = None,
        severity: str | None = None,
        asset_criticality: str | None = None,
        mode: str = "dry-run",
    ) -> str:
        """Return an action while preserving the original confidence-only API."""
        if attack_type is None and severity is None and asset_criticality is None:
            tier = self.classify_confidence(confidence)
            if tier == "High":
                return "block"
            if tier == "Medium":
                return "rate_limit"
            return "log"
        return self.evaluate_policy(
            confidence,
            attack_type=attack_type,
            severity=severity,
            asset_criticality=asset_criticality,
            mode=mode,
        ).action

    def evaluate_policy(self, confidence: float, **context: Any) -> PolicyDecision:
        """Expose the explainable policy result for API and audit integrations."""
        return evaluate_policy(confidence=confidence, **context)

    def apply_action(self, ip: str, action: str) -> Dict[str, Any]:
        if ip in self.whitelist:
            result = {"status": "whitelisted", "ip": ip}
            self._audit(ip, action, result)
            return result

        if not self._rate_limit_action():
            result = {"status": "action_rate_limited", "ip": ip, "action": action}
            self._audit(ip, action, result)
            return result

        if action == "block":
            result = self._block(ip)
            self._audit(ip, action, result)
            return result
        if action == "rate_limit":
            result = self._rate_limit(ip)
            self._audit(ip, action, result)
            return result
        if action in {"alert", "notify", "isolate", "quarantine"}:
            result = {"status": action, "ip": ip}
            self._audit(ip, action, result)
            return result
        result = self._log(ip)
        self._audit(ip, action, result)
        return result

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
        adapter_result = self.adapter.block(ip, dry_run=self.dry_run)
        if self.dry_run:
            return {"status": "dry_run_blocked", "ip": ip, "unblock_at": unblock_time, "adapter": adapter_result}
        return {"status": "blocked", "ip": ip, "unblock_at": unblock_time, "adapter": adapter_result}

    def manual_unblock(self, ip: str) -> Dict[str, Any]:
        with self.lock:
            self._prune_expired_locked()
            if ip in self.blocked:
                del self.blocked[ip]
                adapter_result = self.adapter.unblock(ip, dry_run=self.dry_run)
                result = {"status": "unblocked", "ip": ip, "adapter": adapter_result}
                self._audit(ip, "unblock", result)
                return result
            return {"status": "not_blocked", "ip": ip}

    def _prune_expired_locked(self, now: float | None = None):
        now = time.time() if now is None else now
        expired = [ip for ip, unblock_time in self.blocked.items() if unblock_time <= now]
        for ip in expired:
            del self.blocked[ip]

    def _rate_limit_action(self) -> bool:
        now = time.time()
        with self.lock:
            self.action_timestamps = [timestamp for timestamp in self.action_timestamps if timestamp > now - 60]
            if len(self.action_timestamps) >= self.max_actions_per_minute:
                return False
            self.action_timestamps.append(now)
            return True

    def _audit(self, ip: str, action: str, result: Dict[str, Any]) -> None:
        with self.audit_lock:
            self.audit_log.append(
                {"timestamp": time.time(), "ip": ip, "action": action, "result": result}
            )


# default instance
engine = ResponseEngine()
