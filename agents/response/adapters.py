"""Firewall adapters with dry-run-safe execution."""
from __future__ import annotations

from abc import ABC, abstractmethod
import platform
import subprocess
from typing import Any


class FirewallAdapter(ABC):
    @abstractmethod
    def block(self, ip: str, *, dry_run: bool = True) -> dict[str, Any]:
        raise NotImplementedError

    @abstractmethod
    def unblock(self, ip: str, *, dry_run: bool = True) -> dict[str, Any]:
        raise NotImplementedError


class MockFirewallAdapter(FirewallAdapter):
    def __init__(self):
        self.operations: list[dict[str, str]] = []

    def block(self, ip: str, *, dry_run: bool = True) -> dict[str, Any]:
        self.operations.append({"operation": "block", "ip": ip})
        return {"adapter": "mock", "operation": "block", "executed": not dry_run, "ip": ip}

    def unblock(self, ip: str, *, dry_run: bool = True) -> dict[str, Any]:
        self.operations.append({"operation": "unblock", "ip": ip})
        return {"adapter": "mock", "operation": "unblock", "executed": not dry_run, "ip": ip}


class CommandFirewallAdapter(FirewallAdapter):
    """OS adapter; commands are never invoked while dry-run is enabled."""

    def __init__(self, system: str | None = None):
        self.system = (system or platform.system()).lower()

    def _command(self, operation: str, ip: str) -> list[str]:
        if self.system == "windows":
            name = f"AegisAI-{ip}-{operation}"
            if operation == "block":
                return ["netsh", "advfirewall", "firewall", "add", "rule", f"name={name}", "dir=in", "action=block", f"remoteip={ip}"]
            return ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"]
        if operation == "block":
            return ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
        return ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]

    def _run(self, operation: str, ip: str, dry_run: bool) -> dict[str, Any]:
        command = self._command(operation, ip)
        if dry_run:
            return {"adapter": self.system, "operation": operation, "executed": False, "command": command, "ip": ip}
        completed = subprocess.run(command, capture_output=True, text=True, check=False, timeout=10)
        return {"adapter": self.system, "operation": operation, "executed": completed.returncode == 0, "returncode": completed.returncode, "stderr": completed.stderr[-500:], "ip": ip}

    def block(self, ip: str, *, dry_run: bool = True) -> dict[str, Any]:
        return self._run("block", ip, dry_run)

    def unblock(self, ip: str, *, dry_run: bool = True) -> dict[str, Any]:
        return self._run("unblock", ip, dry_run)


def default_adapter() -> FirewallAdapter:
    return CommandFirewallAdapter()