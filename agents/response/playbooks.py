"""Safe, inspectable response playbooks for common attack classes."""

PLAYBOOKS: dict[str, list[str]] = {
    "DoS": ["confirm traffic burst", "rate-limit the source", "preserve evidence", "review recovery"],
    "DDoS": ["confirm distributed sources", "engage upstream filtering", "preserve evidence", "review recovery"],
    "Port Scan": ["validate scan pattern", "restrict exposed services", "monitor recurrence", "review source reputation"],
    "Brute Force": ["confirm repeated authentication attempts", "rate-limit authentication", "enforce MFA", "review account logs"],
    "Web Attack": ["validate request indicators", "apply WAF/rate limits", "patch affected service", "review application logs"],
    "Botnet": ["validate IOC match", "isolate affected host", "preserve evidence", "rotate exposed credentials"],
}


def get_playbook(attack_type: str) -> list[str]:
    return list(PLAYBOOKS.get(attack_type, ["validate detection", "preserve evidence", "review response"]))