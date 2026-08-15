"""
Reporting helpers: generate textual summaries from detections.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable, List, Optional


def generate_report(
    period_start,
    period_end,
    detections: Optional[Iterable[Any]] = None,
) -> Dict[str, Any]:
    detections = list(detections or [])
    labels: List[str] = []
    for d in detections:
        if isinstance(d, dict):
            labels.append(str(d.get("predicted") or d.get("predicted_class") or d))
        else:
            labels.append(str(d))
    counts = Counter(labels)
    return {
        "start": period_start,
        "end": period_end,
        "total": len(labels),
        "by_class": dict(counts),
        "summary": f"{len(labels)} detections; classes={dict(counts)}",
    }
