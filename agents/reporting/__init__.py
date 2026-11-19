"""
Reporting helpers: generate textual summaries from detections.
"""
from __future__ import annotations

from collections import Counter
from typing import Any, Dict, Iterable, List, Optional
import json

from .incident_correlation import correlate_incidents


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


def generate_incident_report(incident: Dict[str, Any], export_format: str = "json") -> Any:
    """Create a plain-language incident report in JSON, Markdown, or text."""
    if export_format not in {"json", "markdown", "text"}:
        raise ValueError("export_format must be json, markdown, or text")
    events = incident.get("events", [])
    narrative = (
        f"A {incident.get('severity', 'unknown')} severity {incident.get('attack_type', 'unknown')} "
        f"incident was observed from {incident.get('source_ip', 'unknown')} "
        f"against {incident.get('dest_ip', 'unknown')}. "
        f"{len(events)} related detection event(s) were correlated in the "
        f"{incident.get('kill_chain_stage', 'unknown')} stage."
    )
    if export_format == "json":
        return {"executive_summary": narrative, "technical_appendix": incident}
    appendix = json.dumps(incident, indent=2, default=str)
    return "# Incident Report\n\n## Executive Summary\n" + narrative + "\n\n## Technical Appendix\n```json\n" + appendix + "\n```\n"


def generate_pdf_report(incident: Dict[str, Any]) -> bytes:
    """Return a minimal standards-compliant PDF without external dependencies."""
    text = generate_incident_report(incident, "text").replace("(", "\\(").replace(")", "\\)")
    stream = f"BT /F1 10 Tf 50 760 Td ({text[:3000]}) Tj ET"
    objects = ["<< /Type /Catalog /Pages 2 0 R >>", "<< /Type /Pages /Kids [3 0 R] /Count 1 >>", "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 4 0 R >> >> /Contents 5 0 R >>", "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", f"<< /Length {len(stream.encode())} >>\nstream\n{stream}\nendstream"]
    pdf = "%PDF-1.4\n"; offsets = [0]
    for index, obj in enumerate(objects, 1):
        offsets.append(len(pdf.encode())); pdf += f"{index} 0 obj\n{obj}\nendobj\n"
    xref = len(pdf.encode()); pdf += f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n" + "".join(f"{offset:010d} 00000 n \n" for offset in offsets[1:]) + f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF"
    return pdf.encode()
