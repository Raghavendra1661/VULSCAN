"""Build a compact JSON-serializable scan summary."""
from datetime import datetime, timezone

def summarize(host, open_ports, findings, duration, scanned_count):
    counts = {"High": 0, "Medium": 0, "Low": 0, "Info": 0}
    for item in findings:
        severity = item.get("severity", "Info")
        counts[severity] = counts.get(severity, 0) + 1
    return {
        "target": host,
        "scanned_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "duration_seconds": round(duration, 2),
        "ports_checked": scanned_count,
        "open_ports": open_ports,
        "findings": findings,
        "summary": counts,
        "note": "Automated checks can produce false positives and do not replace a professional security assessment."
    }
