def calculate_severity_summary(findings):
    summary = {
        "critical": 0,
        "high": 0,
        "medium": 0,
        "low": 0,
        "info": 0,
        "total": len(findings)
    }

    for finding in findings:
        severity = str(finding.get("severity", "info")).lower()

        if severity in ("critical", "high", "medium", "low", "info"):
            summary[severity] += 1
        else:
            summary["info"] += 1

    return summary
