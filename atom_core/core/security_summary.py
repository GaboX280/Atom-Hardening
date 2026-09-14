from collections import Counter, defaultdict

from atom_core.models.finding import Finding


class SecuritySummary:
    """Build a stable, machine-readable summary from findings."""

    @staticmethod
    def summarize(findings: list[Finding]) -> dict:
        status = Counter(finding.status for finding in findings)
        severity = Counter(finding.severity for finding in findings)
        categories: dict[str, Counter[str]] = defaultdict(Counter)

        for finding in findings:
            category = finding.category or "General"
            categories[category][finding.status] += 1

        total = len(findings)
        actionable = sum(
            count for state, count in status.items() if state != "PASS"
        )
        failed = status.get("FAIL", 0)
        errors = status.get("ERROR", 0)

        category_summary = {
            category: {
                "PASS": values.get("PASS", 0),
                "WARNING": values.get("WARNING", 0),
                "FAIL": values.get("FAIL", 0),
                "ERROR": values.get("ERROR", 0),
            }
            for category, values in categories.items()
        }

        return {
            "total": total,
            "actionable": actionable,
            "pass_rate": round(
                (status.get("PASS", 0) / total) * 100, 2
            ) if total else 0.0,
            "failure_rate": round((failed / total) * 100, 2) if total else 0.0,
            "error_rate": round((errors / total) * 100, 2) if total else 0.0,
            "status": {
                "PASS": status.get("PASS", 0),
                "WARNING": status.get("WARNING", 0),
                "FAIL": failed,
                "ERROR": errors,
            },
            "severity": {
                "CRITICAL": severity.get("CRITICAL", 0),
                "HIGH": severity.get("HIGH", 0),
                "MEDIUM": severity.get("MEDIUM", 0),
                "LOW": severity.get("LOW", 0),
                "INFO": severity.get("INFO", 0),
            },
            "categories": category_summary,
        }
