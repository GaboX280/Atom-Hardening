from collections import Counter


class SecuritySummary:

    @staticmethod
    def summarize(findings):

        status = Counter(
            f.status.upper()
            for f in findings
        )

        severity = Counter(
            f.severity.upper()
            for f in findings
        )

        modules = Counter(
            f.module
            for f in findings
        )

        categories = Counter(
            f.category
            for f in findings
        )


        return {

            "total": len(findings),

            "status": dict(status),

            "severity": dict(severity),

            "modules": dict(modules),

            "categories": dict(categories)

        }