from collections import Counter


class SecuritySummary:

    @staticmethod
    def summarize(findings):

        status = Counter(
            finding.status.upper()
            for finding in findings
        )

        severity = Counter(
            finding.severity.upper()
            for finding in findings
        )

        return {

            "total": len(findings),

            "status": {

                "PASS": status.get("PASS", 0),
                "WARNING": status.get("WARNING", 0),
                "FAIL": status.get("FAIL", 0),
                "ERROR": status.get("ERROR", 0)

            },

            "severity": {

                "CRITICAL": severity.get("CRITICAL", 0),
                "HIGH": severity.get("HIGH", 0),
                "MEDIUM": severity.get("MEDIUM", 0),
                "LOW": severity.get("LOW", 0),
                "INFO": severity.get("INFO", 0)

            }

        }