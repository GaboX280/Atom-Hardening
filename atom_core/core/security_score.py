from typing import ClassVar

from atom_core.models.finding import Finding


class SecurityScore:
    """Calculate a bounded security posture score from normalized findings."""

    PENALTIES: ClassVar[dict[str, int]] = {
        "CRITICAL": 60,
        "HIGH": 20,
        "MEDIUM": 15,
        "LOW": 5,
        "INFO": 0,
    }

    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    ORANGE = "\033[33m"
    RED = "\033[91m"
    RESET = "\033[0m"

    @classmethod
    def calculate(cls, findings: list[Finding]) -> int:
        """Return a score from 0 to 100 based on actionable findings.

        PASS and ERROR do not reduce the score. ERROR means the check could not
        evaluate the system and must remain visible in the summary without being
        treated as a discovered security weakness.
        """
        score = 100

        for finding in findings:
            if finding.status in {"PASS", "ERROR"}:
                continue

            penalty = (
                finding.severity_score
                if finding.severity_score > 0
                else cls.PENALTIES[finding.severity]
            )
            score -= penalty

        return max(0, min(100, score))

    @classmethod
    def rating(cls, score: int) -> str:
        """Return the canonical rating and the matching score range."""
        if not 0 <= score <= 100:
            raise ValueError("score must be between 0 and 100")

        if score >= 90:
            label, minimum, maximum, color = "EXCELENTE", 90, 100, cls.GREEN
        elif score >= 75:
            label, minimum, maximum, color = "BUENO", 75, 89, cls.YELLOW
        elif score >= 50:
            label, minimum, maximum, color = "MODERADO", 50, 74, cls.ORANGE
        else:
            label, minimum, maximum, color = "CRITICO", 0, 49, cls.RED

        return f"{color}{label} ({minimum}-{maximum}){cls.RESET}"
