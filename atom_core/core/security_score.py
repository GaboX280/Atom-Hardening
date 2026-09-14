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

    RATINGS: ClassVar[tuple[tuple[int, str], ...]] = (
        (90, "EXCELENTE"),
        (75, "BUENO"),
        (50, "MODERADO"),
        (0, "CRITICO"),
    )

    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    ORANGE = "\033[33m"
    RED = "\033[91m"
    RESET = "\033[0m"

    @classmethod
    def calculate(cls, findings: list[Finding]) -> int:
        """Start at 100 and deduct only from actionable non-PASS findings.

        ERROR represents an inability to evaluate a check and therefore does not
        reduce the security posture score. A positive ``severity_score`` overrides
        the default severity penalty for findings that need custom weighting.
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
        """Return the normalized rating and its canonical score range."""
        if not 0 <= score <= 100:
            raise ValueError("score must be between 0 and 100")

        for minimum, label in cls.RATINGS:
            if score >= minimum:
                maximum = 100 if minimum == 90 else next(
                    lower - 1
                    for lower, _ in cls.RATINGS
                    if lower < minimum
                )
                color = {
                    "EXCELENTE": cls.GREEN,
                    "BUENO": cls.YELLOW,
                    "MODERADO": cls.ORANGE,
                    "CRITICO": cls.RED,
                }[label]
                return f"{color}{label} ({minimum}-{maximum}){cls.RESET}"

        return f"{cls.RED}CRITICO (0-49){cls.RESET}"
