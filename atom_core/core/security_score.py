from typing import ClassVar


class SecurityScore:
    # Penalty values per severity (higher penalties for critical findings)
    PENALTIES: ClassVar[dict[str, int]] = {
        "CRITICAL": 60,
        "HIGH": 20,
        "MEDIUM": 15,
        "LOW": 5,
        "INFO": 0,
    }

    # ANSI color codes for terminal output
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    ORANGE = "\033[33m"
    RED = "\033[91m"
    RESET = "\033[0m"

    @staticmethod
    def calculate(findings):
        """Calculate a security score based on findings.

        Starts at 100 and subtracts penalties for each finding that is not a PASS.
        """
        score = 100
        for finding in findings:
            if finding.status != "PASS":
                penalty = SecurityScore.PENALTIES.get(finding.severity.upper(), 5)
                score -= penalty
        return max(0, score)

    @staticmethod
    def rating(score):
        """Return a colored Spanish rating string based on the score.

        The ranges roughly follow:
        - 90‑100: EXCELENTE (verde)
        - 75‑89 : BUENO (amarillo)
        - 50‑74 : MODERADO (naranja)
        - 0‑49  : CRITICO (rojo)
        """
        if score >= 90:
            return f"{SecurityScore.GREEN}EXCELENTE (80-100){SecurityScore.RESET}"
        elif score >= 75:
            return f"{SecurityScore.YELLOW}BUENO (60-79){SecurityScore.RESET}"
        elif score >= 50:
            return f"{SecurityScore.ORANGE}MODERADO (40-59){SecurityScore.RESET}"
        else:
            return f"{SecurityScore.RED}CRITICO (0-39){SecurityScore.RESET}"
