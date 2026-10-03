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
        """Return a plain Spanish rating string based on the score.

        Ranges:
        - 90-100: EXCELENTE
        - 75-89 : BUENO
        - 50-74 : MODERADO
        - 0-49  : CRITICO

        La función devuelve texto sin códigos ANSI para que el valor sea
        reutilizable en reportes JSON, HTML y otras integraciones.
        """
        if score >= 90:
            return "EXCELENTE (90-100)"
        elif score >= 75:
            return "BUENO (75-89)"
        elif score >= 50:
            return "MODERADO (50-74)"
        else:
            return "CRITICO (0-49)"
