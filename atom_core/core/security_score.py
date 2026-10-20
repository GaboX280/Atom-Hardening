from typing import ClassVar

from atom_core.models.finding import Finding


class SecurityScore:
    """Calcula una puntuación acotada a partir de hallazgos normalizados."""

    PENALTIES: ClassVar[dict[str, int]] = {
        "CRITICAL": 60,
        "HIGH": 20,
        "MEDIUM": 15,
        "LOW": 5,
        "INFO": 0,
    }

    @classmethod
    def calculate(cls, findings: list[Finding]) -> int:
        """Calcula una puntuación entre 0 y 100.

        Los hallazgos PASS y ERROR no reducen la puntuación. ERROR indica que
        el control no pudo evaluar el sistema y no confirma por sí mismo una
        debilidad de seguridad.
        """
        score = 100

        for finding in findings:
            if finding.status in {"PASS", "ERROR"}:
                continue

            severity = finding.severity.upper()
            penalty = (
                finding.severity_score
                if finding.severity_score > 0
                else cls.PENALTIES.get(severity, 5)
            )
            score -= penalty

        return max(0, min(100, score))

    @staticmethod
    def rating(score: int) -> str:
        """Devuelve la clasificación en español sin códigos ANSI."""
        if not 0 <= score <= 100:
            raise ValueError("score debe estar entre 0 y 100")

        if score >= 90:
            return "EXCELENTE (90-100)"
        if score >= 75:
            return "BUENO (75-89)"
        if score >= 50:
            return "MODERADO (50-74)"
        return "CRITICO (0-49)"
