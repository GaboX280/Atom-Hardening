import pytest

from atom_core.models.finding import Finding


def test_finding_defaults_and_to_dict() -> None:
    """Verifica defaults, normalización y conversión a diccionario."""
    finding = Finding(
        title="Check Test",
        status=" pass ",
        severity="info",
        details="Detalles de prueba",
    )

    assert finding.title == "Check Test"
    assert finding.status == "PASS"
    assert finding.severity == "INFO"
    assert finding.confidence == "HIGH"
    assert len(finding.finding_id) == 8
    assert finding.timestamp is not None
    assert isinstance(finding.compliance, list)

    data = finding.to_dict()
    assert isinstance(data, dict)
    assert data["title"] == "Check Test"
    assert data["status"] == "PASS"
    assert data["finding_id"] == finding.finding_id
    assert data["confidence"] == "HIGH"


def test_finding_str_repr() -> None:
    """Verifica que la representación contenga la información requerida."""
    finding = Finding(
        title="Verificación Crítica",
        status="FAIL",
        severity="CRITICAL",
        details="Falla detectada",
        recommendation="Corregir inmediato",
        confidence="medium",
    )

    text = str(finding)
    assert "[FAIL] Verificación Crítica" in text
    assert "Severity: CRITICAL" in text
    assert "Confidence: MEDIUM" in text
    assert "Details: Falla detectada" in text
    assert "Recommendation: Corregir inmediato" in text


def test_finding_rejects_invalid_status() -> None:
    with pytest.raises(ValueError, match="Invalid finding status"):
        Finding(title="Invalid", status="UNKNOWN", severity="LOW")


def test_finding_rejects_invalid_severity() -> None:
    with pytest.raises(ValueError, match="Invalid finding severity"):
        Finding(title="Invalid", status="FAIL", severity="UNKNOWN")


def test_finding_rejects_negative_score() -> None:
    with pytest.raises(ValueError, match="cannot be negative"):
        Finding(title="Invalid", status="FAIL", severity="HIGH", severity_score=-1)
