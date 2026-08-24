from atom_core.models.finding import Finding


def test_finding_defaults_and_to_dict() -> None:
    """Verifica la generación por defecto de ID, marca de tiempo y conversión a diccionario."""
    finding = Finding(
        title="Check Test",
        status="PASS",
        severity="INFO",
        details="Detalles de prueba",
    )

    assert finding.title == "Check Test"
    assert len(finding.finding_id) == 8
    assert finding.timestamp is not None
    assert isinstance(finding.compliance, list)

    data = finding.to_dict()
    assert isinstance(data, dict)
    assert data["title"] == "Check Test"
    assert data["status"] == "PASS"
    assert data["finding_id"] == finding.finding_id


def test_finding_str_repr() -> None:
    """Verifica que la representación en texto contenga la información requerida."""
    finding = Finding(
        title="Verificación Crítica",
        status="FAIL",
        severity="CRITICAL",
        details="Falla detectada",
        recommendation="Corregir inmediato",
    )

    text = str(finding)
    assert "[FAIL] Verificación Crítica" in text
    assert "Severity: CRITICAL" in text
    assert "Details: Falla detectada" in text
    assert "Recommendation: Corregir inmediato" in text
