from atom_core.core.security_summary import SecuritySummary
from atom_core.models.finding import Finding


def test_security_summary_basic() -> None:
    """Verifica que el resumen agrupe correctamente los estados, severidades y categorías."""
    findings = [
        Finding(
            title="Firewall Activo",
            status="PASS",
            severity="INFO",
            category="Red",
            module="Mod1",
        ),
        Finding(
            title="Puerto Expuesto",
            status="WARNING",
            severity="MEDIUM",
            category="Red",
            module="Mod1",
        ),
        Finding(
            title="Password Debil",
            status="FAIL",
            severity="HIGH",
            category="Autenticación",
            module="Mod2",
        ),
    ]

    summary = SecuritySummary.summarize(findings)

    assert summary["total"] == 3
    assert summary["status"]["PASS"] == 1
    assert summary["status"]["WARNING"] == 1
    assert summary["status"]["FAIL"] == 1
    assert summary["status"]["ERROR"] == 0

    assert summary["severity"]["HIGH"] == 1
    assert summary["severity"]["MEDIUM"] == 1
    assert summary["severity"]["INFO"] == 1

    assert summary["categories"]["Red"]["PASS"] == 1
    assert summary["categories"]["Red"]["WARNING"] == 1
    assert summary["categories"]["Autenticación"]["FAIL"] == 1


def test_security_summary_empty() -> None:
    """Verifica el resumen cuando no se proporcionan hallazgos."""
    summary = SecuritySummary.summarize([])

    assert summary["total"] == 0
    assert summary["status"]["PASS"] == 0
    assert summary["status"]["FAIL"] == 0
    assert summary["categories"] == {}
