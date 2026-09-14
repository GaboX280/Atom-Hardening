from atom_core.core.security_summary import SecuritySummary
from atom_core.models.finding import Finding


def test_security_summary_basic() -> None:
    """Verifica estados, severidades, categorías y métricas derivadas."""
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
        Finding(
            title="Check no disponible",
            status="ERROR",
            severity="HIGH",
            category="Sistema",
            module="Mod3",
        ),
    ]

    summary = SecuritySummary.summarize(findings)

    assert summary["total"] == 4
    assert summary["actionable"] == 3
    assert summary["pass_rate"] == 25.0
    assert summary["failure_rate"] == 25.0
    assert summary["error_rate"] == 25.0

    assert summary["status"]["PASS"] == 1
    assert summary["status"]["WARNING"] == 1
    assert summary["status"]["FAIL"] == 1
    assert summary["status"]["ERROR"] == 1

    assert summary["severity"]["HIGH"] == 2
    assert summary["severity"]["MEDIUM"] == 1
    assert summary["severity"]["INFO"] == 1

    assert summary["categories"]["Red"]["PASS"] == 1
    assert summary["categories"]["Red"]["WARNING"] == 1
    assert summary["categories"]["Autenticación"]["FAIL"] == 1
    assert summary["categories"]["Sistema"]["ERROR"] == 1


def test_security_summary_empty() -> None:
    """Verifica métricas seguras cuando no existen hallazgos."""
    summary = SecuritySummary.summarize([])

    assert summary["total"] == 0
    assert summary["actionable"] == 0
    assert summary["pass_rate"] == 0.0
    assert summary["failure_rate"] == 0.0
    assert summary["error_rate"] == 0.0
    assert summary["status"]["PASS"] == 0
    assert summary["status"]["FAIL"] == 0
    assert summary["categories"] == {}
