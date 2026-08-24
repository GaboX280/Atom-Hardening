from atom_core.base_auditor import BaseAuditor


class DummyAuditor(BaseAuditor):
    """Clase concreta para probar la funcionalidad de BaseAuditor."""

    def ejecutar(self) -> None:
        pass


def test_base_auditor_add_and_clear_finding() -> None:
    """Verifica la adición y limpieza de hallazgos en BaseAuditor."""
    auditor = DummyAuditor()
    assert len(auditor.report) == 0

    auditor.add_finding(
        title="Prueba 1",
        status="PASS",
        severity="INFO",
        details="Detalles prueba",
    )

    assert len(auditor.report) == 1
    assert auditor.report[0].title == "Prueba 1"

    auditor.clear_report()
    assert len(auditor.report) == 0


def test_base_auditor_command_exists() -> None:
    """Verifica la comprobación de existencia de comandos en el sistema."""
    auditor = DummyAuditor()
    # 'python' o el shell ejecutable debe existir en el sistema actual
    assert auditor.command_exists("python") or auditor.command_exists("cmd") or auditor.command_exists("sh")
    assert not auditor.command_exists("non_existent_command_12345")


def test_base_auditor_run_checks_handling_exception() -> None:
    """Verifica que run_checks maneje adecuadamente las excepciones internas de los checks."""
    auditor = DummyAuditor()

    def failing_check(aud: BaseAuditor) -> None:
        raise ValueError("Error simulado en check")

    def passing_check(aud: BaseAuditor) -> None:
        aud.add_finding(title="OK Check", status="PASS", severity="INFO")

    results = auditor.run_checks([passing_check, failing_check], clear=True)

    assert len(results) == 2
    assert results[0].title == "OK Check"
    assert results[1].status == "ERROR"
    assert "Error simulado en check" in results[1].details
