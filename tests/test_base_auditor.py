import sys

from atom_core.base_auditor import BaseAuditor
from atom_core.models.finding import Finding


class DummyAuditor(BaseAuditor):
    """Clase concreta para probar la funcionalidad de BaseAuditor."""

    def ejecutar(self) -> list[Finding]:
        return []


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


def test_base_auditor_run_command_returns_structured_success() -> None:
    """Verifica que una ejecución correcta devuelva campos separados."""
    auditor = DummyAuditor()

    result = auditor._run_command([sys.executable, "-c", "print('salida')"])

    assert result.stdout == "salida"
    assert result.stderr == ""
    assert result.returncode == 0
    assert result.error is None


def test_base_auditor_run_command_preserves_nonzero_exit_code() -> None:
    """Un código distinto de cero no debe confundirse con un error de ejecución."""
    auditor = DummyAuditor()
    command = [
        sys.executable,
        "-c",
        "import sys; print('diagnostico', file=sys.stderr); sys.exit(7)",
    ]

    result = auditor._run_command(command)

    assert result.stdout == ""
    assert result.stderr == "diagnostico"
    assert result.returncode == 7
    assert result.error is None
    assert auditor._record_command_error(result, "Comprobación de prueba") is False
    assert auditor.report == []


def test_base_auditor_run_command_reports_timeout_as_error() -> None:
    """Verifica que un timeout se registre como error de ejecución."""
    auditor = DummyAuditor()
    result = auditor._run_command(
        [sys.executable, "-c", "import time; time.sleep(2)"],
        timeout=0.05,
    )

    assert result.error == "COMMAND_TIMEOUT"
    assert result.returncode is not None
    assert auditor._record_command_error(result, "Comprobación de prueba") is True
    assert len(auditor.report) == 1
    assert auditor.report[0].status == "ERROR"
