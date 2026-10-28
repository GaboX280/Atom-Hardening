from unittest.mock import Mock

import pytest

from atom_core.base_auditor import CommandResult
from atom_core.modules.windows.checks.password_policy import audit_password_policy


@pytest.fixture
def auditor() -> Mock:
    mock = Mock()
    mock.log = Mock()
    mock.config = {"password_policy": {"min_length": 14}}
    mock.add_finding = Mock()

    def record_command_error(
        result: CommandResult,
        title: str,
        allowed_returncodes: tuple[int, ...] = (0,),
    ) -> bool:
        if result.error is None and result.returncode in allowed_returncodes:
            return False
        mock.add_finding(
            title=title,
            status="ERROR",
            severity="HIGH",
            details=result.error or f"El comando terminó con código {result.returncode}.",
            recommendation="Verificar la ejecución del comando.",
            category="Execution Error",
            confidence="HIGH",
        )
        return True

    mock._record_command_error = Mock(side_effect=record_command_error)
    return mock


def run_check(auditor: Mock, output: str, returncode: int = 0) -> None:
    auditor._run_command.return_value = CommandResult(
        stdout=output,
        stderr="",
        returncode=returncode,
    )
    audit_password_policy(auditor)


def test_password_policy_passes_when_minimum_length_meets_target(auditor: Mock) -> None:
    run_check(auditor, '{"minimum_password_length":14}')
    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "PASS"
    assert "14 caracteres" in finding["details"]


def test_password_policy_fails_when_minimum_length_is_too_low(auditor: Mock) -> None:
    run_check(auditor, '{"minimum_password_length":0}')
    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "FAIL"
    assert "0 caracteres" in finding["details"]


def test_password_policy_reports_invalid_json_as_error(auditor: Mock) -> None:
    run_check(auditor, "unexpected output")
    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "ERROR"
    assert finding["severity"] == "HIGH"


def test_password_policy_reports_command_errors(auditor: Mock) -> None:
    auditor._run_command.return_value = CommandResult(
        stdout="",
        stderr="access denied",
        returncode=None,
        error="ACCESS_DENIED",
    )
    audit_password_policy(auditor)
    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "ERROR"
