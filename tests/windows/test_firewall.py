from unittest.mock import Mock

import pytest

from atom_core.base_auditor import CommandResult
from atom_core.modules.windows.checks.firewall import audit_firewall


@pytest.fixture
def auditor() -> Mock:
    mock = Mock()
    mock.log = Mock()
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
    audit_firewall(auditor)


def test_firewall_passes_with_structured_output_independent_of_os_language(auditor: Mock) -> None:
    run_check(
        auditor,
        '[{"Name":"Domain","Enabled":true},'
        '{"Name":"Private","Enabled":true},'
        '{"Name":"Public","Enabled":true}]',
    )
    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "PASS"
    assert finding["severity"] == "INFO"
    assert finding["confidence"] == "HIGH"
    auditor._run_command.assert_called_once()
    assert isinstance(auditor._run_command.call_args.args[0], list)


def test_firewall_fails_when_any_profile_is_disabled(auditor: Mock) -> None:
    run_check(
        auditor,
        '[{"Name":"Domain","Enabled":true},'
        '{"Name":"Private","Enabled":false},'
        '{"Name":"Public","Enabled":true}]',
    )
    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "FAIL"
    assert finding["severity"] == "HIGH"
    assert "PRIVATE" in finding["details"]


def test_firewall_reports_unparseable_structured_output_as_error(auditor: Mock) -> None:
    run_check(auditor, "unexpected output")
    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "ERROR"
    assert finding["severity"] == "HIGH"


def test_firewall_reports_command_errors(auditor: Mock) -> None:
    auditor._run_command.return_value = CommandResult(
        stdout="",
        stderr="access denied",
        returncode=None,
        error="ACCESS_DENIED",
    )
    audit_firewall(auditor)
    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "ERROR"
    assert finding["severity"] == "HIGH"
