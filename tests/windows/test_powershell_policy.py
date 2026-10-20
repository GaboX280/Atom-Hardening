from unittest.mock import Mock

import pytest

from atom_core.base_auditor import CommandResult
from atom_core.modules.windows.checks.powershell_policy import audit_powershell_policy


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
    audit_powershell_policy(auditor)


@pytest.mark.parametrize("policy", ["RemoteSigned", "AllSigned", "Restricted"])
def test_powershell_policy_passes_for_known_restrictive_policies(
    auditor: Mock, policy: str
) -> None:
    run_check(auditor, policy)
    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "PASS"
    assert policy in finding["details"]


@pytest.mark.parametrize("policy", ["Bypass", "Unrestricted"])
def test_powershell_policy_fails_for_permissive_policies(
    auditor: Mock, policy: str
) -> None:
    run_check(auditor, policy)
    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "FAIL"
    assert finding["severity"] == "HIGH"


def test_powershell_policy_reports_empty_output_as_error(auditor: Mock) -> None:
    run_check(auditor, "")
    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "ERROR"


def test_powershell_policy_reports_command_errors(auditor: Mock) -> None:
    auditor._run_command.return_value = CommandResult(
        stdout="",
        stderr="access denied",
        returncode=None,
        error="ACCESS_DENIED",
    )
    audit_powershell_policy(auditor)
    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "ERROR"
