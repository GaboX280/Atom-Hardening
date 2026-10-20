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


def run_check(auditor: Mock, output: str) -> None:
    if output.startswith("ERROR: "):
        auditor._run_command.return_value = CommandResult(
            stdout="",
            stderr="",
            returncode=None,
            error=output.removeprefix("ERROR: "),
        )
    else:
        auditor._run_command.return_value = CommandResult(
            stdout=output,
            stderr="",
            returncode=0,
        )
    audit_firewall(auditor)


def test_firewall_passes_when_all_profiles_are_on(auditor: Mock) -> None:
    run_check(
        auditor,
        """
        Domain Profile Settings:
            State ON
        Private Profile Settings:
            State ON
        Public Profile Settings:
            State ON
        """,
    )

    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "PASS"
    assert finding["severity"] == "INFO"
    assert finding["confidence"] == "HIGH"


def test_firewall_fails_when_any_profile_is_off(auditor: Mock) -> None:
    run_check(
        auditor,
        """
        Domain Profile Settings:
            State ON
        Private Profile Settings:
            State OFF
        Public Profile Settings:
            State ON
        """,
    )

    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "FAIL"
    assert finding["severity"] == "HIGH"


def test_firewall_warns_when_output_cannot_be_interpreted(auditor: Mock) -> None:
    run_check(auditor, "unexpected output")

    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "WARNING"
    assert finding["confidence"] == "LOW"


def test_firewall_reports_command_errors(auditor: Mock) -> None:
    run_check(auditor, "ERROR: ACCESS_DENIED")

    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "ERROR"
    assert finding["severity"] == "HIGH"
