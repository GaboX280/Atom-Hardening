from unittest.mock import Mock

import pytest

from atom_core.modules.windows.checks.firewall import audit_firewall


@pytest.fixture
def auditor() -> Mock:
    mock = Mock()
    mock.log = Mock()
    mock.add_finding = Mock()
    return mock


def run_check(auditor: Mock, output: str) -> None:
    auditor._run_command.return_value = output
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
    assert finding["severity"] == "MEDIUM"
