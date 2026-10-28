from unittest.mock import Mock

import pytest

from atom_core.base_auditor import CommandResult
from atom_core.modules.linux.checks.password_policy import audit_password_policy


@pytest.fixture
def auditor() -> Mock:
    mock = Mock()
    mock.log = Mock()
    mock.config = {"password_policy": {"max_age_days": 90}}
    mock.add_finding = Mock()
    mock._record_command_error = Mock(return_value=False)
    return mock


@pytest.mark.parametrize("days", [1, 30, 90])
def test_password_policy_passes_within_configured_limit(
    auditor: Mock, days: int
) -> None:
    auditor._run_command.return_value = CommandResult(
        f"PASS_MAX_DAYS {days}", "", 0
    )

    audit_password_policy(auditor)

    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "PASS"
    assert f"{days} días" in finding["details"]


@pytest.mark.parametrize("days", [91, 120])
def test_password_policy_warns_when_age_exceeds_configured_limit(
    auditor: Mock, days: int
) -> None:
    auditor._run_command.return_value = CommandResult(
        f"PASS_MAX_DAYS {days}", "", 0
    )

    audit_password_policy(auditor)

    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "WARNING"
    assert "límite configurado es 90 días" in finding["details"]


@pytest.mark.parametrize("days", [-1, 0])
def test_password_policy_warns_for_special_age_values(
    auditor: Mock, days: int
) -> None:
    auditor._run_command.return_value = CommandResult(
        f"PASS_MAX_DAYS {days}", "", 0
    )

    audit_password_policy(auditor)

    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "WARNING"


def test_password_policy_uses_configured_maximum_age(auditor: Mock) -> None:
    auditor.config["password_policy"]["max_age_days"] = 60
    auditor._run_command.return_value = CommandResult("PASS_MAX_DAYS 90", "", 0)

    audit_password_policy(auditor)

    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "WARNING"
    assert "límite configurado es 60 días" in finding["details"]


@pytest.mark.parametrize(
    "output",
    [
        "",
        "# PASS_MAX_DAYS 90",
        "PASS_MAX_DAYS invalid",
    ],
)
def test_password_policy_warns_when_value_cannot_be_parsed(
    auditor: Mock, output: str
) -> None:
    auditor._run_command.return_value = CommandResult(output, "", 0)

    audit_password_policy(auditor)

    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "WARNING"
    assert finding["confidence"] == "LOW"
