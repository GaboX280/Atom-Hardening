from unittest.mock import Mock

import pytest

from atom_core.base_auditor import CommandResult
from atom_core.modules.windows.checks.password_policy import audit_password_policy


@pytest.fixture
def auditor() -> Mock:
    mock = Mock()
    mock.log = Mock()
    mock.config = {"password_policy": {"min_length": 8}}
    mock.add_finding = Mock()
    mock._record_command_error = Mock(return_value=False)
    return mock


@pytest.mark.parametrize(
    "output",
    [
        "Minimum password length: 12",
        "Longitud mínima de contraseña: 12",
    ],
)
def test_password_policy_passes_for_sufficient_length(
    auditor: Mock, output: str
) -> None:
    auditor._run_command.return_value = CommandResult(output, "", 0)

    audit_password_policy(auditor)

    assert auditor.add_finding.call_args.kwargs["status"] == "PASS"
    assert auditor.add_finding.call_args.kwargs["severity"] == "INFO"


@pytest.mark.parametrize(
    "output",
    [
        "Minimum password length: 4",
        "Longitud mínima de contraseña: 0",
    ],
)
def test_password_policy_fails_for_insufficient_length(
    auditor: Mock, output: str
) -> None:
    auditor._run_command.return_value = CommandResult(output, "", 0)

    audit_password_policy(auditor)

    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "FAIL"
    assert finding["severity"] == "MEDIUM"


@pytest.mark.parametrize(
    "output",
    [
        "unexpected command output",
        "Minimum password length: unknown",
        "Longitud mínima de contraseña: desconocida",
    ],
)
def test_password_policy_warns_when_length_cannot_be_parsed(
    auditor: Mock, output: str
) -> None:
    auditor._run_command.return_value = CommandResult(output, "", 0)

    audit_password_policy(auditor)

    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "WARNING"
    assert finding["confidence"] == "LOW"


def test_password_policy_returns_when_command_fails(auditor: Mock) -> None:
    result = CommandResult("", "Access denied", 1)
    auditor._run_command.return_value = result
    auditor._record_command_error.return_value = True

    audit_password_policy(auditor)

    auditor._record_command_error.assert_called_once_with(
        result, "Password Policy Check"
    )
    auditor.add_finding.assert_not_called()
