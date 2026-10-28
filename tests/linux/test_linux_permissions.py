from unittest.mock import Mock

import pytest

from atom_core.base_auditor import CommandResult
from atom_core.modules.linux.checks.permissions import audit_permissions


@pytest.fixture
def auditor() -> Mock:
    mock = Mock()
    mock.log = Mock()
    mock.add_finding = Mock()
    mock._record_command_error = Mock(return_value=False)
    return mock


def run_check(auditor: Mock, modes: dict[str, str]) -> None:
    auditor._run_command.side_effect = lambda command: CommandResult(
        stdout=modes[command.rsplit(" ", 1)[-1]],
        stderr="",
        returncode=0,
    )
    audit_permissions(auditor)


def test_permissions_accept_common_secure_modes(auditor: Mock) -> None:
    run_check(
        auditor,
        {
            "/etc/passwd": "644",
            "/etc/shadow": "640",
            "/etc/sudoers": "440",
        },
    )

    findings = [call.kwargs for call in auditor.add_finding.call_args_list]
    assert len(findings) == 3
    assert all(finding["status"] == "PASS" for finding in findings)


@pytest.mark.parametrize(
    ("path", "mode"),
    [
        ("/etc/passwd", "666"),
        ("/etc/shadow", "644"),
        ("/etc/shadow", "660"),
        ("/etc/sudoers", "664"),
        ("/etc/sudoers", "4750"),
    ],
)
def test_permissions_fail_for_excessive_access(
    auditor: Mock, path: str, mode: str
) -> None:
    modes = {
        "/etc/passwd": "644",
        "/etc/shadow": "640",
        "/etc/sudoers": "440",
    }
    modes[path] = mode
    run_check(auditor, modes)

    findings = [call.kwargs for call in auditor.add_finding.call_args_list]
    finding = next(item for item in findings if path in item["title"])
    assert finding["status"] == "FAIL"
    assert finding["severity"] == "HIGH"


def test_permissions_report_invalid_octal_mode_as_error(auditor: Mock) -> None:
    run_check(
        auditor,
        {
            "/etc/passwd": "888",
            "/etc/shadow": "640",
            "/etc/sudoers": "440",
        },
    )

    finding = auditor.add_finding.call_args_list[0].kwargs
    assert finding["status"] == "ERROR"
    assert finding["confidence"] == "LOW"
