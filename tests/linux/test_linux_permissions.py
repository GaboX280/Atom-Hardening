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


def run_check(auditor: Mock, metadata: dict[str, str]) -> None:
    auditor._run_command.side_effect = lambda command: CommandResult(
        stdout=metadata[command.rsplit(" ", 1)[-1]],
        stderr="",
        returncode=0,
    )
    audit_permissions(auditor)


def secure_metadata() -> dict[str, str]:
    return {
        "/etc/passwd": "644:root:root",
        "/etc/shadow": "640:root:shadow",
        "/etc/sudoers": "440:root:root",
    }


def test_permissions_and_ownership_accept_common_secure_metadata(auditor: Mock) -> None:
    run_check(auditor, secure_metadata())

    findings = [call.kwargs for call in auditor.add_finding.call_args_list]
    assert len(findings) == 3
    assert all(finding["status"] == "PASS" for finding in findings)


@pytest.mark.parametrize(
    ("path", "metadata"),
    [
        ("/etc/passwd", "666:root:root"),
        ("/etc/shadow", "644:root:shadow"),
        ("/etc/shadow", "660:root:shadow"),
        ("/etc/sudoers", "664:root:root"),
        ("/etc/sudoers", "4750:root:root"),
    ],
)
def test_permissions_fail_for_excessive_access(
    auditor: Mock, path: str, metadata: str
) -> None:
    values = secure_metadata()
    values[path] = metadata
    run_check(auditor, values)

    findings = [call.kwargs for call in auditor.add_finding.call_args_list]
    finding = next(item for item in findings if path in item["title"])
    assert finding["status"] == "FAIL"
    assert finding["severity"] == "HIGH"


@pytest.mark.parametrize(
    ("path", "metadata"),
    [
        ("/etc/passwd", "644:daemon:root"),
        ("/etc/passwd", "644:root:users"),
        ("/etc/shadow", "640:daemon:shadow"),
        ("/etc/shadow", "640:root:users"),
        ("/etc/sudoers", "440:daemon:root"),
        ("/etc/sudoers", "440:root:wheel"),
    ],
)
def test_permissions_fail_for_unexpected_owner_or_group(
    auditor: Mock, path: str, metadata: str
) -> None:
    values = secure_metadata()
    values[path] = metadata
    run_check(auditor, values)

    findings = [call.kwargs for call in auditor.add_finding.call_args_list]
    finding = next(item for item in findings if path in item["title"])
    assert finding["status"] == "FAIL"
    assert finding["severity"] == "HIGH"
    assert "propietario/grupo inesperado" in finding["details"]


def test_shadow_accepts_root_group(auditor: Mock) -> None:
    values = secure_metadata()
    values["/etc/shadow"] = "640:root:root"
    run_check(auditor, values)

    findings = [call.kwargs for call in auditor.add_finding.call_args_list]
    finding = next(item for item in findings if "/etc/shadow" in item["title"])
    assert finding["status"] == "PASS"


def test_permissions_report_invalid_octal_mode_as_error(auditor: Mock) -> None:
    values = secure_metadata()
    values["/etc/passwd"] = "888:root:root"
    run_check(auditor, values)

    finding = auditor.add_finding.call_args_list[0].kwargs
    assert finding["status"] == "ERROR"
    assert finding["confidence"] == "LOW"


def test_permissions_report_invalid_metadata_format_as_error(auditor: Mock) -> None:
    values = secure_metadata()
    values["/etc/passwd"] = "644:root"
    run_check(auditor, values)

    finding = auditor.add_finding.call_args_list[0].kwargs
    assert finding["status"] == "ERROR"
    assert finding["confidence"] == "LOW"
