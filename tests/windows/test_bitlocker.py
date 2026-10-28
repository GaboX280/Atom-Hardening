from unittest.mock import Mock

import pytest

from atom_core.base_auditor import CommandResult
from atom_core.modules.windows.checks.bitlocker import audit_bitlocker


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
    audit_bitlocker(auditor)


def test_bitlocker_passes_when_encrypted_and_protected(auditor: Mock) -> None:
    run_check(auditor, '{"VolumeStatus":"FullyEncrypted","ProtectionStatus":"On"}')
    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "PASS"
    assert finding["severity"] == "INFO"


def test_bitlocker_warns_when_encrypted_but_protection_is_off(auditor: Mock) -> None:
    run_check(auditor, '{"VolumeStatus":"FullyEncrypted","ProtectionStatus":"Off"}')
    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "WARNING"
    assert finding["severity"] == "HIGH"


def test_bitlocker_fails_when_fully_decrypted(auditor: Mock) -> None:
    run_check(auditor, '{"VolumeStatus":"FullyDecrypted","ProtectionStatus":"Off"}')
    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "FAIL"
    assert finding["severity"] == "HIGH"


def test_bitlocker_reports_command_errors_as_error(auditor: Mock) -> None:
    auditor._run_command.return_value = CommandResult(
        stdout="",
        stderr="access denied",
        returncode=None,
        error="ACCESS_DENIED",
    )
    audit_bitlocker(auditor)
    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "ERROR"
    assert finding["severity"] == "HIGH"


def test_bitlocker_reports_unparseable_output_as_error(auditor: Mock) -> None:
    run_check(auditor, "unexpected output")
    finding = auditor.add_finding.call_args.kwargs
    assert finding["status"] == "ERROR"
    assert finding["severity"] == "HIGH"
