from unittest.mock import Mock

import pytest

from atom_core.base_auditor import CommandResult
from atom_core.modules.windows.checks._accounts import read_builtin_account


@pytest.fixture
def auditor() -> Mock:
    mock = Mock()
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
            details=result.error or f"Unexpected return code: {result.returncode}",
            recommendation="Retry the query.",
            category="Execution Error",
        )
        return True

    mock._record_command_error = Mock(side_effect=record_command_error)
    return mock


def run_query(auditor: Mock, output: str) -> tuple[bool, dict | None]:
    auditor._run_command.return_value = CommandResult(stdout=output, stderr="", returncode=0)
    return read_builtin_account(auditor, "500", "Account Check")


def test_builtin_account_reads_disabled_flag(auditor: Mock) -> None:
    success, account = run_query(
        auditor,
        '{"Name":"Administrator","SID":"S-1-5-21-1-2-3-500","Disabled":true}',
    )
    assert success is True
    assert account is not None
    assert account["Disabled"] is True


def test_builtin_account_handles_missing_account(auditor: Mock) -> None:
    assert run_query(auditor, "[]") == (True, None)


def test_builtin_account_reports_invalid_payload(auditor: Mock) -> None:
    success, account = run_query(auditor, '{"Name":"Administrator"}')
    assert (success, account) == (False, None)
    assert auditor.add_finding.call_args.kwargs["status"] == "ERROR"
