from unittest.mock import Mock

import pytest

from atom_core.base_auditor import CommandResult
from atom_core.modules.windows.checks._registry import read_registry_value


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


def run_query(auditor: Mock, output: str, error: str | None = None) -> tuple[bool, bool, object]:
    auditor._run_command.return_value = CommandResult(
        stdout=output,
        stderr="",
        returncode=1 if error else 0,
        error=error,
    )
    return read_registry_value(auditor, r"HKLM:\Software\Example", "ExampleValue", "Registry Check")


def test_registry_reader_returns_typed_value(auditor: Mock) -> None:
    assert run_query(auditor, '{"exists":true,"value":0}') == (True, True, 0)


def test_registry_reader_distinguishes_missing_value(auditor: Mock) -> None:
    assert run_query(auditor, '{"exists":false,"value":null}') == (True, False, None)


def test_registry_reader_reports_invalid_json(auditor: Mock) -> None:
    success, exists, value = run_query(auditor, "not json")
    assert (success, exists, value) == (False, False, None)
    assert auditor.add_finding.call_args.kwargs["status"] == "ERROR"


def test_registry_reader_reports_execution_error(auditor: Mock) -> None:
    success, exists, value = run_query(auditor, "", error="ACCESS_DENIED")
    assert (success, exists, value) == (False, False, None)
    assert auditor.add_finding.call_args.kwargs["status"] == "ERROR"
