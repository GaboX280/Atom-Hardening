from unittest.mock import Mock, patch

import pytest

from atom_core.modules.windows.checks import anonymous_lookup


@pytest.fixture
def auditor() -> Mock:
    return Mock()


def test_uses_lanmanserver_registry_path(auditor: Mock) -> None:
    with patch.object(
        anonymous_lookup,
        "read_registry_value",
        return_value=(True, True, 1),
    ) as read_value:
        anonymous_lookup.audit_anonymous_lookup(auditor)

    assert read_value.call_args.args[1] == (
        r"HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters"
    )
    assert read_value.call_args.args[2] == "RestrictNullSessAccess"
    assert auditor.add_finding.call_args.kwargs["status"] == "PASS"


@pytest.mark.parametrize(
    ("result", "expected_status"),
    [
        ((True, True, 1), "PASS"),
        ((True, True, 0), "FAIL"),
        ((True, False, None), "WARNING"),
        ((True, True, "invalid"), "ERROR"),
        ((True, True, 2), "ERROR"),
    ],
)
def test_classifies_registry_values(
    auditor: Mock,
    result: tuple[bool, bool, object],
    expected_status: str,
) -> None:
    with patch.object(anonymous_lookup, "read_registry_value", return_value=result):
        anonymous_lookup.audit_anonymous_lookup(auditor)

    assert auditor.add_finding.call_args.kwargs["status"] == expected_status


def test_stops_when_registry_query_fails(auditor: Mock) -> None:
    with patch.object(
        anonymous_lookup,
        "read_registry_value",
        return_value=(False, False, None),
    ):
        anonymous_lookup.audit_anonymous_lookup(auditor)

    auditor.add_finding.assert_not_called()
