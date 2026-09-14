from unittest.mock import patch

import pytest

from atom_core.models.finding import Finding
from atom_core.runners.audit_runner import AuditRunner


class StubAuditor:
    os_type = "Linux"
    distro = "TestOS"

    def ejecutar(self) -> list[Finding]:
        return [
            Finding(
                title="Firewall",
                status="PASS",
                severity="INFO",
                category="Network Security",
            ),
            Finding(
                title="Weak SSH",
                status="FAIL",
                severity="HIGH",
                category="Access Control",
            ),
        ]


def test_runner_builds_summary_and_generates_requested_report() -> None:
    with (
        patch(
            "atom_core.runners.audit_runner.AuditorFactory.get_auditor",
            return_value=StubAuditor(),
        ),
        patch(
            "atom_core.runners.audit_runner.ConsoleReporter.display"
        ) as console_display,
        patch(
            "atom_core.runners.audit_runner.JsonReporter.save",
            return_value="report.json",
        ) as json_save,
    ):
        reports = AuditRunner().run(
            option="1",
            fmt="json",
            output_dir="reports",
            quiet=False,
        )

    assert reports == {"json": "report.json"}
    json_save.assert_called_once()
    console_display.assert_called_once()

    summary = json_save.call_args.args[0]
    findings = json_save.call_args.args[1]
    assert summary["score"] == 80
    assert "BUENO (75-89)" in summary["rating"]
    assert summary["system"] == "Linux"
    assert summary["distribution"] == "TestOS"
    assert summary["status"]["FAIL"] == 1
    assert len(findings) == 2


def test_runner_rejects_unknown_report_format() -> None:
    with patch(
        "atom_core.runners.audit_runner.AuditorFactory.get_auditor"
    ) as factory:
        with pytest.raises(ValueError, match="Formato de reporte no soportado"):
            AuditRunner().run(fmt="xml")
        factory.assert_not_called()
