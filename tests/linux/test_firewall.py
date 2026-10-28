from atom_core.base_auditor import BaseAuditor, CommandResult
from atom_core.models.finding import Finding
from atom_core.modules.linux.checks.firewall import audit_firewall


class DummyAuditor(BaseAuditor):
    """Auditor de prueba para comprobar la lógica del firewall Linux."""

    def ejecutar(self) -> list[Finding]:
        return self.report


def make_auditor(monkeypatch, command_outputs: dict[str, str]) -> DummyAuditor:
    auditor = DummyAuditor()
    commands = {
        "ufw": "ufw status",
        "nft": "nft list ruleset",
        "firewall-cmd": "firewall-cmd --state",
        "iptables": "iptables -L -n",
    }
    available = set(command_outputs)

    monkeypatch.setattr(
        auditor, "command_exists", lambda command: command in available
    )
    monkeypatch.setattr(
        auditor,
        "_run_command",
        lambda command, timeout=10: CommandResult(
            stdout=command_outputs[next(name for name, value in commands.items() if value == command)],
            stderr="",
            returncode=0,
        ),
    )
    return auditor


def test_inactive_ufw_does_not_hide_active_nftables(monkeypatch) -> None:
    """Debe revisar otros backends si UFW está instalado pero inactivo."""
    auditor = make_auditor(
        monkeypatch,
        {
            "ufw": "Status: inactive",
            "nft": (
                "table inet filter {\n"
                " chain input { type filter hook input priority filter; policy drop; }\n"
                "}"
            ),
        },
    )

    audit_firewall(auditor)

    assert len(auditor.report) == 1
    assert auditor.report[0].status == "PASS"
    assert auditor.report[0].title == "Linux Firewall nftables"


def test_inactive_ufw_without_alternate_backend_is_warning(monkeypatch) -> None:
    """No debe marcar como PASS un firewall UFW deshabilitado."""
    auditor = make_auditor(monkeypatch, {"ufw": "Status: inactive"})

    audit_firewall(auditor)

    assert len(auditor.report) == 1
    assert auditor.report[0].status == "WARNING"
    assert "UFW está instalado pero deshabilitado" in auditor.report[0].details



def test_permissive_nftables_ruleset_is_not_a_pass(monkeypatch) -> None:
    """Una cadena con política accept no demuestra filtrado efectivo."""
    auditor = make_auditor(
        monkeypatch,
        {
            "nft": (
                "table inet filter {\\n"
                " chain input { type filter hook input priority filter; policy accept; }\\n"
                "}"
            )
        },
    )

    audit_firewall(auditor)

    assert len(auditor.report) == 1
    assert auditor.report[0].status == "WARNING"
    assert "drop/reject" in auditor.report[0].details


def test_firewalld_is_checked_after_permissive_nftables(monkeypatch) -> None:
    """Un ruleset nftables permisivo no debe ocultar otro backend activo."""
    auditor = make_auditor(
        monkeypatch,
        {
            "nft": (
                "table inet filter {\\n"
                " chain input { type filter hook input priority filter; policy accept; }\\n"
                "}"
            ),
            "firewall-cmd": "running",
        },
    )

    audit_firewall(auditor)

    assert len(auditor.report) == 1
    assert auditor.report[0].status == "PASS"
    assert auditor.report[0].title == "Linux Firewall Firewalld"
