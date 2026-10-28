from atom_core.base_auditor import BaseAuditor
from atom_core.modules.windows.checks._accounts import read_builtin_account


def audit_guest_account(auditor: BaseAuditor) -> None:
    """Audit the built-in Guest account using its stable SID."""
    auditor.log("Evaluando cuenta Invitado...")

    success, account = read_builtin_account(auditor, "501", "Guest Account Check")
    if not success:
        return

    if account is None:
        status, severity = "PASS", "INFO"
        details = "La cuenta Invitado integrada no fue encontrada."
        recommendation = "Mantener cuentas innecesarias deshabilitadas."
    elif account["Disabled"]:
        status, severity = "PASS", "INFO"
        details = "La cuenta Invitado integrada está deshabilitada."
        recommendation = "Mantener cuentas innecesarias deshabilitadas."
    else:
        status, severity = "FAIL", "MEDIUM"
        details = "La cuenta Invitado integrada está habilitada."
        recommendation = "Deshabilitar la cuenta Invitado si no existe una necesidad justificada."

    auditor.add_finding(
        title="Guest Account",
        status=status,
        severity=severity,
        category="Identity Management",
        details=details,
        recommendation=recommendation,
        reference="Microsoft Security Baseline / CIS Windows Benchmark",
        impact="Una cuenta de invitado habilitada puede permitir accesos no autorizados.",
        compliance=["CIS Controls v8 - Control 5", "NIST SP 800-53 AC-2"],
    )
