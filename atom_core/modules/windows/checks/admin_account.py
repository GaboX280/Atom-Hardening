from atom_core.base_auditor import BaseAuditor
from atom_core.modules.windows.checks._accounts import read_builtin_account


def audit_admin_account(auditor: BaseAuditor) -> None:
    """Audit the built-in Administrator account using its stable SID."""
    auditor.log("Evaluando cuenta Administrador...")

    success, account = read_builtin_account(auditor, "500", "Admin Account Check")
    if not success:
        return

    if account is None:
        status, severity = "PASS", "INFO"
        details = "La cuenta Administrador integrada no fue encontrada."
        recommendation = "Mantener las cuentas privilegiadas controladas y aplicar mínimo privilegio."
    elif account["Disabled"]:
        status, severity = "PASS", "INFO"
        details = "La cuenta Administrador integrada está deshabilitada."
        recommendation = "Mantener cuentas privilegiadas controladas y utilizar el principio de mínimo privilegio."
    else:
        status, severity = "FAIL", "HIGH"
        details = "La cuenta Administrador integrada está habilitada."
        recommendation = (
            "Deshabilitar la cuenta Administrador integrada si no es necesaria "
            "y utilizar cuentas administrativas individuales."
        )

    auditor.add_finding(
        title="Default Administrator Account",
        status=status,
        severity=severity,
        category="Privileged Access Management",
        details=details,
        recommendation=recommendation,
        reference="Microsoft Security Baseline / CIS Windows Benchmark",
        impact="Una cuenta administrativa integrada activa puede aumentar el riesgo de abuso de privilegios.",
        compliance=["CIS Controls v8 - Control 5", "NIST SP 800-53 AC-2", "NIST SP 800-53 AC-6"],
    )
