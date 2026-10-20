from atom_core.base_auditor import BaseAuditor
from atom_core.modules.windows.checks._powershell import run_powershell_json


def audit_powershell_policy(auditor: BaseAuditor) -> None:
    """Check the effective PowerShell execution policy."""
    auditor.log("Evaluando directiva de ejecución de PowerShell...")

    script = "ConvertTo-Json -InputObject (Get-ExecutionPolicy) -Compress"
    success, policy = run_powershell_json(auditor, script, "Powershell Policy Check")
    if not success:
        return

    if not isinstance(policy, str) or not policy.strip():
        auditor.add_finding(
            title="PowerShell Execution Policy",
            status="ERROR",
            severity="HIGH",
            category="Execution Error",
            details="PowerShell no devolvió una directiva de ejecución reconocible.",
            recommendation="Verificar Get-ExecutionPolicy y repetir la auditoría.",
            confidence="LOW",
        )
        return

    policy = policy.strip()
    normalized = policy.upper()
    if normalized in {"BYPASS", "UNRESTRICTED"}:
        status, severity = "FAIL", "HIGH"
        details = f"Directiva permisiva detectada: {policy}."
        recommendation = "Evaluar una política más restrictiva, como RemoteSigned o AllSigned, según las necesidades."
    elif normalized in {"RESTRICTED", "ALLSIGNED", "REMOTESIGNED", "DEFAULT", "UNDEFINED"}:
        status, severity = "PASS", "INFO"
        details = f"Directiva actual: {policy}."
        recommendation = "Mantener políticas adecuadas y revisar periódicamente su configuración."
    else:
        status, severity = "ERROR", "HIGH"
        details = f"Directiva de ejecución desconocida: {policy}."
        recommendation = "Verificar manualmente la directiva efectiva."

    auditor.add_finding(
        title="PowerShell Execution Policy",
        status=status,
        severity=severity,
        category="System Hardening",
        details=details,
        recommendation=recommendation,
        reference="Microsoft Security Baseline / CIS Windows Benchmark",
        impact="Una política permisiva puede facilitar la ejecución de scripts no confiables.",
        confidence="LOW" if status == "ERROR" else "HIGH",
        compliance=["CIS Controls v8 - Control 10", "NIST SP 800-53 CM-7"],
    )
