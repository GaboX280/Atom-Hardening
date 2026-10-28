from atom_core.base_auditor import BaseAuditor
from atom_core.modules.windows.checks._powershell import run_powershell_json


def audit_windows_defender(auditor: BaseAuditor) -> None:
    """Check Defender real-time protection using a Boolean property."""
    auditor.log("Comprobando protección de Windows Defender...")

    script = r"""
$ErrorActionPreference = 'Stop'
try {
    $enabled = (Get-MpComputerStatus -ErrorAction Stop).RealTimeProtectionEnabled
    ConvertTo-Json -InputObject ([bool]$enabled) -Compress
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
"""
    success, enabled = run_powershell_json(auditor, script, "Windows Defender Check")
    if not success:
        return

    if not isinstance(enabled, bool):
        auditor.add_finding(
            title="Windows Defender",
            status="ERROR",
            severity="HIGH",
            category="Execution Error",
            details="La consulta de Defender no devolvió un valor booleano.",
            recommendation="Verificar la disponibilidad de Get-MpComputerStatus y repetir la auditoría.",
            confidence="LOW",
        )
        return

    if enabled:
        status, severity = "PASS", "INFO"
        details = "La protección en tiempo real de Windows Defender está activa."
        recommendation = "Mantener las firmas antivirus actualizadas y revisar periódicamente la protección."
    else:
        status, severity = "FAIL", "HIGH"
        details = "La protección en tiempo real de Windows Defender está deshabilitada."
        recommendation = "Verificar y activar la protección en tiempo real según las políticas del sistema."

    auditor.add_finding(
        title="Windows Defender",
        status=status,
        severity=severity,
        category="Endpoint Protection",
        details=details,
        recommendation=recommendation,
        reference="Microsoft Defender Security Baseline / CIS Windows Benchmark",
        impact="La protección activa ayuda a prevenir malware y amenazas conocidas en el endpoint.",
        compliance=["CIS Controls v8 - Control 10", "NIST SP 800-53 SI-3"],
    )
