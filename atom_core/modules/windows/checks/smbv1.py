from atom_core.base_auditor import BaseAuditor
from atom_core.modules.windows.checks._powershell import run_powershell_json


def audit_smbv1(auditor: BaseAuditor) -> None:
    """Check SMBv1 server configuration using a Boolean property."""
    auditor.log("Comprobando configuración SMBv1...")

    script = r"""
$ErrorActionPreference = 'Stop'
try {
    $enabled = (Get-SmbServerConfiguration -ErrorAction Stop).EnableSMB1Protocol
    ConvertTo-Json -InputObject ([bool]$enabled) -Compress
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
"""
    success, enabled = run_powershell_json(auditor, script, "Smbv1 Check")
    if not success:
        return

    if not isinstance(enabled, bool):
        auditor.add_finding(
            title="SMBv1 Protocol",
            status="ERROR",
            severity="HIGH",
            category="Execution Error",
            details="La consulta SMBv1 no devolvió un valor booleano.",
            recommendation="Verificar que Get-SmbServerConfiguration esté disponible.",
            confidence="LOW",
        )
        return

    if enabled:
        status, severity = "FAIL", "CRITICAL"
        details = "SMBv1 está habilitado."
        recommendation = "Deshabilitar SMBv1 debido a sus vulnerabilidades conocidas y utilizar versiones modernas de SMB."
    else:
        status, severity = "PASS", "INFO"
        details = "SMBv1 está deshabilitado."
        recommendation = "Mantener protocolos obsoletos deshabilitados."

    auditor.add_finding(
        title="SMBv1 Protocol",
        status=status,
        severity=severity,
        category="Network Security",
        details=details,
        recommendation=recommendation,
        reference="Microsoft Security Baseline / CIS Windows Benchmark",
        impact="SMBv1 puede aumentar la exposición a explotación remota y movimiento lateral.",
        compliance=["CIS Controls v8 - Control 4", "NIST SP 800-53 CM-7"],
    )
