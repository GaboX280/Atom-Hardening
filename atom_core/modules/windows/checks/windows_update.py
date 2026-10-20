from atom_core.base_auditor import BaseAuditor
from atom_core.modules.windows.checks._powershell import run_powershell_json


def audit_windows_update(auditor: BaseAuditor) -> None:
    """Check Windows Update service status using a structured property."""
    auditor.log("Comprobando estado del servicio Windows Update...")

    script = r"""
$ErrorActionPreference = 'Stop'
try {
    $service = Get-Service -Name 'wuauserv' -ErrorAction Stop
    [pscustomobject]@{ Name = $service.Name; Status = $service.Status.ToString() } | ConvertTo-Json -Compress
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
"""
    success, payload = run_powershell_json(auditor, script, "Windows Update Check")
    if not success:
        return

    if not isinstance(payload, dict) or not isinstance(payload.get("Status"), str):
        auditor.add_finding(
            title="Windows Update Service",
            status="ERROR",
            severity="HIGH",
            category="Execution Error",
            details="La consulta no devolvió un estado válido para Windows Update.",
            recommendation="Verificar que el servicio wuauserv exista y repetir la auditoría.",
            confidence="LOW",
        )
        return

    service_status = payload["Status"].upper()
    if service_status == "RUNNING":
        status, severity = "PASS", "INFO"
        details = "El servicio Windows Update está ejecutándose."
        recommendation = "Mantener actualizaciones automáticas y aplicar parches regularmente."
    elif service_status == "STOPPED":
        status, severity = "WARNING", "MEDIUM"
        details = "El servicio Windows Update está detenido."
        recommendation = "Verificar si la detención es intencional y revisar la configuración de actualizaciones."
    else:
        status, severity = "WARNING", "MEDIUM"
        details = f"Windows Update tiene el estado {service_status}."
        recommendation = "Verificar el estado del servicio y la política de actualización."

    auditor.add_finding(
        title="Windows Update Service",
        status=status,
        severity=severity,
        category="Patch Management",
        details=details,
        recommendation=recommendation,
        reference="Microsoft Security Baseline / CIS Windows Benchmark",
        impact="Un servicio de actualización detenido puede retrasar la aplicación de parches de seguridad.",
        compliance=["CIS Controls v8 - Control 7", "NIST SP 800-53 SI-2"],
    )
