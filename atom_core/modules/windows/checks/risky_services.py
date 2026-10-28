from atom_core.base_auditor import BaseAuditor
from atom_core.modules.windows.checks._powershell import run_powershell_json


def audit_risky_services(auditor: BaseAuditor) -> None:
    """Detect selected services using their structured status property."""
    auditor.log("Auditando servicios riesgosos...")

    risky_services = {
        "Spooler": "Print Spooler",
        "RemoteRegistry": "Remote Registry",
        "SSDPSRV": "SSDP Discovery",
    }

    for service, description in risky_services.items():
        script = f"""
$ErrorActionPreference = 'Stop'
try {{
    $item = Get-Service -Name '{service}' -ErrorAction Stop
    [pscustomobject]@{{ Name = $item.Name; Status = $item.Status.ToString() }} | ConvertTo-Json -Compress
}} catch {{
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}}
"""
        success, payload = run_powershell_json(
            auditor, script, f"Risky Service Check: {service}"
        )
        if not success:
            continue

        if not isinstance(payload, dict) or not isinstance(payload.get("Status"), str):
            auditor.add_finding(
                title=f"Risky Service: {description}",
                status="ERROR",
                severity="HIGH",
                category="Execution Error",
                details="La consulta no devolvió un estado de servicio válido.",
                recommendation="Verificar la consulta del servicio y repetir la auditoría.",
                confidence="LOW",
            )
            continue

        service_status = payload["Status"].upper()
        if service_status == "RUNNING":
            status, severity = "FAIL", "MEDIUM"
            details = f"El servicio {description} está ejecutándose."
            recommendation = "Deshabilitar servicios innecesarios o restringir su exposición según los requerimientos."
        elif service_status == "STOPPED":
            status, severity = "PASS", "INFO"
            details = f"El servicio {description} no está activo."
            recommendation = "Mantener únicamente los servicios necesarios."
        else:
            status, severity = "WARNING", "MEDIUM"
            details = f"El servicio {description} tiene el estado {service_status}."
            recommendation = "Verificar si el estado del servicio es apropiado para el entorno."

        auditor.add_finding(
            title=f"Risky Service: {description}",
            status=status,
            severity=severity,
            category="Service Management",
            details=details,
            recommendation=recommendation,
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact=f"El servicio {description} puede aumentar la superficie de ataque del sistema.",
            compliance=["CIS Controls v8 - Control 4", "NIST SP 800-53 CM-7"],
        )
