from atom_core.base_auditor import BaseAuditor
from atom_core.modules.windows.checks._registry import read_registry_value


def audit_remote_desktop(auditor: BaseAuditor) -> None:
    """Check Remote Desktop configuration using its typed registry value."""
    auditor.log("Evaluando Escritorio Remoto...")

    success, exists, value = read_registry_value(
        auditor,
        r"HKLM:\System\CurrentControlSet\Control\Terminal Server",
        "fDenyTSConnections",
        "Remote Desktop Check",
    )
    if not success:
        return

    if not exists:
        auditor.add_finding(
            title="Remote Desktop (RDP)",
            status="WARNING",
            severity="MEDIUM",
            category="Remote Access",
            details="No se encontró el valor explícito fDenyTSConnections.",
            recommendation="Verificar la configuración efectiva de Escritorio Remoto.",
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact="No se pudo confirmar si RDP está habilitado o deshabilitado.",
            confidence="LOW",
            compliance=["CIS Controls v8 - Control 6", "NIST SP 800-53 AC-17"],
        )
        return

    try:
        deny_connections = int(value)
    except (TypeError, ValueError):
        deny_connections = -1

    if deny_connections == 1:
        status, severity = "PASS", "INFO"
        details = "Escritorio Remoto está deshabilitado."
        recommendation = "Mantener el acceso remoto restringido y habilitarlo solo cuando sea necesario."
        confidence = "HIGH"
    elif deny_connections == 0:
        status, severity = "WARNING", "MEDIUM"
        details = "Escritorio Remoto está habilitado."
        recommendation = "Deshabilitar RDP si no es requerido; si lo es, restringirlo con VPN, MFA y firewall."
        confidence = "HIGH"
    else:
        status, severity = "ERROR", "HIGH"
        details = f"Valor fDenyTSConnections desconocido: {value!r}."
        recommendation = "Verificar el valor de configuración de RDP."
        confidence = "LOW"

    auditor.add_finding(
        title="Remote Desktop (RDP)",
        status=status,
        severity=severity,
        category="Remote Access",
        details=details,
        recommendation=recommendation,
        reference="Microsoft Security Baseline / CIS Windows Benchmark",
        impact="RDP habilitado puede aumentar la exposición a ataques de acceso remoto.",
        confidence=confidence,
        compliance=["CIS Controls v8 - Control 6", "NIST SP 800-53 AC-17"],
    )
