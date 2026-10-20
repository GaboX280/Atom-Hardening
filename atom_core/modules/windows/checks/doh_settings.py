from atom_core.base_auditor import BaseAuditor
from atom_core.modules.windows.checks._registry import read_registry_value


def audit_doh_settings(auditor: BaseAuditor) -> None:
    """Check DNS-over-HTTPS configuration using a typed registry value."""
    auditor.log("Verificando DNS over HTTPS...")

    success, exists, value = read_registry_value(
        auditor,
        r"HKLM:\SYSTEM\CurrentControlSet\Services\Dnscache\Parameters",
        "EnableAutoDoh",
        "Doh Settings Check",
    )
    if not success:
        return

    try:
        doh_value = int(value) if exists else None
    except (TypeError, ValueError):
        auditor.add_finding(
            title="DNS over HTTPS",
            status="ERROR",
            severity="HIGH",
            category="Execution Error",
            details="El valor EnableAutoDoh no es un entero interpretable.",
            recommendation="Verificar la configuración de DNS over HTTPS y repetir la auditoría.",
            confidence="LOW",
        )
        return

    if doh_value == 2:
        auditor.add_finding(
            title="DNS over HTTPS",
            status="PASS",
            severity="INFO",
            category="Network Security",
            details="EnableAutoDoh tiene el valor que indica habilitación de DoH.",
            recommendation="Mantener la configuración si es compatible con la infraestructura.",
            reference="Microsoft documentation",
            impact="DNS over HTTPS puede proteger las consultas DNS durante el tránsito.",
            compliance=["NIST SP 800-53 SC-8"],
        )
    else:
        state = "no está configurado explícitamente" if not exists else f"tiene el valor {doh_value}"
        auditor.add_finding(
            title="DNS over HTTPS",
            status="WARNING",
            severity="LOW",
            category="Network Security",
            details=f"DNS over HTTPS no se confirmó como habilitado: EnableAutoDoh {state}.",
            recommendation="Verificar la configuración efectiva de DoH y las políticas aplicables.",
            reference="Microsoft documentation",
            impact="No se pudo confirmar que las consultas DNS usen DNS over HTTPS.",
            confidence="MEDIUM",
            compliance=["NIST SP 800-53 SC-8"],
        )
