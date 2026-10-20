from atom_core.base_auditor import BaseAuditor
from atom_core.modules.windows.checks._registry import read_registry_value


def audit_llmnr(auditor: BaseAuditor) -> None:
    """Verify LLMNR policy using the registry's typed value."""
    auditor.log("Comprobando mitigación LLMNR...")

    success, exists, value = read_registry_value(
        auditor,
        r"HKLM:\Software\Policies\Microsoft\Windows NT\DNSClient",
        "EnableMulticast",
        "Llmnr Check",
    )
    if not success:
        return

    if not exists:
        auditor.add_finding(
            title="LLMNR Protocol",
            status="WARNING",
            severity="MEDIUM",
            category="Network Security",
            details="No existe una política explícita para LLMNR.",
            recommendation="Crear una política de grupo para deshabilitar LLMNR.",
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact="Sin una política definida, el comportamiento puede depender de la configuración local.",
            compliance=["CIS Controls v8 - Control 4", "NIST SP 800-53 CM-7"],
        )
        return

    try:
        enabled = int(value)
    except (TypeError, ValueError):
        auditor.add_finding(
            title="LLMNR Protocol",
            status="ERROR",
            severity="HIGH",
            category="Execution Error",
            details="El valor EnableMulticast no es un entero interpretable.",
            recommendation="Verificar manualmente la política LLMNR y repetir la auditoría.",
            confidence="LOW",
        )
        return

    if enabled == 0:
        auditor.add_finding(
            title="LLMNR Protocol",
            status="PASS",
            severity="INFO",
            category="Network Security",
            details="LLMNR está deshabilitado por política.",
            recommendation="Mantener la política y revisar periódicamente su aplicación.",
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact="Deshabilitar LLMNR reduce el riesgo de spoofing y captura de credenciales NTLM.",
            compliance=["CIS Controls v8 - Control 4", "NIST SP 800-53 CM-7"],
        )
    elif enabled == 1:
        auditor.add_finding(
            title="LLMNR Protocol",
            status="FAIL",
            severity="HIGH",
            category="Network Security",
            details="LLMNR está habilitado por política.",
            recommendation="Deshabilitar LLMNR mediante una política de grupo.",
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact="LLMNR habilitado puede permitir ataques de spoofing y captura de credenciales.",
            compliance=["CIS Controls v8 - Control 4", "NIST SP 800-53 CM-7"],
        )
    else:
        auditor.add_finding(
            title="LLMNR Protocol",
            status="ERROR",
            severity="HIGH",
            category="Execution Error",
            details=f"Valor EnableMulticast desconocido: {enabled}.",
            recommendation="Verificar el valor de política admitido por Windows.",
            confidence="LOW",
        )
