from atom_core.base_auditor import BaseAuditor
from atom_core.modules.windows.checks._registry import read_registry_value


def audit_anonymous_lookup(auditor: BaseAuditor) -> None:
    """Verifica las restricciones de sesiones anónimas mediante el Registro."""
    auditor.log("Evaluando Null Sessions...")

    success, exists, value = read_registry_value(
        auditor,
        r"HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters",
        "RestrictNullSessAccess",
        "Anonymous Lookup Check",
    )
    if not success:
        return

    if not exists:
        auditor.add_finding(
            title="Anonymous Access Restrictions",
            status="WARNING",
            severity="MEDIUM",
            category="Network Security",
            details="No se encontró configuración explícita de RestrictNullSessAccess en la ruta del servicio LanmanServer.",
            recommendation="Verificar la política efectiva y configurar restricciones contra acceso anónimo.",
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact="La ausencia del valor explícito requiere verificar el comportamiento efectivo de Windows.",
            compliance=["CIS Controls v8 - Control 4", "NIST SP 800-53 AC-3"],
        )
        return

    try:
        restricted = int(value)
    except (TypeError, ValueError):
        auditor.add_finding(
            title="Anonymous Access Restrictions",
            status="ERROR",
            severity="HIGH",
            category="Execution Error",
            details="El valor RestrictNullSessAccess no es un entero interpretable.",
            recommendation="Verificar la configuración del servicio LanmanServer y repetir la auditoría.",
            confidence="LOW",
        )
        return

    if restricted == 1:
        auditor.add_finding(
            title="Anonymous Access Restrictions",
            status="PASS",
            severity="INFO",
            category="Network Security",
            details="Las restricciones contra acceso anónimo están activadas.",
            recommendation="Mantener las restricciones para reducir la enumeración anónima.",
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact="Las restricciones reducen la exposición de información a usuarios no autenticados.",
            compliance=["CIS Controls v8 - Control 4", "NIST SP 800-53 AC-3"],
        )
    elif restricted == 0:
        auditor.add_finding(
            title="Anonymous Access Restrictions",
            status="FAIL",
            severity="HIGH",
            category="Network Security",
            details="RestrictNullSessAccess está desactivado.",
            recommendation="Configurar RestrictNullSessAccess para restringir sesiones nulas.",
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact="Las sesiones nulas pueden permitir enumeración de recursos sin autenticación.",
            compliance=["CIS Controls v8 - Control 4", "NIST SP 800-53 AC-3"],
        )
    else:
        auditor.add_finding(
            title="Anonymous Access Restrictions",
            status="ERROR",
            severity="HIGH",
            category="Execution Error",
            details=f"Valor RestrictNullSessAccess desconocido: {restricted}.",
            recommendation="Verificar el valor admitido por Windows y repetir la auditoría.",
            confidence="LOW",
        )
