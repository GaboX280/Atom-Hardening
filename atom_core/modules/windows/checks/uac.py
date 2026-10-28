from atom_core.base_auditor import BaseAuditor
from atom_core.modules.windows.checks._registry import read_registry_value


def audit_uac(auditor: BaseAuditor) -> None:
    """Check UAC elevation prompting using a typed registry value."""
    auditor.log("Evaluando configuración UAC...")

    success, exists, value = read_registry_value(
        auditor,
        r"HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
        "ConsentPromptBehaviorAdmin",
        "Uac Check",
    )
    if not success:
        return

    if not exists:
        auditor.add_finding(
            title="User Account Control (UAC)",
            status="WARNING",
            severity="MEDIUM",
            category="Privilege Management",
            details="No se encontró el valor explícito ConsentPromptBehaviorAdmin.",
            recommendation="Verificar la configuración efectiva de UAC y las políticas aplicadas.",
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact="No se pudo confirmar el comportamiento de las solicitudes de elevación.",
            confidence="LOW",
            compliance=["CIS Controls v8 - Control 5", "NIST SP 800-53 AC-6"],
        )
        return

    try:
        prompt_behavior = int(value)
    except (TypeError, ValueError):
        prompt_behavior = -1

    if prompt_behavior == 0:
        status, severity = "FAIL", "HIGH"
        details = "UAC permite elevaciones administrativas sin solicitar confirmación."
        recommendation = "Configurar UAC para solicitar confirmación o credenciales durante la elevación."
        confidence = "HIGH"
    elif prompt_behavior in {1, 2, 3, 4, 5}:
        status, severity = "PASS", "INFO"
        details = f"UAC tiene configurado ConsentPromptBehaviorAdmin={prompt_behavior}."
        recommendation = "Mantener una configuración de UAC adecuada para el entorno."
        confidence = "MEDIUM"
    else:
        status, severity = "ERROR", "HIGH"
        details = f"Valor ConsentPromptBehaviorAdmin desconocido: {value!r}."
        recommendation = "Verificar el valor de configuración de UAC."
        confidence = "LOW"

    auditor.add_finding(
        title="User Account Control (UAC)",
        status=status,
        severity=severity,
        category="Privilege Management",
        details=details,
        recommendation=recommendation,
        reference="Microsoft Security Baseline / CIS Windows Benchmark",
        impact="UAC correctamente configurado reduce ejecuciones no autorizadas con privilegios administrativos.",
        confidence=confidence,
        compliance=["CIS Controls v8 - Control 5", "NIST SP 800-53 AC-6"],
    )
