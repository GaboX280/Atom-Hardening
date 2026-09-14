import re

from atom_core.base_auditor import BaseAuditor


STATE_PATTERN = re.compile(r"\bState\s+(ON|OFF)\b", re.IGNORECASE)


def audit_firewall(auditor: BaseAuditor) -> None:
    """Evaluate the state of all Windows Firewall profiles."""
    auditor.log("Evaluando el estado del Firewall de Windows...")

    resultado = auditor._run_command("netsh advfirewall show allprofiles state")

    if resultado.startswith("ERROR:"):
        auditor.add_finding(
            title="Windows Firewall",
            status="ERROR",
            severity="MEDIUM",
            category="Network Security",
            details=resultado,
            recommendation="Ejecutar la auditoría con permisos suficientes y repetir el análisis.",
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact="No fue posible determinar el estado de los perfiles del firewall.",
            compliance=["CIS Controls v8 - Control 13", "NIST SP 800-53 SC-7"],
        )
        return

    states = [state.upper() for state in STATE_PATTERN.findall(resultado)]

    if not states:
        auditor.add_finding(
            title="Windows Firewall",
            status="WARNING",
            severity="MEDIUM",
            category="Network Security",
            details="No se pudieron interpretar los estados de los perfiles del firewall.",
            recommendation="Revisar la salida de netsh y ejecutar Atom con privilegios adecuados.",
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact="La postura del firewall no pudo verificarse de forma confiable.",
            confidence="LOW",
            compliance=["CIS Controls v8 - Control 13", "NIST SP 800-53 SC-7"],
        )
        return

    enabled = states.count("ON")
    disabled = states.count("OFF")

    if disabled > 0:
        status = "FAIL"
        severity = "HIGH"
        details = f"Se detectaron {disabled} perfil(es) del firewall desactivado(s)."
        recommendation = "Activar Windows Firewall en todos los perfiles y revisar sus reglas."
        confidence = "HIGH" if len(states) >= 3 else "MEDIUM"
    elif enabled == len(states) and len(states) >= 3:
        status = "PASS"
        severity = "INFO"
        details = "Los tres perfiles de Windows Firewall están activos."
        recommendation = "Mantener las reglas del firewall actualizadas y revisarlas periódicamente."
        confidence = "HIGH"
    else:
        status = "WARNING"
        severity = "MEDIUM"
        details = f"Se verificaron {len(states)} perfil(es); no se obtuvo el conjunto completo esperado."
        recommendation = "Confirmar manualmente el estado de Domain, Private y Public."
        confidence = "MEDIUM"

    auditor.add_finding(
        title="Windows Firewall",
        status=status,
        severity=severity,
        category="Network Security",
        details=details,
        recommendation=recommendation,
        reference="Microsoft Security Baseline / CIS Windows Benchmark",
        impact="Un firewall correctamente configurado reduce la exposición de servicios no autorizados.",
        confidence=confidence,
        compliance=["CIS Controls v8 - Control 13", "NIST SP 800-53 SC-7"],
    )
