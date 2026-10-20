import json

from atom_core.base_auditor import BaseAuditor

EXPECTED_PROFILES = {"DOMAIN", "PRIVATE", "PUBLIC"}


def audit_firewall(auditor: BaseAuditor) -> None:
    """Evaluate Windows Firewall profiles without parsing localized text."""
    auditor.log("Evaluando el estado del Firewall de Windows...")

    # PowerShell devuelve propiedades tipadas en JSON, no texto localizado de netsh.
    command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Get-NetFirewallProfile | Select-Object Name, Enabled | ConvertTo-Json -Compress",
    ]
    result = auditor._run_command(command)

    if auditor._record_command_error(result, "Firewall Check"):
        return

    try:
        profiles = json.loads(result.stdout)
        if isinstance(profiles, dict):
            profiles = [profiles]
        if not isinstance(profiles, list) or not profiles:
            raise ValueError("La consulta no devolvió una lista de perfiles.")

        normalized = {}
        for profile in profiles:
            if not isinstance(profile, dict):
                raise TypeError("Formato de perfil no válido.")
            name = profile.get("Name")
            enabled = profile.get("Enabled")
            if not isinstance(name, str) or not isinstance(enabled, bool):
                raise TypeError("Faltan las propiedades Name o Enabled.")
            normalized[name.upper()] = enabled

        if set(normalized) != EXPECTED_PROFILES:
            raise ValueError(
                "No se recibieron exactamente los perfiles Domain, Private y Public."
            )
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        auditor.add_finding(
            title="Windows Firewall",
            status="ERROR",
            severity="HIGH",
            category="Network Security",
            details=f"No se pudo interpretar la respuesta estructurada del firewall: {exc}",
            recommendation="Verificar la disponibilidad de Get-NetFirewallProfile y repetir la auditoría.",
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact="No fue posible determinar de forma confiable el estado de todos los perfiles.",
            confidence="LOW",
            compliance=["CIS Controls v8 - Control 13", "NIST SP 800-53 SC-7"],
        )
        return

    disabled = [name for name, enabled in normalized.items() if not enabled]
    if disabled:
        status = "FAIL"
        severity = "HIGH"
        details = "Perfiles del firewall desactivados: " + ", ".join(sorted(disabled))
        recommendation = "Activar Windows Firewall en todos los perfiles y revisar sus reglas."
        confidence = "HIGH"
    else:
        status = "PASS"
        severity = "INFO"
        details = "Los perfiles Domain, Private y Public de Windows Firewall están activos."
        recommendation = "Mantener las reglas del firewall actualizadas y revisarlas periódicamente."
        confidence = "HIGH"

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
