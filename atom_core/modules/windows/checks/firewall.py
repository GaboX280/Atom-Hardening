import json

from atom_core.base_auditor import BaseAuditor

EXPECTED_PROFILE_COUNT = 3


def audit_firewall(auditor: BaseAuditor) -> None:
    """Evaluate Windows Firewall profiles without parsing localized text."""
    auditor.log("Evaluando el estado del Firewall de Windows...")

    script = r"""
$ErrorActionPreference = 'Stop'
try {
    $profiles = @(Get-NetFirewallProfile -ErrorAction Stop | ForEach-Object {
        [pscustomobject]@{
            Name = [string]$_.Name
            Enabled = [bool]$_.Enabled
        }
    })
    ConvertTo-Json -InputObject $profiles -Compress
} catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
"""
    result = auditor._run_command(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=15,
    )
    if auditor._record_command_error(result, "Firewall Check"):
        return

    try:
        profiles = json.loads(result.stdout)
        if isinstance(profiles, dict):
            profiles = [profiles]
        if not isinstance(profiles, list):
            raise TypeError("La consulta no devolvió una lista de perfiles.")
        if len(profiles) != EXPECTED_PROFILE_COUNT:
            raise ValueError(
                f"Se esperaban {EXPECTED_PROFILE_COUNT} perfiles y se recibieron {len(profiles)}."
            )

        normalized = []
        for profile in profiles:
            if not isinstance(profile, dict):
                raise TypeError("Formato de perfil no válido.")
            name = profile.get("Name")
            enabled = profile.get("Enabled")
            if not isinstance(name, str) or not isinstance(enabled, bool):
                raise TypeError("La respuesta no contiene Name (texto) y Enabled (booleano).")
            normalized.append((name, enabled))
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        auditor.add_finding(
            title="Windows Firewall",
            status="ERROR",
            severity="HIGH",
            category="Network Security",
            details=f"No se pudo interpretar la respuesta estructurada del firewall: {exc}",
            recommendation="Verificar la disponibilidad de Get-NetFirewallProfile y repetir la auditoría.",
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact="No fue posible determinar de forma confiable el estado de los tres perfiles.",
            confidence="LOW",
            compliance=["CIS Controls v8 - Control 13", "NIST SP 800-53 SC-7"],
        )
        return

    disabled = [name for name, enabled in normalized if not enabled]
    if disabled:
        status, severity = "FAIL", "HIGH"
        details = "Perfiles del firewall desactivados: " + ", ".join(sorted(disabled))
        recommendation = "Activar Windows Firewall en todos los perfiles y revisar sus reglas."
    else:
        status, severity = "PASS", "INFO"
        details = "Los tres perfiles de Windows Firewall están activos."
        recommendation = "Mantener las reglas del firewall actualizadas y revisarlas periódicamente."

    auditor.add_finding(
        title="Windows Firewall",
        status=status,
        severity=severity,
        category="Network Security",
        details=details,
        recommendation=recommendation,
        reference="Microsoft Security Baseline / CIS Windows Benchmark",
        impact="Un firewall correctamente configurado reduce la exposición de servicios no autorizados.",
        confidence="HIGH",
        compliance=["CIS Controls v8 - Control 13", "NIST SP 800-53 SC-7"],
    )
