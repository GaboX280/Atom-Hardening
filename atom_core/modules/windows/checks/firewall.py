from atom_core.base_auditor import BaseAuditor


def audit_firewall(auditor: BaseAuditor) -> None: # [TYPING ADDED]

    auditor.log("Evaluando el estado del Firewall de Windows...")

    resultado = auditor._run_command("netsh advfirewall show allprofiles state")

    if "ON" in resultado.upper():
        auditor.add_finding(
            title="Windows Firewall",
            status="PASS",
            severity="INFO",
            category="Network Security",
            details=(
                "El Firewall de Windows está activo en los perfiles configurados."
            ),
            recommendation=(
                "Mantener las reglas del firewall actualizadas "
                "y revisar configuraciones periódicamente."
            ),
            reference=("Microsoft Security Baseline / CIS Windows Benchmark"),
            impact=(
                "Un firewall correctamente configurado reduce la exposición "
                "de servicios no autorizados y limita accesos no deseados."
            ),
            compliance=["CIS Controls v8 - Control 13", "NIST SP 800-53 SC-7"],
        )

    else:
        auditor.add_finding(
            title="Windows Firewall",
            status="FAIL",
            severity="HIGH",
            category="Network Security",
            details=(
                "El Firewall de Windows parece estar desactivado en uno o más perfiles."
            ),
            recommendation=(
                "Activar Windows Firewall en todos los perfiles "
                "(Domain, Private y Public)."
            ),
            reference=("Microsoft Security Baseline / CIS Windows Benchmark"),
            impact=(
                "Un firewall deshabilitado aumenta la superficie de ataque "
                "permitiendo conexiones no filtradas hacia el sistema."
            ),
            compliance=["CIS Controls v8 - Control 13", "NIST SP 800-53 SC-7"],
        )
