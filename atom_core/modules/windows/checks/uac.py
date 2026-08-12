from atom_core.base_auditor import BaseAuditor


def audit_uac(auditor: BaseAuditor) -> None: # [TYPING ADDED]

    auditor.log("Evaluando configuración UAC...")

    comando = (
        "powershell -Command "
        '"Get-ItemProperty '
        "-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
        "-Name 'ConsentPromptBehaviorAdmin'"
        '"'
    )

    resultado = auditor._run_command(comando).upper()

    if ": 0" in resultado or ":0" in resultado:
        auditor.add_finding(
            title="User Account Control (UAC)",
            status="FAIL",
            severity="HIGH",
            category="Privilege Management",
            details=(
                "UAC está configurado en un nivel inseguro. "
                "Las elevaciones administrativas pueden ejecutarse "
                "sin solicitar confirmación."
            ),
            recommendation=(
                "Habilitar solicitudes de elevación UAC y mantener "
                "la configuración recomendada por Microsoft."
            ),
            reference=("Microsoft Security Baseline / CIS Windows Benchmark"),
            impact=(
                "Una configuración insegura de UAC facilita que malware "
                "o usuarios con acceso limitado puedan ejecutar acciones "
                "con privilegios elevados."
            ),
            compliance=["CIS Controls v8 - Control 5", "NIST SP 800-53 AC-6"],
        )

    else:
        auditor.add_finding(
            title="User Account Control (UAC)",
            status="PASS",
            severity="INFO",
            category="Privilege Management",
            details=("Configuración UAC segura."),
            recommendation=("Mantener la configuración recomendada de UAC."),
            reference=("Microsoft Security Baseline / CIS Windows Benchmark"),
            impact=(
                "UAC correctamente configurado reduce ejecuciones "
                "no autorizadas con privilegios administrativos."
            ),
            compliance=["CIS Controls v8 - Control 5", "NIST SP 800-53 AC-6"],
        )
