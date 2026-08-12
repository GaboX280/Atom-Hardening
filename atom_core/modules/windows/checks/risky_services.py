from atom_core.base_auditor import BaseAuditor


def audit_risky_services(auditor: BaseAuditor) -> None: # [TYPING ADDED]
    """
    Detecta servicios con superficie de ataque elevada.
    """

    auditor.log("Auditando servicios riesgosos...")

    risky_services = {
        "Spooler": "Print Spooler",
        "RemoteRegistry": "Remote Registry",
        "SSDPSRV": "SSDP Discovery",
    }

    for service, description in risky_services.items():
        comando = (
            f"powershell -Command "
            f'"(Get-Service {service} '
            '-ErrorAction SilentlyContinue).Status"'
        )

        resultado = auditor._run_command(comando).strip().upper()

        if "RUNNING" in resultado:
            auditor.add_finding(
                title=f"Risky Service: {description}",
                status="FAIL",
                severity="MEDIUM",
                category="Service Management",
                details=(f"El servicio {description} está ejecutándose."),
                recommendation=(
                    "Deshabilitar servicios innecesarios o restringir "
                    "su exposición según los requerimientos del sistema."
                ),
                reference=("Microsoft Security Baseline / CIS Windows Benchmark"),
                impact=(
                    f"El servicio {description} aumenta la superficie "
                    "de ataque del sistema y puede ser utilizado como "
                    "vector de explotación o movimiento lateral."
                ),
                compliance=["CIS Controls v8 - Control 4", "NIST SP 800-53 CM-7"],
            )

        else:
            auditor.add_finding(
                title=f"Risky Service: {description}",
                status="PASS",
                severity="INFO",
                category="Service Management",
                details=(f"El servicio {description} no está activo."),
                recommendation=(
                    "Mantener únicamente servicios necesarios "
                    "para reducir la superficie de ataque."
                ),
                reference=("Microsoft Security Baseline / CIS Windows Benchmark"),
                impact=(
                    "Mantener servicios innecesarios deshabilitados "
                    "reduce puntos potenciales de ataque."
                ),
                compliance=["CIS Controls v8 - Control 4", "NIST SP 800-53 CM-7"],
            )
