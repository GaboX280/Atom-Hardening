from atom_core.base_auditor import BaseAuditor


def audit_password_policy(auditor: BaseAuditor) -> None: # [TYPING ADDED]

    auditor.log("Evaluando política de expiración de contraseñas...")

    resultado = auditor._run_command("grep PASS_MAX_DAYS /etc/login.defs")

    if resultado.startswith("ERROR"):
        auditor.add_finding(
            title="Password Expiration Policy",
            status="ERROR",
            severity="MEDIUM",
            category="Authentication Security",
            details=(
                "No fue posible consultar la política de expiración de contraseñas."
            ),
            recommendation=("Verificar permisos de lectura sobre /etc/login.defs."),
            impact=(
                "Una política débil de expiración puede "
                "permitir el uso prolongado de credenciales "
                "comprometidas."
            ),
            compliance=["CIS Linux Benchmark"],
        )

        return

    dias = None

    for linea in resultado.splitlines():
        linea = linea.strip()

        if "PASS_MAX_DAYS" in linea and not linea.startswith("#"):
            partes = linea.split()

            if len(partes) >= 2:
                try:
                    dias = int(partes[1])

                except ValueError:
                    dias = None

    if dias is not None and dias <= 90:
        auditor.add_finding(
            title="Password Expiration Policy",
            status="PASS",
            severity="INFO",
            category="Authentication Security",
            details=(f"Caducidad máxima configurada: {dias} días."),
            recommendation=("Mantener una política segura de expiración."),
            reference=("https://man7.org/linux/man-pages/man5/login.defs.5.html"),
            impact=("Reduce la ventana de exposición de credenciales comprometidas."),
            compliance=["CIS Linux Benchmark", "NIST SP 800-53 IA-5"],
        )

    else:
        auditor.add_finding(
            title="Password Expiration Policy",
            status="WARNING",
            severity="MEDIUM",
            category="Authentication Security",
            details=(
                f"Valor encontrado: {dias}. "
                "La política supera los 90 días recomendados."
            ),
            recommendation=(
                "Configurar PASS_MAX_DAYS a un valor menor o igual a 90 días."
            ),
            reference=("https://man7.org/linux/man-pages/man5/login.defs.5.html"),
            impact=(
                "Contraseñas con larga duración aumentan el riesgo ante filtraciones."
            ),
            compliance=["CIS Linux Benchmark"],
        )
