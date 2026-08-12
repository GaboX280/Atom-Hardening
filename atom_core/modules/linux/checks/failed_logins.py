from atom_core.base_auditor import BaseAuditor


def audit_failed_logins(auditor: BaseAuditor) -> None: # [TYPING ADDED]

    auditor.log("Evaluando intentos fallidos de autenticación...")

    logs = ["/var/log/auth.log", "/var/log/secure"]

    encontrado = False

    cantidad = 0

    for log_file in logs:
        resultado = auditor._run_command(
            f"grep 'Failed password' {log_file} 2>/dev/null"
        )

        if resultado and not resultado.startswith("ERROR"):
            encontrado = True

            cantidad += len(resultado.splitlines())

    if encontrado:
        auditor.add_finding(
            title="Failed SSH Logins",
            status="WARNING",
            severity="MEDIUM",
            category="Authentication Security",
            details=(
                f"Se detectaron {cantidad} intentos fallidos de autenticación SSH."
            ),
            recommendation=(
                "Revisar registros de acceso, aplicar "
                "políticas de bloqueo y fortalecer SSH."
            ),
            reference=("https://man7.org/linux/man-pages/man8/sshd.8.html"),
            impact=(
                "Múltiples intentos fallidos pueden indicar ataques de fuerza bruta."
            ),
            compliance=["CIS Linux Benchmark", "NIST SP 800-53 AC-7"],
        )

    else:
        auditor.add_finding(
            title="Failed SSH Logins",
            status="PASS",
            severity="INFO",
            category="Authentication Security",
            details=("No se encontraron intentos fallidos de autenticación SSH."),
            recommendation=("Mantener monitoreo continuo de logs."),
            reference=("https://man7.org/linux/man-pages/man5/auth.conf.5.html"),
            impact=("Reduce el riesgo de accesos no autorizados por fuerza bruta."),
            compliance=["CIS Linux Benchmark"],
        )
