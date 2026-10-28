from pathlib import Path

from atom_core.base_auditor import BaseAuditor


def audit_failed_logins(auditor: BaseAuditor) -> None: # [TIPADO AÑADIDO]

    auditor.log("Evaluando intentos fallidos de autenticación...")

    logs = ["/var/log/auth.log", "/var/log/secure"]

    encontrado = False

    cantidad = 0
    logs_consultados = 0

    for log_file in logs:
        if not Path(log_file).is_file():
            continue

        logs_consultados += 1
        resultado_comando = auditor._run_command(
            f"grep 'Failed password' {log_file} 2>/dev/null"
        )

        if auditor._record_command_error(
            resultado_comando,
            "Failed SSH Logins",
            allowed_returncodes=(0, 1),
        ):
            return

        resultado = resultado_comando.stdout

        if resultado:
            encontrado = True

            cantidad += len(resultado.splitlines())

    if logs_consultados == 0:
        auditor.add_finding(
            title="Failed SSH Logins",
            status="ERROR",
            severity="MEDIUM",
            category="Authentication Security",
            details="No se encontró un archivo de registro de autenticación compatible.",
            recommendation="Verificar la configuración de registros de autenticación del sistema.",
            compliance=["CIS Linux Benchmark"],
        )
        return

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
