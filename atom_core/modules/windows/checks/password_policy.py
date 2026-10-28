import re

from atom_core.base_auditor import BaseAuditor


def audit_password_policy(auditor: BaseAuditor) -> None:
    """Audit the configured minimum password length on Windows."""
    auditor.log("Evaluando política de contraseñas...")

    result = auditor._run_command("net accounts")
    if auditor._record_command_error(result, "Password Policy Check"):
        return

    minimum_length: int | None = None
    for line in result.stdout.splitlines():
        if (
            "LONGITUD MÍNIMA" in line.upper()
            or "MINIMUM PASSWORD LENGTH" in line.upper()
        ):
            match = re.search(r"\d+", line)
            if match:
                minimum_length = int(match.group())
            break

    if minimum_length is None:
        auditor.add_finding(
            title="Password Policy",
            status="WARNING",
            severity="MEDIUM",
            category="Identity Management",
            details=(
                "No se pudo interpretar la longitud mínima de contraseña "
                "en la salida de net accounts."
            ),
            recommendation=(
                "Verificar manualmente la política de contraseñas y repetir "
                "la auditoría con la salida del sistema esperada."
            ),
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact=(
                "No fue posible confirmar si la longitud mínima de contraseña "
                "cumple el umbral configurado."
            ),
            confidence="LOW",
            compliance=["CIS Controls v8 - Control 5", "NIST SP 800-53 IA-5"],
        )
        return

    target_min_length = auditor.config.get("password_policy", {}).get(
        "min_length", 8
    )

    if minimum_length >= target_min_length:
        auditor.add_finding(
            title="Password Policy",
            status="PASS",
            severity="INFO",
            category="Identity Management",
            details=f"Longitud mínima configurada: {minimum_length} caracteres.",
            recommendation="Mantener políticas robustas de contraseña.",
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact=(
                "Una política adecuada reduce el riesgo de ataques "
                "de fuerza bruta y compromiso de credenciales."
            ),
            compliance=["CIS Controls v8 - Control 5", "NIST SP 800-53 IA-5"],
        )
    else:
        auditor.add_finding(
            title="Password Policy",
            status="FAIL",
            severity="MEDIUM",
            category="Identity Management",
            details=f"Longitud mínima encontrada: {minimum_length} caracteres.",
            recommendation=(
                f"Configurar una longitud mínima de {target_min_length} "
                "caracteres o superior."
            ),
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact=(
                "Contraseñas débiles aumentan la posibilidad de "
                "compromiso de cuentas mediante ataques de fuerza bruta."
            ),
            compliance=["CIS Controls v8 - Control 5", "NIST SP 800-53 IA-5"],
        )
