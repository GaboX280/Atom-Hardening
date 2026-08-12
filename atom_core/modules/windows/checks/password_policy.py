from atom_core.base_auditor import BaseAuditor


def audit_password_policy(auditor: BaseAuditor) -> None: # [TYPING ADDED]
    """
    Audita la política mínima de contraseñas.
    """

    auditor.log("Evaluando política de contraseñas...")

    resultado = auditor._run_command("net accounts")

    longitud_minima = 0

    for linea in resultado.splitlines():
        if (
            "LONGITUD MÍNIMA" in linea.upper()
            or "MINIMUM PASSWORD LENGTH" in linea.upper()
        ):
            numeros = [int(x) for x in linea.split() if x.isdigit()]

            if numeros:
                longitud_minima = numeros[0]

                break

    target_min_length = auditor.config.get("password_policy", {}).get("min_length", 8)

    if longitud_minima >= target_min_length:
        auditor.add_finding(
            title="Password Policy",
            status="PASS",
            severity="INFO",
            category="Identity Management",
            details=(f"Longitud mínima configurada: {longitud_minima} caracteres."),
            recommendation=("Mantener políticas robustas de contraseña."),
            reference=("Microsoft Security Baseline / CIS Windows Benchmark"),
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
            details=(f"Longitud mínima encontrada: {longitud_minima} caracteres."),
            recommendation=(
                f"Configurar una longitud mínima de {target_min_length} caracteres o superior."
            ),
            reference=("Microsoft Security Baseline / CIS Windows Benchmark"),
            impact=(
                "Contraseñas débiles aumentan la posibilidad de "
                "compromiso de cuentas mediante ataques de fuerza bruta."
            ),
            compliance=["CIS Controls v8 - Control 5", "NIST SP 800-53 IA-5"],
        )
