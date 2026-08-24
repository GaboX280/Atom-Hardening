from atom_core.base_auditor import BaseAuditor


def audit_admin_account(auditor: BaseAuditor) -> None: # [TIPADO AÑADIDO]

    auditor.log("Evaluando cuenta Administrador...")

    resultado = auditor._run_command(["net", "user", "Administrador"])

    resultado_upper = resultado.upper()

    activa_es = False
    if not resultado.startswith("ERROR"):
        activa_es = "CUENTA ACTIVA" in resultado_upper and "SÍ" in resultado_upper

    activa_en = False
    if not activa_es:
        resultado_en = auditor._run_command(["net", "user", "Administrator"]).upper()
        activa_en = "ACCOUNT ACTIVE" in resultado_en and "YES" in resultado_en

    activa = activa_es or activa_en

    if activa:
        auditor.add_finding(
            title="Default Administrator Account",
            status="FAIL",
            severity="HIGH",
            category="Privileged Access Management",
            details=("La cuenta Administrador nativa está habilitada."),
            recommendation=(
                "Deshabilitar la cuenta Administrador integrada si no "
                "es necesaria y utilizar cuentas administrativas "
                "individuales con privilegios controlados."
            ),
            reference=("Microsoft Security Baseline / CIS Windows Benchmark"),
            impact=(
                "Una cuenta administrativa conocida y activa aumenta "
                "el riesgo de ataques de fuerza bruta, robo de credenciales "
                "y movimiento lateral dentro de la red."
            ),
            compliance=[
                "CIS Controls v8 - Control 5",
                "NIST SP 800-53 AC-2",
                "NIST SP 800-53 AC-6",
            ],
        )

    else:
        auditor.add_finding(
            title="Default Administrator Account",
            status="PASS",
            severity="INFO",
            category="Privileged Access Management",
            details=(
                "La cuenta Administrador nativa está deshabilitada o no fue encontrada."
            ),
            recommendation=(
                "Mantener cuentas privilegiadas controladas y utilizar "
                "el principio de mínimo privilegio."
            ),
            reference=("Microsoft Security Baseline / CIS Windows Benchmark"),
            impact=(
                "Reducir cuentas administrativas innecesarias disminuye "
                "la superficie de ataque y limita posibles abusos "
                "de privilegios."
            ),
            compliance=[
                "CIS Controls v8 - Control 5",
                "NIST SP 800-53 AC-2",
                "NIST SP 800-53 AC-6",
            ],
        )
