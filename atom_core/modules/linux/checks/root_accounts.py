from atom_core.base_auditor import BaseAuditor


def audit_root_accounts(auditor: BaseAuditor) -> None: # [TYPING ADDED]

    auditor.log("Evaluando cuentas con UID 0...")

    usuarios = auditor._run_command("awk -F: '($3 == 0) {print $1}' /etc/passwd")

    if usuarios.startswith("ERROR"):
        auditor.add_finding(
            title="Root Account Enumeration",
            status="ERROR",
            severity="HIGH",
            category="Identity Management",
            details=("No fue posible consultar cuentas con UID 0."),
            recommendation=("Ejecutar la auditoría con permisos suficientes."),
            impact=(
                "No validar cuentas privilegiadas puede ocultar "
                "usuarios con privilegios administrativos."
            ),
            compliance=["CIS Linux Benchmark"],
        )

        return

    cuentas = usuarios.splitlines()

    if len(cuentas) > 1:
        auditor.add_finding(
            title="Multiple Root Accounts",
            status="FAIL",
            severity="HIGH",
            category="Identity Management",
            details=(
                f"Se detectaron múltiples cuentas con UID 0: {', '.join(cuentas)}"
            ),
            recommendation=(
                "Mantener únicamente cuentas privilegiadas necesarias y utilizar sudo."
            ),
            reference=("https://man7.org/linux/man-pages/man5/passwd.5.html"),
            impact=(
                "Múltiples cuentas root aumentan la superficie "
                "de ataque y dificultan la trazabilidad."
            ),
            compliance=["CIS Linux Benchmark", "NIST SP 800-53 AC-6"],
        )

    else:
        auditor.add_finding(
            title="Root Account Security",
            status="PASS",
            severity="INFO",
            category="Identity Management",
            details=("Solo existe una cuenta con UID 0."),
            recommendation=("Mantener control de privilegios mediante sudo."),
            reference=("https://man7.org/linux/man-pages/man5/passwd.5.html"),
            impact=(
                "Una correcta gestión de cuentas privilegiadas "
                "reduce riesgos de escalamiento."
            ),
            compliance=["CIS Linux Benchmark"],
        )
