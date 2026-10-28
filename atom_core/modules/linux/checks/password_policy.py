from atom_core.base_auditor import BaseAuditor


def audit_password_policy(auditor: BaseAuditor) -> None:
    """Audit maximum password age in /etc/login.defs."""
    auditor.log("Evaluando política de expiración de contraseñas...")

    result = auditor._run_command("grep PASS_MAX_DAYS /etc/login.defs")
    if auditor._record_command_error(
        result, "Password Expiration Policy", allowed_returncodes=(0, 1)
    ):
        return

    max_age_days: int | None = None
    for line in result.stdout.splitlines():
        line = line.strip()
        if "PASS_MAX_DAYS" not in line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) >= 2:
            try:
                max_age_days = int(parts[1])
            except ValueError:
                max_age_days = None
        break

    if max_age_days is None:
        auditor.add_finding(
            title="Password Expiration Policy",
            status="WARNING",
            severity="MEDIUM",
            category="Authentication Security",
            details="No fue posible interpretar PASS_MAX_DAYS en /etc/login.defs.",
            recommendation="Verificar manualmente la política de expiración y repetir la auditoría.",
            reference="https://man7.org/linux/man-pages/man5/login.defs.5.html",
            impact="No fue posible confirmar el límite de antigüedad de las contraseñas.",
            confidence="LOW",
            compliance=["CIS Linux Benchmark"],
        )
        return

    policy = auditor.config.get("password_policy", {})
    configured_max_age = (
        policy.get("max_age_days", 90) if isinstance(policy, dict) else 90
    )
    if (
        not isinstance(configured_max_age, int)
        or isinstance(configured_max_age, bool)
        or configured_max_age < 1
    ):
        configured_max_age = 90

    if max_age_days < 1:
        if max_age_days == -1:
            detail = "PASS_MAX_DAYS está configurado en -1; la caducidad por antigüedad está deshabilitada."
        else:
            detail = (
                f"PASS_MAX_DAYS está configurado en {max_age_days}; "
                "el valor no representa un límite de antigüedad normal."
            )

        auditor.add_finding(
            title="Password Expiration Policy",
            status="WARNING",
            severity="MEDIUM",
            category="Authentication Security",
            details=detail,
            recommendation=(
                f"Configurar PASS_MAX_DAYS con un valor entre 1 y "
                f"{configured_max_age} días, según la política de la organización."
            ),
            reference="https://man7.org/linux/man-pages/man5/login.defs.5.html",
            impact="La política actual no confirma un límite de antigüedad adecuado.",
            compliance=["CIS Linux Benchmark"],
        )
        return

    if max_age_days <= configured_max_age:
        auditor.add_finding(
            title="Password Expiration Policy",
            status="PASS",
            severity="INFO",
            category="Authentication Security",
            details=f"Caducidad máxima configurada: {max_age_days} días.",
            recommendation="Mantener la política definida por la organización.",
            reference="https://man7.org/linux/man-pages/man5/login.defs.5.html",
            impact="La antigüedad máxima está dentro del umbral configurado.",
            compliance=["CIS Linux Benchmark", "NIST SP 800-53 IA-5"],
        )
        return

    auditor.add_finding(
        title="Password Expiration Policy",
        status="WARNING",
        severity="MEDIUM",
        category="Authentication Security",
        details=(
            f"Caducidad máxima encontrada: {max_age_days} días; "
            f"el límite configurado es {configured_max_age} días."
        ),
        recommendation=(
            f"Configurar PASS_MAX_DAYS a un valor menor o igual a "
            f"{configured_max_age} días, según la política de la organización."
        ),
        reference="https://man7.org/linux/man-pages/man5/login.defs.5.html",
        impact="Contraseñas con una antigüedad superior al umbral aumentan el riesgo de exposición prolongada.",
        compliance=["CIS Linux Benchmark"],
    )
