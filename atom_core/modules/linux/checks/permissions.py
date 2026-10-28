from atom_core.base_auditor import BaseAuditor


def _permissions_are_secure(path: str, mode: int) -> bool:
    """Apply conservative permission-bit checks for critical system files."""
    execute_or_special_bits = 0o111 | 0o7000

    if path == "/etc/passwd":
        # Read access for group/others is expected, but writes and execute bits
        # are not appropriate for this file.
        return not mode & (0o022 | execute_or_special_bits)

    # /etc/shadow and /etc/sudoers must not be accessible to "others".
    # Group read may be needed for the shadow group; group write is not allowed.
    return not mode & (0o027 | execute_or_special_bits)


def audit_permissions(auditor: BaseAuditor) -> None:
    """Check access permissions on critical Linux authentication files."""
    auditor.log("Evaluando permisos críticos del sistema...")

    files = ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]

    for path in files:
        result = auditor._run_command(f"stat -c '%a' {path}")
        if auditor._record_command_error(result, "File Permissions Check"):
            continue

        permission_text = result.stdout.strip()
        try:
            mode = int(permission_text, 8)
        except ValueError:
            auditor.add_finding(
                title=f"Permissions {path}",
                status="ERROR",
                severity="MEDIUM",
                category="File Permissions",
                details=f"Formato de permisos inesperado: {permission_text}",
                recommendation="Revisar los permisos del archivo manualmente.",
                confidence="LOW",
            )
            continue

        if _permissions_are_secure(path, mode):
            auditor.add_finding(
                title=f"Secure Permissions {path}",
                status="PASS",
                severity="INFO",
                category="File Permissions",
                details=(
                    f"Permisos detectados: {permission_text}. "
                    "Los bits de acceso cumplen los límites comprobados; "
                    "la propiedad del archivo no se ha verificado."
                ),
                recommendation="Mantener permisos mínimos y verificar también propietario y grupo.",
                reference="https://man7.org/linux/man-pages/man1/stat.1.html",
                impact="Los permisos restrictivos reducen la exposición de archivos críticos.",
                compliance=["CIS Linux Benchmark"],
            )
        else:
            auditor.add_finding(
                title=f"Unsafe Permissions {path}",
                status="FAIL",
                severity="HIGH",
                category="File Permissions",
                details=(
                    f"Permisos potencialmente inseguros detectados: {permission_text}."
                ),
                recommendation=(
                    "Eliminar escritura para grupo/otros en /etc/passwd; "
                    "restringir todo acceso de otros y la escritura de grupo "
                    "en /etc/shadow y /etc/sudoers; revisar también propietario y grupo."
                ),
                reference="https://man7.org/linux/man-pages/man1/stat.1.html",
                impact=(
                    "Permisos excesivos pueden exponer o permitir modificar "
                    "archivos críticos de autenticación y privilegios."
                ),
                compliance=["CIS Linux Benchmark", "NIST SP 800-53 AC-3"],
            )
