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


def _ownership_is_secure(path: str, owner: str, group: str) -> bool:
    """Validate expected root ownership and an allowlisted group."""
    if owner != "root":
        return False

    if path == "/etc/shadow":
        # Distributions commonly use either root or shadow as the group.
        return group in {"root", "shadow"}

    return group == "root"


def audit_permissions(auditor: BaseAuditor) -> None:
    """Check permissions and ownership of critical Linux authentication files."""
    auditor.log("Evaluando permisos y propiedad de archivos críticos del sistema...")

    files = ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]

    for path in files:
        result = auditor._run_command(f"stat -c '%a:%U:%G' {path}")
        if auditor._record_command_error(result, "File Permissions Check"):
            continue

        metadata = result.stdout.strip().split(":")
        if len(metadata) != 3:
            auditor.add_finding(
                title=f"File Metadata {path}",
                status="ERROR",
                severity="MEDIUM",
                category="File Permissions",
                details=f"Formato de metadatos inesperado: {result.stdout.strip()}",
                recommendation="Revisar manualmente permisos, propietario y grupo del archivo.",
                confidence="LOW",
            )
            continue

        permission_text, owner, group = metadata
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

        permissions_secure = _permissions_are_secure(path, mode)
        ownership_secure = _ownership_is_secure(path, owner, group)

        if permissions_secure and ownership_secure:
            auditor.add_finding(
                title=f"Secure Permissions and Ownership {path}",
                status="PASS",
                severity="INFO",
                category="File Permissions",
                details=(
                    f"Permisos: {permission_text}; propietario: {owner}; grupo: {group}. "
                    "Los bits de acceso y la propiedad cumplen los criterios comprobados."
                ),
                recommendation="Mantener permisos mínimos y propietario/grupo esperados.",
                reference="https://man7.org/linux/man-pages/man1/stat.1.html",
                impact="La configuración restrictiva reduce la exposición de archivos críticos.",
                compliance=["CIS Linux Benchmark"],
            )
        else:
            issues = []
            if not permissions_secure:
                issues.append(f"permisos excesivos ({permission_text})")
            if not ownership_secure:
                issues.append(f"propietario/grupo inesperado ({owner}:{group})")

            auditor.add_finding(
                title=f"Unsafe Permissions or Ownership {path}",
                status="FAIL",
                severity="HIGH",
                category="File Permissions",
                details=f"Configuración insegura detectada en {path}: " + "; ".join(issues) + ".",
                recommendation=(
                    "Verificar y corregir permisos y propiedad según la distribución. "
                    "Se espera propietario root; grupo root para /etc/passwd y /etc/sudoers; "
                    "grupo root o shadow para /etc/shadow."
                ),
                reference="https://man7.org/linux/man-pages/man1/stat.1.html",
                impact=(
                    "Permisos o propiedad incorrectos pueden exponer o permitir modificar "
                    "archivos críticos de autenticación y privilegios."
                ),
                compliance=["CIS Linux Benchmark", "NIST SP 800-53 AC-3"],
            )
