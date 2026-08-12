from atom_core.base_auditor import BaseAuditor


def audit_permissions(auditor: BaseAuditor) -> None: # [TYPING ADDED]

    auditor.log("Evaluando permisos críticos del sistema...")

    archivos = ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]

    for archivo in archivos:
        permisos = auditor._run_command(f"stat -c '%a' {archivo}").strip()

        if permisos.startswith("ERROR"):
            auditor.add_finding(
                title=f"Permissions {archivo}",
                status="ERROR",
                severity="HIGH",
                category="File Permissions",
                details=(permisos),
                recommendation=(
                    "Verificar existencia del archivo y permisos "
                    "de ejecución de la auditoría."
                ),
                impact=(
                    "Permisos incorrectos pueden exponer información "
                    "sensible del sistema."
                ),
                compliance=["CIS Linux Benchmark"],
            )

            continue

        if not permisos.isdigit():
            auditor.add_finding(
                title=f"Permissions {archivo}",
                status="ERROR",
                severity="MEDIUM",
                category="File Permissions",
                details=(f"Formato de permisos inesperado: {permisos}"),
                recommendation=("Revisar permisos manualmente."),
            )

            continue

        permisos_otros = permisos[-1]

        if permisos_otros in ["2", "3", "6", "7"]:
            auditor.add_finding(
                title=f"Unsafe Permissions {archivo}",
                status="FAIL",
                severity="HIGH",
                category="File Permissions",
                details=(
                    f"Permisos inseguros detectados: {permisos}. "
                    "El grupo otros tiene permisos de escritura."
                ),
                recommendation=(
                    "Eliminar permisos de escritura pública sobre archivos críticos."
                ),
                reference=("https://man7.org/linux/man-pages/man1/stat.1.html"),
                impact=(
                    "Usuarios no privilegiados podrían modificar "
                    "archivos críticos del sistema."
                ),
                compliance=["CIS Linux Benchmark", "NIST SP 800-53 AC-3"],
            )

        else:
            auditor.add_finding(
                title=f"Secure Permissions {archivo}",
                status="PASS",
                severity="INFO",
                category="File Permissions",
                details=(f"Permisos seguros detectados: {permisos}"),
                recommendation=("Mantener permisos mínimos requeridos."),
                reference=("https://man7.org/linux/man-pages/man1/stat.1.html"),
                impact=("Reduce riesgo de modificación no autorizada."),
                compliance=["CIS Linux Benchmark"],
            )
