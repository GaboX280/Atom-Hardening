from atom_core.base_auditor import BaseAuditor


def audit_suid(auditor: BaseAuditor) -> None: # [TYPING ADDED]

    auditor.log("Evaluando binarios SUID...")

    comando = "find / -xdev -perm -4000 -type f 2>/dev/null"

    resultado = auditor._run_command(comando, timeout=30)

    if resultado.startswith("ERROR"):
        auditor.add_finding(
            title="SUID Binary Enumeration",
            status="WARNING",
            severity="MEDIUM",
            category="Privilege Management",
            details=("No fue posible completar la búsqueda SUID."),
            recommendation=("Ejecutar Atom con sudo para obtener mayor visibilidad."),
            reference=("https://man7.org/linux/man-pages/man1/find.1.html"),
            impact=(
                "La falta de visibilidad puede ocultar riesgos "
                "de escalación de privilegios."
            ),
            compliance=["CIS Linux Benchmark"],
        )

        return

    binarios = [x.strip() for x in resultado.splitlines() if x.strip()]

    if not binarios:
        auditor.add_finding(
            title="SUID Binary Enumeration",
            status="PASS",
            severity="INFO",
            category="Privilege Management",
            details=("No se detectaron binarios con permisos SUID."),
            recommendation=("Mantener auditorías periódicas."),
            reference=("https://man7.org/linux/man-pages/man1/find.1.html"),
            impact=("No existen binarios SUID adicionales detectados."),
            compliance=["CIS Linux Benchmark"],
        )

        return

    # Binarios considerados de alto riesgo
    peligrosos = [
        "/bin/bash",
        "/bin/sh",
        "/usr/bin/python",
        "/usr/bin/python3",
        "/usr/bin/perl",
        "/usr/bin/ruby",
        "/usr/bin/vim",
        "/usr/bin/find",
        "/usr/bin/nmap",
        "/usr/bin/awk",
    ]

    sospechosos = []

    for binario in binarios:
        if binario in peligrosos:
            sospechosos.append(binario)

    if sospechosos:
        auditor.add_finding(
            title="Dangerous SUID Binaries",
            status="WARNING",
            severity="HIGH",
            category="Privilege Management",
            details=(
                "Se detectaron binarios SUID con posible "
                "capacidad de escalación: " + ", ".join(sospechosos)
            ),
            recommendation=(
                "Revisar si estos binarios requieren permisos SUID "
                "y eliminarlos si no son necesarios."
            ),
            reference=("Linux Privilege Escalation"),
            impact=(
                "Un atacante local podría abusar de estos binarios "
                "para obtener privilegios elevados."
            ),
            compliance=["CIS Linux Benchmark"],
        )

    else:
        auditor.add_finding(
            title="SUID Binary Enumeration",
            status="PASS",
            severity="INFO",
            category="Privilege Management",
            details=(
                f"Se detectaron {len(binarios)} binarios SUID "
                "sin patrones críticos conocidos."
            ),
            recommendation=("Mantener revisión periódica de permisos SUID."),
            reference=("https://man7.org/linux/man-pages/man1/find.1.html"),
            impact=(
                "Los permisos SUID existentes parecen corresponder "
                "a binarios legítimos del sistema."
            ),
            compliance=["CIS Linux Benchmark"],
        )
