from atom_core.base_auditor import BaseAuditor


def audit_suid(
    auditor: BaseAuditor
):


    auditor.log(
        "Evaluando binarios SUID..."
    )


    comando = (
        "find / "
        "-perm -4000 "
        "-type f "
        "-exec ls -l {} \\; "
        "2>/dev/null"
    )


    resultado = auditor._run_command(
        comando,
        timeout=30
    )



    if (
        resultado.startswith("ERROR")
        or
        "Permission denied" in resultado
    ):


        auditor.add_finding(

            title="SUID Binary Enumeration",

            status="WARNING",

            severity="MEDIUM",

            category="Privilege Management",

            details=(
                "No fue posible completar la búsqueda "
                "de binarios SUID completamente."
            ),

            recommendation=(
                "Ejecutar Atom con privilegios elevados "
                "para obtener una auditoría completa."
            ),

            reference=(
                "https://man7.org/linux/man-pages/man1/find.1.html"
            ),

            impact=(
                "Binarios SUID inseguros pueden permitir "
                "escalación de privilegios."
            ),

            compliance=[
                "CIS Linux Benchmark"
            ]

        )


        return




    if resultado.strip():


        cantidad = len(
            resultado.splitlines()
        )


        auditor.add_finding(

            title="SUID Binary Enumeration",

            status="WARNING",

            severity="MEDIUM",

            category="Privilege Management",

            details=(
                f"Se detectaron {cantidad} binarios SUID."
            ),

            recommendation=(
                "Revisar binarios SUID innecesarios "
                "y eliminar permisos privilegiados."
            ),

            reference=(
                "https://man7.org/linux/man-pages/man1/find.1.html"
            ),

            impact=(
                "Los binarios SUID pueden ser utilizados "
                "para escalación de privilegios."
            ),

            compliance=[
                "CIS Linux Benchmark"
            ]

        )


    else:


        auditor.add_finding(

            title="SUID Binary Enumeration",

            status="PASS",

            severity="INFO",

            category="Privilege Management",

            details=(
                "No se detectaron binarios SUID."
            ),

            recommendation=(
                "Mantener revisiones periódicas."
            ),

            reference=(
                "https://man7.org/linux/man-pages/man1/find.1.html"
            ),

            impact=(
                "No se encontraron superficies SUID adicionales."
            ),

            compliance=[
                "CIS Linux Benchmark"
            ]

        )