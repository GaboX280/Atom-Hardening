from atom_core.base_auditor import BaseAuditor


def audit_suid(
    auditor: BaseAuditor
):

    auditor.log(
        "Evaluando binarios SUID..."
    )


    comando = (
        "find / "
        "-xdev "
        "-perm -4000 "
        "-type f "
        "2>/dev/null"
    )


    resultado = auditor._run_command(
        comando,
        timeout=30
    )



    if resultado.startswith("ERROR"):


        auditor.add_finding(

            title="SUID Binary Enumeration",

            status="WARNING",

            severity="MEDIUM",

            category="Privilege Management",

            details=(
                "No fue posible completar la búsqueda SUID."
            ),

            recommendation=(
                "Ejecutar Atom con sudo para mayor visibilidad."
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




    binarios = resultado.splitlines()



    if not binarios:


        auditor.add_finding(

            title="SUID Binary Enumeration",

            status="PASS",

            severity="INFO",

            category="Privilege Management",

            details=(
                "No se detectaron binarios SUID."
            ),

            recommendation=(
                "Mantener auditorías periódicas."
            ),

            compliance=[
                "CIS Linux Benchmark"
            ]

        )

        return




    # Binarios que suelen ser críticos
    peligrosos = [

        "bash",
        "sh",
        "python",
        "perl",
        "ruby",
        "vim",
        "find",
        "nmap",
        "awk"

    ]



    sospechosos = []


    for binario in binarios:

        for peligro in peligrosos:

            if binario.endswith(peligro):

                sospechosos.append(
                    binario
                )




    if sospechosos:


        auditor.add_finding(

            title="Dangerous SUID Binaries",

            status="FAIL",

            severity="HIGH",

            category="Privilege Management",

            details=(

                "Binarios SUID potencialmente peligrosos: "
                +
                ", ".join(sospechosos)

            ),

            recommendation=(

                "Eliminar permisos SUID innecesarios."

            ),

            reference=(

                "Linux Privilege Escalation"

            ),

            impact=(

                "Puede permitir escalación local de privilegios."

            ),

            compliance=[

                "CIS Linux Benchmark"

            ]

        )


    else:


        auditor.add_finding(

            title="SUID Binary Enumeration",

            status="WARNING",

            severity="LOW",

            category="Privilege Management",

            details=(

                f"Se detectaron {len(binarios)} "
                "binarios SUID estándar."

            ),

            recommendation=(

                "Revisar periódicamente permisos SUID."

            ),

            reference=(

                "https://man7.org/linux/man-pages/man1/find.1.html"

            ),

            impact=(

                "Los binarios SUID aumentan superficie de ataque."

            ),

            compliance=[

                "CIS Linux Benchmark"

            ]

        )