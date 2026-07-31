from atom_core.base_auditor import BaseAuditor


def audit_suid(auditor: BaseAuditor):


    auditor.log(
        "Buscando binarios SUID..."
    )


    resultado = auditor._run_command(
        "find / -perm -4000 -type f 2>/dev/null",
        timeout=30
    )


    if resultado.startswith("ERROR"):


        auditor.add_finding(

            title="SUID Binary Enumeration",

            status="ERROR",

            severity="MEDIUM",

            category="Privilege Management",

            details=(

                "No fue posible completar la búsqueda de "
                "binarios SUID."

            ),

            recommendation=(

                "Ejecutar la auditoría con permisos adecuados."

            ),

            impact=(

                "No identificar binarios SUID puede ocultar "
                "posibles vectores de escalamiento de privilegios."

            ),

            compliance=[

                "CIS Linux Benchmark"

            ]

        )

        return



    if resultado.strip():


        binarios = resultado.splitlines()

        cantidad = len(binarios)



        auditor.add_finding(

            title="SUID Binaries",

            status="WARNING",

            severity="MEDIUM",

            category="Privilege Management",

            details=(

                f"Se encontraron {cantidad} binarios SUID."

            ),

            recommendation=(

                "Revisar cada binario SUID y eliminar permisos "
                "innecesarios."

            ),

            reference=(

                "https://man7.org/linux/man-pages/man2/chmod.2.html"

            ),

            impact=(

                "Los binarios SUID pueden permitir escalamiento "
                "de privilegios si contienen vulnerabilidades."

            ),

            compliance=[

                "CIS Linux Benchmark",
                "NIST SP 800-53 AC-6"

            ]

        )



    else:


        auditor.add_finding(

            title="SUID Binaries",

            status="PASS",

            severity="INFO",

            category="Privilege Management",

            details=(

                "No se detectaron binarios SUID."

            ),

            recommendation=(

                "Mantener revisión periódica de permisos especiales."

            ),

            reference=(

                "https://man7.org/linux/man-pages/man2/chmod.2.html"

            ),

            impact=(

                "Reduce el riesgo de escalamiento de privilegios."

            ),

            compliance=[

                "CIS Linux Benchmark"

            ]

        )