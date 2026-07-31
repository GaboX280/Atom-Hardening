from atom_core.base_auditor import BaseAuditor


def audit_network(auditor: BaseAuditor):


    auditor.log(
        "Evaluando servicios de red escuchando..."
    )


    resultado = auditor._run_command(
        "ss -tulpn"
    )



    if resultado.startswith("ERROR"):


        auditor.add_finding(

            title="Listening Network Services",

            status="ERROR",

            severity="MEDIUM",

            category="Network Security",

            details=(

                "No fue posible obtener los servicios "
                "de red activos."

            ),

            recommendation=(

                "Ejecutar la auditoría con permisos "
                "suficientes."

            ),

            impact=(

                "No identificar servicios expuestos puede "
                "ocultar superficies de ataque."

            ),

            compliance=[

                "CIS Linux Benchmark"

            ]

        )

        return



    lineas = resultado.splitlines()



    # Eliminamos la cabecera de ss
    servicios = (
        len(lineas) - 1
        if len(lineas) > 1
        else 0
    )



    if servicios > 0:


        auditor.add_finding(

            title="Listening Network Services",

            status="WARNING",

            severity="MEDIUM",

            category="Network Security",

            details=(

                f"Servicios escuchando detectados: {servicios}"

            ),

            recommendation=(

                "Revisar puertos expuestos y deshabilitar "
                "servicios innecesarios."

            ),

            reference=(

                "https://man7.org/linux/man-pages/man8/ss.8.html"

            ),

            impact=(

                "Servicios innecesarios expuestos aumentan "
                "la superficie de ataque."

            ),

            compliance=[

                "CIS Linux Benchmark",
                "NIST SP 800-53 CM-7"

            ]

        )



    else:


        auditor.add_finding(

            title="Listening Network Services",

            status="PASS",

            severity="INFO",

            category="Network Security",

            details=(

                "No se detectaron servicios escuchando."

            ),

            recommendation=(

                "Mantener monitoreo periódico de puertos."

            ),

            reference=(

                "https://man7.org/linux/man-pages/man8/ss.8.html"

            ),

            impact=(

                "Reduce la exposición de servicios "
                "no autorizados."

            ),

            compliance=[

                "CIS Linux Benchmark"

            ]

        )