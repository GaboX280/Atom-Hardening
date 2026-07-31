from atom_core.base_auditor import BaseAuditor


def audit_firewall(
    auditor: BaseAuditor
):

    auditor.log(
        f"Evaluando firewall Linux ({auditor.distro})..."
    )


    # =====================================================
    # UFW
    # =====================================================

    if auditor.command_exists("ufw"):


        resultado = auditor._run_command(
            "ufw status"
        ).lower()


        if "status: active" in resultado:


            auditor.add_finding(

                title="Linux Firewall UFW",

                status="PASS",

                severity="INFO",

                category="Network Security",

                details=(
                    "UFW está instalado y activo."
                ),

                recommendation=(
                    "Mantener reglas restrictivas y actualizadas."
                ),

                reference=(
                    "UFW Documentation"
                ),

                impact=(
                    "El tráfico no autorizado es filtrado."
                ),

                compliance=[
                    "CIS Linux Benchmark"
                ]
            )


        else:


            auditor.add_finding(

                title="Linux Firewall UFW",

                status="WARNING",

                severity="MEDIUM",

                category="Network Security",

                details=(
                    "UFW está instalado pero deshabilitado."
                ),

                recommendation=(
                    "Activar UFW si el equipo requiere filtrado de red."
                ),

                reference=(
                    "UFW Documentation"
                ),

                impact=(
                    "Los servicios pueden quedar expuestos."
                ),

                compliance=[
                    "CIS Linux Benchmark"
                ]
            )


        return




    # =====================================================
    # nftables
    # =====================================================

    if auditor.command_exists("nft"):


        resultado = auditor._run_command(
            "nft list ruleset"
        )


        if resultado.startswith("ERROR"):


            auditor.add_finding(

                title="Linux Firewall nftables",

                status="ERROR",

                severity="MEDIUM",

                category="Network Security",

                details=resultado,

                recommendation=(
                    "Ejecutar auditoría con permisos adecuados."
                )
            )

            return



        reglas = resultado.strip()



        if (
            reglas
            and
            (
                "table inet" in reglas
                or
                "chain" in reglas.lower()
            )
        ):


            auditor.add_finding(

                title="Linux Firewall nftables",

                status="PASS",

                severity="INFO",

                category="Network Security",

                details=(
                    "nftables posee reglas configuradas."
                ),

                recommendation=(
                    "Mantener revisión periódica de reglas."
                ),

                reference=(
                    "nftables Documentation"
                ),

                impact=(
                    "El kernel aplica filtrado de tráfico."
                ),

                compliance=[
                    "CIS Linux Benchmark"
                ]
            )


        else:


            auditor.add_finding(

                title="Linux Firewall nftables",

                status="WARNING",

                severity="MEDIUM",

                category="Network Security",

                details=(

                    "nftables está instalado pero no posee reglas."
                ),

                recommendation=(

                    "Configurar reglas de filtrado según el uso del sistema."
                ),

                reference=(

                    "nftables Documentation"
                ),

                impact=(

                    "El sistema no posee una política efectiva de filtrado."
                ),

                compliance=[
                    "CIS Linux Benchmark"
                ]
            )


        return




    # =====================================================
    # Firewalld
    # =====================================================

    if auditor.command_exists(
        "firewall-cmd"
    ):


        resultado = auditor._run_command(
            "firewall-cmd --state"
        ).lower()


        if "running" in resultado:


            auditor.add_finding(

                title="Linux Firewall Firewalld",

                status="PASS",

                severity="INFO",

                category="Network Security",

                details=(
                    "Firewalld está activo."
                ),

                recommendation=(
                    "Mantener zonas y reglas actualizadas."
                ),

                compliance=[
                    "CIS Linux Benchmark"
                ]
            )


        else:


            auditor.add_finding(

                title="Linux Firewall Firewalld",

                status="WARNING",

                severity="MEDIUM",

                category="Network Security",

                details=(
                    "Firewalld está instalado pero detenido."
                ),

                recommendation=(
                    "Activar firewalld si es requerido."
                )
            )


        return




    # =====================================================
    # IPTABLES LEGACY
    # =====================================================

    if auditor.command_exists(
        "iptables"
    ):


        resultado = auditor._run_command(
            "iptables -L -n"
        )


        if (
            resultado
            and
            "Chain" in resultado
        ):


            auditor.add_finding(

                title="Linux Firewall iptables",

                status="WARNING",

                severity="MEDIUM",

                category="Network Security",

                details=(
                    "iptables está disponible y posee cadenas."
                ),

                recommendation=(
                    "Migrar reglas a nftables cuando sea posible."
                ),

                compliance=[
                    "CIS Linux Benchmark"
                ]
            )


        return




    # =====================================================
    # SIN FIREWALL
    # =====================================================


    auditor.add_finding(

        title="Linux Firewall",

        status="WARNING",

        severity="MEDIUM",

        category="Network Security",

        details=(

            "No se detectó una solución firewall configurada."
        ),

        recommendation=(

            "Configurar nftables, UFW o firewalld según el escenario."
        ),

        reference=(

            "CIS Linux Benchmark"
        ),

        impact=(

            "La máquina puede aceptar tráfico no filtrado."
        ),

        compliance=[
            "CIS Linux Benchmark"
        ]
    )