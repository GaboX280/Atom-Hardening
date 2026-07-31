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
                    "Mantener reglas del firewall actualizadas."
                ),
                reference=(
                    "UFW Documentation"
                ),
                impact=(
                    "Filtra tráfico entrante y reduce superficie de ataque."
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
                    "Activar UFW y aplicar política restrictiva."
                ),
                reference=(
                    "UFW Documentation"
                ),
                impact=(
                    "El sistema puede aceptar tráfico no autorizado."
                ),
                compliance=[
                    "CIS Linux Benchmark"
                ]
            )


        return




    # =====================================================
    # Firewalld
    # =====================================================

    if auditor.command_exists("firewall-cmd"):


        resultado = auditor._run_command(
            "firewall-cmd --state"
        ).lower()



        if resultado.strip() == "running":


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
                reference=(
                    "Firewalld Documentation"
                ),
                impact=(
                    "Controla tráfico mediante zonas de seguridad."
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
                    "Activar firewalld."
                ),
                reference=(
                    "Firewalld Documentation"
                ),
                impact=(
                    "Puede existir exposición de servicios."
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



        if (
            resultado
            and
            not resultado.startswith("ERROR")
            and
            "table" in resultado
        ):


            auditor.add_finding(
                title="Linux Firewall nftables",
                status="PASS",
                severity="INFO",
                category="Network Security",
                details=(
                    "nftables está configurado con reglas activas."
                ),
                recommendation=(
                    "Realizar auditorías periódicas de reglas."
                ),
                reference=(
                    "nftables Documentation"
                ),
                impact=(
                    "Controla tráfico mediante filtrado a nivel kernel."
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
                    "nftables está instalado pero no tiene reglas activas."
                ),
                recommendation=(
                    "Crear reglas restrictivas."
                ),
                reference=(
                    "nftables Documentation"
                ),
                impact=(
                    "El sistema puede carecer de filtrado efectivo."
                ),
                compliance=[
                    "CIS Linux Benchmark"
                ]
            )


        return




    # =====================================================
    # iptables
    # =====================================================

    if auditor.command_exists("iptables"):


        resultado = auditor._run_command(
            "iptables -L -n"
        )



        if (
            resultado
            and
            not resultado.startswith("ERROR")
            and
            "Chain" in resultado
        ):


            auditor.add_finding(
                title="Linux Firewall iptables",
                status="WARNING",
                severity="MEDIUM",
                category="Network Security",
                details=(
                    "iptables está configurado."
                ),
                recommendation=(
                    "Revisar reglas y migrar a nftables cuando sea posible."
                ),
                reference=(
                    "iptables Documentation"
                ),
                impact=(
                    "Una configuración incorrecta puede permitir accesos."
                ),
                compliance=[
                    "CIS Linux Benchmark"
                ]
            )


        return




    # =====================================================
    # Sin firewall
    # =====================================================

    auditor.add_finding(
        title="Linux Firewall",
        status="FAIL",
        severity="HIGH",
        category="Network Security",
        details=(
            "No se detectó ningún mecanismo firewall."
        ),
        recommendation=(
            "Configurar UFW, firewalld, nftables o iptables."
        ),
        reference=(
            "CIS Linux Benchmark"
        ),
        impact=(
            "El sistema puede estar expuesto a conexiones no filtradas."
        ),
        compliance=[
            "CIS Linux Benchmark"
        ]
    )