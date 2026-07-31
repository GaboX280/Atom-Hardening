from atom_core.base_auditor import BaseAuditor


def audit_firewall(
    auditor: BaseAuditor
):


    auditor.log(
        f"Evaluando firewall Linux ({auditor.distro})..."
    )



    # ==========================
    # Debian / Ubuntu
    # ==========================

    if auditor.distro in [
        "ubuntu",
        "debian"
    ]:


        if auditor.command_exists(
            "ufw"
        ):


            resultado = auditor._run_command(
                "ufw status"
            ).strip().lower()



            if resultado.startswith(
                "status: active"
            ):


                auditor.add_finding(
                    title="Linux Firewall UFW",
                    status="PASS",
                    severity="INFO",
                    category="Network Security",
                    details=(
                        "UFW está activo."
                    ),
                    recommendation=(
                        "Mantener reglas del firewall actualizadas."
                    ),
                    reference=(
                        "UFW Documentation"
                    ),
                    impact=(
                        "Reduce exposición de servicios no autorizados."
                    ),
                    compliance=[
                        "CIS Ubuntu Linux Benchmark"
                    ]
                )



            else:


                auditor.add_finding(
                    title="Linux Firewall UFW",
                    status="FAIL",
                    severity="HIGH",
                    category="Network Security",
                    details=(
                        "UFW está instalado pero deshabilitado."
                    ),
                    recommendation=(
                        "Activar UFW y configurar reglas restrictivas."
                    ),
                    reference=(
                        "UFW Documentation"
                    ),
                    impact=(
                        "El sistema puede aceptar conexiones no autorizadas."
                    ),
                    compliance=[
                        "CIS Ubuntu Linux Benchmark"
                    ]
                )



        else:


            auditor.add_finding(
                title="Linux Firewall UFW",
                status="WARNING",
                severity="MEDIUM",
                category="Network Security",
                details=(
                    "UFW no está instalado."
                ),
                recommendation=(
                    "Instalar UFW o verificar otro firewall activo."
                ),
                reference=(
                    "CIS Linux Benchmark"
                ),
                impact=(
                    "No se detectó una solución firewall estándar."
                ),
                compliance=[
                    "CIS Linux Benchmark"
                ]
            )




    # ==========================
    # Fedora / RHEL
    # ==========================

    elif auditor.distro in [
        "fedora",
        "rhel"
    ]:


        if auditor.command_exists(
            "firewall-cmd"
        ):


            resultado = auditor._run_command(
                "firewall-cmd --state"
            ).strip().lower()



            if resultado == "running":


                auditor.add_finding(
                    title="Linux Firewall Firewalld",
                    status="PASS",
                    severity="INFO",
                    category="Network Security",
                    details=(
                        "Firewalld está activo."
                    ),
                    recommendation=(
                        "Mantener reglas actualizadas."
                    ),
                    reference=(
                        "Firewalld Documentation"
                    ),
                    impact=(
                        "Controla tráfico entrante y saliente."
                    ),
                    compliance=[
                        "CIS Linux Benchmark"
                    ]
                )



            else:


                auditor.add_finding(
                    title="Linux Firewall Firewalld",
                    status="FAIL",
                    severity="HIGH",
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
                        "El sistema puede quedar expuesto a tráfico no filtrado."
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
                    "Firewalld no está instalado."
                ),
                recommendation=(
                    "Configurar un firewall compatible."
                ),
                reference=(
                    "CIS Linux Benchmark"
                ),
                impact=(
                    "Puede existir falta de filtrado de tráfico."
                ),
                compliance=[
                    "CIS Linux Benchmark"
                ]
            )




    # ==========================
    # Arch / Otros
    # ==========================

    else:


        if auditor.command_exists(
            "nft"
        ):


            auditor.add_finding(
                title="Linux Firewall nftables",
                status="WARNING",
                severity="MEDIUM",
                category="Network Security",
                details=(
                    f"Se detectó nftables en {auditor.distro}."
                ),
                recommendation=(
                    "Verificar reglas configuradas."
                ),
                reference=(
                    "nftables Documentation"
                ),
                impact=(
                    "Una configuración incorrecta puede exponer servicios."
                ),
                compliance=[
                    "CIS Linux Benchmark"
                ]
            )



        elif auditor.command_exists(
            "iptables"
        ):


            auditor.add_finding(
                title="Linux Firewall iptables",
                status="WARNING",
                severity="MEDIUM",
                category="Network Security",
                details=(
                    f"Se detectó iptables en {auditor.distro}."
                ),
                recommendation=(
                    "Revisar reglas activas del firewall."
                ),
                reference=(
                    "Linux Firewall Configuration"
                ),
                impact=(
                    "Reglas incorrectas pueden permitir accesos no autorizados."
                ),
                compliance=[
                    "CIS Linux Benchmark"
                ]
            )



        else:


            auditor.add_finding(
                title="Linux Firewall",
                status="FAIL",
                severity="HIGH",
                category="Network Security",
                details=(
                    "No se detectó firewall compatible."
                ),
                recommendation=(
                    "Configurar un firewall basado en la distribución."
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