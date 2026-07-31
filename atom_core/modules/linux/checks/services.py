from atom_core.base_auditor import BaseAuditor


def audit_services(
    auditor: BaseAuditor
):


    auditor.log(
        f"Evaluando servicios críticos Linux ({auditor.distro})..."
    )



    # =====================================================
    # Servicios según distribución
    # =====================================================

    if auditor.distro in [
        "debian",
        "ubuntu"
    ]:

        servicios = [

            {
                "name": "cron",
                "description": "Cron Scheduler"
            },

            {
                "name": "ssh",
                "description": "SSH Service"
            }

        ]



    elif auditor.distro in [
        "fedora",
        "rhel"
    ]:

        servicios = [

            {
                "name": "crond",
                "description": "Cron Scheduler"
            },

            {
                "name": "sshd",
                "description": "SSH Service"
            }

        ]



    else:

        servicios = [

            {
                "name": "sshd",
                "description": "SSH Service"
            }

        ]




    # =====================================================
    # Auditoría de servicios
    # =====================================================

    for servicio in servicios:


        nombre = servicio["name"]

        descripcion = servicio["description"]



        estado = auditor._run_command(
            f"systemctl is-active {nombre}"
        ).strip().lower()



        if estado == "active":


            auditor.add_finding(

                title=f"Service {descripcion}",

                status="PASS",

                severity="INFO",

                category="Service Management",

                details=(
                    f"El servicio {descripcion} está activo."
                ),

                recommendation=(
                    "Mantener monitoreo y configuración segura."
                ),

                reference=(
                    "CIS Linux Benchmark"
                ),

                impact=(
                    "Los servicios requeridos están funcionando correctamente."
                ),

                compliance=[
                    "CIS Linux Benchmark"
                ]

            )




        elif (
            "not-found" in estado
            or
            "could not be found" in estado
            or
            estado.startswith("error")
        ):


            auditor.add_finding(

                title=f"Service {descripcion}",

                status="INFO",

                severity="LOW",

                category="Service Management",

                details=(
                    f"El servicio {descripcion} no está instalado."
                ),

                recommendation=(
                    "Verificar si el servicio es requerido."
                ),

                reference=(
                    "CIS Linux Benchmark"
                ),

                impact=(
                    "No representa riesgo si el servicio no es necesario."
                ),

                compliance=[
                    "CIS Linux Benchmark"
                ]

            )




        else:


            auditor.add_finding(

                title=f"Service {descripcion}",

                status="WARNING",

                severity="MEDIUM",

                category="Service Management",

                details=(
                    f"El servicio {descripcion} no está activo."
                ),

                recommendation=(
                    "Verificar si debe estar habilitado."
                ),

                reference=(
                    "CIS Linux Benchmark"
                ),

                impact=(
                    "Servicios críticos detenidos pueden afectar seguridad o disponibilidad."
                ),

                compliance=[
                    "CIS Linux Benchmark"
                ]

            )