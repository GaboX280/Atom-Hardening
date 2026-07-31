from atom_core.base_auditor import BaseAuditor


def audit_windows_update(auditor: BaseAuditor):

    auditor.log(
        "Comprobando estado del servicio Windows Update..."
    )


    comando = (
        "powershell -Command "
        "\"(Get-Service wuauserv).Status\""
    )


    resultado = (
        auditor._run_command(comando)
        .strip()
        .upper()
    )



    if "RUNNING" in resultado:


        auditor.add_finding(

            title="Windows Update Service",

            status="PASS",

            severity="INFO",

            category="Patch Management",

            details=(

                "El servicio Windows Update está ejecutándose."

            ),

            recommendation=(

                "Mantener actualizaciones automáticas habilitadas "
                "y aplicar parches de seguridad regularmente."

            ),

            reference=(

                "Microsoft Security Baseline / CIS Windows Benchmark"

            ),

            impact=(

                "Mantener el sistema actualizado reduce la exposición "
                "a vulnerabilidades conocidas y ataques que aprovechan "
                "software desactualizado."

            ),

            compliance=[

                "CIS Controls v8 - Control 7",

                "NIST SP 800-53 SI-2"

            ]

        )



    elif "STOPPED" in resultado:


        auditor.add_finding(

            title="Windows Update Service",

            status="WARNING",

            severity="MEDIUM",

            category="Patch Management",

            details=(

                "El servicio Windows Update está detenido."

            ),

            recommendation=(

                "Verificar si la detención es intencional y habilitar "
                "actualizaciones automáticas."

            ),

            reference=(

                "Microsoft Security Baseline / CIS Windows Benchmark"

            ),

            impact=(

                "Un servicio de actualización detenido puede provocar "
                "que vulnerabilidades conocidas permanezcan sin corregir."

            ),

            compliance=[

                "CIS Controls v8 - Control 7",

                "NIST SP 800-53 SI-2"

            ]

        )



    else:


        auditor.add_finding(

            title="Windows Update Service",

            status="FAIL",

            severity="HIGH",

            category="Patch Management",

            details=(

                "No fue posible determinar el estado del servicio "
                "Windows Update."

            ),

            recommendation=(

                "Verificar que el servicio wuauserv exista, sea accesible "
                "y tenga una configuración correcta."

            ),

            reference=(

                "Microsoft Security Baseline / CIS Windows Benchmark"

            ),

            impact=(

                "La incapacidad de verificar el servicio puede ocultar "
                "un sistema sin actualizaciones de seguridad aplicadas."

            ),

            compliance=[

                "CIS Controls v8 - Control 7",

                "NIST SP 800-53 SI-2"

            ]

        )