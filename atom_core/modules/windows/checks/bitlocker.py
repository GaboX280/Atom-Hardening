from atom_core.base_auditor import BaseAuditor


def audit_bitlocker(auditor: BaseAuditor):

    auditor.log(
        "Evaluando BitLocker..."
    )


    resultado = auditor._run_command(
        "manage-bde -status C:",
        timeout=5
    ).upper()



    if (
        "TIMEOUT" in resultado
        or
        "ERROR" in resultado
    ):


        auditor.add_finding(

            title="BitLocker",

            status="WARNING",

            severity="MEDIUM",

            category="Data Protection",

            details=(

                "No fue posible consultar el estado de BitLocker."

            ),

            recommendation=(

                "Ejecutar la auditoría con privilegios de administrador "
                "para obtener información completa de cifrado."

            ),

            reference=(

                "Microsoft Security Baseline / CIS Windows Benchmark"

            ),

            impact=(

                "No verificar el estado de cifrado impide confirmar si "
                "los datos almacenados están protegidos ante pérdida o "
                "acceso físico no autorizado."

            ),

            compliance=[

                "CIS Controls v8 - Control 3",

                "NIST SP 800-53 SC-28"

            ]

        )



    elif (
        "FULLY ENCRYPTED" in resultado
        or
        "COMPLETAMENTE CIFRADO" in resultado
    ):


        auditor.add_finding(

            title="BitLocker",

            status="PASS",

            severity="INFO",

            category="Data Protection",

            details=(

                "La unidad C está completamente cifrada."

            ),

            recommendation=(

                "Mantener protección BitLocker activa y validar "
                "periódicamente el estado de cifrado."

            ),

            reference=(

                "Microsoft Security Baseline / CIS Windows Benchmark"

            ),

            impact=(

                "El cifrado protege la información almacenada ante "
                "pérdida, robo del dispositivo o acceso físico no autorizado."

            ),

            compliance=[

                "CIS Controls v8 - Control 3",

                "NIST SP 800-53 SC-28"

            ]

        )



    elif (
        "FULLY DECRYPTED" in resultado
        or
        "COMPLETAMENTE DESCIFRADO" in resultado
    ):


        auditor.add_finding(

            title="BitLocker",

            status="FAIL",

            severity="HIGH",

            category="Data Protection",

            details=(

                "La unidad C no está cifrada."

            ),

            recommendation=(

                "Activar BitLocker en unidades críticas "
                "para proteger información sensible."

            ),

            reference=(

                "Microsoft Security Baseline / CIS Windows Benchmark"

            ),

            impact=(

                "Los datos pueden ser extraídos fácilmente si el "
                "dispositivo es perdido, robado o accedido físicamente."

            ),

            compliance=[

                "CIS Controls v8 - Control 3",

                "NIST SP 800-53 SC-28"

            ]

        )



    else:


        auditor.add_finding(

            title="BitLocker",

            status="WARNING",

            severity="MEDIUM",

            category="Data Protection",

            details=(

                "No se pudo determinar completamente el estado "
                "de cifrado."

            ),

            recommendation=(

                "Ejecutar Atom como administrador para obtener "
                "información completa de cifrado."

            ),

            reference=(

                "Microsoft Security Baseline / CIS Windows Benchmark"

            ),

            impact=(

                "La falta de información sobre cifrado puede ocultar "
                "una configuración insegura de protección de datos."

            ),

            compliance=[

                "CIS Controls v8 - Control 3",

                "NIST SP 800-53 SC-28"

            ]

        )