from atom_core.base_auditor import BaseAuditor


def audit_doh_settings(auditor: BaseAuditor):
    """
    Verifica configuración de DNS over HTTPS.
    """

    auditor.log(
        "Verificando DNS over HTTPS..."
    )


    comando = (
        'powershell -Command '
        '"Get-ItemProperty '
        "-Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters' "
        "-Name 'EnableAutoDoh' "
        '-ErrorAction SilentlyContinue"'
    )


    resultado = auditor._run_command(
        comando
    ).upper()



    if (
        "ENABLEAUTODOH" in resultado
        and
        ": 2" in resultado
    ):


        auditor.add_finding(

            title="DNS over HTTPS",

            status="PASS",

            severity="INFO",

            category="Network Security",

            details=(

                "DNS over HTTPS está habilitado."

            ),

            recommendation=(

                "Mantener DNS seguro cuando sea compatible "
                "con la infraestructura existente."

            ),

            reference=(

                "Microsoft Security Baseline"

            ),

            impact=(

                "DNS over HTTPS protege las consultas DNS contra "
                "interceptación y manipulación durante el tránsito."

            ),

            compliance=[

                "NIST SP 800-53 SC-8"

            ]

        )



    else:


        auditor.add_finding(

            title="DNS over HTTPS",

            status="WARNING",

            severity="LOW",

            category="Network Security",

            details=(

                "DNS over HTTPS no está habilitado o configurado."

            ),

            recommendation=(

                "Evaluar habilitar DNS over HTTPS según las políticas "
                "de seguridad y compatibilidad de la organización."

            ),

            reference=(

                "Microsoft Security Baseline"

            ),

            impact=(

                "Las consultas DNS sin protección adicional pueden "
                "ser observadas o manipuladas dependiendo del entorno "
                "de red."

            ),

            compliance=[

                "NIST SP 800-53 SC-8"

            ]

        )