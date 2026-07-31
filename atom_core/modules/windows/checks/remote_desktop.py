from atom_core.base_auditor import BaseAuditor


def audit_remote_desktop(auditor: BaseAuditor):

    auditor.log(
        "Evaluando Escritorio Remoto..."
    )


    comando = (
        'powershell -Command '
        '"Get-ItemProperty '
        "-Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
        "-Name 'fDenyTSConnections'"
        '"'
    )


    resultado = auditor._run_command(
        comando
    ).upper()



    if ": 0" in resultado or ":0" in resultado:


        auditor.add_finding(

            title="Remote Desktop (RDP)",

            status="WARNING",

            severity="MEDIUM",

            category="Remote Access",

            details=(

                "Escritorio Remoto está habilitado."

            ),

            recommendation=(

                "Deshabilitar RDP si no es requerido. "
                "Si es necesario, restringir acceso mediante VPN, "
                "MFA y reglas de firewall."

            ),

            reference=(

                "Microsoft Security Baseline / CIS Windows Benchmark"

            ),

            impact=(

                "RDP expuesto puede ser utilizado para ataques de "
                "fuerza bruta, robo de credenciales y movimiento "
                "lateral dentro de la red."

            ),

            compliance=[

                "CIS Controls v8 - Control 6",

                "NIST SP 800-53 AC-17"

            ]

        )



    else:


        auditor.add_finding(

            title="Remote Desktop (RDP)",

            status="PASS",

            severity="INFO",

            category="Remote Access",

            details=(

                "Escritorio Remoto está deshabilitado."

            ),

            recommendation=(

                "Mantener acceso remoto restringido y habilitarlo "
                "solo cuando sea necesario."

            ),

            reference=(

                "Microsoft Security Baseline / CIS Windows Benchmark"

            ),

            impact=(

                "Mantener RDP deshabilitado reduce la superficie de "
                "ataque asociada a servicios remotos."

            ),

            compliance=[

                "CIS Controls v8 - Control 6",

                "NIST SP 800-53 AC-17"

            ]

        )