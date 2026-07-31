from atom_core.base_auditor import BaseAuditor


def audit_smbv1(auditor: BaseAuditor):

    auditor.log(
        "Comprobando configuración SMBv1..."
    )


    comando = (
        "powershell -Command "
        "\"(Get-SmbServerConfiguration).EnableSMB1Protocol\""
    )


    resultado = (
        auditor._run_command(comando)
        .strip()
        .upper()
    )



    if "TRUE" in resultado:


        auditor.add_finding(

            title="SMBv1 Protocol",

            status="FAIL",

            severity="CRITICAL",

            category="Network Security",

            details=(

                "SMBv1 está habilitado."

            ),

            recommendation=(

                "Deshabilitar SMBv1 debido a vulnerabilidades conocidas "
                "y utilizar versiones modernas del protocolo SMB."

            ),

            reference=(

                "Microsoft Security Baseline / CIS Windows Benchmark"

            ),

            impact=(

                "SMBv1 puede permitir explotación remota, propagación "
                "de malware y movimiento lateral dentro de la red."

            ),

            compliance=[

                "CIS Controls v8 - Control 4",

                "NIST SP 800-53 CM-7"

            ]

        )



    elif "FALSE" in resultado:


        auditor.add_finding(

            title="SMBv1 Protocol",

            status="PASS",

            severity="INFO",

            category="Network Security",

            details=(

                "SMBv1 está deshabilitado."

            ),

            recommendation=(

                "Mantener protocolos obsoletos deshabilitados."

            ),

            reference=(

                "Microsoft Security Baseline / CIS Windows Benchmark"

            ),

            impact=(

                "Mantener SMBv1 deshabilitado reduce la superficie "
                "de ataque asociada a protocolos antiguos."

            ),

            compliance=[

                "CIS Controls v8 - Control 4",

                "NIST SP 800-53 CM-7"

            ]

        )



    else:


        auditor.add_finding(

            title="SMBv1 Protocol",

            status="WARNING",

            severity="MEDIUM",

            category="Network Security",

            details=(

                "SMBv1 no está activo o no pudo detectarse."

            ),

            recommendation=(

                "Verificar manualmente la configuración SMB y "
                "mantener protocolos antiguos deshabilitados."

            ),

            reference=(

                "Microsoft Security Baseline / CIS Windows Benchmark"

            ),

            impact=(

                "No confirmar el estado del protocolo puede ocultar "
                "una configuración insegura de red."

            ),

            compliance=[

                "CIS Controls v8 - Control 4",

                "NIST SP 800-53 CM-7"

            ]

        )