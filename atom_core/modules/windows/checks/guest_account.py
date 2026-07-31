from atom_core.base_auditor import BaseAuditor


def audit_guest_account(auditor: BaseAuditor):

    auditor.log(
        "Evaluando cuenta Invitado..."
    )


    resultado = auditor._run_command(
        "net user Invitado"
    )


    resultado_upper = resultado.upper()


    activa = (
        (
            "CUENTA ACTIVA" in resultado_upper
            and
            "SÍ" in resultado_upper
        )
        or
        (
            "ACCOUNT ACTIVE" in resultado_upper
            and
            "YES" in resultado_upper
        )
    )



    if activa:


        auditor.add_finding(

            title="Guest Account",

            status="FAIL",

            severity="MEDIUM",

            category="Identity Management",

            details=(

                "La cuenta Invitado está habilitada."

            ),

            recommendation=(

                "Deshabilitar cuentas de invitado innecesarias."

            ),

            reference=(

                "Microsoft Security Baseline / CIS Windows Benchmark"

            ),

            impact=(

                "Las cuentas de invitado habilitadas pueden permitir "
                "accesos no autorizados o facilitar movimientos laterales "
                "dentro del sistema."

            ),

            compliance=[

                "CIS Controls v8 - Control 5",

                "NIST SP 800-53 AC-2"

            ]

        )



    else:


        auditor.add_finding(

            title="Guest Account",

            status="PASS",

            severity="INFO",

            category="Identity Management",

            details=(

                "La cuenta Invitado está deshabilitada."

            ),

            recommendation=(

                "Mantener cuentas innecesarias desactivadas."

            ),

            reference=(

                "Microsoft Security Baseline / CIS Windows Benchmark"

            ),

            impact=(

                "Mantener cuentas no utilizadas deshabilitadas reduce "
                "la superficie de ataque y evita accesos no requeridos."

            ),

            compliance=[

                "CIS Controls v8 - Control 5",

                "NIST SP 800-53 AC-2"

            ]

        )