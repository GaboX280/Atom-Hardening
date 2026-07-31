from atom_core.base_auditor import BaseAuditor


def audit_anonymous_lookup(auditor: BaseAuditor):
    """
    Verifica restricciones contra enumeración anónima.
    """

    auditor.log(
        "Evaluando Null Sessions..."
    )


    comando = (
        'powershell -Command '
        '"Get-ItemProperty '
        "-Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
        "-Name 'RestrictNullSessAccess' "
        '-ErrorAction SilentlyContinue"'
    )


    resultado = auditor._run_command(
        comando
    ).upper()



    if "RESTRICTNULLSESSACCESS" in resultado:


        if ": 1" in resultado or ":1" in resultado:


            auditor.add_finding(

                title="Anonymous Access Restrictions",

                status="PASS",

                severity="INFO",

                category="Network Security",

                details=(

                    "Restricciones contra acceso anónimo activadas."

                ),

                recommendation=(

                    "Mantener restricciones LSA para evitar "
                    "enumeración anónima de recursos."

                ),

                reference=(

                    "Microsoft Security Baseline / CIS Windows Benchmark"

                ),

                impact=(

                    "Las restricciones contra sesiones nulas reducen "
                    "la exposición de información del sistema ante "
                    "usuarios no autenticados."

                ),

                compliance=[

                    "CIS Controls v8 - Control 4",

                    "NIST SP 800-53 AC-3"

                ]

            )



        else:


            auditor.add_finding(

                title="Anonymous Access Restrictions",

                status="FAIL",

                severity="HIGH",

                category="Network Security",

                details=(

                    "Las sesiones nulas pueden estar permitidas."

                ),

                recommendation=(

                    "Restringir acceso anónimo mediante "
                    "la configuración RestrictNullSessAccess."

                ),

                reference=(

                    "Microsoft Security Baseline / CIS Windows Benchmark"

                ),

                impact=(

                    "Las sesiones nulas pueden permitir enumeración "
                    "de usuarios, recursos compartidos y configuración "
                    "del sistema sin autenticación."

                ),

                compliance=[

                    "CIS Controls v8 - Control 4",

                    "NIST SP 800-53 AC-3"

                ]

            )



    else:


        auditor.add_finding(

            title="Anonymous Access Restrictions",

            status="WARNING",

            severity="MEDIUM",

            category="Network Security",

            details=(

                "No se encontró configuración explícita."

            ),

            recommendation=(

                "Configurar RestrictNullSessAccess para bloquear "
                "acceso anónimo."

            ),

            reference=(

                "Microsoft Security Baseline / CIS Windows Benchmark"

            ),

            impact=(

                "Una política no definida puede permitir "
                "comportamientos predeterminados que expongan "
                "información del sistema."

            ),

            compliance=[

                "CIS Controls v8 - Control 4",

                "NIST SP 800-53 AC-3"

            ]

        )