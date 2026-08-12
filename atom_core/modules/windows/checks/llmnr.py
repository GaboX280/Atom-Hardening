from atom_core.base_auditor import BaseAuditor


def audit_llmnr(auditor: BaseAuditor) -> None: # [TYPING ADDED]
    """
    Verifica si LLMNR está deshabilitado.
    """

    auditor.log("Comprobando mitigación LLMNR...")

    comando = (
        "powershell -Command "
        '"Get-ItemProperty '
        "-Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient' "
        "-Name 'EnableMulticast' "
        '-ErrorAction SilentlyContinue"'
    )

    resultado = auditor._run_command(comando).upper()

    if "ENABLEMULTICAST" in resultado:
        if ": 0" in resultado or ":0" in resultado:
            auditor.add_finding(
                title="LLMNR Protocol",
                status="PASS",
                severity="INFO",
                category="Network Security",
                details=("LLMNR está deshabilitado."),
                recommendation=(
                    "Mantener mitigaciones contra spoofing "
                    "y ataques de resolución de nombres activas."
                ),
                reference=("Microsoft Security Baseline / CIS Windows Benchmark"),
                impact=(
                    "La deshabilitación de LLMNR reduce ataques de "
                    "poisoning y captura de credenciales NTLM mediante "
                    "herramientas como Responder."
                ),
                compliance=["CIS Controls v8 - Control 4", "NIST SP 800-53 CM-7"],
            )

        else:
            auditor.add_finding(
                title="LLMNR Protocol",
                status="FAIL",
                severity="HIGH",
                category="Network Security",
                details=("LLMNR está habilitado."),
                recommendation=(
                    "Deshabilitar LLMNR mediante políticas de grupo "
                    "para reducir ataques de resolución de nombres."
                ),
                reference=("Microsoft Security Baseline / CIS Windows Benchmark"),
                impact=(
                    "LLMNR habilitado puede permitir ataques de "
                    "spoofing donde un atacante responde solicitudes "
                    "falsas y obtiene hashes NTLM."
                ),
                compliance=["CIS Controls v8 - Control 4", "NIST SP 800-53 CM-7"],
            )

    else:
        auditor.add_finding(
            title="LLMNR Protocol",
            status="WARNING",
            severity="MEDIUM",
            category="Network Security",
            details=("No existe una política explícita para LLMNR."),
            recommendation=("Crear una política de grupo para deshabilitar LLMNR."),
            reference=("Microsoft Security Baseline / CIS Windows Benchmark"),
            impact=(
                "Sin una política definida, el comportamiento del "
                "protocolo puede depender de la configuración local "
                "del sistema."
            ),
            compliance=["CIS Controls v8 - Control 4", "NIST SP 800-53 CM-7"],
        )
