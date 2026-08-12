from atom_core.base_auditor import BaseAuditor


def audit_windows_defender(auditor: BaseAuditor) -> None: # [TYPING ADDED]

    auditor.log("Comprobando protección de Windows Defender...")

    comando = 'powershell -Command "(Get-MpComputerStatus).RealTimeProtectionEnabled"'

    resultado = auditor._run_command(comando)

    if "TRUE" in resultado.upper():
        auditor.add_finding(
            title="Windows Defender",
            status="PASS",
            severity="INFO",
            category="Endpoint Protection",
            details=("La protección en tiempo real de Windows Defender está activa."),
            recommendation=(
                "Mantener las firmas antivirus actualizadas y "
                "verificar periódicamente la configuración de protección."
            ),
            reference=("Microsoft Defender Security Baseline / CIS Windows Benchmark"),
            impact=(
                "La protección activa ayuda a prevenir la ejecución "
                "de malware y amenazas conocidas en el endpoint."
            ),
            compliance=["CIS Controls v8 - Control 10", "NIST SP 800-53 SI-3"],
        )

    else:
        auditor.add_finding(
            title="Windows Defender",
            status="FAIL",
            severity="HIGH",
            category="Endpoint Protection",
            details=(
                "La protección en tiempo real de Windows Defender está deshabilitada."
            ),
            recommendation=(
                "Activar la protección en tiempo real y validar que "
                "Microsoft Defender esté correctamente configurado."
            ),
            reference=("Microsoft Defender Security Baseline / CIS Windows Benchmark"),
            impact=(
                "Un endpoint sin protección activa aumenta el riesgo "
                "de infección por malware, ejecución de código malicioso "
                "y compromiso del sistema."
            ),
            compliance=["CIS Controls v8 - Control 10", "NIST SP 800-53 SI-3"],
        )
