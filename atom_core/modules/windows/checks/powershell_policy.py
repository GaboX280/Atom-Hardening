from atom_core.base_auditor import BaseAuditor


def audit_powershell_policy(auditor: BaseAuditor) -> None: # [TIPADO AÑADIDO]

    auditor.log("Evaluando directiva de ejecución de PowerShell...")

    comando = 'powershell -Command "Get-ExecutionPolicy"'

    resultado = auditor._run_command(comando).strip().upper()

    if "BYPASS" in resultado or "UNRESTRICTED" in resultado:
        auditor.add_finding(
            title="PowerShell Execution Policy",
            status="FAIL",
            severity="HIGH",
            category="System Hardening",
            details=(f"Directiva insegura detectada: {resultado}"),
            recommendation=(
                "Configurar una política de ejecución más restrictiva "
                "como RemoteSigned o AllSigned según los requerimientos "
                "de seguridad."
            ),
            reference=("Microsoft Security Baseline / CIS Windows Benchmark"),
            impact=(
                "Una política permisiva permite ejecutar scripts no "
                "confiables y puede facilitar la ejecución de código "
                "malicioso mediante PowerShell."
            ),
            compliance=["CIS Controls v8 - Control 10", "NIST SP 800-53 CM-7"],
        )

    else:
        auditor.add_finding(
            title="PowerShell Execution Policy",
            status="PASS",
            severity="INFO",
            category="System Hardening",
            details=(f"Directiva actual: {resultado}"),
            recommendation=(
                "Mantener políticas seguras de ejecución y revisar "
                "periódicamente las configuraciones de PowerShell."
            ),
            reference=("Microsoft Security Baseline / CIS Windows Benchmark"),
            impact=(
                "Una política restrictiva ayuda a reducir la ejecución "
                "de scripts no autorizados y limita técnicas de abuso "
                "basadas en PowerShell."
            ),
            compliance=["CIS Controls v8 - Control 10", "NIST SP 800-53 CM-7"],
        )
