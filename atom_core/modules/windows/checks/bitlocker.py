from atom_core.base_auditor import BaseAuditor


def audit_bitlocker(auditor: BaseAuditor) -> None:
    """Evaluate BitLocker encryption and protection state for C:."""
    auditor.log("Evaluando BitLocker...")

    resultado = auditor._run_command("manage-bde -status C:", timeout=5)
    normalized = resultado.upper()

    if normalized.startswith("ERROR:") or "COMMAND_TIMEOUT" in normalized:
        auditor.add_finding(
            title="BitLocker",
            status="ERROR",
            severity="MEDIUM",
            category="Data Protection",
            details=resultado,
            recommendation="Ejecutar la auditoría con privilegios de administrador y repetir el análisis.",
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact="No fue posible verificar el estado de cifrado de la unidad C:.",
            compliance=["CIS Controls v8 - Control 3", "NIST SP 800-53 SC-28"],
        )
        return

    fully_encrypted = (
        "FULLY ENCRYPTED" in normalized or "COMPLETAMENTE CIFRADO" in normalized
    )
    protection_enabled = (
        "PROTECTION ON" in normalized
        or "PROTECCIÓN ACTIVADA" in normalized
        or "PROTECCION ACTIVADA" in normalized
    )
    fully_decrypted = (
        "FULLY DECRYPTED" in normalized or "COMPLETAMENTE DESCIFRADO" in normalized
    )

    if fully_encrypted and protection_enabled:
        auditor.add_finding(
            title="BitLocker",
            status="PASS",
            severity="INFO",
            category="Data Protection",
            details="La unidad C: está completamente cifrada y la protección BitLocker está activa.",
            recommendation="Mantener BitLocker activo y validar periódicamente el estado de protección.",
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact="El cifrado y la protección activa reducen el riesgo de exposición de datos ante pérdida o acceso físico.",
            compliance=["CIS Controls v8 - Control 3", "NIST SP 800-53 SC-28"],
        )
        return

    if fully_encrypted and not protection_enabled:
        auditor.add_finding(
            title="BitLocker",
            status="WARNING",
            severity="HIGH",
            category="Data Protection",
            details="La unidad C: está cifrada, pero no se confirmó que la protección BitLocker esté activa.",
            recommendation="Verificar y activar la protección BitLocker antes de considerar el control conforme.",
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact="Una unidad cifrada con la protección suspendida puede ofrecer menor protección frente a acceso físico.",
            confidence="MEDIUM",
            compliance=["CIS Controls v8 - Control 3", "NIST SP 800-53 SC-28"],
        )
        return

    if fully_decrypted:
        auditor.add_finding(
            title="BitLocker",
            status="FAIL",
            severity="HIGH",
            category="Data Protection",
            details="La unidad C: no está cifrada con BitLocker.",
            recommendation="Activar BitLocker en la unidad del sistema para proteger los datos almacenados.",
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact="Los datos quedan más expuestos ante pérdida, robo o acceso físico no autorizado.",
            compliance=["CIS Controls v8 - Control 3", "NIST SP 800-53 SC-28"],
        )
        return

    auditor.add_finding(
        title="BitLocker",
        status="WARNING",
        severity="MEDIUM",
        category="Data Protection",
        details="La salida de manage-bde no permitió determinar con suficiente confianza el estado completo de BitLocker.",
        recommendation="Revisar manualmente el estado de BitLocker y repetir la auditoría con permisos adecuados.",
        reference="Microsoft Security Baseline / CIS Windows Benchmark",
        impact="Un estado de cifrado no verificable impide confirmar la protección efectiva de los datos.",
        confidence="LOW",
        compliance=["CIS Controls v8 - Control 3", "NIST SP 800-53 SC-28"],
    )
