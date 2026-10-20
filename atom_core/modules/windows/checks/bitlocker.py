import json

from atom_core.base_auditor import BaseAuditor


def audit_bitlocker(auditor: BaseAuditor) -> None:
    """Evaluate BitLocker state using stable PowerShell properties."""
    auditor.log("Evaluando BitLocker...")

    command = [
        "powershell.exe",
        "-NoProfile",
        "-NonInteractive",
        "-Command",
        "Get-BitLockerVolume -MountPoint 'C:' | "
        "Select-Object VolumeStatus, ProtectionStatus | ConvertTo-Json -Compress",
    ]
    result = auditor._run_command(command, timeout=15)
    if auditor._record_command_error(result, "Bitlocker Check"):
        return

    try:
        volume = json.loads(result.stdout)
        if isinstance(volume, list):
            if len(volume) != 1:
                raise ValueError("No se recibió exactamente un resultado para C:.")
            volume = volume[0]
        if not isinstance(volume, dict):
            raise ValueError("La respuesta no contiene un objeto de volumen.")

        volume_status = volume.get("VolumeStatus")
        protection_status = volume.get("ProtectionStatus")
        if not isinstance(volume_status, str) or not isinstance(protection_status, str):
            raise ValueError("Faltan VolumeStatus o ProtectionStatus.")
        volume_status = volume_status.upper()
        protection_status = protection_status.upper()
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        auditor.add_finding(
            title="BitLocker",
            status="ERROR",
            severity="HIGH",
            category="Data Protection",
            details=f"No se pudo interpretar el estado estructurado de BitLocker: {exc}",
            recommendation="Verificar que Get-BitLockerVolume esté disponible y repetir la auditoría.",
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact="No fue posible verificar el estado de cifrado de la unidad C:.",
            confidence="LOW",
            compliance=["CIS Controls v8 - Control 3", "NIST SP 800-53 SC-28"],
        )
        return

    if volume_status == "FULLYENCRYPTED" and protection_status == "ON":
        status, severity = "PASS", "INFO"
        details = "La unidad C: está completamente cifrada y la protección BitLocker está activa."
        recommendation = "Mantener BitLocker activo y validar periódicamente el estado de protección."
        confidence = "HIGH"
    elif volume_status == "FULLYENCRYPTED" and protection_status != "ON":
        status, severity = "WARNING", "HIGH"
        details = "La unidad C: está cifrada, pero la protección BitLocker no está activa."
        recommendation = "Verificar y activar la protección BitLocker antes de considerar el control conforme."
        confidence = "HIGH"
    elif volume_status == "FULLYDECRYPTED":
        status, severity = "FAIL", "HIGH"
        details = "La unidad C: no está cifrada con BitLocker."
        recommendation = "Activar BitLocker en la unidad del sistema para proteger los datos almacenados."
        confidence = "HIGH"
    else:
        status, severity = "WARNING", "MEDIUM"
        details = (
            f"Estado de BitLocker no concluyente: volumen={volume_status}, "
            f"protección={protection_status}."
        )
        recommendation = "Revisar el estado de BitLocker y repetir la auditoría."
        confidence = "MEDIUM"

    auditor.add_finding(
        title="BitLocker",
        status=status,
        severity=severity,
        category="Data Protection",
        details=details,
        recommendation=recommendation,
        reference="Microsoft Security Baseline / CIS Windows Benchmark",
        impact="El cifrado y la protección activa reducen el riesgo de exposición de datos ante pérdida o acceso físico.",
        confidence=confidence,
        compliance=["CIS Controls v8 - Control 3", "NIST SP 800-53 SC-28"],
    )
