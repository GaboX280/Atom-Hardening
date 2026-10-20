import json

from atom_core.base_auditor import BaseAuditor


def read_builtin_account(
    auditor: BaseAuditor,
    sid_suffix: str,
    finding_title: str,
) -> tuple[bool, dict | None]:
    """Read a built-in local account by its stable well-known SID suffix."""
    script = f"""
$ErrorActionPreference = 'Stop'
$accounts = @(Get-CimInstance -ClassName Win32_UserAccount -Filter "LocalAccount=True" |
    Where-Object {{ $_.SID -match '-{sid_suffix}$' }} |
    Select-Object Name, SID, Disabled)
ConvertTo-Json -InputObject $accounts -Compress
"""
    result = auditor._run_command(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=15,
    )
    if auditor._record_command_error(result, finding_title):
        return False, None

    try:
        payload = json.loads(result.stdout)
        if payload is None or payload == []:
            return True, None
        if isinstance(payload, dict):
            payload = [payload]
        if not isinstance(payload, list) or len(payload) != 1:
            raise ValueError("La consulta no devolvió exactamente una cuenta integrada.")
        account = payload[0]
        if not isinstance(account, dict) or not isinstance(account.get("Disabled"), bool):
            raise TypeError("La respuesta no contiene el estado Disabled esperado.")
        return True, account
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        auditor.add_finding(
            title=finding_title,
            status="ERROR",
            severity="HIGH",
            category="Execution Error",
            details=f"No se pudo interpretar el estado de la cuenta integrada: {exc}",
            recommendation="Verificar la consulta CIM y repetir la auditoría.",
            confidence="LOW",
        )
        return False, None
