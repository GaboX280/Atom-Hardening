import json
from typing import Any

from atom_core.base_auditor import BaseAuditor


def read_registry_value(
    auditor: BaseAuditor,
    path: str,
    name: str,
    finding_title: str,
) -> tuple[bool, bool, Any]:
    """Read a registry value as JSON without relying on localized PowerShell text."""
    script = f"""
$ErrorActionPreference = 'Stop'
$path = '{path}'
$name = '{name}'
try {{
    $item = Get-Item -LiteralPath $path -ErrorAction Stop
    if ($item.GetValueNames() -contains $name) {{
        [pscustomobject]@{{ exists = $true; value = $item.GetValue($name) }} | ConvertTo-Json -Compress
    }} else {{
        [pscustomobject]@{{ exists = $false; value = $null }} | ConvertTo-Json -Compress
    }}
}} catch {{
    if ($_.CategoryInfo.Category -eq 'ObjectNotFound') {{
        [pscustomobject]@{{ exists = $false; value = $null }} | ConvertTo-Json -Compress
    }} else {{
        [Console]::Error.WriteLine($_.Exception.Message)
        exit 1
    }}
}}
"""
    result = auditor._run_command(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script]
    )
    if auditor._record_command_error(result, finding_title):
        return False, False, None

    try:
        payload = json.loads(result.stdout)
        if not isinstance(payload, dict) or not isinstance(payload.get("exists"), bool):
            raise TypeError("La respuesta del Registro no tiene el formato esperado.")
        if payload["exists"] and "value" not in payload:
            raise ValueError("La respuesta no contiene el valor del Registro.")
        return True, payload["exists"], payload.get("value")
    except (json.JSONDecodeError, TypeError, ValueError) as exc:
        auditor.add_finding(
            title=finding_title,
            status="ERROR",
            severity="HIGH",
            category="Execution Error",
            details=f"No se pudo interpretar la respuesta del Registro: {exc}",
            recommendation="Verificar la consulta y repetir la auditoría.",
            confidence="LOW",
        )
        return False, False, None
