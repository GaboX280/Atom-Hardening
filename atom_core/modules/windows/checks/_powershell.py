import json
from typing import Any

from atom_core.base_auditor import BaseAuditor


def run_powershell_json(
    auditor: BaseAuditor,
    script: str,
    finding_title: str,
    timeout: float = 10,
) -> tuple[bool, Any]:
    """Run PowerShell and parse JSON, recording execution or parsing failures."""
    result = auditor._run_command(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=timeout,
    )
    if auditor._record_command_error(result, finding_title):
        return False, None

    try:
        return True, json.loads(result.stdout)
    except (json.JSONDecodeError, TypeError) as exc:
        auditor.add_finding(
            title=finding_title,
            status="ERROR",
            severity="HIGH",
            category="Execution Error",
            details=f"No se pudo interpretar la respuesta estructurada de PowerShell: {exc}",
            recommendation="Verificar el comando y repetir la auditoría.",
            confidence="LOW",
        )
        return False, None
