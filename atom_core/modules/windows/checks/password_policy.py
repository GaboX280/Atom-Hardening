import json

from atom_core.base_auditor import BaseAuditor


def audit_password_policy(auditor: BaseAuditor) -> None:
    """Audit the minimum password length using locale-independent policy data."""
    auditor.log("Evaluando política de contraseñas...")

    # secedit exporta claves de política estables; el script devuelve solo JSON.
    script = r"""
$ErrorActionPreference = 'Stop'
$configPath = Join-Path $env:TEMP ('atom-policy-' + [guid]::NewGuid().ToString('N') + '.cfg')
try {
    & secedit.exe /export /cfg $configPath /areas SECURITYPOLICY | Out-Null
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path -LiteralPath $configPath)) {
        throw 'No se pudo exportar la política de seguridad local.'
    }
    $match = Select-String -Path $configPath -Pattern '^\s*MinimumPasswordLength\s*=\s*(\d+)\s*$'
    if (-not $match) {
        throw 'No se encontró MinimumPasswordLength en la política exportada.'
    }
    $length = [int]$match.Matches[0].Groups[1].Value
    [pscustomobject]@{ minimum_password_length = $length } | ConvertTo-Json -Compress
}
finally {
    Remove-Item -LiteralPath $configPath -Force -ErrorAction SilentlyContinue
}
"""
    result = auditor._run_command(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
        timeout=15,
    )
    if auditor._record_command_error(result, "Password Policy Check"):
        return

    try:
        policy = json.loads(result.stdout)
        minimum_length = policy["minimum_password_length"]
        if isinstance(minimum_length, bool) or not isinstance(minimum_length, int):
            raise ValueError("minimum_password_length no es un entero.")
        if minimum_length < 0:
            raise ValueError("La longitud mínima no puede ser negativa.")
    except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
        auditor.add_finding(
            title="Password Policy",
            status="ERROR",
            severity="HIGH",
            category="Identity Management",
            details=f"No se pudo interpretar la política de contraseñas: {exc}",
            recommendation="Verificar la exportación de la política local y repetir la auditoría.",
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact="No se pudo confirmar la longitud mínima de contraseña configurada.",
            confidence="LOW",
            compliance=["CIS Controls v8 - Control 5", "NIST SP 800-53 IA-5"],
        )
        return

    target_min_length = auditor.config.get("password_policy", {}).get("min_length", 8)

    if minimum_length >= target_min_length:
        auditor.add_finding(
            title="Password Policy",
            status="PASS",
            severity="INFO",
            category="Identity Management",
            details=f"Longitud mínima configurada: {minimum_length} caracteres.",
            recommendation="Mantener políticas robustas de contraseña.",
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact=(
                "Una política adecuada reduce el riesgo de ataques "
                "de fuerza bruta y compromiso de credenciales."
            ),
            compliance=["CIS Controls v8 - Control 5", "NIST SP 800-53 IA-5"],
        )
    else:
        auditor.add_finding(
            title="Password Policy",
            status="FAIL",
            severity="MEDIUM",
            category="Identity Management",
            details=f"Longitud mínima configurada: {minimum_length} caracteres.",
            recommendation=f"Configurar una longitud mínima de {target_min_length} caracteres o superior.",
            reference="Microsoft Security Baseline / CIS Windows Benchmark",
            impact=(
                "Una longitud mínima insuficiente puede aumentar el riesgo de "
                "compromiso de credenciales."
            ),
            compliance=["CIS Controls v8 - Control 5", "NIST SP 800-53 IA-5"],
        )
