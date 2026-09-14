import json
import platform
import shutil
import subprocess
from abc import ABC, abstractmethod
from pathlib import Path

from atom_core.models.finding import Finding


class BaseAuditor(ABC):
    """Shared execution primitives for platform-specific auditors."""

    def __init__(self) -> None:
        self.report: list[Finding] = []
        self.os_type = platform.system()
        self.module_name = self.__class__.__name__
        self.distro: str | None = None
        self.config: dict = self._load_config()

        self.GREEN = "\033[92m"
        self.RED = "\033[91m"
        self.CYAN = "\033[96m"
        self.YELLOW = "\033[93m"
        self.RESET = "\033[0m"

    def _load_config(self) -> dict:
        """Load project configuration, falling back to safe defaults."""
        config_path = Path(__file__).resolve().parents[1] / "config.json"
        try:
            with config_path.open("r", encoding="utf-8") as file:
                data = json.load(file)
                return data if isinstance(data, dict) else {}
        except (FileNotFoundError, json.JSONDecodeError, OSError):
            return {
                "password_policy": {"min_length": 14, "max_age_days": 90},
                "network": {"allowed_ports": [22, 80, 443]},
                "reports": {"output_dir": "reports", "format": "json"},
            }

    def add_finding(
        self,
        title: str,
        status: str,
        severity: str,
        details: str = "",
        recommendation: str = "",
        category: str = "General",
        module: str | None = None,
        reference: str = "",
        impact: str = "",
        compliance: list[str] | None = None,
        severity_score: int = 0,
        confidence: str = "HIGH",
    ) -> None:
        """Append a validated, normalized finding to the current report."""
        self.report.append(
            Finding(
                title=title,
                status=status,
                severity=severity,
                details=details,
                recommendation=recommendation,
                category=category,
                module=module or self.module_name,
                reference=reference,
                impact=impact,
                compliance=[] if compliance is None else compliance,
                severity_score=severity_score,
                confidence=confidence,
            )
        )

    def clear_report(self) -> None:
        self.report.clear()

    def log(self, message: str, level: str = "INFO") -> None:
        prefix = {
            "INFO": self.CYAN + "[*]",
            "OK": self.GREEN + "[+]",
            "WARN": self.YELLOW + "[!]",
            "ERROR": self.RED + "[-]",
        }
        print(f"{prefix.get(level, self.CYAN + '[*]')}{self.RESET} {message}")

    def _run_command(self, command: str | list[str], timeout: int = 10) -> str:
        """Execute a local audit command with a bounded timeout."""
        try:
            flags = subprocess.CREATE_NO_WINDOW if self.os_type == "Windows" else 0
            use_shell = isinstance(command, str)
            process = subprocess.Popen(
                command,
                shell=use_shell,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=flags,
            )

            try:
                stdout, stderr = process.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate()
                return "ERROR: COMMAND_TIMEOUT"

            stdout = stdout.strip()
            stderr = stderr.strip()

            if process.returncode != 0:
                return (
                    f"ERROR: {stderr}"
                    if stderr
                    else f"ERROR: COMMAND_FAILED ({process.returncode})"
                )

            return stdout

        except PermissionError:
            return "ERROR: ACCESS_DENIED"
        except OSError as exc:
            return f"ERROR: {exc!s}"

    def command_exists(self, command: str) -> bool:
        """Return whether an executable is available on PATH."""
        return shutil.which(command) is not None

    def run_checks(
        self,
        checks: list,
        clear: bool = True,
    ) -> list[Finding]:
        """Execute checks and convert unexpected exceptions into ERROR findings."""
        if clear:
            self.clear_report()

        for check in checks:
            try:
                check(self)
            except Exception as exc:  # noqa: BLE001
                self.add_finding(
                    title=check.__name__,
                    status="ERROR",
                    severity="HIGH",
                    details=str(exc),
                    recommendation="Revisar el módulo afectado y repetir la auditoría.",
                    category="Internal Error",
                    confidence="HIGH",
                )

        return self.report

    @abstractmethod
    def ejecutar(self) -> list[Finding]:
        """Run the platform-specific audit and return its findings."""
        pass
