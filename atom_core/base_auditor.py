import json
import os
import platform
import subprocess
from abc import ABC, abstractmethod

from atom_core.core.security_score import SecurityScore
from atom_core.core.security_summary import SecuritySummary
from atom_core.models.finding import Finding
from atom_core.reporters.json_reporter import JsonReporter
from atom_core.reporters.text_reporter import TextReporter


class BaseAuditor(ABC):
    def __init__(self) -> None: # [TIPADO AÑADIDO] -> None
        self.report: list[Finding] = []

        self.os_type = platform.system()

        self.module_name = self.__class__.__name__

        self.distro = None
        
        self.config: dict = self._load_config()

        self.GREEN = "\033[92m"
        self.RED = "\033[91m"
        self.CYAN = "\033[96m"
        self.YELLOW = "\033[93m"
        self.RESET = "\033[0m"

    def _load_config(self) -> dict:
        config_path = "config.json"
        if os.path.exists(config_path):
            try:
                with open(config_path, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:  # noqa: BLE001
                print(f"Error loading config.json: {e}. Using defaults.")
        # Fallback defaults
        return {
            "password_policy": {"min_length": 14, "max_age_days": 90},
            "network": {"allowed_ports": [22, 80, 443]},
            "reports": {"output_dir": "reports", "format": "json"}
        }

    # =====================================================
    # HALLAZGOS
    # =====================================================

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
    ) -> None: # [TIPADO AÑADIDO] -> None

        self.report.append(
            Finding(
                title=title,
                status=status,
                severity=severity,
                details=details,
                recommendation=recommendation,
                category=category,
                module=module if module else self.module_name,
                reference=reference,
                impact=impact,
                compliance=[] if compliance is None else compliance,
            )
        )

    def clear_report(self) -> None: # [TIPADO AÑADIDO] -> None

        self.report.clear()

    # =====================================================
    # PUNTUACIÓN DE SEGURIDAD
    # =====================================================

    def calculate_security_score(self) -> int: # [TIPADO AÑADIDO] -> int

        return SecurityScore.calculate(self.report)

    def get_score_rating(self, score: int) -> str: # [TIPADO AÑADIDO] -> str

        return SecurityScore.rating(score)

    def print_security_score(self) -> None: # [TIPADO AÑADIDO] -> None

        score = self.calculate_security_score()

        rating = self.get_score_rating(score)

        print("\n" + "=" * 45)
        print(f" SECURITY SCORE: {score}/100")
        print(f" STATUS: {rating}")
        print("=" * 45)

    def get_security_summary(self) -> dict: # [TIPADO AÑADIDO] -> dict

        score = self.calculate_security_score()

        summary = SecuritySummary.summarize(self.report)

        summary["system"] = self.os_type

        summary["module"] = self.module_name

        summary["score"] = score

        summary["rating"] = self.get_score_rating(score)

        return summary

    # =====================================================
    # REGISTRO DE LOGS
    # =====================================================

    def log(self, message: str, level: str = "INFO") -> None: # [TIPADO AÑADIDO] level: str, -> None

        prefix = {
            "INFO": self.CYAN + "[*]",
            "OK": self.GREEN + "[+]",
            "WARN": self.YELLOW + "[!]",
            "ERROR": self.RED + "[-]",
        }

        print(f"{prefix.get(level, self.CYAN + '[*]')}{self.RESET} {message}")

    # =====================================================
    # EJECUCIÓN DE COMANDOS
    # =====================================================

    def _run_command(self, command: str | list[str], timeout: int = 10) -> str: # [TIPADO AÑADIDO] -> str

        try:
            flags = 0

            if self.os_type == "Windows":
                flags = subprocess.CREATE_NO_WINDOW

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

        except Exception as e:  # noqa: BLE001
            return f"ERROR: {e!s}"

    # =====================================================
    # UTILIDADES DEL SISTEMA
    # =====================================================

    def command_exists(self, command: str) -> bool: # [TIPADO AÑADIDO] -> bool
        """
        Verifica si un comando existe en el sistema.
        """
        import shutil
        return shutil.which(command) is not None

    # =====================================================
    # MOTOR DE EJECUCIÓN
    # =====================================================

    def run_checks(self, checks: list, clear: bool = True) -> list[Finding]: # [TIPADO AÑADIDO] -> list[Finding]

        if clear:
            self.clear_report()

        for check in checks:
            try:
                check(self)

            except Exception as e:  # noqa: BLE001
                self.add_finding(
                    title=check.__name__,
                    status="ERROR",
                    severity="HIGH",
                    details=str(e),
                    recommendation=("Revisar módulo afectado."),
                    category="Internal Error",
                )

        self.print_security_score()

        return self.report

    # =====================================================
    # REPORTE
    # =====================================================

    def save_report_to_file(self) -> dict[str, str]: # [TIPADO AÑADIDO] -> dict[str, str]

        txt = TextReporter.save(self.get_security_summary(), self.report)

        json = JsonReporter.save(self.get_security_summary(), self.report)

        return {"text": txt, "json": json}

    @abstractmethod
    def ejecutar(self) -> None: # [TIPADO AÑADIDO] -> None

        pass
