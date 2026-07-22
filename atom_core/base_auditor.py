import subprocess
import platform
import datetime
import os
from abc import ABC, abstractmethod

from atom_core.models.finding import Finding


class BaseAuditor(ABC):

    def __init__(self):

        self.report: list[Finding] = []

        self.os_type = platform.system()

        self.GREEN = "\033[92m"
        self.RED = "\033[91m"
        self.CYAN = "\033[96m"
        self.YELLOW = "\033[93m"
        self.RESET = "\033[0m"


    def add_finding(
        self,
        title: str,
        status: str,
        severity: str,
        details: str = "",
        recommendation: str = ""
    ):

        self.report.append(
            Finding(
                title=title,
                status=status,
                severity=severity,
                details=details,
                recommendation=recommendation
            )
        )


    def clear_report(self):

        self.report.clear()



    def log(
        self,
        message: str,
        level="INFO"
    ):

        prefix = {

            "INFO": self.CYAN + "[*]",

            "OK": self.GREEN + "[+]",

            "WARN": self.YELLOW + "[!]",

            "ERROR": self.RED + "[-]"

        }


        print(
            f"{prefix.get(level, '[*]')}{self.RESET} {message}"
        )



    def _run_command(
        self,
        command,
        timeout=10
    ):
        """
        Ejecuta comandos del sistema de forma segura.
        Maneja timeouts, procesos colgados y errores.
        """

        try:

            creation_flags = 0


            if self.os_type == "Windows":

                creation_flags = (
                    subprocess.CREATE_NO_WINDOW
                )


            proceso = subprocess.Popen(

                command,

                shell=True,

                stdout=subprocess.PIPE,

                stderr=subprocess.PIPE,

                text=True,

                creationflags=creation_flags

            )


            try:

                stdout, stderr = proceso.communicate(
                    timeout=timeout
                )


            except subprocess.TimeoutExpired:


                proceso.kill()


                stdout, stderr = proceso.communicate()


                return (
                    "ERROR: COMMAND_TIMEOUT"
                )



            stdout = stdout.strip()

            stderr = stderr.strip()



            if proceso.returncode != 0:

                if stderr:

                    return (
                        f"ERROR: {stderr}"
                    )


                return (
                    f"ERROR: COMMAND_FAILED ({proceso.returncode})"
                )


            return stdout



        except FileNotFoundError:

            return (
                "ERROR: COMMAND_NOT_FOUND"
            )



        except PermissionError:

            return (
                "ERROR: ACCESS_DENIED"
            )



        except Exception as e:

            return (
                f"ERROR: {str(e)}"
            )



    def run_checks(
        self,
        checks
    ):

        """
        Ejecuta todos los módulos de auditoría.
        Un fallo individual no detiene todo el análisis.
        """

        self.clear_report()



        for check in checks:


            try:

                check()


            except Exception as e:


                self.add_finding(

                    title=check.__name__,

                    status="ERROR",

                    severity="HIGH",

                    details=str(e),

                    recommendation=(
                        "Revisar el módulo afectado."
                    )

                )



        return self.report




    def save_report_to_file(self):


        home = os.path.expanduser("~")


        escritorio = os.path.join(
            home,
            "Desktop"
        )


        carpeta = os.path.join(
            escritorio,
            "Atom Logs"
        )


        os.makedirs(
            carpeta,
            exist_ok=True
        )



        timestamp = datetime.datetime.now().strftime(
            "%Y%m%d_%H%M%S"
        )


        archivo = os.path.join(

            carpeta,

            f"reporte_atom_{timestamp}.txt"

        )



        with open(
            archivo,
            "w",
            encoding="utf-8"
        ) as f:



            f.write(
                "===== REPORTE ATOM =====\n\n"
            )


            f.write(
                f"Sistema: {self.os_type}\n"
            )


            f.write(
                f"Fecha: {datetime.datetime.now()}\n\n"
            )


            for finding in self.report:


                f.write(
                    f"[{finding.status}] "
                    f"{finding.title}\n"
                )


                f.write(
                    f"Severidad: {finding.severity}\n"
                )


                f.write(
                    f"Detalles: {finding.details}\n"
                )


                f.write(
                    f"Recomendación: "
                    f"{finding.recommendation}\n\n"
                )



        return archivo



    @abstractmethod
    def ejecutar(self):

        pass