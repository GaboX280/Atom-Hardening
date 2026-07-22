import subprocess
import platform
import datetime
import os
from typing import Optional

from abc import ABC, abstractmethod

from atom_core.models.finding import Finding



class BaseAuditor(ABC):


    def __init__(self):

        self.report: list[Finding] = []

        self.os_type = platform.system()

        self.module_name = self.__class__.__name__


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
        recommendation: str = "",
        category: str = "General",
        module: Optional[str] = None
    ):


        self.report.append(

            Finding(

                title=title,

                status=status,

                severity=severity,

                details=details,

                recommendation=recommendation,

                category=category,

                module=(
                    module
                    if module
                    else self.module_name
                )

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


            "INFO":
                self.CYAN + "[*]",


            "OK":
                self.GREEN + "[+]",


            "WARN":
                self.YELLOW + "[!]",


            "ERROR":
                self.RED + "[-]"


        }


        print(
            f"{prefix.get(level,self.CYAN+'[*]')}"
            f"{self.RESET} {message}"
        )



    def _run_command(
        self,
        command,
        timeout=10
    ):

        try:


            flags = 0


            if self.os_type == "Windows":

                flags = subprocess.CREATE_NO_WINDOW



            process = subprocess.Popen(

                command,

                shell=True,

                stdout=subprocess.PIPE,

                stderr=subprocess.PIPE,

                text=True,

                creationflags=flags

            )



            try:


                stdout, stderr = process.communicate(
                    timeout=timeout
                )


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
                    else
                    f"ERROR: COMMAND_FAILED ({process.returncode})"
                )



            return stdout



        except PermissionError:


            return "ERROR: ACCESS_DENIED"



        except Exception as e:


            return f"ERROR: {str(e)}"




    def run_checks(
        self,
        checks
    ):


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
                        "Revisar módulo afectado."
                    ),

                    category="Internal Error"

                )


        return self.report




    def save_report_to_file(self):


        home = os.path.expanduser("~")


        carpeta = os.path.join(

            home,

            "Desktop",

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
                "========== ATOM SECURITY REPORT ==========\n\n"
            )


            f.write(
                f"System: {self.os_type}\n"
            )


            f.write(
                f"Module: {self.module_name}\n"
            )


            f.write(
                f"Date: {datetime.datetime.now()}\n\n"
            )



            for finding in self.report:


                f.write(
                    str(finding)
                )


                f.write(
                    "\n\n"
                )



        return archivo



    @abstractmethod
    def ejecutar(self):

        pass