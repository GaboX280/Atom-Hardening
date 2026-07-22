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



    # =====================================================
    # FINDINGS
    # =====================================================


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



    # =====================================================
    # SECURITY SCORE
    # =====================================================


    def calculate_security_score(self):

        score = 100


        penalties = {

            "CRITICAL": 25,
            "HIGH": 15,
            "MEDIUM": 8,
            "LOW": 3,
            "INFO": 0

        }


        for finding in self.report:


            if finding.status in [
                "FAIL",
                "WARNING",
                "ERROR"
            ]:


                score -= penalties.get(
                    finding.severity.upper(),
                    5
                )


        return max(
            0,
            score
        )



    def get_score_rating(
        self,
        score
    ):


        if score >= 90:
            return "EXCELLENT"


        if score >= 75:
            return "GOOD"


        if score >= 50:
            return "MODERATE"


        return "CRITICAL"




    def print_security_score(self):

        score = self.calculate_security_score()

        rating = self.get_score_rating(score)


        print(
            "\n"
            "=" * 45
        )

        print(
            f" SECURITY SCORE: {score}/100"
        )

        print(
            f" STATUS: {rating}"
        )

        print(
            "=" * 45
        )



    # =====================================================
    # LOGGING
    # =====================================================


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



    # =====================================================
    # COMMAND EXECUTION
    # =====================================================


    def _run_command(
        self,
        command: str,
        timeout: int = 10
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




    # =====================================================
    # EXECUTION ENGINE
    # =====================================================


    def run_checks(
        self,
        checks: list
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



        self.print_security_score()


        return self.report




    # =====================================================
    # REPORT
    # =====================================================


    def save_report_to_file(self):


        home = os.path.expanduser("~")


        folder = os.path.join(

            home,

            "Desktop",

            "Atom Logs"

        )


        os.makedirs(

            folder,

            exist_ok=True

        )



        timestamp = datetime.datetime.now().strftime(

            "%Y%m%d_%H%M%S"

        )


        filename = os.path.join(

            folder,

            f"reporte_atom_{timestamp}.txt"

        )


        score = self.calculate_security_score()



        with open(

            filename,

            "w",

            encoding="utf-8"

        ) as file:



            file.write(

                "========== ATOM SECURITY REPORT ==========\n\n"

            )


            file.write(

                f"SYSTEM: {self.os_type}\n"

            )


            file.write(

                f"MODULE: {self.module_name}\n"

            )


            file.write(

                f"DATE: {datetime.datetime.now()}\n"

            )


            file.write(

                f"SECURITY SCORE: {score}/100\n\n"

            )



            for finding in self.report:


                file.write(

                    str(finding)

                )


                file.write(

                    "\n\n"

                )



        return filename



    @abstractmethod
    def ejecutar(self):

        pass