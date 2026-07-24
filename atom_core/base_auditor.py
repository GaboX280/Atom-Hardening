import platform
import subprocess
from abc import ABC, abstractmethod

from atom_core.core.security_score import SecurityScore
from atom_core.core.security_summary import SecuritySummary
from atom_core.models.finding import Finding
from atom_core.reporters.json_reporter import JsonReporter
from atom_core.reporters.text_reporter import TextReporter


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
        module: str | None = None
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

        return SecurityScore.calculate(
            self.report
        )


    def get_score_rating(
        self,
        score: int
    ):

        return SecurityScore.rating(
            score
        )


    def print_security_score(self):

        score = self.calculate_security_score()

        rating = self.get_score_rating(score)

        print("\n" + "=" * 45)
        print(f" SECURITY SCORE: {score}/100")
        print(f" STATUS: {rating}")
        print("=" * 45)


    def get_security_summary(self):

        score = self.calculate_security_score()

        summary = SecuritySummary.summarize(
            self.report
        )

        summary["system"] = self.os_type

        summary["module"] = self.module_name

        summary["score"] = score

        summary["rating"] = self.get_score_rating(
            score
        )

        return summary



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
        checks: list,
        clear: bool = True
    ):


        if clear:

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
        txt = TextReporter.save(
            self.get_security_summary(),
            self.report
        )
        
        json = JsonReporter.save(
            self.get_security_summary(),
            self.report
        )
        
        return {
            "text": txt,
            "json": json
        }



    @abstractmethod
    def ejecutar(self):

        pass