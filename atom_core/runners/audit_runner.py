from atom_core.auditor_factory import AuditorFactory

from atom_core.reporters.console_reporter import ConsoleReporter
from atom_core.reporters.text_reporter import TextReporter
from atom_core.reporters.json_reporter import JsonReporter
from atom_core.reporters.html_reporter import HTMLReporter

from atom_core.core.security_score import SecurityScore
from atom_core.core.security_summary import SecuritySummary



class AuditRunner:



    AUDITS = {

        "1": "system",
        "2": "file",
        "3": "ssh"

    }




    def run(
        self,
        option
    ):


        auditor_type = self.AUDITS.get(option)



        if not auditor_type:


            print(
                "[!] Auditoría inválida"
            )

            return




        auditor = AuditorFactory.get_auditor(
            auditor_type
        )



        findings = auditor.ejecutar()



        if not findings:


            print(
                "[!] El auditor no devolvió resultados."
            )

            return





        # ==========================
        # SECURITY ANALYSIS
        # ==========================


        score = SecurityScore.calculate(
            findings
        )


        rating = SecurityScore.rating(
            score
        )


        summary = SecuritySummary.summarize(
            findings
        )


        summary["score"] = score

        summary["rating"] = rating

        summary["module"] = auditor.__class__.__name__






        # ==========================
        # CONSOLE REPORT
        # ==========================


        ConsoleReporter.display(

            findings,

            score,

            rating

        )





        # ==========================
        # FILE REPORTS
        # ==========================


        reports = {}



        reports["text"] = TextReporter.save(

            summary,

            findings

        )



        reports["json"] = JsonReporter.save(

            summary,

            findings

        )



        reports["html"] = HTMLReporter.save(

            summary,

            findings

        )





        print(

            "\n[+] Reportes generados:"

        )



        print(

            f"    TXT : {reports['text']}"

        )


        print(

            f"    JSON: {reports['json']}"

        )


        print(

            f"    HTML: {reports['html']}"

        )



        return reports