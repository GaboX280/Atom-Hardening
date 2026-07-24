from atom_core.auditor_factory import AuditorFactory
from atom_core.reporters.console_reporter import ConsoleReporter


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



        if findings is None:


            print(
                "[!] El auditor no devolvió resultados."
            )

            return




        ConsoleReporter.display(
            findings
        )



        reports = auditor.save_report_to_file()



        print(
            "\n[+] Reportes generados:"
        )



        if isinstance(
            reports,
            dict
        ):


            print(
                f"    TXT : {reports.get('text','NO GENERADO')}"
            )


            print(
                f"    JSON: {reports.get('json','NO GENERADO')}"
            )


        else:


            print(
                f"    {reports}"
            )