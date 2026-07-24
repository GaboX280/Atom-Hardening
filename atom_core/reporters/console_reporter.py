class ConsoleReporter:


    @staticmethod
    def display(
        findings: list
    ):

        print(
            f"\n{'='*15} REPORTE DE SEGURIDAD {'='*15}"
        )


        for finding in findings:

            print(finding)
    

        print(
            "=" * 50
        )