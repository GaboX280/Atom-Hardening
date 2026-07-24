class ConsoleReporter:


    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    RESET = "\033[0m"



    @staticmethod
    def display(findings):


        print(
            "\n"
            + "="*60
        )

        print(
            "              ATOM SECURITY REPORT"
        )

        print(
            "="*60
        )



        for finding in findings:


            color = ConsoleReporter.GREEN


            if finding.status == "FAIL":

                color = ConsoleReporter.RED


            elif finding.status == "WARNING":

                color = ConsoleReporter.YELLOW



            print(
                f"\n{color}"
                f"[{finding.status}] "
                f"{finding.title}"
                f"{ConsoleReporter.RESET}"
            )


            print(
                f"Severity : {finding.severity}"
            )


            print(
                f"Details  : {finding.details}"
            )


            print(
                f"Fix      : {finding.recommendation}"
            )


            print("-"*60)