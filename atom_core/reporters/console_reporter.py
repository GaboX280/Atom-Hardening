from collections import Counter


class ConsoleReporter:


    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    WHITE = "\033[97m"
    RESET = "\033[0m"



    @staticmethod
    def display(findings):


        summary = Counter(
            finding.status.upper()
            for finding in findings
        )


        score_color = ConsoleReporter.GREEN


        if summary.get("FAIL", 0) > 0:

            score_color = ConsoleReporter.RED


        elif summary.get("WARNING", 0) > 0:

            score_color = ConsoleReporter.YELLOW



        print("\n")


        print(
            f"{ConsoleReporter.CYAN}"
            "=" * 70,
            f"{ConsoleReporter.RESET}"
        )


        print(
            f"{ConsoleReporter.CYAN}"
            "                 ATOM SECURITY REPORT"
            f"{ConsoleReporter.RESET}"
        )


        print(
            f"{ConsoleReporter.CYAN}"
            "=" * 70,
            f"{ConsoleReporter.RESET}"
        )



        print()


        print(
            f"{ConsoleReporter.WHITE}"
            " SECURITY SUMMARY"
            f"{ConsoleReporter.RESET}"
        )


        print("-" * 70)


        print(
            f" Total Checks : {len(findings)}"
        )


        print(
            f"{ConsoleReporter.GREEN}"
            f" PASS         : {summary.get('PASS',0)}"
            f"{ConsoleReporter.RESET}"
        )


        print(
            f"{ConsoleReporter.YELLOW}"
            f" WARNING      : {summary.get('WARNING',0)}"
            f"{ConsoleReporter.RESET}"
        )


        print(
            f"{ConsoleReporter.RED}"
            f" FAIL         : {summary.get('FAIL',0)}"
            f"{ConsoleReporter.RESET}"
        )


        print(
            f"{ConsoleReporter.RED}"
            f" ERROR        : {summary.get('ERROR',0)}"
            f"{ConsoleReporter.RESET}"
        )


        print("-" * 70)



        print(
            f"\n{ConsoleReporter.WHITE}"
            " SECURITY FINDINGS"
            f"{ConsoleReporter.RESET}"
        )


        print("-" * 70)



        for finding in findings:


            status = finding.status.upper()



            if status == "PASS":

                color = ConsoleReporter.GREEN
                icon = "[+]"



            elif status == "WARNING":

                color = ConsoleReporter.YELLOW
                icon = "[!]"



            elif status in ["FAIL", "ERROR"]:

                color = ConsoleReporter.RED
                icon = "[X]"



            else:

                color = ConsoleReporter.WHITE
                icon = "[?]"




            print()


            print(
                f"{color}"
                f"{icon} {finding.title}"
                f"{ConsoleReporter.RESET}"
            )


            print(
                f"    Status      : {status}"
            )


            print(
                f"    Severity    : {finding.severity}"
            )


            print(
                f"    Category    : {finding.category}"
            )


            print(
                f"    Module      : {finding.module}"
            )


            print(
                f"    Details     : {finding.details}"
            )


            print(
                f"    Recommendation:"
            )


            print(
                f"    -> {finding.recommendation}"
            )


            if finding.reference:

                print(
                    f"    Reference   : {finding.reference}"
                )


            print(
                "-" * 70
            )



        print()


        print(
            f"{ConsoleReporter.CYAN}"
            "=" * 70,
            f"{ConsoleReporter.RESET}"
        )


        print(
            f"{score_color}"
            "        Audit Completed Successfully"
            f"{ConsoleReporter.RESET}"
        )


        print(
            f"{ConsoleReporter.CYAN}"
            "=" * 70,
            f"{ConsoleReporter.RESET}"
        )
