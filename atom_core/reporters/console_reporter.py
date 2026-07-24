from collections import Counter


class ConsoleReporter:


    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BLUE = "\033[94m"
    WHITE = "\033[97m"
    MAGENTA = "\033[95m"
    RESET = "\033[0m"



    @staticmethod
    def display(
        findings,
        score=None,
        rating=None
    ):


        if not findings:

            print(
                f"{ConsoleReporter.YELLOW}"
                "\n[!] No se encontraron resultados."
                f"{ConsoleReporter.RESET}"
            )

            return



        status_summary = Counter(

            finding.status.upper()

            for finding in findings

        )


        severity_summary = Counter(

            finding.severity.upper()

            for finding in findings

        )



        print("\n")


        ConsoleReporter._line()


        print(
            f"{ConsoleReporter.CYAN}"
            "                 ATOM SECURITY REPORT"
            f"{ConsoleReporter.RESET}"
        )


        print(
            f"{ConsoleReporter.BLUE}"
            "                 Version 1.0"
            f"{ConsoleReporter.RESET}"
        )


        ConsoleReporter._line()



        # ===============================
        # SECURITY SCORE
        # ===============================


        if score is not None:


            score_color = ConsoleReporter.GREEN


            if score < 50:

                score_color = ConsoleReporter.RED


            elif score < 75:

                score_color = ConsoleReporter.YELLOW



            print()


            print(
                " SECURITY SCORE"
            )


            print("-" * 70)


            print(
                f"{score_color}"
                f"        {score}/100"
                f"{ConsoleReporter.RESET}"
            )


            if rating:

                print(
                    f"        Rating: {rating}"
                )


            print("-" * 70)




        # ===============================
        # SUMMARY
        # ===============================


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


        ConsoleReporter._print_count(

            "PASS",
            status_summary.get("PASS",0),
            ConsoleReporter.GREEN

        )


        ConsoleReporter._print_count(

            "WARNING",
            status_summary.get("WARNING",0),
            ConsoleReporter.YELLOW

        )


        ConsoleReporter._print_count(

            "FAIL",
            status_summary.get("FAIL",0),
            ConsoleReporter.RED

        )


        ConsoleReporter._print_count(

            "ERROR",
            status_summary.get("ERROR",0),
            ConsoleReporter.RED

        )


        print()



        print(
            f"{ConsoleReporter.MAGENTA}"
            " SEVERITY SUMMARY"
            f"{ConsoleReporter.RESET}"
        )


        print("-" * 70)


        for severity in [

            "CRITICAL",
            "HIGH",
            "MEDIUM",
            "LOW",
            "INFO"

        ]:


            print(

                f" {severity:<10}: "
                f"{severity_summary.get(severity,0)}"

            )



        print("-" * 70)



        # ===============================
        # FINDINGS
        # ===============================


        print()


        print(
            f"{ConsoleReporter.WHITE}"
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



            elif status in [

                "FAIL",
                "ERROR"

            ]:

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
                f"    ID          : {finding.finding_id}"
            )


            print(
                f"    Status      : {finding.status}"
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
                f"    Fix         : {finding.recommendation}"
            )



            if finding.reference:


                print(
                    f"    Reference   : {finding.reference}"
                )



            print(
                f"    Timestamp   : {finding.timestamp}"
            )



            print(
                "-" * 70
            )



        ConsoleReporter._line()


        print(

            f"{ConsoleReporter.GREEN}"
            "        Audit Completed Successfully"
            f"{ConsoleReporter.RESET}"

        )


        ConsoleReporter._line()





    # ==================================
    # HELPERS
    # ==================================


    @staticmethod
    def _line():

        print(

            f"{ConsoleReporter.CYAN}"
            + "=" * 70
            + f"{ConsoleReporter.RESET}"

        )




    @staticmethod
    def _print_count(
        name,
        value,
        color
    ):

        print(

            f"{color}"
            f" {name:<12}: {value}"
            f"{ConsoleReporter.RESET}"

        )