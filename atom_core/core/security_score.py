class SecurityScore:


    PENALTIES = {
        "CRITICAL": 25,
        "HIGH": 15,
        "MEDIUM": 8,
        "LOW": 3,
        "INFO": 0
    }


    @staticmethod
    def calculate(findings):

        score = 100

        for finding in findings:

            if finding.status != "PASS":

                penalty = SecurityScore.PENALTIES.get(
                    finding.severity.upper(),
                    5
                )

                score -= penalty


        return max(0, score)