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


            if finding.status in [
                "FAIL",
                "WARNING",
                "ERROR"
            ]:


                score -= SecurityScore.PENALTIES.get(
                    finding.severity.upper(),
                    5
                )


        return max(
            0,
            score
        )



    @staticmethod
    def rating(score):

        if score >= 90:
            return "EXCELLENT"


        elif score >= 75:
            return "GOOD"


        elif score >= 50:
            return "MODERATE"


        return "CRITICAL"