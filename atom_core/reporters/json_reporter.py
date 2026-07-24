import json
import os
import datetime


class JsonReporter:


    @staticmethod
    def save(
        summary: dict,
        findings: list
    ):


        folder = JsonReporter._get_report_folder()


        filename = JsonReporter._generate_filename(
            folder
        )


        data = {

            "report": {

                "generated": datetime.datetime.now(
                    datetime.UTC
                ).isoformat(),

                "summary": summary,

                "findings": [

                    finding.to_dict()

                    for finding in findings

                ]

            }

        }



        with open(
            filename,
            "w",
            encoding="utf-8"
        ) as file:


            json.dump(

                data,

                file,

                indent=4,

                ensure_ascii=False

            )



        return filename





    @staticmethod
    def _get_report_folder():


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


        return folder





    @staticmethod
    def _generate_filename(
        folder
    ):


        timestamp = datetime.datetime.now().strftime(

            "%Y%m%d_%H%M%S"

        )


        return os.path.join(

            folder,

            f"reporte_atom_{timestamp}.json"

        )