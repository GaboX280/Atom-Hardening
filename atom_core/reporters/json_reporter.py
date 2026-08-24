import datetime
import json
import os


class JsonReporter:
    @staticmethod
    def save(summary: dict, findings: list, output_dir: str | None = None) -> str:

        folder = JsonReporter._get_report_folder(output_dir)

        filename = JsonReporter._generate_filename(folder)

        data = {
            "report": {
                "generated": datetime.datetime.now(
                    datetime.timezone.utc
                ).isoformat(),
                "summary": summary,
                "findings": [finding.to_dict() for finding in findings],
            }
        }

        with open(filename, "w", encoding="utf-8") as file:
            json.dump(data, file, indent=4, ensure_ascii=False)

        return filename

    # ==================================
    # RUTA
    # ==================================

    @staticmethod
    def _get_report_folder(output_dir: str | None = None) -> str:

        if output_dir:
            os.makedirs(output_dir, exist_ok=True)
            return output_dir

        home = os.path.expanduser("~")

        folder = os.path.join(home, "Desktop", "Atom Logs")

        os.makedirs(folder, exist_ok=True)

        return folder

    @staticmethod
    def _generate_filename(folder):

        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime(
            "%Y%m%d_%H%M%S"
        )

        return os.path.join(folder, f"reporte_atom_{timestamp}.json")
