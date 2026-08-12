import datetime
import os


class TextReporter:
    def __init__(self):
        pass

    @staticmethod
    def save(summary: dict, findings: list):

        folder = TextReporter._get_report_folder()

        filename = TextReporter._generate_filename(folder)

        with open(filename, "w", encoding="utf-8") as file:
            file.write(TextReporter._build_header(summary))

            file.write(TextReporter._build_summary(summary))

            file.write(TextReporter._build_findings(findings))

        return filename

    # ==========================================
    # PATH MANAGEMENT
    # ==========================================

    @staticmethod
    def _get_report_folder():

        home = os.path.expanduser("~")

        folder = os.path.join(home, "Desktop", "Atom Logs")

        os.makedirs(folder, exist_ok=True)

        return folder

    @staticmethod
    def _generate_filename(folder):

        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

        return os.path.join(folder, f"reporte_atom_{timestamp}.txt")

    # ==========================================
    # REPORT BUILDERS
    # ==========================================

    @staticmethod
    def _build_header(summary):

        return (
            "========== ATOM SECURITY REPORT ==========\n\n"
            f"SYSTEM: {summary.get('system', 'UNKNOWN')}\n"
            f"MODULE: {summary.get('module', 'UNKNOWN')}\n"
            f"SCORE: {summary.get('score', 0)}/100\n"
            f"RATING: {summary.get('rating', 'UNKNOWN')}\n"
            f"DATE: {datetime.datetime.now()}\n\n"
        )

    @staticmethod
    def _build_summary(summary):

        status = summary.get("status", {})

        severity = summary.get("severity", {})

        return (
            "========== SUMMARY ==========\n\n"
            f"TOTAL FINDINGS: "
            f"{summary.get('total', 0)}\n\n"
            "STATUS:\n"
            f"  PASS: {status.get('PASS', 0)}\n"
            f"  WARNING: {status.get('WARNING', 0)}\n"
            f"  FAIL: {status.get('FAIL', 0)}\n"
            f"  ERROR: {status.get('ERROR', 0)}\n\n"
            "SEVERITY:\n"
            f"  CRITICAL: {severity.get('CRITICAL', 0)}\n"
            f"  HIGH: {severity.get('HIGH', 0)}\n"
            f"  MEDIUM: {severity.get('MEDIUM', 0)}\n"
            f"  LOW: {severity.get('LOW', 0)}\n"
            f"  INFO: {severity.get('INFO', 0)}\n\n"
        )

    @staticmethod
    def _build_findings(findings):

        output = "========== FINDINGS ==========\n\n"

        for finding in findings:
            output += str(finding)

            output += "\n\n"

        return output
