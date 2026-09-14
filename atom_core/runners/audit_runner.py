"""Orquestación de auditorías, análisis y generación de reportes."""

from atom_core.auditor_factory import AuditorFactory
from atom_core.core.security_score import SecurityScore
from atom_core.core.security_summary import SecuritySummary
from atom_core.reporters.console_reporter import ConsoleReporter
from atom_core.reporters.html_reporter import HTMLReporter
from atom_core.reporters.json_reporter import JsonReporter
from atom_core.reporters.text_reporter import TextReporter


class AuditRunner:
    """Coordinate audit execution and convert findings into reports."""

    VALID_FORMATS = {"all", "json", "html", "text", "txt"}

    def run(
        self,
        option: str = "1",
        fmt: str = "all",
        output_dir: str | None = None,
        quiet: bool = False,
    ) -> dict[str, str] | None:
        """Run the selected audit and generate the requested report formats."""
        if option != "1":
            if not quiet:
                print("[!] Auditoría inválida")
            return None

        target_fmt = fmt.lower()
        if target_fmt not in self.VALID_FORMATS:
            raise ValueError(f"Formato de reporte no soportado: {fmt}")

        auditor = AuditorFactory.get_auditor()
        findings = auditor.ejecutar()

        if not findings:
            if not quiet:
                print("[!] El auditor no devolvió resultados.")
            return None

        summary = SecuritySummary.summarize(findings)
        summary["score"] = SecurityScore.calculate(findings)
        summary["rating"] = SecurityScore.rating(summary["score"])
        summary["system"] = auditor.os_type
        summary["module"] = auditor.__class__.__name__
        if getattr(auditor, "distro", None):
            summary["distribution"] = auditor.distro

        if not quiet:
            ConsoleReporter.display(
                findings,
                summary["score"],
                summary["rating"],
            )

        reports: dict[str, str] = {}
        if target_fmt in {"all", "text", "txt"}:
            reports["text"] = TextReporter.save(
                summary, findings, output_dir=output_dir
            )
        if target_fmt in {"all", "json"}:
            reports["json"] = JsonReporter.save(
                summary, findings, output_dir=output_dir
            )
        if target_fmt in {"all", "html"}:
            reports["html"] = HTMLReporter.save(
                summary, findings, output_dir=output_dir
            )

        if not quiet and reports:
            print("\n[+] Reportes generados:")
            for report_type, report_path in reports.items():
                print(f"    {report_type.upper():<4}: {report_path}")

        return reports
