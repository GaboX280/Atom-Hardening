"""Rich-powered terminal report for Atom security audits."""

import re
from collections import Counter
from typing import ClassVar

from rich.console import Console
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table


class ConsoleReporter:
    """Render audit summaries and findings in a readable terminal layout."""

    STATUS_STYLES: ClassVar[dict[str, tuple[str, str]]] = {
        "PASS": ("bright_green", "PASS"),
        "WARNING": ("yellow", "WARN"),
        "FAIL": ("bright_red", "FAIL"),
        "ERROR": ("bright_red", "ERROR"),
    }
    SEVERITY_STYLES: ClassVar[dict[str, str]] = {
        "CRITICAL": "bold bright_red",
        "HIGH": "bright_red",
        "MEDIUM": "yellow",
        "LOW": "bright_blue",
        "INFO": "dim",
    }

    @staticmethod
    def display(findings, score=None, rating=None) -> None:
        """Display a score panel, summary tables, and detailed findings."""
        console = Console()
        if not findings:
            console.print(
                Panel(
                    "[yellow]No se encontraron resultados.[/]",
                    title="[bold bright_cyan]ATOM SECURITY REPORT[/]",
                    border_style="yellow",
                )
            )
            return

        status_summary = Counter(finding.status.upper() for finding in findings)
        severity_summary = Counter(finding.severity.upper() for finding in findings)

        console.print()
        console.print(
            Panel(
                "[bold bright_cyan]ATOM SECURITY REPORT[/]\n"
                "[dim]Automated Security Hardening Framework[/]",
                border_style="bright_blue",
                padding=(1, 2),
            )
        )

        if score is not None:
            score_style = (
                "bright_green" if score >= 90
                else "yellow" if score >= 75
                else "bright_red" if score < 50
                else "bright_blue"
            )
            filled = max(1, min(20, score // 5))
            score_table = Table.grid(expand=True, padding=(0, 1))
            score_table.add_column(ratio=1)
            score_table.add_column(justify="right")
            score_table.add_row(
                f"[bold]Security score[/]  [{score_style}]{score}/100[/]",
                f"[{score_style}]{'━' * filled}{'─' * (20 - filled)}[/]",
            )
            if rating:
                clean_rating = re.sub(r"\x1b\[[0-9;]*m", "", str(rating))
                score_table.add_row("[dim]Rating[/]", escape(clean_rating))
            console.print(
                Panel(
                    score_table,
                    title="[bold bright_blue]POSTURE[/]",
                    border_style="blue",
                )
            )

        summary = Table(
            title="AUDIT SUMMARY",
            header_style="bold bright_cyan",
            border_style="blue",
            show_lines=False,
        )
        summary.add_column("Metric", style="white")
        summary.add_column("Count", justify="right", style="bold")
        summary.add_row("Total checks", str(len(findings)))
        for status, style in (
            ("PASS", "bright_green"),
            ("WARNING", "yellow"),
            ("FAIL", "bright_red"),
            ("ERROR", "bright_red"),
        ):
            summary.add_row(
                f"[{style}]{status}[/]",
                f"[{style}]{status_summary.get(status, 0)}[/]",
            )
        console.print(summary)

        severity = Table(
            title="SEVERITY DISTRIBUTION",
            header_style="bold bright_cyan",
            border_style="blue",
        )
        severity.add_column("Severity")
        severity.add_column("Count", justify="right")
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            style = ConsoleReporter.SEVERITY_STYLES[level]
            severity.add_row(
                f"[{style}]{level}[/]", str(severity_summary.get(level, 0))
            )
        console.print(severity)

        details = Table(
            title="SECURITY FINDINGS",
            header_style="bold bright_cyan",
            border_style="bright_blue",
            show_lines=True,
            expand=True,
        )
        details.add_column("Status", width=8, no_wrap=True)
        details.add_column("Severity", width=10, no_wrap=True)
        details.add_column("Finding", min_width=18, ratio=2)
        details.add_column("Category", min_width=12, ratio=1)
        details.add_column("Details", min_width=20, ratio=3)
        details.add_column("Recommendation", min_width=20, ratio=3)

        for finding in findings:
            status = finding.status.upper()
            status_style, status_label = ConsoleReporter.STATUS_STYLES.get(
                status, ("white", status or "UNKNOWN")
            )
            severity_style = ConsoleReporter.SEVERITY_STYLES.get(
                finding.severity.upper(), "white"
            )
            details.add_row(
                f"[{status_style}]{escape(status_label)}[/]",
                f"[{severity_style}]{escape(finding.severity)}[/]",
                f"[bold]{escape(finding.title)}[/]\n[dim]{escape(finding.finding_id)}[/]",
                escape(finding.category or "General"),
                escape(finding.details or "—"),
                escape(finding.recommendation or "—"),
            )
        console.print(details)
        console.print(
            Panel(
                f"[bold bright_cyan]Audit finished[/]  "
                f"[dim]{len(findings)} controls evaluated[/]",
                border_style="bright_blue",
            )
        )
