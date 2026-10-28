"""Terminal interface for Atom."""

import logging
import platform
import sys
from collections import Counter
from pathlib import Path

from pyfiglet import Figlet  # type: ignore
from rich import box
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

logger = logging.getLogger(__name__)

ATOM_ART_PATH = Path(__file__).with_name("atom_art.txt")
ART_SCALE = 3
ART_PRIORITY = {"@": 5, "%": 4, "#": 3, "*": 2, "+": 1}
ART_STYLES = {
    "@": "bold bright_white",
    "%": "bold bright_cyan",
    "#": "bright_cyan",
    "*": "bright_blue",
    "+": "blue",
}


class AtomInterface:
    """Presentation and input layer for the interactive CLI."""

    VERSION = "1.3.0"
    FONT = "slant"
    OPTIONS = ("Run security audit", "View audit results", "Exit")

    OPTION_DETAILS = (
        "Evaluate endpoint controls and calculate the security score",
        "Review the latest findings, severity levels, and recommendations",
        "Close the ATOM console",
    )

    def __init__(self) -> None:
        self.console = Console()
        self.atom_art = self._build_atom_art()
        self.figlet: Figlet | None = None
        for font_name in (self.FONT, "standard", "small"):
            try:
                self.figlet = Figlet(font=font_name)
                break
            except Exception as exc:  # noqa: BLE001
                logger.debug("Could not load Figlet font %s: %s", font_name, exc)

    @staticmethod
    def _build_atom_art() -> Text:
        """Load the custom ASCII logo and scale it to fit a regular terminal."""
        try:
            lines = ATOM_ART_PATH.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            logger.warning("Could not load ATOM artwork: %s", exc)
            lines = [
                "          .-o-.",
                "      .-' / | \\ '-.",
                "   o----- ( @ ) -----o",
                "      '-. \\ | / .-'",
                "          '-o-'",
            ]

        lines = [line for line in lines if line]
        if not lines:
            return Text("ATOM", style="bold bright_cyan", justify="center")

        source_width = max(map(len, lines))
        padded_lines = [line.ljust(source_width) for line in lines]
        art = Text(justify="center", no_wrap=True, overflow="crop")

        for row_start in range(0, len(padded_lines), ART_SCALE):
            for col_start in range(0, source_width, ART_SCALE):
                sample = [
                    padded_lines[row][col]
                    for row in range(
                        row_start, min(row_start + ART_SCALE, len(padded_lines))
                    )
                    for col in range(
                        col_start, min(col_start + ART_SCALE, source_width)
                    )
                ]
                shades = [character for character in sample if character != " "]
                if not shades:
                    art.append(" ")
                    continue

                counts = Counter(shades)
                character = max(
                    counts,
                    key=lambda item: (counts[item], ART_PRIORITY.get(item, 0)),
                )
                art.append(character, style=ART_STYLES.get(character, "bright_cyan"))

            if row_start + ART_SCALE < len(padded_lines):
                art.append("\n")

        return art

    def clear_screen(self) -> None:
        """Clear the terminal using Rich's cross-platform console support."""
        if self.console.is_terminal:
            self.console.clear()

    def show_banner(self) -> None:
        """Render the custom atom drawing beside the ATOM wordmark."""
        logo_text: str | None = None
        if self.figlet is not None:
            try:
                logo_text = self.figlet.renderText("ATOM").rstrip()
            except Exception as exc:  # noqa: BLE001
                logger.debug("Could not render Figlet banner: %s", exc)

        if not logo_text:
            logo_text = "A T O M"

        brand = Table.grid(padding=(0, 0))
        brand.add_column(justify="center")
        brand.add_row(
            Text(logo_text, style="bold bright_cyan", justify="center")
        )
        brand.add_row(
            Text(
                "SECURITY POSTURE MONITOR",
                style="bold bright_blue",
                justify="center",
            )
        )
        brand.add_row(
            Text(
                f"AUTOMATED SECURITY HARDENING FRAMEWORK  •  v{self.VERSION}",
                style="dim",
                justify="center",
            )
        )

        header = Table.grid(expand=True, padding=(0, 2))
        header.add_column(ratio=1, justify="center")
        header.add_column(ratio=2, justify="center")
        header.add_row(self.atom_art, Align.center(brand, vertical="middle"))

        self.console.print(
            Panel(
                header,
                title="[bold bright_blue] ATOM / DEFENSE CONSOLE [/]",
                border_style="bright_blue",
                box=box.DOUBLE,
                padding=(0, 1),
                expand=True,
            )
        )

    @staticmethod
    def _status_cell(label: str, value: str, value_style: str = "bold white") -> Text:
        """Build one compact status item with a clear label/value hierarchy."""
        cell = Text()
        cell.append(label.upper() + "\n", style="dim")
        cell.append(value, style=value_style)
        return cell

    def show_info(self, audit_available: bool = False) -> None:
        """Show runtime details in a compact three-column status strip."""
        info = Table.grid(expand=True, padding=(0, 2))
        info.add_column(ratio=1, justify="center")
        info.add_column(ratio=1, justify="center")
        info.add_column(ratio=1, justify="center")

        audit_state = "Results available" if audit_available else "Not run this session"
        audit_style = "bold bright_green" if audit_available else "yellow"
        info.add_row(
            self._status_cell("Platform", platform.system() or "Unknown"),
            self._status_cell("Version", self.VERSION, "bold bright_cyan"),
            self._status_cell("Audit status", audit_state, audit_style),
        )

        self.console.print(
            Panel(
                info,
                title="[bold bright_cyan] SYSTEM STATUS [/]",
                border_style="blue",
                box=box.ROUNDED,
                padding=(0, 1),
                expand=True,
            )
        )

    def show_menu(self, audit_available: bool = False) -> None:
        """Display a clear, descriptive main menu."""
        self.clear_screen()
        self.show_banner()
        self.show_info(audit_available=audit_available)

        menu = Table(
            box=None,
            show_header=False,
            show_edge=False,
            show_lines=False,
            padding=(1, 1),
            expand=True,
        )
        menu.add_column("ID", width=5, justify="center", no_wrap=True)
        menu.add_column("ACTION", min_width=22, no_wrap=True)
        menu.add_column("DESCRIPTION", ratio=1)

        for index, (option, detail) in enumerate(
            zip(self.OPTIONS, self.OPTION_DETAILS, strict=True),
            start=1,
        ):
            number = Text(f"{index:02}", style="bold bright_cyan")
            title = Text(option, style="bold white")
            description = Text(detail, style="dim")
            menu.add_row(number, title, description)

        self.console.print(
            Panel(
                menu,
                title="[bold bright_blue] MAIN MENU [/]",
                subtitle="[dim]Choose an action[/]",
                border_style="bright_blue",
                box=box.ROUNDED,
                padding=(0, 1),
                expand=True,
            )
        )
        self.console.print(
            Align.center(
                Text("Enter 1, 2, or 3 to continue  •  Ctrl+C to quit", style="dim")
            )
        )
        self.console.print()

    def show_notice(self, message: str, kind: str = "info") -> None:
        """Display a consistent, styled notice for the interactive workflow."""
        styles = {
            "info": ("INFO", "bright_blue"),
            "success": ("SUCCESS", "bright_green"),
            "warning": ("WARNING", "yellow"),
            "error": ("ERROR", "bright_red"),
        }
        label, style = styles.get(kind, styles["info"])
        content = Text()
        content.append(f"{label}  ", style=f"bold {style}")
        content.append(message)
        self.console.print(
            Panel(
                content,
                border_style=style,
                box=box.ROUNDED,
                padding=(0, 1),
                expand=True,
            )
        )

    def pause(self, message: str = "Press Enter to return to the menu...") -> None:
        """Pause without falling back to unstyled input prompts."""
        self.console.print(f"[dim]{message}[/]")
        input()

    def get_options(self) -> tuple[str, ...]:
        """Return the available interactive actions."""
        return self.OPTIONS

    def get_choice(self) -> str:
        """Read the user's menu selection."""
        try:
            self.console.print("[bold bright_cyan]ATOM[/] [dim]›[/]", end=" ")
            return input().strip()
        except KeyboardInterrupt:
            self.show_notice("ATOM interrupted. Closing the console.", kind="warning")
            sys.exit(130)
