"""Terminal interface for Atom.""" 

import logging
import os
import platform
import sys

from pyfiglet import Figlet  # type: ignore
from rich.align import Align
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

logger = logging.getLogger(__name__)


class AtomInterface:
    """Presentation and input layer for the interactive CLI."""

    VERSION = "1.3.0"
    FONT = "slant"
    OPTIONS = ("System Hardening Audit", "Exit")
    CYAN = "bright_cyan"
    BLUE = "bright_blue"
    WHITE = "white"
    RED = "bright_red"

    def __init__(self) -> None:
        self.console = Console()
        self.figlet: Figlet | None = None
        for font_name in (self.FONT, "standard"):
            try:
                self.figlet = Figlet(font=font_name)
                break
            except Exception as exc:  # noqa: BLE001
                logger.debug("Could not load Figlet font %s: %s", font_name, exc)

    def clear_screen(self) -> None:
        """Clear the terminal using Rich's cross-platform console support."""
        if self.console.is_terminal:
            self.console.clear()

    def print_gradient(self, text: str) -> None:
        """Render banner lines with a restrained blue/cyan color progression."""
        palette = ("bright_blue", "blue", "cyan", "bright_cyan")
        for index, line in enumerate(text.splitlines()):
            self.console.print(line, style=palette[index % len(palette)])

    def divider(self) -> None:
        self.console.rule(style="bright_blue")

    def show_banner(self) -> None:
        logo_text: str | None = None
        if self.figlet is not None:
            try:
                logo_text = self.figlet.renderText("ATOM").rstrip()
            except Exception as exc:  # noqa: BLE001
                logger.debug("Could not render Figlet banner: %s", exc)

        if not logo_text:
            logo_text = "  _  _____ ___  __  __\\n / \\|_   _/ _ \\|  \\/  |\\n/ _ \\ | || | | | |\\/| |\\n/_/ \\_\\|_||_| |_|_|  |_|"

        logo = Text(logo_text, style="bold bright_cyan", justify="center")
        subtitle = Text(
            "AUTOMATED SECURITY HARDENING FRAMEWORK",
            style="bold bright_blue",
            justify="center",
        )
        content = Text()
        content.append_text(logo)
        content.append("\\n")
        content.append_text(subtitle)
        self.console.print(
            Panel(
                Align.center(content),
                border_style="bright_blue",
                padding=(1, 2),
                expand=False,
            )
        )

    def show_info(self) -> None:
        info = Table.grid(padding=(0, 2))
        info.add_column(style="bright_cyan", justify="right")
        info.add_column(style="white")
        info.add_row("VERSION", self.VERSION)
        info.add_row("PLATFORM", platform.system() or "Unknown")
        info.add_row("MODE", "Security audit")
        self.console.print(Panel(info, title="[bold bright_blue]SYSTEM[/]", border_style="blue"))

    def show_menu(self) -> None:
        self.clear_screen()
        self.show_banner()
        self.show_info()

        menu = Table(
            title="MAIN MENU",
            box=None,
            show_header=False,
            padding=(0, 2),
            expand=True,
        )
        menu.add_column(style="bold bright_cyan", width=5, justify="right")
        menu.add_column(style="white")
        for index, option in enumerate(self.OPTIONS, start=1):
            menu.add_row(f"[{index}]", option)
        self.console.print(Panel(menu, border_style="bright_blue", padding=(1, 1)))
        self.console.print(
            Align.center("[dim]Select an option and press Enter[/dim]")
        )
        self.console.print()

    def get_options(self) -> tuple[str, ...]:
        return self.OPTIONS

    def get_choice(self) -> str:
        try:
            self.console.print("[bold bright_cyan]atom>[/]", end=" ")
            return input().strip()
        except KeyboardInterrupt:
            self.console.print("\\n[bold bright_red]Exiting ATOM...[/]")
            sys.exit(130)
