"""Terminal interface for Atom."""

import logging
import math
import platform
import sys

from pyfiglet import Figlet  # type: ignore
from rich import box
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
        """Draw three intersecting electron orbits in terminal Braille cells."""
        width, height = 46, 40
        radius_x, radius_y = 21.5, 7.0
        center_x, center_y = (width - 1) / 2, (height - 1) / 2
        angles = (0.0, math.pi / 3, -math.pi / 3)
        orbit_styles = ("bright_blue", "bright_cyan", "cyan")
        pixels: list[list[set[int]]] = [
            [set() for _ in range(width)] for _ in range(height)
        ]

        # Each Braille character contains a 2-by-4 grid of dots. Sampling the
        # ellipses at sub-character resolution produces smoother curves than
        # hand-typed slashes and backslashes.
        samples = 4000
        for orbit_id, angle in enumerate(angles):
            cos_angle = math.cos(angle)
            sin_angle = math.sin(angle)
            for sample in range(samples):
                theta = math.tau * sample / samples
                x = (
                    radius_x * math.cos(theta) * cos_angle
                    - radius_y * math.sin(theta) * sin_angle
                )
                y = (
                    radius_x * math.cos(theta) * sin_angle
                    + radius_y * math.sin(theta) * cos_angle
                )
                col = round(center_x + x)
                row = round(center_y + y)
                if 0 <= col < width and 0 <= row < height:
                    pixels[row][col].add(orbit_id)

        # Put one electron on each orbit, plus a brighter nucleus in the center.
        electrons: dict[tuple[int, int], tuple[str, str]] = {}
        electron_angles = (0.55, 2.6, 4.65)
        for orbit_id, (angle, theta) in enumerate(zip(angles, electron_angles, strict=True)):
            x = (
                radius_x * math.cos(theta) * math.cos(angle)
                - radius_y * math.sin(theta) * math.sin(angle)
            )
            y = (
                radius_x * math.cos(theta) * math.sin(angle)
                + radius_y * math.sin(theta) * math.cos(angle)
            )
            char_position = (
                round(center_x + x) // 2,
                round(center_y + y) // 4,
            )
            electrons[char_position] = ("●", "bold white")

        nucleus_position = (round(center_x) // 2, round(center_y) // 4)
        electrons[nucleus_position] = ("●", "bold bright_cyan")

        # Unicode Braille bit positions, indexed by (row, column).
        braille_bits = {
            (0, 0): 0,
            (1, 0): 1,
            (2, 0): 2,
            (3, 0): 6,
            (0, 1): 3,
            (1, 1): 4,
            (2, 1): 5,
            (3, 1): 7,
        }
        art = Text(justify="center", no_wrap=True)
        char_rows, char_cols = height // 4, width // 2

        for char_row in range(char_rows):
            for char_col in range(char_cols):
                position = (char_col, char_row)
                overlay = electrons.get(position)
                if overlay is not None:
                    character, style = overlay
                    art.append(character, style=style)
                    continue

                bits = 0
                orbit_counts = [0, 0, 0]
                for dot_row in range(4):
                    for dot_col in range(2):
                        active_orbits = pixels[char_row * 4 + dot_row][
                            char_col * 2 + dot_col
                        ]
                        if active_orbits:
                            bits |= 1 << braille_bits[(dot_row, dot_col)]
                            for orbit_id in active_orbits:
                                orbit_counts[orbit_id] += 1

                if bits:
                    dominant_orbit = max(range(3), key=orbit_counts.__getitem__)
                    art.append(chr(0x2800 + bits), style=orbit_styles[dominant_orbit])
                else:
                    art.append(" ")

            if char_row < char_rows - 1:
                art.append("\n")

        return art

    def clear_screen(self) -> None:
        """Clear the terminal using Rich's cross-platform console support."""
        if self.console.is_terminal:
            self.console.clear()

    def show_banner(self) -> None:
        """Render the ATOM wordmark and a drawn atomic-orbit mark."""
        logo_text: str | None = None
        if self.figlet is not None:
            try:
                logo_text = self.figlet.renderText("ATOM").rstrip()
            except Exception as exc:  # noqa: BLE001
                logger.debug("Could not render Figlet banner: %s", exc)

        if not logo_text:
            logo_text = "A T O M"

        header = Table.grid(expand=True, padding=(0, 0))
        header.add_column(justify="center")
        header.add_row(self.atom_art)
        header.add_row(Text(logo_text, style="bold bright_cyan", justify="center"))
        header.add_row(
            Text(
                "SECURITY POSTURE MONITOR",
                style="bold bright_blue",
                justify="center",
            )
        )
        header.add_row(
            Text(
                f"AUTOMATED SECURITY HARDENING FRAMEWORK  •  v{self.VERSION}",
                style="dim",
                justify="center",
            )
        )

        self.console.print(
            Panel(
                header,
                title="[bold bright_blue] ATOM / DEFENSE CONSOLE [/]",
                border_style="bright_blue",
                box=box.DOUBLE,
                padding=(0, 2),
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
