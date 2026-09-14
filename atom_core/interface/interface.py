"""Terminal interface for Atom."""

import os
import platform
import sys

from pyfiglet import Figlet  # type: ignore

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")


class AtomInterface:
    """Presentation and input layer for the interactive CLI."""

    NAVY = "\033[38;5;18m"
    BLUE = "\033[38;5;25m"
    ROYAL = "\033[38;5;33m"
    SKY = "\033[38;5;39m"
    LIGHT = "\033[38;5;45m"
    WHITE = "\033[97m"
    RED = "\033[91m"
    RESET = "\033[0m"

    COLORS = (NAVY, BLUE, ROYAL, SKY, LIGHT, SKY, ROYAL, BLUE)
    VERSION = "1.3.0"
    FONT = "smisome1"
    OPTIONS = ("System Hardening Audit", "Exit")

    def __init__(self) -> None:
        self.figlet = None
        for font_name in (self.FONT, "slant", "standard"):
            try:
                self.figlet = Figlet(font=font_name)
                break
            except Exception:  # noqa: BLE001
                continue

    def clear_screen(self) -> None:
        os.system("cls" if os.name == "nt" else "clear")

    def print_gradient(self, text: str) -> None:
        for index, line in enumerate(text.splitlines()):
            print(self.COLORS[index % len(self.COLORS)] + line)
        print(self.RESET, end="")

    def divider(self) -> None:
        print("-" * 60)

    def show_banner(self) -> None:
        logo_text: str | None = None
        if self.figlet is not None:
            try:
                logo_text = str(self.figlet.renderText("ATOM"))
            except Exception:  # noqa: BLE001
                logo_text = None

        if not logo_text:
            logo_text = (
                "  AAA  TTTTT  OOO  M   M\n"
                " A   A   T   O   O MM MM\n"
                " AAAAA   T   O   O M M M\n"
                " A   A   T   O   O M   M\n"
                " A   A   T    OOO  M   M\n"
            )

        self.print_gradient(logo_text)
        print(
            f"{self.LIGHT}          Automated Security Hardening Framework{self.RESET}"
        )
        self.divider()

    def show_info(self) -> None:
        print(
            f"{self.WHITE}"
            f" Version : {self.VERSION}\n"
            f" Platform: {platform.system()}\n"
            f"{self.RESET}"
        )

    def show_menu(self) -> None:
        self.clear_screen()
        self.show_banner()
        self.show_info()
        for index, option in enumerate(self.OPTIONS, start=1):
            print(f"{self.LIGHT}[{index}]{self.WHITE} {option}{self.RESET}")
        self.divider()

    def get_options(self) -> tuple[str, ...]:
        return self.OPTIONS

    def get_choice(self) -> str:
        try:
            return input(f"\n{self.SKY}atom>{self.WHITE} ").strip()
        except KeyboardInterrupt:
            print(f"\n{self.RED}[!] Exiting Atom...{self.RESET}")
            sys.exit(130)
