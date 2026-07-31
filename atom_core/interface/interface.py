import os
import platform
import sys

from pyfiglet import Figlet


class AtomInterface:

    # ===== Color Theme =====
    NAVY = "\033[38;5;18m"         # Azul muy oscuro
    BLUE = "\033[38;5;25m"         # Azul
    ROYAL = "\033[38;5;33m"        # Azul real
    SKY = "\033[38;5;39m"          # Azul claro
    LIGHT = "\033[38;5;45m"        # Celeste

    WHITE = "\033[97m"
    RED = "\033[91m"
    RESET = "\033[0m"

    COLORS = (
        NAVY,
        BLUE,
        ROYAL,
        SKY,
        LIGHT,
        SKY,
        ROYAL,
        BLUE,
    )

    VERSION = "1.0"

    def __init__(self):
        self.figlet = Figlet(font="smisome1")

    def clear_screen(self):
        os.system("cls" if os.name == "nt" else "clear")

    def print_gradient(self, text):

        for i, line in enumerate(text.splitlines()):
            print(self.COLORS[i % len(self.COLORS)] + line)

        print(self.RESET, end="")

    def divider(self):
        print(self.ROYAL + "─" * 60 + self.RESET)

    def show_banner(self):

        logo = self.figlet.renderText("ATOM")

        self.print_gradient(logo)

        print(
            f"{self.LIGHT}"
            "          Automated Security Hardening Framework"
            f"{self.RESET}"
        )

        self.divider()

    def show_info(self):

        print(
            f"{self.WHITE}"
            f" Version : {self.VERSION}\n"
            f" Platform: {platform.system()}\n"
            f"{self.RESET}"
        )

    def show_menu(self):

        self.clear_screen()

        self.show_banner()

        self.show_info()

        options = (
            "System Hardening Audit",
            "Critical File Audit",
            "SSH Configuration Audit",
            "Exit",
        )

        for i, option in enumerate(options, start=1):

            print(
                f"{self.LIGHT}[{i}]"
                f"{self.WHITE} {option}"
                f"{self.RESET}"
            )

        self.divider()

    def get_choice(self):

        try:
            return input(
                f"\n{self.SKY}atom>{self.WHITE} "
            )

        except KeyboardInterrupt:

            print(
                f"\n{self.RED}[!] Exiting Atom...{self.RESET}"
            )

            sys.exit()