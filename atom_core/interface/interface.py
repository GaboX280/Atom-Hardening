"""Modulo para la interfaz de usuario de Atom.
Proporciona una interfaz de línea de comandos para interactuar con el usuario,
mostrar banners, menús y recibir entradas.
La interfaz de usuario es responsable de la presentación visual y la interacción
con el usuario, mientras que la lógica de auditoría se maneja en otros módulos.
"""

# Importacion de librerias necesarias
import os
import platform
import sys
# Asegurar salida UTF-8 en consolas Windows
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8")

from pyfiglet import Figlet  # type: ignore

# =====================================#
# Clase AtomInterface
# =====================================#


class AtomInterface:
    # ===== Tema de Colores =====

    NAVY = "\033[38;5;18m"
    BLUE = "\033[38;5;25m"
    ROYAL = "\033[38;5;33m"
    SKY = "\033[38;5;39m"
    LIGHT = "\033[38;5;45m"

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

    VERSION = "1.2.0"
    FONT = "smisome1"

    # ========================
    # OPCIONES DEL MENU
    # ========================

    OPTIONS = (
        "System Hardening Audit",
        "Exit",
    )

    def __init__(self) -> None: # [TIPADO AÑADIDO] -> None

        try:
            self.figlet = Figlet(font=self.FONT)

        except OSError:
            self.figlet = Figlet(font="slant")

    # ========================
    # METODO PARA LIMPIAR PANTALLA
    # ========================

    def clear_screen(self) -> None: # [TIPADO AÑADIDO] -> None

        os.system("cls" if os.name == "nt" else "clear")

    # ========================
    # METODO PARA MOSTRAR GRADIENTE
    # ========================

    def print_gradient(self, text: str) -> None: # [TIPADO AÑADIDO] -> None

        for i, line in enumerate(text.splitlines()):
            print(self.COLORS[i % len(self.COLORS)] + line)

        print(self.RESET, end="")

    # ========================
    # METODO PARA MOSTRAR DIVISOR
    # ========================

    def divider(self) -> None: # [TIPADO AÑADIDO] -> None

        print("-" * 60)

    # ========================
    # METODO PARA MOSTRAR BANNER
    # ========================

    def show_banner(self) -> None: # [TIPADO AÑADIDO] -> None

        logo = self.figlet.renderText("ATOM")

        self.print_gradient(logo)

        print(
            f"{self.LIGHT}          Automated Security Hardening Framework{self.RESET}"
        )

        self.divider()

    # ========================
    # METODO PARA MOSTRAR INFORMACION
    # ========================

    def show_info(self) -> None: # [TIPADO AÑADIDO] -> None

        print(
            f"{self.WHITE}"
            f" Version : {self.VERSION}\n"
            f" Platform: {platform.system()}\n"
            f"{self.RESET}"
        )

    # ========================
    # METODO PARA MOSTRAR MENU
    # ========================

    def show_menu(self) -> None: # [TIPADO AÑADIDO] -> None

        self.clear_screen()

        self.show_banner()

        self.show_info()

        for i, option in enumerate(self.OPTIONS, start=1):
            print(f"{self.LIGHT}[{i}]{self.WHITE} {option}{self.RESET}")

        self.divider()

    # ========================
    # METODO PARA OBTENER OPCIONES
    # ========================

    def get_options(self) -> tuple[str, ...]: # [TIPADO AÑADIDO] -> tuple[str, ...]

        return self.OPTIONS

    # ========================
    # METODO PARA OBTENER OPCION
    # ========================

    def get_choice(self) -> str: # [TIPADO AÑADIDO] -> str

        try:
            return input(f"\n{self.SKY}atom>{self.WHITE} ")

        except KeyboardInterrupt:
            print(f"\n{self.RED}[!] Exiting Atom...{self.RESET}")

            sys.exit()
