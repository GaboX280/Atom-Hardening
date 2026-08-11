''' Modulo para la interfaz de usuario de Atom.
    Proporciona una interfaz de línea de comandos para interactuar con el usuario,
    mostrar banners, menús y recibir entradas.
    La interfaz de usuario es responsable de la presentación visual y la interacción
    con el usuario, mientras que la lógica de auditoría se maneja en otros módulos.
'''
# Importacion de librerias necesarias
import os
import platform
import sys

from pyfiglet import Figlet

#=====================================#
# Clase AtomInterface
#=====================================#

class AtomInterface:

    # ===== Color Theme =====

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

    def __init__(self):

        try:

            self.figlet = Figlet(
                font=self.FONT
            )

        except OSError:

            self.figlet = Figlet(
                font="slant"
            )

    # ========================
    # METODO PARA LIMPIAR PANTALLA
    # ========================

    def clear_screen(self):

        os.system(
            "cls"
            if os.name == "nt"
            else "clear"
        )

    # ========================
    # METODO PARA MOSTRAR GRADIENTE
    # ========================

    def print_gradient(self, text):

        for i, line in enumerate(
            text.splitlines()
        ):

            print(
                self.COLORS[
                    i % len(self.COLORS)
                ]
                + line
            )

        print(
            self.RESET,
            end=""
        )

    # ========================
    # METODO PARA MOSTRAR DIVISOR
    # ========================

    def divider(self):

        print(
            self.ROYAL
            + "─" * 60
            + self.RESET
        )

    # ========================
    # METODO PARA MOSTRAR BANNER
    # ========================

    def show_banner(self):

        logo = self.figlet.renderText(
            "ATOM"
        )

        self.print_gradient(
            logo
        )

        print(
            f"{self.LIGHT}"
            "          Automated Security Hardening Framework"
            f"{self.RESET}"
        )

        self.divider()

    # ========================
    # METODO PARA MOSTRAR INFORMACION
    # ========================

    def show_info(self):

        print(
            f"{self.WHITE}"
            f" Version : {self.VERSION}\n"
            f" Platform: {platform.system()}\n"
            f"{self.RESET}"
        )

    # ========================
    # METODO PARA MOSTRAR MENU
    # ========================

    def show_menu(self):

        self.clear_screen()

        self.show_banner()

        self.show_info()

        for i, option in enumerate(
            self.OPTIONS,
            start=1
        ):

            print(
                f"{self.LIGHT}[{i}]"
                f"{self.WHITE} {option}"
                f"{self.RESET}"
            )

        self.divider()

    # ========================
    # METODO PARA OBTENER OPCIONES
    # ========================

    def get_options(self):

        return self.OPTIONS

    # ========================
    # METODO PARA OBTENER OPCION
    # ========================

    def get_choice(self):

        try:

            return input(
                f"\n{self.SKY}atom>{self.WHITE} "
            )

        except KeyboardInterrupt:

            print(
                f"\n{self.RED}"
                "[!] Exiting Atom..."
                f"{self.RESET}"
            )

            sys.exit()
