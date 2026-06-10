import os
import sys

class AtomInterface:
    def __init__(self):
        self.BLUE = '\033[94m'
        self.GREEN = '\033[92m'
        self.YELLOW = '\033[93m'
        self.RED = '\033[91m'
        self.RESET = '\033[0m'
        
    def clear_screen(self):
        os.system('cls' if os.name == 'nt' else 'clear')
        
    def show_menu(self):
        """Dibuja el banner principal y las opciones del menú."""
        self.clear_screen()
        
        # Un banner de presentacion simple pero llamativo
        print(f"{self.GREEN}")
        print("█████╗ ████████╗ ██████╗ ███╗   ███╗")
        print("██╔══██╗╚══██╔══╝██╔═══██╗████╗ ████║")
        print("███████║   ██║   ██║   ██║██╔████╔██║")
        print("██╔══██║   ██║   ██║   ██║██║╚██╔╝██║")
        print("██║  ██║   ██║   ╚██████╔╝██║ ╚═╝ ██║")
        print("╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝     ╚═╝")
        print(f"      [ Herramienta de Hardening ]{self.RESET}\n")
        
        print("-" * 45)
        print(f"{self.GREEN}1.{self.RESET} Correr Auditoría Completa del Sistema")
        print(f"{self.GREEN}2.{self.RESET} Revisar Permisos de Archivos Críticos")
        print(f"{self.GREEN}3.{self.RESET} Analizar Configuración de Servicios (SSH)")
        print(f"{self.GREEN}4.{self.RESET} Salir")
        print("-" * 45)

    def get_choice(self):
        """Solicita al usuario que elija una opción válida."""
        try:
            choice = input(f"\n{self.YELLOW}Selecciona una opción (1-4): {self.RESET}")
            return choice
        except KeyboardInterrupt:
            # Por si el usuario presiona Ctrl+C para salir abruptamente
            print(f"\n\n[!] Saliendo de Atom...")
            sys.exit(0)