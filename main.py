"""
Modulo principal de ATOM. Este módulo contiene la función main() que sirve como punto de entrada para la ejecución del programa. La función main() se encarga de inicializar la interfaz de usuario, manejar el flujo de control del programa y coordinar la ejecución de auditorías según las opciones seleccionadas por el usuario.
"""

# Importacion de librerias necesarias
import argparse

# =====================================#
import json
import os
import subprocess

from atom_core.interface.interface import AtomInterface
from atom_core.runners.audit_runner import AuditRunner


def load_config() -> dict:
    """Load config.json from project root. Return empty dict if missing."""
    cfg_path = os.path.join(os.path.dirname(__file__), "config.json")
    try:
        with open(cfg_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def cmd_audit(args, interface, runner):
    """Execute audit based on args. Handles legacy flags as well as sub‑command usage."""
    if args.audit:
        if args.no_gui:
            print(f"[*] Iniciando auditoría {args.audit} en modo silencioso (no-gui)...")
            runner.run(args.audit)
        else:
            interface.clear_screen()
            interface.show_banner()
            runner.run(args.audit)
    else:
        # Fallback to interactive flow
        while True:
            interface.clear_screen()
            interface.show_menu()
            option = interface.get_choice()
            if option.isdigit():
                option_number = int(option)
                options = interface.get_options()
                if 1 <= option_number <= len(options):
                    selected = options[option_number - 1]
                    if selected == "Exit":
                        print("\n[+] Gracias por usar Atom.")
                        return
                    runner.run(option)
                    input("\nPresiona Enter para regresar...")
                    continue
            print("\n[!] Opción inválida.")
            input("\nPresiona Enter para regresar...")

def cmd_list(args, interface, runner):
    """List available audit options."""
    options = interface.get_options()
    print("Opciones de auditoría disponibles:")
    for idx, opt in enumerate(options, start=1):
        print(f"  {idx}. {opt}")

def cmd_config(args, interface, runner):
    """Show configuration content."""
    cfg = load_config()
    if not cfg:
        print("[!] config.json no encontrado o está vacío.")
    else:
        print(json.dumps(cfg, indent=4, ensure_ascii=False))
# FUNCION PARA LIMPIAR LA TERMINAL
# =====================================#


def clear_screen():

    subprocess.run(  # noqa: PLW1510
        "cls" if os.name == "nt" else "clear", shell=True
    )


# =====================================#

# FUNCION PRINCIPAL DE ATOM

# =====================================#


def main():

    # Build main parser with sub‑commands
    parser = argparse.ArgumentParser(description="ATOM - Automated Security Hardening Framework")
    subparsers = parser.add_subparsers(dest="command", help="Sub‑comandos disponibles")

    # audit subcommand
    audit_parser = subparsers.add_parser("audit", help="Ejecutar una auditoría (modo automático o interactivo)")
    audit_parser.add_argument("--audit", type=str, help="Identificador de auditoría específica (p. ej. '1')")
    audit_parser.add_argument("--no-gui", action="store_true", help="Desactivar la UI interactiva")

    # list subcommand
    subparsers.add_parser("list", help="Listar todas las auditorías disponibles")

    # config subcommand
    config_parser = subparsers.add_parser("config", help="Mostrar la configuración actual")
    config_parser.add_argument("--show", action="store_true", default=True, help="Mostrar config.json (por defecto)")

    # Backward compatibility: allow legacy flags without a sub‑command
    parser.add_argument("--audit", type=str, help=argparse.SUPPRESS)
    parser.add_argument("--no-gui", action="store_true", help=argparse.SUPPRESS)

    args = parser.parse_args()

    # Creacion de la interfaz de ATOM.

    interface = AtomInterface()

    # Creacion del administrador de auditorias.

    runner = AuditRunner()

    # Obtiene las opciones disponibles
    # desde la interfaz.

    options = interface.get_options()

    # Dispatch sub‑commands
    if args.command == "audit":
        cmd_audit(args, interface, runner)
    elif args.command == "list":
        cmd_list(args, interface, runner)
    elif args.command == "config":
        cmd_config(args, interface, runner)
    else:
        # No sub‑command supplied – fallback to legacy interactive flow
        pass

    # ==========================
    # BUCLE PRINCIPAL
    # ==========================

    try:
        while True:
            # Limpia la terminal.

            interface.clear_screen()

            # Muestra el menu principal.

            interface.show_menu()

            # Obtiene la opcion seleccionada
            # por el usuario.

            option = interface.get_choice()

            if option.isdigit():
                option_number = int(option)

                if 1 <= option_number <= len(options):
                    selected_option = options[option_number - 1]

                    if selected_option == "Exit":
                        print("\n[+] Gracias por usar Atom.")
                        break

                    # ==========================
                    # AUDITORIAS
                    # ==========================
                    runner.run(option)
                    input("\nPresiona Enter para regresar...")
                    continue

            # ==========================
            # OPCIÓN INVÁLIDA
            # ==========================

            print("\n[!] Opción inválida.")

            input("\nPresiona Enter para regresar...")
            
    except KeyboardInterrupt:
        print("\n\n[+] Saliendo de Atom (Interrumpido).")


# =====================================#
# PUNTO DE ENTRADA DE ATOM
# =====================================#

if __name__ == "__main__":
    main()
