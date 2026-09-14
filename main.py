"""Punto de entrada de ATOM (CLI e interfaz interactiva)."""

import argparse
import json
import os
import subprocess
import sys

from atom_core.interface.interface import AtomInterface
from atom_core.runners.audit_runner import AuditRunner

VERSION = "1.3.0"


def load_config() -> dict:
    """Load config.json from the project root."""
    cfg_path = os.path.join(os.path.dirname(__file__), "config.json")
    try:
        with open(cfg_path, "r", encoding="utf-8") as file:
            data = json.load(file)
            return data if isinstance(data, dict) else {}
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return {}


def clear_screen() -> None:
    """Clear the terminal according to the host operating system."""
    subprocess.run("cls" if os.name == "nt" else "clear", shell=True, check=False)


def interactive_menu(interface: AtomInterface, runner: AuditRunner) -> None:
    """Run the interactive Atom menu."""
    options = interface.get_options()
    try:
        while True:
            interface.clear_screen()
            interface.show_menu()
            option = interface.get_choice()

            if option.isdigit():
                option_number = int(option)
                if 1 <= option_number <= len(options):
                    selected_option = options[option_number - 1]
                    if selected_option == "Exit":
                        print("\n[+] Gracias por usar Atom.")
                        break

                    runner.run(option)
                    input("\nPresiona Enter para regresar...")
                    continue

            print("\n[!] Opción inválida.")
            input("\nPresiona Enter para regresar...")

    except KeyboardInterrupt:
        print("\n\n[+] Saliendo de Atom (Interrumpido).")


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser."""
    parser = argparse.ArgumentParser(
        description="ATOM - Framework de Auditoría y Hardening de Seguridad Automatizado"
    )

    parser.add_argument(
        "-s",
        "--scan",
        action="store_true",
        help="Ejecutar escaneo directo sin menú interactivo",
    )
    parser.add_argument(
        "-f",
        "--format",
        choices=["all", "json", "html", "text", "txt"],
        default="all",
        help="Formato de reporte de salida",
    )
    parser.add_argument(
        "-o",
        "--output-dir",
        type=str,
        default=None,
        help="Directorio personalizado para guardar reportes",
    )
    parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Modo silencioso",
    )
    parser.add_argument(
        "-v",
        "--version",
        action="store_true",
        help="Mostrar la versión de ATOM y salir",
    )

    subparsers = parser.add_subparsers(dest="command", help="Subcomandos disponibles")

    audit_parser = subparsers.add_parser(
        "audit", help="Ejecutar auditoría (modo automático o interactivo)"
    )
    audit_parser.add_argument(
        "--audit", type=str, default="1", help="ID de auditoría (por defecto '1')"
    )
    audit_parser.add_argument(
        "--no-gui", action="store_true", help="Desactivar la UI interactiva"
    )

    subparsers.add_parser("list", help="Listar opciones de auditoría disponibles")

    config_parser = subparsers.add_parser(
        "config", help="Mostrar configuración actual"
    )
    config_parser.add_argument(
        "--show", action="store_true", default=True, help="Mostrar config.json"
    )

    return parser


def main() -> None:
    """Main application entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        print(f"ATOM v{VERSION}")
        sys.exit(0)

    interface = AtomInterface()
    runner = AuditRunner()

    if args.command == "list":
        print("Opciones de auditoría disponibles:")
        for idx, option in enumerate(interface.get_options(), start=1):
            print(f"  {idx}. {option}")
        return

    if args.command == "config":
        cfg = load_config()
        if not cfg:
            print("[!] config.json no encontrado o está vacío.")
        else:
            print(json.dumps(cfg, indent=4, ensure_ascii=False))
        return

    if args.scan or (args.command == "audit" and getattr(args, "no_gui", False)):
        if not args.quiet:
            interface.clear_screen()
            interface.show_banner()
            print("[*] Iniciando auditoría automática...")
        runner.run(
            option="1",
            fmt=args.format,
            output_dir=args.output_dir,
            quiet=args.quiet,
        )
        return

    interactive_menu(interface, runner)


if __name__ == "__main__":
    main()
