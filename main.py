"""Punto de entrada de ATOM (CLI e interfaz interactiva)."""

import argparse
import json
import os
import subprocess
import sys

from atom_core.interface.interface import AtomInterface
from atom_core.runners.audit_runner import AuditRunner

VERSION = "1.3.0"
AVAILABLE_AUDIT_IDS = ("1",)


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
            interface.show_menu(audit_available=runner.last_findings is not None)
            option = interface.get_choice()

            if option.isdigit():
                option_number = int(option)
                if 1 <= option_number <= len(options):
                    selected_option = options[option_number - 1]
                    if selected_option == "Exit":
                        print("\n[+] Gracias por usar Atom.")
                        break

                    if selected_option == "View audit results":
                        runner.show_last_results()
                        input("\nPresiona Enter para regresar al menú...")
                        continue

                    runner.run(option, show_results=False)
                    if runner.last_findings is not None:
                        print(
                            "\n[+] Auditoría completada. "
                            "Selecciona 'View audit results' para consultar el informe."
                        )
                    input("\nPresiona Enter para regresar al menú...")
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
        "--audit",
        choices=AVAILABLE_AUDIT_IDS,
        default="1",
        help="ID de auditoría disponible (actualmente: 1)",
    )
    audit_parser.add_argument(
        "--no-gui", action="store_true", help="Desactivar la UI interactiva"
    )
    audit_parser.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        default=argparse.SUPPRESS,
        help="Suprimir banner y salida de consola (también disponible después de 'audit')",
    )

    subparsers.add_parser("list", help="Listar opciones de auditoría disponibles")
    subparsers.add_parser("config", help="Mostrar la configuración actual (config.json)")

    return parser


def main() -> None:
    """Main application entry point."""
    parser = build_parser()
    args = parser.parse_args()

    if args.version:
        print(f"ATOM v{VERSION}")
        sys.exit(0)

    interface = AtomInterface()

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

    runner = AuditRunner()
    direct_audit = args.command == "audit" and args.no_gui

    if args.scan or direct_audit:
        if not args.quiet:
            interface.clear_screen()
            interface.show_banner()
            print("[*] Iniciando auditoría automática...")
        option = args.audit if args.command == "audit" else "1"
        runner.run(
            option=option,
            fmt=args.format,
            output_dir=args.output_dir,
            quiet=args.quiet,
        )
        return

    interactive_menu(interface, runner)


if __name__ == "__main__":
    main()
