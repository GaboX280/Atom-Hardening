import os
import subprocess
import sys

from atom_core.auditor_factory import AuditorFactory
from atom_core.interface.interface import AtomInterface
from atom_core.reporters.console_reporter import ConsoleReporter
from atom_core.runners.audit_runner import AuditRunner


def clear_screen():

    subprocess.run(
        "cls" if os.name == "nt" else "clear",
        shell=True
    )


def run_audit(option):

    tipos_auditoria = {

        "1": "system",
        "2": "file",
        "3": "ssh"

    }


    auditor = AuditorFactory.get_auditor(
        tipos_auditoria[option]
    )


    resultados = auditor.ejecutar()


    if resultados is None:

        print(
            "\n[!] El auditor no devolvió resultados."
        )

        return



    # Mostrar reporte en consola
    ConsoleReporter.display(
            resultados
    )

    # Guardar reporte en archivo
    archivo = auditor.save_report_to_file()


    print(
        "\n[+] Reporte generado:"
    )


    print(
        f"    {archivo}"
    )



def main():

    interface = AtomInterface()
    runner = AuditRunner()


    while True:

        interface.clear_screen()

        interface.show_menu()

        opcion = interface.get_choice()


        if opcion in {"1","2","3"}:

            runner.run(opcion)

            input(
                "\nPresiona Enter para regresar..."
            )


        elif opcion == "4":

            print(
                "\n[+] Gracias por usar Atom."
            )

            break



if __name__ == "__main__":

    main()