'''
Modulo principal de ATOM. Este módulo contiene la función main() que sirve como punto de entrada para la ejecución del programa. La función main() se encarga de inicializar la interfaz de usuario, manejar el flujo de control del programa y coordinar la ejecución de auditorías según las opciones seleccionadas por el usuario.
'''
# Importacion de librerias necesarias
import os
import subprocess

from atom_core.interface.interface import AtomInterface
from atom_core.runners.audit_runner import AuditRunner

#=====================================#
# FUNCION PARA LIMPIAR LA TERMINAL
#=====================================#

def clear_screen():

    subprocess.run(  # noqa: PLW1510
        "cls" if os.name == "nt" else "clear",
        shell=True
    )


#=====================================#

# FUNCION PRINCIPAL DE ATOM

#=====================================#

def main():

    # Creacion de la interfaz de ATOM.

    interface = AtomInterface()

    # Creacion del administrador de auditorias.

    runner = AuditRunner()

    # Obtiene las opciones disponibles
    # desde la interfaz.

    options = interface.get_options()

    # La ultima opcion del menu corresponde
    # a la salida de ATOM.

    exit_option = str(len(options))

    # ==========================
    # BUCLE PRINCIPAL
    # ==========================

    while True:

        # Limpia la terminal.

        interface.clear_screen()

        # Muestra el menu principal.

        interface.show_menu()

        # Obtiene la opcion seleccionada
        # por el usuario.

        option = interface.get_choice()

        # ==========================
        # EXIT
        # ==========================

        if option == exit_option:

            print(
                "\n[+] Gracias por usar Atom."
            )

            break

        # ==========================
        # AUDITORIAS
        # ==========================

        if option.isdigit():

            option_number = int(option)

            # Verifica que la opcion seleccionada
            # corresponda a una opcion existente.

            if 1 <= option_number < len(options):

                runner.run(option)

                input(
                    "\nPresiona Enter para regresar..."
                )

                continue

        # ==========================
        # INVALID OPTION
        # ==========================

        print(
            "\n[!] Opción inválida."
        )

        input(
            "\nPresiona Enter para regresar..."
        )


#=====================================#
# PUNTO DE ENTRADA DE ATOM
#=====================================#

if __name__ == "__main__":

    main()

