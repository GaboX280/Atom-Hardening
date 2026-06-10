import sys
import os
import subprocess
from atom_core.utils.interface import AtomInterface
from atom_core.auditor_factory import AuditorFactory

def main():
    interface = AtomInterface()
    
    while True:
        subprocess.run("cls" if os.name == "nt" else "clear", shell=True)
        try:
            interface.show_menu()
            opcion = interface.get_choice()
            
            # El diccionario ya incluye '3': 'ssh'
            tipos_auditoria = {"1": "system", "2": "file", "3": "ssh"}
            
            if opcion in tipos_auditoria:
                # La factory instancia el auditor correcto (System, File o SSH)
                auditor = AuditorFactory.get_auditor(tipos_auditoria[opcion])
                resultados = auditor.ejecutar()
                
                # Verificamos que resultados sea una lista válida
                if resultados is not None:
                    print(f"\n{'='*15} REPORTE DE SEGURIDAD {'='*15}")
                    for hallazgo in resultados:
                        print(hallazgo)
                    print("=" * 50)
                else:
                    print("\n[!] El auditor no devolvió resultados.")
                    
                input("\nPresiona Enter para regresar al menú...")
            
            elif opcion == "4":
                print("\n[+] Gracias por usar Atom.")
                subprocess.run("cls" if os.name == "nt" else "clear", shell=True)
                sys.exit(0)
            
            else:
                print("\n[!] Opción no válida.")
                input("\nPresiona Enter para continuar...")

        except Exception as e:
            # Esto atrapará errores como 'NotImplementedError' de la Factory 
            # o fallos en los módulos
            print(f"\n[!] Error inesperado: {e}")
            input("\nPresiona Enter para continuar...")

if __name__ == "__main__":
    main()