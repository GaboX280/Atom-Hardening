import sys
import os
import subprocess
from atom_core.utils.interface import AtomInterface
from atom_core.auditor_factory import AuditorFactory

def main():
    interface = AtomInterface()
    
    while True:
        # Limpieza de pantalla al inicio del bucle
        subprocess.run("cls" if os.name == "nt" else "clear", shell=True)
        try:
            interface.show_menu()
            opcion = interface.get_choice()
            
            tipos_auditoria = {"1": "system", "2": "file", "3": "ssh"}
            
            if opcion in tipos_auditoria:
                auditor = AuditorFactory.get_auditor(tipos_auditoria[opcion])
                resultados = auditor.ejecutar()
                
                if resultados is not None:
                    print(f"\n{'='*15} REPORTE DE SEGURIDAD {'='*15}")
                    for hallazgo in resultados:
                        print(hallazgo)
                    print("=" * 50)
                    
                    # NUEVA LOGICA: Guardar reporte
                    guardar = input("\n[?] ¿Deseas guardar el reporte en un archivo? (s/n): ").lower()
                    if guardar == 's':
                        nombre_archivo = auditor.save_report_to_file()
                        print(f"[+] Reporte guardado exitosamente en: {nombre_archivo}")
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
            print(f"\n[!] Error inesperado: {e}")
            input("\nPresiona Enter para continuar...")

if __name__ == "__main__":
    main()