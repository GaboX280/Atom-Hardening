import sys
from atom_core.utils.interface import AtomInterface
from atom_core.modules.windows_mod import WindowsAuditor

def main():
    interface = AtomInterface()
    
    while True:
        try:
            interface.show_menu()
            opcion = interface.get_choice()
            
            if opcion == "1":
                auditor = WindowsAuditor()
                resultados = auditor.run_full_audit()
                
                print("\n" + "="*15 + " REPORTE DE HUELLAS DE SEGURIDAD " + "="*15)
                # Eliminamos el f-string manual que duplicaba el '[+]'
                for hallazgo in resultados:
                    print(hallazgo)
                print("=" * 50)
                
                input("\nPresiona Enter para regresar al menú...")
                
            elif opcion == "2" or opcion == "3":
                print("\n[*] Esta función se integrará en la auditoría completa general. (Próximamente)")
                input("\nPresiona Enter para continuar...")
                
            elif opcion == "4":
                print("\n[+] Gracias por usar Atom. ¡Hasta luego!")
                sys.exit(0)
                
            else:
                print("\n[!] Opción no válida. Por favor, selecciona un número del 1 al 4.")
                input("\nPresiona Enter para continuar...")

        except KeyboardInterrupt:
            print("\n\n[!] Saliendo de Atom...")
            sys.exit(0)

if __name__ == "__main__":
    main()