from atom_core.base_auditor import BaseAuditor

class WindowsFileAuditor(BaseAuditor):
    def __init__(self):
        # Es fundamental llamar al constructor de la clase base
        # para inicializar self.report y los colores.
        super().__init__()

    def ejecutar(self):
        """
        Método unificado que cumple con el contrato de BaseAuditor.
        Audita permisos en archivos críticos.
        """
        print(f"\n{self.CYAN}[*]{self.RESET} Iniciando auditoría de permisos de archivos...")
        
        # Archivos críticos definidos para la auditoría
        archivos_criticos = [
            r"C:\Windows\System32\drivers\etc\hosts",
            r"C:\Windows\System32\config\SAM"
        ]
        
        for archivo in archivos_criticos:
            # Mensaje de progreso para que el usuario vea que el proceso está activo
            print(f"  {self.CYAN}->{self.RESET} Analizando archivo: {archivo.split('\\')[-1]}...")
            self._analizar_permisos(archivo)
            
        print(f"{self.GREEN}[+]{self.RESET} Auditoría de archivos finalizada correctamente.")
        
        # Retornamos el reporte para que el main.py pueda procesarlo
        return self.report

    def _analizar_permisos(self, ruta):
        try:
            # Usamos el método de la clase base para ejecutar comandos de forma segura
            resultado = self._run_command(f'icacls "{ruta}"')
            
            # Grupos que no deberían tener control total o escritura
            grupos_peligrosos = ["Everyone", "Todos", "Users", "Authenticated Users"]
            
            es_vulnerable = False
            for grupo in grupos_peligrosos:
                # (F) = Full Control, (M) = Modify, (W) = Write
                if grupo in resultado and (":(F)" in resultado or ":(M)" in resultado or ":(W)" in resultado):
                    es_vulnerable = True
                    break
            
            if es_vulnerable:
                self.report.append(f"{self.RED}[-]{self.RESET} {ruta}: RIESGO (Permisos excesivos detectados) {self.RED}[PELIGRO]{self.RESET}")
            else:
                self.report.append(f"{self.GREEN}[+]{self.RESET} {ruta}: SEGURO {self.GREEN}[OK]{self.RESET}")
                
        except Exception as e:
            self.report.append(f"{self.RED}[!]{self.RESET} {ruta}: Error al acceder ({str(e)})")