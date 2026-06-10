from atom_core.base_auditor import BaseAuditor


class LinuxFileAuditor(BaseAuditor):
    def __init__(self):
        # Inicializa la clase base para tener self.report y los colores disponibles
        super().__init__()

    def ejecutar(self):
        """
        Método unificado que cumple con el contrato de BaseAuditor.
        Audita permisos críticos en archivos de Linux.
        """
        print(f"{self.CYAN}[*]{self.RESET} Iniciando auditoría de archivos en Linux...")
        
        # Archivos críticos de Linux
        archivos = ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]
        
        for f in archivos:
            self._analizar_permisos_linux(f)
            
        return self.report

    def _analizar_permisos_linux(self, archivo):
        try:
            # Usamos el método de la clase base para consistencia
            permisos = self._run_command(f"stat -c '%a' {archivo}").strip()
            
            # Verificamos si hubo error en el comando
            if "Error" in permisos:
                self.report.append(f"{self.RED}[!]{self.RESET} No se pudo auditar {archivo}: {permisos}")
                return

            # El último dígito representa permisos de 'others'. 
            # 2 (write), 3 (write+execute), 6 (read+write), 7 (all) son peligrosos.
            if permisos[-1] in ['2', '3', '6', '7']:
                self.report.append(f"{self.RED}[-]{self.RESET} {archivo}: RIESGO (Permisos {permisos} peligrosos) {self.RED}[PELIGRO]{self.RESET}")
            else:
                self.report.append(f"{self.GREEN}[+]{self.RESET} {archivo}: SEGURO (Permisos {permisos}) {self.GREEN}[OK]{self.RESET}")
                
        except Exception as e:
            self.report.append(f"{self.RED}[!]{self.RESET} Error inesperado en {archivo}: {str(e)}")