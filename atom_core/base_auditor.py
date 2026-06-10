import subprocess
import platform
import datetime
import os
import re
from abc import ABC, abstractmethod

class BaseAuditor(ABC):
    def __init__(self):
        self.report = []
        self.os_type = platform.system()
        # Colores
        self.GREEN = "\033[92m"
        self.RED = "\033[91m"
        self.CYAN = "\033[96m"
        self.YELLOW = "\033[93m"
        self.RESET = "\033[0m"

    def _run_command(self, command):
        try:
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            return result.stdout.strip()
        except Exception as e:
            return f"Error ejecutando comando: {str(e)}"

    def save_report_to_file(self):
        """
        Guarda el reporte en la carpeta 'Atom Logs' del escritorio.
        Detecta automáticamente si el escritorio se llama 'Desktop' o 'Escritorio'.
        """
        home = os.path.expanduser("~")
        rutas_escritorio = [
            os.path.join(home, "Desktop"),
            os.path.join(home, "Escritorio")
        ]
        
        # Selecciona la ruta que realmente exista en el sistema
        escritorio = next((ruta for ruta in rutas_escritorio if os.path.exists(ruta)), rutas_escritorio[0])
        carpeta_logs = os.path.join(escritorio, "Atom Logs")
        
        if not os.path.exists(carpeta_logs):
            os.makedirs(carpeta_logs)
            
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = os.path.join(carpeta_logs, f"reporte_atom_{timestamp}.txt")
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write("--- REPORTE DE AUDITORIA ATOM ---\n")
            f.write(f"Fecha: {datetime.datetime.now()}\n")
            f.write(f"Sistema: {self.os_type}\n")
            f.write("="*30 + "\n\n")
            
            for line in self.report:
                clean_line = self._remove_ansi_colors(line)
                f.write(clean_line + "\n")
        
        return filename

    def _remove_ansi_colors(self, text):
        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        return ansi_escape.sub('', text)

    @abstractmethod
    def ejecutar(self):
        pass