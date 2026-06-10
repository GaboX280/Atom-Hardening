import subprocess
import platform

class AtomAuditor:
    def __init__(self):
        # Lista compartida donde guardaremos los hallazgos de seguridad
        self.report = []
        # Detectamos el sistema operativo del host automáticamente
        self.os_type = platform.system()
        # Definimos colores para resaltar hallazgos en la terminal (si el sistema lo soporta)
        # Códigos ANSI para dar color en la terminal
        self.GREEN = "\033[92m"   # Para éxitos y estados [OK] o [+]
        self.RED = "\033[91m"     # Para peligros [PELIGRO] o [-]
        self.CYAN = "\033[96m"    # Para información [*]
        self.YELLOW = "\033[93m"  # Para advertencias [!]
        self.RESET = "\033[0m"    # Para limpiar el color

    def _run_command(self, command):
        """
        Ejecuta de forma segura un comando en la terminal del sistema 
        y devuelve lo que el comando imprima (stdout).
        """
        try:
            # shell=True permite usar comandos nativos de la terminal.
            # capture_output=True guarda el resultado para que Python lo procese.
            # text=True hace que el resultado venga como texto (string) y no como bytes.
            result = subprocess.run(command, shell=True, capture_output=True, text=True)
            return result.stdout.strip()
        except Exception as e:
            return f"Error ejecutando comando: {str(e)}"