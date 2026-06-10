import subprocess
import platform
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

    @abstractmethod
    def ejecutar(self):
        """
        Obligamos a que cualquier clase hija (WindowsAuditor, FileAuditor, etc.) 
        implemente su propia lógica dentro de este método.
        """
        pass