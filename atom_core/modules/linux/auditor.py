'''
Modulo para la auditoria de sistemas Linux en ATOM.
Este módulo contiene la clase LinuxAuditor, que hereda de BaseAuditor y se encarga de ejecutar auditorías específicas para sistemas Linux. La clase LinuxAuditor detecta la distribución Linux en la que se está ejecutando ATOM y realiza los checks correspondientes definidos en LINUX_AUDITS.
La lógica de auditoría específica para cada distribución Linux se maneja mediante la función detect_distro y los checks definidos en el módulo audits.py
'''
# Importacion de librerias necesarias
from atom_core.base_auditor import BaseAuditor

from ...utils.distro import detect_distro
from .audits import LINUX_AUDITS

#=====================================#
# Clase LinuxAuditor
#=====================================#

class LinuxAuditor(BaseAuditor):

    # ========================
    # METODO PARA INICIALIZAR AUDITOR
    # ========================

    def __init__(self):

        # Inicializa los atributos heredados
        # desde la clase BaseAuditor.

        super().__init__()

        # Detecta la distribucion Linux actual
        # donde se esta ejecutando ATOM.

        self.distro = detect_distro(
            self
        )

    # ========================
    # METODO PARA EJECUTAR AUDITORIA
    # ========================

    def ejecutar(self):

        # Registra el inicio de la auditoria
        # indicando la distribucion detectada.

        self.log(
            f"Iniciando auditoría Linux ({self.distro})..."
        )

        # Ejecuta todos los checks definidos
        # para sistemas Linux.

        return self.run_checks(
            LINUX_AUDITS
        )