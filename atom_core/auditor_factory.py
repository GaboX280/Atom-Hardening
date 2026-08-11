''' Modulo para la creación de auditores según el sistema operativo.

    La selección del auditor se realiza automáticamente
    según el sistema operativo donde se ejecuta ATOM.

    Los checks específicos de cada sistema operativo
    son responsabilidad de su auditor correspondiente.
'''

# Importacion de librerias necesarias

import platform

#=====================================#
# Clase AuditorFactory
#=====================================#

class AuditorFactory:

    @staticmethod
    # ========================
    # METODO PARA OBTENER AUDITOR
    # ========================
    def get_auditor():

        so = platform.system()

        # =========================
        # AUDITORIA SISTEMA
        # =========================

        # Deteccion del sistema operativo y creación del auditor correspondiente.

        if so == "Windows":
            # Importar el auditor de Windows y devolver una instancia de WindowsAuditor.
            from atom_core.modules.windows.auditor import WindowsAuditor

            return WindowsAuditor()

        elif so == "Linux":
            # Importar el auditor de Linux y devolver una instancia de LinuxAuditor.
            from atom_core.modules.linux.auditor import LinuxAuditor

            return LinuxAuditor()

        raise NotImplementedError(
            # En caso de error devolver la falla de compatibilidad.
            f"No hay auditor disponible "
            f"para sistema='{so}'"
        )
