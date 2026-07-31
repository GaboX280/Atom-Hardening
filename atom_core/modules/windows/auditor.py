from atom_core.base_auditor import BaseAuditor

from .audit import WINDOWS_CHECKS


class WindowsAuditor(BaseAuditor):

    def ejecutar(self):

        self.log(
            "Iniciando auditoría completa de Windows..."
        )

        return self.run_checks(
            WINDOWS_CHECKS
        )