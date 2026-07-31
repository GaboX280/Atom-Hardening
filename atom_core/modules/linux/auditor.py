from atom_core.base_auditor import BaseAuditor

from ...utils.distro import detect_distro

from .audits import LINUX_AUDITS



class LinuxAuditor(BaseAuditor):


    def __init__(self):

        super().__init__()

        self.distro = detect_distro(
            self
        )



    def ejecutar(self):

        self.log(
            f"Iniciando auditoría Linux ({self.distro})..."
        )


        return self.run_checks(
            LINUX_AUDITS
        )