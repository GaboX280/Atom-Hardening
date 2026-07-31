import platform


class AuditorFactory:


    @staticmethod
    def get_auditor(
        tipo="system"
    ):

        so = platform.system()


        # =========================
        # AUDITORIA SISTEMA
        # =========================

        if tipo == "system":


            if so == "Windows":

                from atom_core.modules.windows.auditor import WindowsAuditor

                return WindowsAuditor()



            elif so == "Linux":

                from atom_core.modules.linux.linux_mod import LinuxAuditor

                return LinuxAuditor()



        # =========================
        # AUDITORIA ARCHIVOS
        # =========================

        elif tipo == "file":


            if so == "Windows":

                from atom_core.modules.windows.file_audit import WindowsFileAuditor

                return WindowsFileAuditor()



            elif so == "Linux":

                from atom_core.modules.linux.file_audit import LinuxFileAuditor

                return LinuxFileAuditor()




        # =========================
        # SSH
        # =========================

        elif tipo == "ssh":


            from atom_core.modules.ssh.ssh_audit import SSHAuditor

            return SSHAuditor()




        raise NotImplementedError(

            f"No hay auditor disponible para "
            f"tipo='{tipo}' sistema='{so}'"

        )