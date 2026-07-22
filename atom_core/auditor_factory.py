import platform


class AuditorFactory:

    @staticmethod
    def get_auditor(tipo="system"):

        so = platform.system()


        if tipo == "system":

            if so == "Windows":

                from atom_core.modules.windows.windows_mod import WindowsAuditor
                return WindowsAuditor()


            elif so == "Linux":

                from atom_core.modules.linux.linux_mod import LinuxAuditor
                return LinuxAuditor()



        elif tipo == "file":

            if so == "Windows":

                from atom_core.modules.windows.file_audit import WindowsFileAuditor
                return WindowsFileAuditor()



        elif tipo == "ssh":

            from atom_core.modules.ssh.ssh_audit import SSHAuditor
            return SSHAuditor()



        raise NotImplementedError(
            f"No hay auditor de tipo {tipo} para {so}"
        )