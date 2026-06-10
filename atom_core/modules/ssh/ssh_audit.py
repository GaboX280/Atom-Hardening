from atom_core.base_auditor import BaseAuditor

class SSHAuditor(BaseAuditor):
    def __init__(self):
        super().__init__()

    def ejecutar(self):
        print(f"\n{self.CYAN}[*]{self.RESET} Auditando configuración de SSH...")
        
        if self.os_type == "Windows":
            self._audit_windows_ssh()
        else:
            self._audit_linux_ssh()
            
        return self.report

    def _audit_windows_ssh(self):
        # Verifica si el servicio 'sshd' (OpenSSH Server) está ejecutándose
        resultado = self._run_command("powershell -Command \"(Get-Service sshd -ErrorAction SilentlyContinue).Status\"")
        if "Running" in resultado:
            self.report.append(f"{self.RED}[-]{self.RESET} SSH en Windows: EJECUTÁNDOSE (Verificar configuración en C:\\ProgramData\\ssh\\sshd_config) {self.RED}[PELIGRO]{self.RESET}")
        else:
            self.report.append(f"{self.GREEN}[+]{self.RESET} SSH en Windows: NO DETECTADO o DESACTIVADO {self.GREEN}[OK]{self.RESET}")

    def _audit_linux_ssh(self):
        # Verifica si el servicio corre
        status = self._run_command("systemctl is-active sshd")
        if "active" in status:
            self.report.append(f"{self.RED}[-]{self.RESET} SSH en Linux: EJECUTÁNDOSE {self.RED}[PELIGRO]{self.RESET}")
            
            # Revisar si permite login de root
            config = self._run_command("grep '^PermitRootLogin' /etc/ssh/sshd_config")
            if "no" in config.lower() or "#" in config:
                self.report.append(f"{self.GREEN}[+]{self.RESET} SSH Login Root: DESHABILITADO {self.GREEN}[OK]{self.RESET}")
            else:
                self.report.append(f"{self.RED}[-]{self.RESET} SSH Login Root: PERMITIDO (Inseguro) {self.RED}[PELIGRO]{self.RESET}")
        else:
            self.report.append(f"{self.GREEN}[+]{self.RESET} SSH en Linux: NO DETECTADO {self.GREEN}[OK]{self.RESET}")