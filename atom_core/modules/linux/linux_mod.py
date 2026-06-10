from atom_core.base_auditor import BaseAuditor

class LinuxAuditor(BaseAuditor):
    def __init__(self):
        super().__init__()

    def ejecutar(self):
        print(f"\n{self.CYAN}[*]{self.RESET} Iniciando auditoría de sistema Linux...")
        
        self._check_firewall()
        self._check_services()
        self._check_root_accounts()
        self._binary_SUID_check()
        self._config_directory_permissions()
        self._check_unnecessary_services()
        self._check_world_writable_files()
        self._check_password_policy()

        return self.report

    def _check_firewall(self):
        # Verifica si UFW (Uncomplicated Firewall) está activo en el sistema.
        resultado = self._run_command("sudo ufw status")
        if "active" in resultado:
            self.report.append(f"{self.GREEN}[+]{self.RESET} Firewall UFW: ACTIVADO {self.GREEN}[OK]{self.RESET}")
        else:
            self.report.append(f"{self.RED}[-]{self.RESET} Firewall UFW: DESACTIVADO {self.RED}[PELIGRO]{self.RESET}")

    def _check_services(self):
        # Este método revisa servicios comunes que deberían estar activos en un sistema seguro, como 'cron', 'ssh', etc.
        resultado = self._run_command("systemctl is-active cron")
        if "active" in resultado:
            self.report.append(f"{self.GREEN}[+]{self.RESET} Servicio Cron: ACTIVO {self.GREEN}[OK]{self.RESET}")
        else:
            self.report.append(f"{self.YELLOW}[!]{self.RESET} Servicio Cron: INACTIVO {self.YELLOW}[ADVERTENCIA]{self.RESET}")
            
    def _check_root_accounts(self):
        # Este comando busca usuarios con UID 0, lo cual es un riesgo si hay cuentas no autorizadas con privilegios de root.
        usuarios = self._run_command("awk -F: '($3 == \"0\") {print $1}' /etc/passwd").strip()
        if usuarios:
            self.report.append(f"{self.RED}[-]{self.RESET} Usuarios con privilegios Root: {usuarios} {self.RED}[PELIGRO]{self.RESET}")
        else:
            self.report.append(f"{self.GREEN}[+]{self.RESET} No hay usuarios root sospechosos {self.GREEN}[OK]{self.RESET}")
            
    def _binary_SUID_check(self):
        # Este comando busca archivos con el bit SUID activo, lo cual puede ser un riesgo si no se gestionan adecuadamente.
        resultado = self._run_command("find / -perm -4000 -type f 2>/dev/null")
        if resultado:
            self.report.append(f"{self.RED}[-]{self.RESET} Binarios SUID encontrados: {len(resultado.splitlines())} {self.RED}[PELIGRO]{self.RESET}")
        else:
            self.report.append(f"{self.GREEN}[+]{self.RESET} No se detectaron binarios SUID {self.GREEN}[OK]{self.RESET}")
            
    def _config_directory_permissions(self):
        # Este comando busca directorios en /etc que sean escribibles por cualquiera, lo cual es un riesgo de seguridad.
        resultado = self._run_command("find /etc -type d -perm -002 -ls 2>/dev/null")
        if resultado:
            directorios = resultado.splitlines()
            self.report.append(f"{self.RED}[-]{self.RESET} Directorios en /etc/ con permisos inseguros: {len(directorios)} {self.RED}[PELIGRO]{self.RESET}")
            for linea in directorios:
                ruta = linea.split()[-1]
                self.report.append(f"   {self.YELLOW}[!]{self.RESET} Riesgo en: {ruta}")
        else:
            self.report.append(f"{self.GREEN}[+]{self.RESET} Permisos en directorios /etc/: SEGURO {self.GREEN}[OK]{self.RESET}")
            
    def _check_unnecessary_services(self):
        # Este método revisa servicios comunes que no deberían estar activos en un sistema seguro.
        # aquí podrías añadir una lista de servicios comunes que no deberían estar activos en un sistema seguro, como 'avahi-daemon', 'cups', 'rpcbind', etc.
        services = ["avahi-daemon", "cups", "rpcbind"]
        for svc in services:
            status = self._run_command(f"systemctl is-active {svc} 2>/dev/null").strip()
            if status == "active":
                self.report.append(f"{self.YELLOW}[!]{self.RESET} Servicio innecesario: {svc} {self.YELLOW}[ADVERTENCIA]{self.RESET}")
                
    def _check_world_writable_files(self):
        # Este comando busca archivos en /home que sean escribibles por cualquiera, lo cual es un riesgo de seguridad.
        resultado = self._run_command("find /home -type f -perm -0002 2>/dev/null")
        if resultado:
            self.report.append(f"{self.RED}[-]{self.RESET} Archivos escribibles por cualquiera en /home: {len(resultado.splitlines())} {self.RED}[PELIGRO]{self.RESET}")
        else:
            self.report.append(f"{self.GREEN}[+]{self.RESET} Permisos en /home: SEGURO {self.GREEN}[OK]{self.RESET}")
            
    def _check_password_policy(self):
        # Verifica la política de expiración de contraseñas
        dias = self._run_command("grep '^PASS_MAX_DAYS' /etc/login.defs | awk '{print $2}'").strip()
        if dias and int(dias) > 90:
            self.report.append(f"{self.YELLOW}[!]{self.RESET} Política contraseñas: PASS_MAX_DAYS es {dias} (se recomienda <= 90) {self.YELLOW}[ADVERTENCIA]{self.RESET}")
        else:
            self.report.append(f"{self.GREEN}[+]{self.RESET} Política de contraseñas: OK ({dias} días) {self.GREEN}[OK]{self.RESET}")
            
    def _check_open_ports(self):
        # Escanea puertos en escucha
        resultado = self._run_command("ss -tulpn | grep LISTEN")
        if resultado:
            self.report.append(f"{self.CYAN}[i]{self.RESET} Servicios escuchando en red (Revisar si son necesarios):")
            for linea in resultado.splitlines():
                self.report.append(f"   {self.CYAN}->{self.RESET} {linea.strip()}")
        else:
            self.report.append(f"{self.GREEN}[+]{self.RESET} No se detectaron servicios escuchando externamente {self.GREEN}[OK]{self.RESET}")
            
    def _check_failed_logins(self):
        # Busca intentos fallidos en /var/log/auth.log
        resultado = self._run_command("grep 'Failed password' /var/log/auth.log | tail -n 5 2>/dev/null")
        if resultado:
            self.report.append(f"{self.RED}[-]{self.RESET} Intentos de login fallidos recientes detectados en auth.log!")
        else:
            self.report.append(f"{self.GREEN}[+]{self.RESET} No se detectaron intentos de login fallidos recientes {self.GREEN}[OK]{self.RESET}")