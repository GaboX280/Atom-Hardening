from atom_core.base_auditor import BaseAuditor


class LinuxAuditor(BaseAuditor):

    def __init__(self):
        super().__init__()
        self.distro = self.detect_distro()


    def detect_distro(self):

        resultado = self._run_command(
            "cat /etc/os-release"
        ).lower()


        if "ubuntu" in resultado:
            return "ubuntu"

        if "debian" in resultado:
            return "debian"

        if "fedora" in resultado:
            return "fedora"

        if "rhel" in resultado or "red hat" in resultado:
            return "rhel"

        if "arch" in resultado:
            return "arch"


        return "unknown"
    
    
    
    def _command_exists(self, command):

        resultado = self._run_command(
            f"command -v {command}"
        )

        return resultado != ""
    
    def audit_firewall(self):

            self.log(
                "Evaluando firewall Linux..."
            )


            if self._command_exists("ufw"):

                resultado = self._run_command(
                    "ufw status"
                )


                if "active" in resultado.lower():

                    self.add_finding(
                        title="Linux Firewall UFW",
                        status="PASS",
                        severity="INFO",
                        details="UFW está activo.",
                        recommendation="Mantener reglas actualizadas."
                    )

                else:

                    self.add_finding(
                        title="Linux Firewall UFW",
                        status="FAIL",
                        severity="HIGH",
                        details="UFW está deshabilitado.",
                        recommendation="Activar firewall."
                    )


            elif self._command_exists("firewall-cmd"):

                resultado = self._run_command(
                    "firewall-cmd --state"
                )


                if "running" in resultado:

                    self.add_finding(
                        title="Firewalld",
                        status="PASS",
                        severity="INFO",
                        details="Firewalld activo.",
                        recommendation="Mantener configuración."
                    )


            else:

                resultado = self._run_command(
                    "iptables -L"
                )


                if resultado:

                    self.add_finding(
                        title="iptables",
                        status="WARNING",
                        severity="MEDIUM",
                        details="Firewall detectado mediante iptables.",
                        recommendation="Revisar reglas."
                    )
                    
                    
    def audit_services(self):

        servicios = [
            "cron",
            "crond",
            "sshd"
        ]


        for servicio in servicios:

            estado = self._run_command(
                f"systemctl is-active {servicio}"
            )


            if estado.strip()=="active":

                self.add_finding(
                    title=f"Service {servicio}",
                    status="PASS",
                    severity="INFO",
                    details="Servicio activo.",
                    recommendation="Mantener monitoreo."
                )
                
    def audit_failed_logins(self):

        logs=[
            "/var/log/auth.log",
            "/var/log/secure"
        ]


        encontrado=False


        for log in logs:

            resultado=self._run_command(
                f"grep 'Failed password' {log} 2>/dev/null"
            )

            if resultado:
                encontrado=True


        if encontrado:

            self.add_finding(
                title="Failed SSH Logins",
                status="WARNING",
                severity="MEDIUM",
                details="Intentos fallidos encontrados.",
                recommendation="Revisar accesos SSH."
            )

        else:

            self.add_finding(
                title="Failed SSH Logins",
                status="PASS",
                severity="INFO",
                details="No se encontraron intentos fallidos.",
                recommendation="Mantener monitoreo."
            )
            
            
    def audit_root_accounts(self):

        self.log(
            "Evaluando cuentas con UID 0..."
        )


        usuarios = self._run_command(
            "awk -F: '($3 == 0) {print $1}' /etc/passwd"
        )


        cuentas = usuarios.splitlines()


        if len(cuentas) > 1:

            self.add_finding(
                title="Multiple Root Accounts",
                status="FAIL",
                severity="HIGH",
                details=(
                    f"Se detectaron cuentas privilegiadas: {', '.join(cuentas)}"
                ),
                recommendation=(
                    "Mantener únicamente cuentas root necesarias."
                )
            )

        else:

            self.add_finding(
                title="Root Account Security",
                status="PASS",
                severity="INFO",
                details=(
                    "Solo existe la cuenta root."
                ),
                recommendation=(
                    "Mantener control de privilegios."
                )
            )
            
    def audit_suid(self):

        self.log(
            "Buscando binarios SUID..."
        )


        resultado = self._run_command(
            "find / -perm -4000 -type f 2>/dev/null"
        )


        if resultado:

            cantidad = len(
                resultado.splitlines()
            )


            self.add_finding(
                title="SUID Binaries",
                status="WARNING",
                severity="MEDIUM",
                details=(
                    f"Se encontraron {cantidad} binarios SUID."
                ),
                recommendation=(
                    "Revisar binarios SUID innecesarios."
                )
            )


        else:

            self.add_finding(
                title="SUID Binaries",
                status="PASS",
                severity="INFO",
                details=(
                    "No se detectaron binarios SUID."
                ),
                recommendation=(
                    "Mantener revisión periódica."
                )
            )
            
    def audit_permissions(self):

        self.log(
            "Evaluando permisos críticos..."
        )


        archivos=[

            "/etc/passwd",
            "/etc/shadow",
            "/etc/sudoers"

        ]


        for archivo in archivos:


            permisos = self._run_command(
                f"stat -c '%a' {archivo}"
            ).strip()


            if "ERROR" in permisos.upper():

                self.add_finding(
                    title=f"Permissions {archivo}",
                    status="ERROR",
                    severity="HIGH",
                    details=permisos,
                    recommendation="Verificar permisos."
                )

                continue



            if permisos[-1] in [
                "2",
                "3",
                "6",
                "7"
            ]:


                self.add_finding(
                    title=f"Permissions {archivo}",
                    status="FAIL",
                    severity="HIGH",
                    details=(
                        f"Permisos inseguros detectados: {permisos}"
                    ),
                    recommendation=(
                        "Eliminar permisos de escritura pública."
                    )
                )


            else:

                self.add_finding(
                    title=f"Permissions {archivo}",
                    status="PASS",
                    severity="INFO",
                    details=(
                        f"Permisos seguros: {permisos}"
                    ),
                    recommendation=(
                        "Mantener permisos mínimos."
                    )
                )
                
    def audit_password_policy(self):

        self.log(
            "Evaluando política de contraseñas..."
        )


        resultado = self._run_command(
            "grep PASS_MAX_DAYS /etc/login.defs"
        )


        dias = None


        for linea in resultado.splitlines():

            if "PASS_MAX_DAYS" in linea:

                partes=linea.split()

                if len(partes)>=2:
                    dias=int(partes[1])


        if dias and dias <= 90:

            self.add_finding(
                title="Password Expiration Policy",
                status="PASS",
                severity="INFO",
                details=f"Caducidad máxima: {dias} días.",
                recommendation="Mantener política."
            )


        else:

            self.add_finding(
                title="Password Expiration Policy",
                status="WARNING",
                severity="MEDIUM",
                details=f"Valor encontrado: {dias}",
                recommendation="Configurar <= 90 días."
            )
            
    def audit_network(self):

        self.log(
            "Evaluando servicios escuchando..."
        )


        resultado = self._run_command(
            "ss -tulpn"
        )


        if resultado:

            lineas=len(
                resultado.splitlines()
            )


            self.add_finding(
                title="Listening Network Services",
                status="WARNING",
                severity="MEDIUM",
                details=(
                    f"Servicios escuchando detectados: {lineas}"
                ),
                recommendation=(
                    "Revisar puertos expuestos."
                )
            )

        else:

            self.add_finding(
                title="Listening Network Services",
                status="PASS",
                severity="INFO",
                details="No se detectaron servicios.",
                recommendation="Mantener monitoreo."
            )
                
            
    def ejecutar(self):

        self.log(
            f"Iniciando auditoría Linux ({self.distro})..."
        )


        checks=[

            self.audit_firewall,
            self.audit_services,
            self.audit_root_accounts,
            self.audit_suid,
            self.audit_permissions,
            self.audit_password_policy,
            self.audit_failed_logins,
            self.audit_network

        ]


        return self.run_checks(checks)