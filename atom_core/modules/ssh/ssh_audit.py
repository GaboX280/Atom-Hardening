from atom_core.base_auditor import BaseAuditor


class SSHAuditor(BaseAuditor):


    def __init__(self):

        super().__init__()



    def ejecutar(self):

        self.log(
            "Auditando configuración SSH..."
        )


        checks = []


        if self.os_type == "Windows":

            checks = [

                self.audit_windows_ssh

            ]

        else:

            checks = [

                self.audit_linux_service,
                self.audit_linux_config,
                self.audit_root_login,
                self.audit_password_auth,
                self.audit_ssh_port

            ]


        return self.run_checks(checks)




    # ==================================================
    # WINDOWS
    # ==================================================

    def audit_windows_ssh(self):

        self.log(
            "Evaluando servicio OpenSSH en Windows..."
        )


        comando = (
            'powershell -Command '
            '"(Get-Service sshd '
            '-ErrorAction SilentlyContinue).Status"'
        )


        resultado = (
            self._run_command(comando)
            .strip()
            .upper()
        )



        if "RUNNING" in resultado:


            self.add_finding(

                title="Windows SSH Service",

                status="WARNING",

                severity="MEDIUM",
                
                category="Remote Access",

                details=(
                    "El servicio OpenSSH Server está activo."
                ),

                recommendation=(
                    "Revisar sshd_config y restringir accesos."
                )

            )


        else:


            self.add_finding(

                title="Windows SSH Service",

                status="PASS",

                severity="INFO",
                
                category="Remote Access",

                details=(
                    "El servicio OpenSSH no está activo."
                ),

                recommendation=(
                    "Mantener SSH deshabilitado si no es necesario."
                )

            )





    # ==================================================
    # LINUX SERVICE
    # ==================================================

    def audit_linux_service(self):

        self.log(
            "Evaluando servicio SSH Linux..."
        )


        servicios = [

            "sshd",
            "ssh"

        ]


        activo = False


        servicio_detectado = ""


        for servicio in servicios:


            estado = (

                self._run_command(
                    f"systemctl is-active {servicio}"
                )
                .strip()
                .lower()

            )


            if estado == "active":

                activo = True
                servicio_detectado = servicio
                break




        if activo:


            self.add_finding(

                title="Linux SSH Service",

                status="WARNING",

                severity="MEDIUM",
                
                category="Remote Access",

                details=(

                    f"Servicio SSH activo ({servicio_detectado})."

                ),

                recommendation=(

                    "Revisar configuración SSH."

                )

            )


        else:


            self.add_finding(

                title="Linux SSH Service",

                status="PASS",

                severity="INFO",
                
                category="Remote Access",

                details=(

                    "Servicio SSH no activo."

                ),

                recommendation=(

                    "Mantener servicios remotos innecesarios apagados."

                )

            )





    # ==================================================
    # SSH CONFIG
    # ==================================================

    def audit_linux_config(self):

        self.log(
            "Revisando configuración sshd..."
        )


        rutas = [

            "/etc/ssh/sshd_config",

            "/etc/ssh/sshd_config.d"

        ]


        encontrado = False


        for ruta in rutas:


            resultado = self._run_command(

                f"test -e {ruta} && echo FOUND"

            )


            if "FOUND" in resultado:

                encontrado = True
                break




        if encontrado:


            self.add_finding(

                title="SSH Configuration",

                status="PASS",

                severity="INFO",
                
                category="Remote Access",

                details=(

                    "Archivo de configuración SSH encontrado."

                ),

                recommendation=(

                    "Mantener configuración revisada."

                )

            )


        else:


            self.add_finding(

                title="SSH Configuration",

                status="WARNING",

                severity="LOW",
                
                category="Remote Access",

                details=(

                    "No se encontró sshd_config."

                ),

                recommendation=(

                    "Verificar instalación SSH."

                )

            )





    # ==================================================
    # ROOT LOGIN
    # ==================================================

    def audit_root_login(self):

        self.log(
            "Revisando acceso root SSH..."
        )


        resultado = self._run_command(

            "grep -Ei '^PermitRootLogin' /etc/ssh/sshd_config"

        ).lower()



        if "permitrootlogin no" in resultado:


            self.add_finding(

                title="SSH Root Login",

                status="PASS",

                severity="INFO",
                
                category="Remote Access",

                details=(

                    "Login SSH directo de root deshabilitado."

                ),

                recommendation=(

                    "Mantener root login bloqueado."

                )

            )


        else:


            self.add_finding(

                title="SSH Root Login",

                status="FAIL",

                severity="HIGH",
                
                category="Remote Access",

                details=(

                    "SSH permite posiblemente acceso directo root."

                ),

                recommendation=(

                    "Configurar PermitRootLogin no."

                )

            )





    # ==================================================
    # PASSWORD AUTH
    # ==================================================

    def audit_password_auth(self):

        self.log(
            "Revisando autenticación por contraseña..."
        )


        resultado = self._run_command(

            "grep -Ei '^PasswordAuthentication' /etc/ssh/sshd_config"

        ).lower()



        if "passwordauthentication no" in resultado:


            self.add_finding(

                title="SSH Password Authentication",

                status="PASS",

                severity="INFO",
                
                category="Remote Access",

                details=(

                    "Autenticación por contraseña deshabilitada."

                ),

                recommendation=(

                    "Usar autenticación mediante claves SSH."

                )

            )


        else:


            self.add_finding(

                title="SSH Password Authentication",

                status="WARNING",

                severity="MEDIUM",
                
                category="Remote Access",

                details=(

                    "Autenticación por contraseña habilitada."

                ),

                recommendation=(

                    "Considerar usar claves SSH."

                )

            )





    # ==================================================
    # SSH PORT
    # ==================================================

    def audit_ssh_port(self):

        self.log(
            "Verificando puerto SSH..."
        )


        resultado = self._run_command(

            "ss -tulpn | grep ssh"

        )


        if resultado:


            self.add_finding(

                title="SSH Network Exposure",

                status="WARNING",

                severity="MEDIUM",
                
                category="Remote Access",

                details=(

                    "SSH está escuchando en red."

                ),

                recommendation=(

                    "Limitar acceso mediante firewall."

                )

            )


        else:


            self.add_finding(

                title="SSH Network Exposure",

                status="PASS",

                severity="INFO",
                
                category="Remote Access",

                details=(

                    "No se detectaron puertos SSH abiertos."

                ),

                recommendation=(

                    "Mantener exposición mínima."

                )

            )