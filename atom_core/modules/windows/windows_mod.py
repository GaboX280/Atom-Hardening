from atom_core.base_auditor import BaseAuditor


class WindowsAuditor(BaseAuditor):


    def audit_firewall(self):
        """Verifica el estado del Firewall de Windows."""

        self.log(
            "Evaluando el estado del Firewall de Windows..."
        )

        comando = "netsh advfirewall show allprofiles state"

        resultado = self._run_command(comando)


        if (
            "ON" in resultado.upper()
            or
            "ACTIVAR" in resultado.upper()
        ):

            self.add_finding(
                title="Windows Firewall",
                status="PASS",
                severity="INFO",
                category="Network Security",
                details="El Firewall de Windows está activo.",
                recommendation=(
                    "Mantener las reglas del firewall actualizadas."
                )
            )


        else:

            self.add_finding(
                title="Windows Firewall",
                status="FAIL",
                severity="HIGH",
                category="Network Security",
                details=(
                    "El Firewall de Windows parece estar desactivado."
                ),
                recommendation=(
                    "Activar Windows Firewall en todos los perfiles."
                )
            )



    def audit_windows_defender(self):
        """Verifica protección en tiempo real de Windows Defender."""

        self.log(
            "Comprobando protección de Windows Defender..."
        )


        comando = (
            "powershell -Command "
            "\"(Get-MpComputerStatus).RealTimeProtectionEnabled\""
        )


        resultado = self._run_command(comando)


        if "TRUE" in resultado.upper():

            self.add_finding(
                title="Windows Defender",
                status="PASS",
                severity="INFO",
                category="Antivirus Protection",
                details=(
                    "La protección en tiempo real está activa."
                ),
                recommendation=(
                    "Mantener las firmas antivirus actualizadas."
                )
            )


        else:

            self.add_finding(
                title="Windows Defender",
                status="FAIL",
                severity="HIGH",
                category="Antivirus Protection",
                details=(
                    "La protección en tiempo real está deshabilitada."
                ),
                recommendation=(
                    "Activar la protección en tiempo real."
                )
            )



    def audit_password_policy(self):
        """Audita la política mínima de contraseñas."""

        self.log(
            "Evaluando política de contraseñas..."
        )


        resultado = self._run_command(
            "net accounts"
        )


        longitud_minima = 0


        for linea in resultado.splitlines():

            if (
                "LONGITUD MÍNIMA" in linea.upper()
                or
                "MINIMUM PASSWORD LENGTH" in linea.upper()
            ):

                numeros = [
                    int(x)
                    for x in linea.split()
                    if x.isdigit()
                ]


                if numeros:

                    longitud_minima = numeros[0]
                    break



        if longitud_minima >= 8:

            self.add_finding(
                title="Password Policy",
                status="PASS",
                severity="INFO",
                details=(
                    f"Longitud mínima configurada: {longitud_minima}"
                ),
                recommendation=(
                    "Mantener políticas robustas de contraseña."
                )
            )


        else:

            self.add_finding(
                title="Password Policy",
                status="FAIL",
                severity="MEDIUM",
                category="Password Policy",
                details=(
                    f"Longitud mínima encontrada: {longitud_minima}"
                ),
                recommendation=(
                    "Configurar mínimo de 8 caracteres."
                )
            )



    def audit_guest_account(self):

        self.log(
            "Evaluando cuenta Invitado..."
        )


        resultado = self._run_command(
            "net user Invitado"
        )


        resultado_upper = resultado.upper()


        activa = (
            (
                "CUENTA ACTIVA" in resultado_upper
                and
                "SÍ" in resultado_upper
            )
            or
            (
                "ACCOUNT ACTIVE" in resultado_upper
                and
                "YES" in resultado_upper
            )
        )


        if activa:

            self.add_finding(
                title="Guest Account",
                status="FAIL",
                severity="MEDIUM",
                category="Identity Management",
                details=(
                    "La cuenta Invitado está habilitada."
                ),
                recommendation=(
                    "Deshabilitar cuentas de invitado innecesarias."
                )
            )


        else:

            self.add_finding(
                title="Guest Account",
                status="PASS",
                severity="INFO",
                category="Identity Management",
                details=(
                    "La cuenta Invitado está deshabilitada."
                ),
                recommendation=(
                    "Mantener cuentas innecesarias desactivadas."
                )
            )


    def audit_remote_desktop(self):

        self.log(
            "Evaluando Escritorio Remoto..."
        )


        comando = (
            'powershell -Command '
            '"Get-ItemProperty '
            "-Path 'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server' "
            "-Name 'fDenyTSConnections'"
            '"'
        )


        resultado = self._run_command(comando).upper()

        if ": 0" in resultado or ":0" in resultado:
            self.add_finding(
                title="Remote Desktop (RDP)",
                status="WARNING",
                severity="MEDIUM",
                category="Remote Access",
                details="Escritorio Remoto está habilitado.",
                recommendation=(
                    "Deshabilitar RDP si no es requerido."
                )
            )
        else:
            self.add_finding(
                title="Remote Desktop (RDP)",
                status="PASS",
                severity="INFO",
                category="Remote Access",
                details="Escritorio Remoto está deshabilitado.",
                recommendation=(
                    "Mantener acceso remoto restringido."
                )
            )

    def audit_uac(self):

        self.log(
            "Evaluando configuración UAC..."
        )


        comando = (
            'powershell -Command '
            '"Get-ItemProperty '
            "-Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System' "
            "-Name 'ConsentPromptBehaviorAdmin'"
            '"'
        )


        resultado = self._run_command(comando).upper()


        if ": 0" in resultado or ":0" in resultado:

            self.add_finding(
                title="User Account Control (UAC)",
                status="FAIL",
                severity="HIGH",
                category="System Hardening",
                details=(
                    "UAC configurado en nivel inseguro."
                ),
                recommendation=(
                    "Habilitar solicitudes de elevación."
                )
            )


        else:

            self.add_finding(
                title="User Account Control (UAC)",
                status="PASS",
                severity="INFO",
                category="System Hardening",
                details=(
                    "Configuración UAC segura."
                ),
                recommendation=(
                    "Mantener configuración recomendada."
                )
            )



    def audit_bitlocker(self):

        self.log(
            "Evaluando BitLocker..."
        )


        resultado = self._run_command(
            "manage-bde -status C:",
            timeout=5
        ).upper()



        if (
            "TIMEOUT" in resultado
            or
            "ERROR" in resultado
        ):

            self.add_finding(
                title="BitLocker",
                status="WARNING",
                severity="MEDIUM",
                category="Data Protection",
                details=(
                    "No fue posible consultar el estado de BitLocker."
                ),
                recommendation=(
                    "Ejecutar la auditoría con privilegios de administrador."
                )
            )


        elif (
            "FULLY ENCRYPTED" in resultado
            or
            "COMPLETAMENTE CIFRADO" in resultado
        ):

            self.add_finding(
                title="BitLocker",
                status="PASS",
                severity="INFO",
                category="Data Protection",
                details=(
                    "La unidad C está completamente cifrada."
                ),
                recommendation=(
                    "Mantener protección BitLocker activa."
                )
            )


        elif (
            "FULLY DECRYPTED" in resultado
            or
            "COMPLETAMENTE DESCIFRADO" in resultado
        ):

            self.add_finding(
                title="BitLocker",
                status="FAIL",
                severity="HIGH",
                category="Data Protection",
                details=(
                    "La unidad C no está cifrada."
                ),
                recommendation=(
                    "Activar BitLocker en unidades críticas."
                )
            )


        else:

            self.add_finding(
                title="BitLocker",
                status="WARNING",
                severity="MEDIUM",
                category="Data Protection",
                details=(
                    "No se pudo determinar completamente el estado de cifrado."
                ),
                recommendation=(
                    "Ejecutar Atom como administrador para obtener información completa de cifrado.."
                )
            )



    def audit_powershell_policy(self):

        self.log(
            "Evaluando directiva de ejecución de PowerShell..."
        )


        comando = (
            "powershell -Command "
            "\"Get-ExecutionPolicy\""
        )


        resultado = (
            self._run_command(comando)
            .strip()
            .upper()
        )


        if (
            "BYPASS" in resultado
            or
            "UNRESTRICTED" in resultado
        ):

            self.add_finding(
                title="PowerShell Execution Policy",
                status="FAIL",
                severity="HIGH",
                category="System Hardening",
                details=(
                    f"Directiva insegura detectada: {resultado}"
                ),
                recommendation=(
                    "Configurar una política de ejecución más restrictiva."
                )
            )


        else:

            self.add_finding(
                title="PowerShell Execution Policy",
                status="PASS",
                severity="INFO",
                category="System Hardening",
                details=(
                    f"Directiva actual: {resultado}"
                ),
                recommendation=(
                    "Mantener políticas seguras de ejecución."
                )
            )



    def audit_windows_update(self):

        self.log(
            "Comprobando estado del servicio Windows Update..."
        )


        comando = (
            "powershell -Command "
            "\"(Get-Service wuauserv).Status\""
        )


        resultado = (
            self._run_command(comando)
            .strip()
            .upper()
        )


        if "RUNNING" in resultado:

            self.add_finding(
                title="Windows Update Service",
                status="PASS",
                severity="INFO",
                category="System Hardening",
                details=(
                    "El servicio Windows Update está ejecutándose."
                ),
                recommendation=(
                    "Mantener actualizaciones automáticas habilitadas."
                )
            )


        elif "STOPPED" in resultado:

            self.add_finding(
                title="Windows Update Service",
                status="WARNING",
                severity="MEDIUM",
                category="System Hardening",
                details=(
                    "El servicio Windows Update está detenido."
                ),
                recommendation=(
                    "Verificar si la detención es intencional y habilitar "
                    "actualizaciones automáticas."
                )
            )


        else:

            self.add_finding(
                title="Windows Update Service",
                status="FAIL",
                severity="HIGH",
                category="System Hardening",
                details=(
                    "No fue posible determinar el estado del servicio Windows Update."
                ),
                recommendation=(
                    "Verificar que el servicio wuauserv exista y sea accesible."
                )
            )



    def audit_admin_account(self):

        self.log(
            "Evaluando cuenta Administrador nativa..."
        )


        resultado = self._run_command(
            "net user Administrador"
        )


        resultado_upper = resultado.upper()


        activa = False


        if "CUENTA ACTIVA" in resultado_upper:

            activa = (
                "SÍ" in resultado_upper
                or
                "YES" in resultado_upper
            )


        else:

            resultado_en = self._run_command(
                "net user Administrator"
            ).upper()


            activa = (
                "ACCOUNT ACTIVE" in resultado_en
                and
                "YES" in resultado_en
            )



        if activa:

            self.add_finding(
                title="Default Administrator Account",
                status="FAIL",
                severity="HIGH",
                category="Identity Management",
                details=(
                    "La cuenta Administrador nativa está habilitada."
                ),
                recommendation=(
                    "Deshabilitar la cuenta si no es necesaria."
                )
            )


        else:

            self.add_finding(
                title="Default Administrator Account",
                status="PASS",
                severity="INFO",
                category="Identity Management",
                details=(
                    "La cuenta Administrador nativa está deshabilitada o no encontrada."
                ),
                recommendation=(
                    "Mantener cuentas privilegiadas controladas."
                )
            )



    def audit_smbv1(self):

        self.log(
            "Comprobando configuración SMBv1..."
        )


        comando = (
            "powershell -Command "
            "\"(Get-SmbServerConfiguration).EnableSMB1Protocol\""
        )


        resultado = (
            self._run_command(comando)
            .strip()
            .upper()
        )


        if "TRUE" in resultado:

            self.add_finding(
                title="SMBv1 Protocol",
                status="FAIL",
                severity="CRITICAL",
                category="Network Security",
                details=(
                    "SMBv1 está habilitado."
                ),
                recommendation=(
                    "Deshabilitar SMBv1 por riesgos conocidos."
                )
            )


        elif "FALSE" in resultado:

            self.add_finding(
                title="SMBv1 Protocol",
                status="PASS",
                severity="INFO",
                category="Network Security",
                details=(
                    "SMBv1 está deshabilitado."
                ),
                recommendation=(
                    "Mantener protocolos obsoletos deshabilitados."
                )
            )


        else:

            self.add_finding(
                title="SMBv1 Protocol",
                status="PASS",
                severity="INFO",
                category="Network Security",
                details=(
                    "SMBv1 no está activo o no pudo detectarse."
                ),
                recommendation=(
                    "Mantener configuración segura."
                )
            )

    
    
    
    
    
    def audit_llmnr(self):
        """Verifica si LLMNR está deshabilitado."""

        self.log(
            "Comprobando mitigación LLMNR..."
        )

        comando = (
            'powershell -Command '
            '"Get-ItemProperty '
            "-Path 'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient' "
            "-Name 'EnableMulticast' "
            '-ErrorAction SilentlyContinue"'
        )

        resultado = self._run_command(comando).upper()


        if "ENABLEMULTICAST" in resultado:

            if ": 0" in resultado or ":0" in resultado:

                self.add_finding(
                    title="LLMNR Protocol",
                    status="PASS",
                    severity="INFO",
                    category="Network Security",
                    details="LLMNR está deshabilitado.",
                    recommendation=(
                        "Mantener mitigaciones contra spoofing activas."
                    )
                )

            else:

                self.add_finding(
                    title="LLMNR Protocol",
                    status="FAIL",
                    severity="HIGH",
                    category="Network Security",
                    details="LLMNR está habilitado.",
                    recommendation=(
                        "Deshabilitar LLMNR para reducir ataques Responder."
                    )
                )

        else:

            self.add_finding(
                title="LLMNR Protocol",
                status="WARNING",
                severity="MEDIUM",
                category="Network Security",
                details=(
                    "No existe una política explícita para LLMNR."
                ),
                recommendation=(
                    "Crear política para deshabilitar LLMNR."
                )
            )



    def audit_anonymous_lookup(self):
        """Verifica restricciones contra enumeración anónima."""

        self.log(
            "Evaluando Null Sessions..."
        )


        comando = (
            'powershell -Command '
            '"Get-ItemProperty '
            "-Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa' "
            "-Name 'RestrictNullSessAccess' "
            '-ErrorAction SilentlyContinue"'
        )


        resultado = self._run_command(comando).upper()


        if "RESTRICTNULLSESSACCESS" in resultado:

            if ": 1" in resultado or ":1" in resultado:

                self.add_finding(
                    title="Anonymous Access Restrictions",
                    status="PASS",
                    severity="INFO",
                    category="Network Security",
                    details=(
                        "Restricciones contra acceso anónimo activadas."
                    ),
                    recommendation=(
                        "Mantener restricciones LSA."
                    )
                )

            else:

                self.add_finding(
                    title="Anonymous Access Restrictions",
                    status="FAIL",
                    severity="HIGH",
                    category="Network Security",
                    details=(
                        "Las sesiones nulas pueden estar permitidas."
                    ),
                    recommendation=(
                        "Restringir acceso anónimo."
                    )
                )

        else:

            self.add_finding(
                title="Anonymous Access Restrictions",
                status="WARNING",
                severity="MEDIUM",
                category="Network Security",
                details=(
                    "No se encontró configuración explícita."
                ),
                recommendation=(
                    "Configurar RestrictNullSessAccess."
                )
            )



    def audit_risky_services(self):
        """Detecta servicios con superficie de ataque elevada."""

        self.log(
            "Auditando servicios riesgosos..."
        )


        risky_services = {
            "Spooler": "Print Spooler",
            "RemoteRegistry": "Remote Registry",
            "SSDPSRV": "SSDP Discovery"
        }


        for service, description in risky_services.items():

            comando = (
                f'powershell -Command '
                f'"(Get-Service {service} '
                '-ErrorAction SilentlyContinue).Status"'
            )


            resultado = (
                self._run_command(comando)
                .strip()
                .upper()
            )


            if "RUNNING" in resultado:

                self.add_finding(
                    title=f"Risky Service: {description}",
                    status="FAIL",
                    severity="MEDIUM",
                    category="Service Management",
                    details=(
                        f"El servicio {description} está ejecutándose."
                    ),
                    recommendation=(
                        "Deshabilitar servicios innecesarios."
                    )
                )


            else:

                self.add_finding(
                    title=f"Risky Service: {description}",
                    status="PASS",
                    severity="INFO",
                    category="Service Management",
                    details=(
                        f"El servicio {description} no está activo."
                    ),
                    recommendation=(
                        "Mantener servicios mínimos."
                    )
                )



    def audit_doh_settings(self):
        """Verifica DNS over HTTPS."""

        self.log(
            "Verificando DNS over HTTPS..."
        )


        comando = (
            'powershell -Command '
            '"Get-ItemProperty '
            "-Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters' "
            "-Name 'EnableAutoDoh' "
            '-ErrorAction SilentlyContinue"'
        )


        resultado = self._run_command(comando).upper()


        if (
            "ENABLEAUTODOH" in resultado
            and
            ": 2" in resultado
        ):

            self.add_finding(
                title="DNS over HTTPS",
                status="PASS",
                severity="INFO",
                category="Network Security",
                details=(
                    "DNS over HTTPS está habilitado."
                ),
                recommendation=(
                    "Mantener DNS seguro cuando sea compatible."
                )
            )

        else:

            self.add_finding(
                title="DNS over HTTPS",
                status="WARNING",
                severity="LOW",
                category="Network Security",
                details=(
                    "DNS over HTTPS no está habilitado o configurado."
                ),
                recommendation=(
                    "Evaluar habilitar DoH según políticas corporativas."
                )
            )



    def ejecutar(self):
        """
        Ejecuta todos los módulos de auditoría de Windows.
        """

        self.log(
            "Iniciando auditoría completa de Windows..."
        )


        checks = [

            self.audit_firewall,

            self.audit_windows_defender,

            self.audit_password_policy,

            self.audit_guest_account,

            self.audit_remote_desktop,

            self.audit_uac,

            self.audit_bitlocker,

            self.audit_powershell_policy,

            self.audit_windows_update,

            self.audit_admin_account,

            self.audit_smbv1,

            self.audit_llmnr,

            self.audit_anonymous_lookup,

            self.audit_risky_services,

            self.audit_doh_settings

        ]


        return self.run_checks(checks)