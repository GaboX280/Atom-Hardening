from atom_core.base_auditor import BaseAuditor

class WindowsAuditor(BaseAuditor):
    
    def audit_firewall(self):
        """Verifica el estado del Firewall de Windows."""

        print(
            f"{self.CYAN}[*]{self.RESET} Evaluando el estado del Firewall de Windows..."
        )

        comando = "netsh advfirewall show allprofiles state"
        resultado = self._run_command(comando)

        if "ON" in resultado.upper() or "ACTIVAR" in resultado.upper():

            self.add_finding(
                title="Windows Firewall",
                status="PASS",
                severity="INFO",
                details="El Firewall de Windows está activo.",
                recommendation="Mantener las reglas del firewall actualizadas."
            )

        else:

            self.add_finding(
                title="Windows Firewall",
                status="FAIL",
                severity="HIGH",
                details="El Firewall de Windows parece estar desactivado.",
                recommendation="Activar Windows Firewall en todos los perfiles."
            )

        
    def audit_windows_defender(self):
        """Verifica protección en tiempo real de Windows Defender."""

        print(
            f"{self.CYAN}[*]{self.RESET} Comprobando protección de Windows Defender..."
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
                details="La protección en tiempo real está activa.",
                recommendation="Mantener las firmas antivirus actualizadas."
            )

        else:

            self.add_finding(
                title="Windows Defender",
                status="FAIL",
                severity="HIGH",
                details="La protección en tiempo real está deshabilitada.",
                recommendation="Activar la protección en tiempo real."
            )

            
    def audit_password_policy(self):
        """Audita la política mínima de contraseñas."""

        print(
            f"{self.CYAN}[*]{self.RESET} Evaluando política de contraseñas..."
        )

        resultado = self._run_command(
            "net accounts"
        )

        longitud_minima = 0

        for linea in resultado.splitlines():

            if (
                "LONGITUD MÍNIMA" in linea.upper()
                or "MINIMUM PASSWORD LENGTH" in linea.upper()
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
                details=f"Longitud mínima configurada: {longitud_minima}",
                recommendation="Mantener políticas robustas de contraseña."
            )

        else:

            self.add_finding(
                title="Password Policy",
                status="FAIL",
                severity="MEDIUM",
                details=f"Longitud mínima encontrada: {longitud_minima}",
                recommendation="Configurar mínimo de 8 caracteres."
            )

            
    def audit_guest_account(self):

        print(
            f"{self.CYAN}[*]{self.RESET} Evaluando cuenta Invitado..."
        )

        resultado = self._run_command(
            "net user Invitado"
        )

        resultado_upper = resultado.upper()

        activa = (
            ("CUENTA ACTIVA" in resultado_upper and "SÍ" in resultado_upper)
            or
            ("ACCOUNT ACTIVE" in resultado_upper and "YES" in resultado_upper)
        )


        if activa:

            self.add_finding(
                title="Guest Account",
                status="FAIL",
                severity="MEDIUM",
                details="La cuenta Invitado está habilitada.",
                recommendation="Deshabilitar cuentas de invitado innecesarias."
            )

        else:

            self.add_finding(
                title="Guest Account",
                status="PASS",
                severity="INFO",
                details="La cuenta Invitado está deshabilitada.",
                recommendation="Mantener cuentas innecesarias desactivadas."
            )
    
                
    def audit_remote_desktop(self):

        print(
            f"{self.CYAN}[*]{self.RESET} Evaluando Escritorio Remoto..."
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
                details="Escritorio Remoto está habilitado.",
                recommendation="Deshabilitar RDP si no es requerido."
            )


        else:

            self.add_finding(
                title="Remote Desktop (RDP)",
                status="PASS",
                severity="INFO",
                details="Escritorio Remoto está deshabilitado.",
                recommendation="Mantener acceso remoto restringido."
            )

            
            
    def audit_uac(self):

        print(
            f"{self.CYAN}[*]{self.RESET} Evaluando configuración UAC..."
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
                details="UAC configurado en nivel inseguro.",
                recommendation="Habilitar solicitudes de elevación."
            )

        else:

            self.add_finding(
                title="User Account Control (UAC)",
                status="PASS",
                severity="INFO",
                details="Configuración UAC segura.",
                recommendation="Mantener configuración recomendada."
            )    
            
            
    def audit_bitlocker(self):

        print(
            f"{self.CYAN}[*]{self.RESET} Evaluando BitLocker..."
        )


        resultado = self._run_command(
            "manage-bde -status C:",
            timeout=5
        ).upper()


        if "COMMAND_TIMEOUT" in resultado or "COMMAND_ERROR" in resultado:

            self.add_finding(
                title="BitLocker",
                status="WARNING",
                severity="MEDIUM",
                details="No fue posible consultar el estado de BitLocker.",
                recommendation="Ejecutar la auditoría con privilegios de administrador."
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
                details="La unidad C está completamente cifrada.",
                recommendation="Mantener protección BitLocker activa."
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
                details="La unidad C no está cifrada.",
                recommendation="Activar BitLocker en unidades críticas."
            )


        else:

            self.add_finding(
                title="BitLocker",
                status="WARNING",
                severity="MEDIUM",
                details="No se pudo determinar completamente el estado de cifrado.",
                recommendation="Revisar manualmente la configuración de BitLocker."
            )

    
    
    
    def audit_powershell_policy(self):
        """Audita la directiva de ejecución global de PowerShell."""

        print(
            f"{self.CYAN}[*]{self.RESET} Evaluando directiva de ejecución de PowerShell..."
        )

        comando = "powershell -Command \"Get-ExecutionPolicy\""
        resultado = self._run_command(comando).strip().upper()

        if "BYPASS" in resultado or "UNRESTRICTED" in resultado:

            self.add_finding(
                title="PowerShell Execution Policy",
                status="FAIL",
                severity="HIGH",
                details=f"Directiva insegura detectada: {resultado}",
                recommendation="Configurar una política de ejecución más restrictiva."
            )

        else:

            self.add_finding(
                title="PowerShell Execution Policy",
                status="PASS",
                severity="INFO",
                details=f"Directiva actual: {resultado}",
                recommendation="Mantener políticas seguras de ejecución."
            )


    def audit_windows_update(self):
        """Verifica si el servicio Windows Update está disponible."""

        print(
            f"{self.CYAN}[*]{self.RESET} Comprobando estado del servicio Windows Update..."
        )

        comando = "powershell -Command \"(Get-Service wuauserv).Status\""
        resultado = self._run_command(comando).strip().upper()

        if "RUNNING" in resultado or "STOPPED" in resultado:

            self.add_finding(
                title="Windows Update Service",
                status="PASS",
                severity="INFO",
                details=f"Servicio Windows Update disponible. Estado: {resultado}",
                recommendation="Mantener actualizaciones automáticas habilitadas."
            )

        else:

            self.add_finding(
                title="Windows Update Service",
                status="FAIL",
                severity="HIGH",
                details="No fue posible validar el servicio Windows Update.",
                recommendation="Verificar disponibilidad y estado del servicio."
            )

    
    
    def audit_admin_account(self):
        """Verifica si la cuenta Administrador nativa está deshabilitada."""

        print(
            f"{self.CYAN}[*]{self.RESET} Evaluando cuenta Administrador nativa..."
        )

        comando = "net user Administrador"
        resultado = self._run_command(comando)

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
                details="La cuenta Administrador nativa está habilitada.",
                recommendation="Deshabilitar la cuenta si no es necesaria."
            )

        else:

            self.add_finding(
                title="Default Administrator Account",
                status="PASS",
                severity="INFO",
                details="La cuenta Administrador nativa está deshabilitada o no encontrada.",
                recommendation="Mantener cuentas privilegiadas controladas."
            )


    def audit_smbv1(self):
        """Verifica si SMBv1 está deshabilitado."""

        print(
            f"{self.CYAN}[*]{self.RESET} Comprobando configuración SMBv1..."
        )

        comando = (
            "powershell -Command "
            "\"(Get-SmbServerConfiguration).EnableSMB1Protocol\""
        )

        resultado = self._run_command(comando).strip().upper()


        if "TRUE" in resultado:

            self.add_finding(
                title="SMBv1 Protocol",
                status="FAIL",
                severity="CRITICAL",
                details="SMBv1 está habilitado.",
                recommendation="Deshabilitar SMBv1 por riesgos conocidos como EternalBlue."
            )


        elif "FALSE" in resultado:

            self.add_finding(
                title="SMBv1 Protocol",
                status="PASS",
                severity="INFO",
                details="SMBv1 está deshabilitado.",
                recommendation="Mantener protocolos obsoletos deshabilitados."
            )


        else:

            self.add_finding(
                title="SMBv1 Protocol",
                status="PASS",
                severity="INFO",
                details="SMBv1 no está activo o no pudo detectarse.",
                recommendation="Mantener configuración segura."
            )

    
    
    
    
    
    def audit_llmnr(self):
        """Verifica si LLMNR está deshabilitado."""

        print(
            f"{self.CYAN}[*]{self.RESET} Comprobando mitigación LLMNR..."
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
                    details="LLMNR está deshabilitado.",
                    recommendation="Mantener mitigaciones contra spoofing activas."
                )

            else:

                self.add_finding(
                    title="LLMNR Protocol",
                    status="FAIL",
                    severity="HIGH",
                    details="LLMNR está habilitado.",
                    recommendation="Deshabilitar LLMNR para reducir ataques Responder."
                )

        else:

            self.add_finding(
                title="LLMNR Protocol",
                status="FAIL",
                severity="HIGH",
                details="No existe una directiva explícita. Windows puede mantener LLMNR activo.",
                recommendation="Crear política para deshabilitar LLMNR."
            )


    def audit_anonymous_lookup(self):
        """Verifica restricciones contra enumeración anónima."""

        print(
            f"{self.CYAN}[*]{self.RESET} Evaluando Null Sessions..."
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
                    details="Restricciones contra acceso anónimo activadas.",
                    recommendation="Mantener restricciones LSA."
                )

            else:

                self.add_finding(
                    title="Anonymous Access Restrictions",
                    status="FAIL",
                    severity="HIGH",
                    details="Las sesiones nulas pueden estar permitidas.",
                    recommendation="Restringir acceso anónimo."
                )

        else:

            self.add_finding(
                title="Anonymous Access Restrictions",
                status="FAIL",
                severity="HIGH",
                details="No se encontró configuración explícita.",
                recommendation="Configurar RestrictNullSessAccess."
            )
    
    
    
    def audit_risky_services(self):
        """Detecta servicios con superficie de ataque elevada."""

        print(
            f"{self.CYAN}[*]{self.RESET} Auditando servicios riesgosos..."
        )

        risky_services = [
            "Spooler",
            "RemoteRegistry",
            "SSDPSRV"
        ]


        for service in risky_services:

            comando = (
                f'powershell -Command '
                f'"(Get-Service {service} '
                '-ErrorAction SilentlyContinue).Status"'
            )


            resultado = self._run_command(comando).strip().upper()


            if "RUNNING" in resultado:

                self.add_finding(
                    title=f"Risky Service: {service}",
                    status="FAIL",
                    severity="MEDIUM",
                    details=f"El servicio {service} está en ejecución.",
                    recommendation="Deshabilitar servicios innecesarios."
                )

            else:

                self.add_finding(
                    title=f"Risky Service: {service}",
                    status="PASS",
                    severity="INFO",
                    details=f"El servicio {service} no está activo.",
                    recommendation="Mantener servicios mínimos."
                )
                
                
    def audit_doh_settings(self):
        """Verifica DNS over HTTPS."""

        print(
            f"{self.CYAN}[*]{self.RESET} Verificando DNS over HTTPS..."
        )


        comando = (
            'powershell -Command '
            '"Get-ItemProperty '
            "-Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters' "
            "-Name 'EnableAutoDoh' "
            '-ErrorAction SilentlyContinue"'
        )


        resultado = self._run_command(comando)


        if (
            "ENABLEAUTODOH" in resultado.upper()
            and
            ": 2" in resultado
        ):

            self.add_finding(
                title="DNS over HTTPS",
                status="PASS",
                severity="INFO",
                details="DNS over HTTPS está habilitado.",
                recommendation="Mantener DNS seguro cuando sea compatible."
            )

        else:

            self.add_finding(
                title="DNS over HTTPS",
                status="WARNING",
                severity="LOW",
                details="DNS over HTTPS no está habilitado o configurado.",
                recommendation="Evaluar habilitar DoH según políticas corporativas."
            )

    
    
            
            

    def ejecutar(self):
        """
        Ejecuta todos los módulos de auditoría de Windows.
        """

        print(
            f"{self.CYAN}[*]{self.RESET} Iniciando auditoría completa de Windows..."
        )

        self.audit_firewall()
        self.audit_windows_defender()
        self.audit_password_policy()
        self.audit_guest_account()
        self.audit_remote_desktop()
        self.audit_uac()
        self.audit_bitlocker()
        self.audit_powershell_policy()
        self.audit_windows_update()
        self.audit_admin_account()
        self.audit_smbv1()
        self.audit_llmnr()
        self.audit_anonymous_lookup()
        self.audit_risky_services()
        self.audit_doh_settings()

        return self.report
    
print(
    "ejecutar pertenece a:",
    WindowsAuditor.ejecutar.__qualname__
)