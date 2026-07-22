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
            "manage-bde -status C:"
        ).upper()


        if (
            "FULLY ENCRYPTED" in resultado
            or
            "COMPLETAMENTE CIFRADO" in resultado
        ):

            self.add_finding(
                title="BitLocker",
                status="PASS",
                severity="INFO",
                details="La unidad C está cifrada.",
                recommendation="Mantener protección BitLocker activa."
            )

        else:

            self.add_finding(
                title="BitLocker",
                status="FAIL",
                severity="HIGH",
                details="No se detectó cifrado completo.",
                recommendation="Activar BitLocker en unidades críticas."
            )

    
    
    
    def audit_powershell_policy(self):
        """Audita la directiva de ejecución global de PowerShell."""
        print(f"{self.CYAN}[*]{self.RESET} Evaluando directiva de ejecución de PowerShell...")
        
        comando = "powershell -Command \"Get-ExecutionPolicy\""
        resultado = self._run_command(comando).strip().upper()
        
        if "BYPASS" in resultado or "UNRESTRICTED" in resultado:
            self.report.append(f"{self.RED}[-]{self.RESET} Ejecución de PowerShell: {resultado} (Inseguro) {self.RED}[PELIGRO]{self.RESET}")
        else:
            self.report.append(f"{self.GREEN}[+]{self.RESET} Ejecución de PowerShell: {resultado} {self.GREEN}[OK]{self.RESET}")

    def audit_windows_update(self):
        """Verifica si el servicio de Windows Update está disponible en el sistema."""
        print(f"{self.CYAN}[*]{self.RESET} Comprobando estado del servicio de Windows Update...")
        
        comando = "powershell -Command \"(Get-Service wuauserv).Status\""
        resultado = self._run_command(comando).strip().upper()
        
        if "RUNNING" in resultado or "STOPPED" in resultado:
            self.report.append(f"{self.GREEN}[+]{self.RESET} Servicio Windows Update: INSTALADO / DISPONIBLE {self.GREEN}[OK]{self.RESET}")
        else:
            self.report.append(f"{self.RED}[-]{self.RESET} Servicio Windows Update: COMPROMETIDO O INACCESIBLE {self.RED}[PELIGRO]{self.RESET}")
    
    
    def audit_admin_account(self):
        """Verifica si la cuenta nativa de Administrador está deshabilitada."""
        print(f"{self.CYAN}[*]{self.RESET} Evaluando estado de la cuenta nativa de Administrador...")
        
        comando = "net user Administrador"
        resultado = self._run_command(comando)
        resultado_upper = resultado.upper()
        
        if "CUENTA ACTIVA" in resultado_upper:
            if "SÍ" in resultado_upper or "YES" in resultado_upper:
                self.report.append(f"{self.RED}[-]{self.RESET} Cuenta Administrador Nativa: ACTIVA (Se recomienda deshabilitar) {self.RED}[PELIGRO]{self.RESET}")
            else:
                self.report.append(f"{self.GREEN}[+]{self.RESET} Cuenta Administrador Nativa: DESHABILITADA {self.GREEN}[OK]{self.RESET}")
        else:
            # Validación en caso de sistemas en inglés (Administrator)
            comando_en = "net user Administrator"
            resultado_en = self._run_command(comando_en).upper()
            if "ACCOUNT ACTIVE" in resultado_en and "YES" in resultado_en:
                self.report.append(f"{self.RED}[-]{self.RESET} Cuenta Administrador Nativa: ACTIVA (Se recomienda deshabilitar) {self.RED}[PELIGRO]{self.RESET}")
            else:
                self.report.append(f"{self.GREEN}[+]{self.RESET} Cuenta Administrador Nativa: DESHABILITADA o No Encontrada {self.GREEN}[OK]{self.RESET}")

    def audit_smbv1(self):
        """Verifica si el protocolo inseguro SMBv1 está deshabilitado en el sistema."""
        print(f"{self.CYAN}[*]{self.RESET} Comprobando configuración del protocolo obsoleto SMBv1...")
        
        comando = "powershell -Command \"(Get-SmbServerConfiguration).EnableSMB1Protocol\""
        resultado = self._run_command(comando).strip().upper()
        
        if "TRUE" in resultado:
            self.report.append(f"{self.RED}[-]{self.RESET} Protocolo SMBv1: HABILITADO (Vulnerable a EternalBlue) {self.RED}[PELIGRO]{self.RESET}")
        elif "FALSE" in resultado:
            self.report.append(f"{self.GREEN}[+]{self.RESET} Protocolo SMBv1: DESHABILITADO {self.GREEN}[OK]{self.RESET}")
        else:
            self.report.append(f"{self.GREEN}[+]{self.RESET} Protocolo SMBv1: No activo o configuración estándar {self.GREEN}[OK]{self.RESET}")
    
    
    
    
    
    def audit_llmnr(self):
        """Verifica si el protocolo inseguro LLMNR está deshabilitado en el Registro."""
        print(f"{self.CYAN}[*]{self.RESET} Comprobando mitigación de spoofing (LLMNR)...")
        
        # Consultamos la directiva de DNS en el registro
        comando = 'powershell -Command "Get-ItemProperty -Path \'HKLM:\\Software\\Policies\\Microsoft\\Windows NT\\DNSClient\' -Name \'EnableMulticast\' -ErrorAction SilentlyContinue"'
        resultado = self._run_command(comando).upper()
        
        if "ENABLEMULTICAST" in resultado:
            # Si EnableMulticast es 0, LLMNR está apagado (Configuración segura)
            if " : 0" in resultado or ":0" in resultado:
                self.report.append(f"{self.GREEN}[+]{self.RESET} Mitigación LLMNR: PROTOCOLO DESACTIVADO {self.GREEN}[OK]{self.RESET}")
            else:
                self.report.append(f"{self.RED}[-]{self.RESET} Mitigación LLMNR: PROTOCOLO ACTIVO (Vulnerable a ataques Responder) {self.RED}[PELIGRO]{self.RESET}")
        else:
            # Por defecto en Windows viene activo si la llave no existe
            self.report.append(f"{self.RED}[-]{self.RESET} Mitigación LLMNR: PROTOCOLO ACTIVO (Configuración por defecto) {self.RED}[PELIGRO]{self.RESET}")

    def audit_anonymous_lookup(self):
        """Verifica que se restrinja el acceso anónimo a cuentas y recursos (Null Sessions)."""
        print(f"{self.CYAN}[*]{self.RESET} Evaluando restricciones de enumeración anónima (Null Sessions)...")
        
        comando = 'powershell -Command "Get-ItemProperty -Path \'HKLM:\\SYSTEM\\CurrentControlSet\\Control\\Lsa\' -Name \'RestrictNullSessAccess\' -ErrorAction SilentlyContinue"'
        resultado = self._run_command(comando).upper()
        
        if "RESTRICTNULLSESSACCESS" in resultado:
            if " : 1" in resultado or ":1" in resultado:
                self.report.append(f"{self.GREEN}[+]{self.RESET} Acceso Anónimo (LSA): RESTRICCIONES ACTIVADAS {self.GREEN}[OK]{self.RESET}")
            else:
                self.report.append(f"{self.RED}[-]{self.RESET} Acceso Anónimo (LSA): PERMISIVO (Se recomienda restringir) {self.RED}[PELIGRO]{self.RESET}")
        else:
            self.report.append(f"{self.RED}[-]{self.RESET} Acceso Anónimo (LSA): Sin directiva explícita de restricción {self.RED}[PELIGRO]{self.RESET}")
    
    
    
    def audit_risky_services(self):
        """Detecta si servicios vulnerables comunes están en ejecución."""
        print(f"{self.CYAN}[*]{self.RESET} Auditando servicios con superficie de ataque...")
        risky_services = ["Spooler", "RemoteRegistry", "SSDPSRV"]
        
        for service in risky_services:
            comando = f'powershell -Command "(Get-Service {service} -ErrorAction SilentlyContinue).Status"'
            resultado = self._run_command(comando).strip().upper()
            
            if "RUNNING" in resultado:
                self.report.append(f"{self.RED}[-]{self.RESET} Servicio riesgoso detectado ({service}): EN EJECUCIÓN {self.RED}[PELIGRO]{self.RESET}")
            else:
                self.report.append(f"{self.GREEN}[+]{self.RESET} Servicio {service}: NO EN EJECUCIÓN {self.GREEN}[OK]{self.RESET}")

    def audit_doh_settings(self):
        """Verifica si el sistema tiene activado DNS over HTTPS (DoH)."""
        print(f"{self.CYAN}[*]{self.RESET} Verificando configuración de DNS Seguro (DoH)...")
        
        comando = 'powershell -Command "Get-ItemProperty -Path \'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Dnscache\\Parameters\' -Name \'EnableAutoDoh\' -ErrorAction SilentlyContinue"'
        resultado = self._run_command(comando)
        
        if "ENABLEAUTODOH" in resultado.upper() and ": 2" in resultado:
            self.report.append(f"{self.GREEN}[+]{self.RESET} DNS over HTTPS (DoH): ACTIVADO {self.GREEN}[OK]{self.RESET}")
        else:
            self.report.append(f"{self.YELLOW}[-]{self.RESET} DNS over HTTPS (DoH): DESACTIVADO o No configurado {self.YELLOW}[AVISO]{self.RESET}")
    
    
    
            
            

    def ejecutar(self):

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

        return self.report