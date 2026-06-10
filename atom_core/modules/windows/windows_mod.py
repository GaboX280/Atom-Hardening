from atom_core.base_auditor import BaseAuditor

class WindowsAuditor(BaseAuditor):
    
    def audit_firewall(self):
        """Verifica si el Firewall de Windows está activo evaluando respuestas en ES/EN."""
        print(f"{self.CYAN}[*]{self.RESET} Evaluando el estado del Firewall de Windows...")
        
        comando = "netsh advfirewall show allprofiles state"
        resultado = self._run_command(comando)

        resultado_upper = resultado.upper()
        
        if "ON" in resultado_upper or "ACTIVAR" in resultado_upper:
            self.report.append(f"{self.GREEN}[+]{self.RESET} Firewall de Windows: ACTIVO {self.GREEN}[OK]{self.RESET}")
        else:
            self.report.append(f"{self.RED}[-]{self.RESET} Firewall de Windows: DESACTIVADO {self.RED}[PELIGRO]{self.RESET}")
        
    def audit_windows_defender(self):
        """Verifica si windows defender esta activo o no"""
        print(f"{self.CYAN}[*]{self.RESET} Comprobando protección en tiempo real de Windows Defender...")
        
        comando = "powershell -Command \"(Get-MpComputerStatus).RealTimeProtectionEnabled\""
        resultado = self._run_command(comando)
        
        if "TRUE" in resultado.upper():
            self.report.append(f"{self.GREEN}[+]{self.RESET} Windows Defender: ACTIVO {self.GREEN}[OK]{self.RESET}")
        else:
            self.report.append(f"{self.RED}[-]{self.RESET} Windows Defender: DESACTIVADO {self.RED}[PELIGRO]{self.RESET}")
            
    def audit_password_policy(self):
        """Audita la longitud mínima requerida para las contraseñas locales."""
        print(f"{self.CYAN}[*]{self.RESET} Evaluando la política de contraseñas de Windows...")
        comando = "net accounts"
        resultado = self._run_command(comando)
        
        longitud_minima = 0
        for linea in resultado.splitlines():
            if "LONGITUD MÍNIMA DE CONTRASEÑA" in linea.upper() or "MINIMUM PASSWORD LENGTH" in linea.upper():
                num = [int(s) for s in linea.split() if s.isdigit()]
                if num:
                    longitud_minima = num[0]
                    break

        if longitud_minima >= 8:
            self.report.append(f"{self.GREEN}[+]{self.RESET} Política de contraseñas: LONGITUD MÍNIMA ADECUADA {self.GREEN}[OK]{self.RESET}")
        else:
            self.report.append(f"{self.RED}[-]{self.RESET} Política de contraseñas: LONGITUD MÍNIMA INSUFICIENTE {self.RED}[PELIGRO]{self.RESET}")
            
    def audit_guest_account(self):
        """Verifica si la cuenta nativa de Invitado (Guest) está deshabilitada."""
        print(f"{self.CYAN}[*]{self.RESET} Evaluando estado de la cuenta de Invitado...")
        
        comando = "net user Invitado"
        resultado = self._run_command(comando)
        resultado_upper = resultado.upper()
        
        if "CUENTA ACTIVA" in resultado_upper:
            if "SÍ" in resultado_upper or "YES" in resultado_upper:
                self.report.append(f"{self.RED}[-]{self.RESET} Cuenta de Invitado: ACTIVA (Se recomienda deshabilitar) {self.RED}[PELIGRO]{self.RESET}")
            else:
                self.report.append(f"{self.GREEN}[+]{self.RESET} Cuenta de Invitado: DESHABILITADA {self.GREEN}[OK]{self.RESET}")
        else:
            if "ACCOUNT ACTIVE" in resultado_upper and "YES" in resultado_upper:
                self.report.append(f"{self.RED}[-]{self.RESET} Cuenta de Invitado: ACTIVA (Se recomienda deshabilitar) {self.RED}[PELIGRO]{self.RESET}")
            else:
                self.report.append(f"{self.GREEN}[+]{self.RESET} Cuenta de Invitado: DESHABILITADA o No Encontrada {self.GREEN}[OK]{self.RESET}")     
                
    def audit_remote_desktop(self):
        """Verifica si el servicio de Escritorio Remoto (RDP) está habilitado en el Registro."""
        print(f"{self.CYAN}[*]{self.RESET} Evaluando estado del Escritorio Remoto (RDP)...")
        
        comando = 'powershell -Command "Get-ItemProperty -Path \'HKLM:\\System\\CurrentControlSet\\Control\\Terminal Server\' -Name \'fDenyTSConnections\'"'
        resultado = self._run_command(comando)
        resultado_upper = resultado.upper()
        
        if "FDENYTSCONNECTIONS" in resultado_upper:
            if " : 1" in resultado_upper or ":1" in resultado_upper:
                self.report.append(f"{self.GREEN}[+]{self.RESET} Escritorio Remoto (RDP): DESHABILITADO {self.GREEN}[OK]{self.RESET}")
            elif " : 0" in resultado_upper or ":0" in resultado_upper:
                self.report.append(f"{self.RED}[-]{self.RESET} Escritorio Remoto (RDP): HABILITADO (Se recomienda apagar si no se usa) {self.RED}[PELIGRO]{self.RESET}")
            else:
                self.report.append(f"{self.GREEN}[+]{self.RESET} Escritorio Remoto (RDP): Protegido o No Accesible {self.GREEN}[OK]{self.RESET}")
        else:
            self.report.append(f"{self.GREEN}[+]{self.RESET} Escritorio Remoto (RDP): Configuración estándar {self.GREEN}[OK]{self.RESET}")
            
            
    def audit_uac(self):
        """Verifica el nivel de comportamiento de las solicitudes de elevación de UAC."""
        print(f"{self.CYAN}[*]{self.RESET} Evaluando la configuración del Control de Cuentas de Usuario (UAC)...")
        
        comando = 'powershell -Command "Get-ItemProperty -Path \'HKLM:\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\' -Name \'ConsentPromptBehaviorAdmin\'"'
        resultado = self._run_command(comando)
        resultado_upper = resultado.upper()
        
        if "CONSENTPROMPTBEHAVIORADMIN" in resultado_upper:
            # Si el valor es 0, significa que está configurado en 'No notificar nunca' (Altamente Inseguro)
            if " : 0" in resultado_upper or ":0" in resultado_upper:
                self.report.append(f"{self.RED}[-]{self.RESET} Control de Cuentas (UAC): DESACTIVADO o Nivel Mínimo {self.RED}[PELIGRO]{self.RESET}")
            else:
                self.report.append(f"{self.GREEN}[+]{self.RESET} Control de Cuentas (UAC): CONFIGURACIÓN SEGURA {self.GREEN}[OK]{self.RESET}")
        else:
            self.report.append(f"{self.GREEN}[+]{self.RESET} Control de Cuentas (UAC): Configuración estándar {self.GREEN}[OK]{self.RESET}")    
            
            
    def audit_bitlocker(self):
        """Verifica el estado de cifrado de BitLocker en la unidad principal C:."""
        print(f"{self.CYAN}[*]{self.RESET} Evaluando estado de cifrado de BitLocker en C:...")
        
        comando = "manage-bde -status C:"
        resultado = self._run_command(comando)
        resultado_upper = resultado.upper()
        
        if "COMPLETAMENTE CIFRADO" in resultado_upper or "FULLY ENCRYPTED" in resultado_upper:
            self.report.append(f"{self.GREEN}[+]{self.RESET} Cifrado de Disco (BitLocker): COMPLETAMENTE CIFRADO {self.GREEN}[OK]{self.RESET}")
        elif "COMPLETAMENTE DESCIFRADO" in resultado_upper or "FULLY DECRYPTED" in resultado_upper:
            self.report.append(f"{self.RED}[-]{self.RESET} Cifrado de Disco (BitLocker): DESACTIVADO {self.RED}[PELIGRO]{self.RESET}")
        else:
            # Captura estados intermedios como 'Cifrado en curso' o restricciones de permisos locales
            if "PROTECCIÓN ACTIVADA" in resultado_upper or "PROTECTION ON" in resultado_upper:
                self.report.append(f"{self.GREEN}[+]{self.RESET} Cifrado de Disco (BitLocker): PROTEGIDO {self.GREEN}[OK]{self.RESET}")
            else:
                self.report.append(f"{self.RED}[-]{self.RESET} Cifrado de Disco (BitLocker): ESTADO INDETERMINADO u OFF {self.RED}[PELIGRO]{self.RESET}")
    
    
    
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
        """Ejecuta todos los módulos de auditoría de Windows secuencialmente."""
        print(f"{self.CYAN}[*]{self.RESET} Iniciando auditoría completa de Windows...")
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