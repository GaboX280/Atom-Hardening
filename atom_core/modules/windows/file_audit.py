from atom_core.base_auditor import BaseAuditor


class WindowsFileAuditor(BaseAuditor):


    def ejecutar(self):

        self.log(
            "Iniciando auditoría de permisos de archivos..."
        )


        checks = [

            self.audit_hosts_file,

            self.audit_sam_file

        ]


        return self.run_checks(checks)



    def audit_hosts_file(self):

        self._analizar_permisos(
            r"C:\Windows\System32\drivers\etc\hosts"
        )



    def audit_sam_file(self):

        self._analizar_proteccion_archivo(
            r"C:\Windows\System32\config\SAM"
        )



    def _analizar_permisos(
        self,
        ruta
    ):

        self.log(
            f"Analizando permisos: {ruta}"
        )


        resultado = self._run_command(
            f'icacls "{ruta}"'
        )


        if resultado.upper().startswith("ERROR:"):

            self.add_finding(
                title=f"File Permissions: {ruta}",
                status="ERROR",
                severity="HIGH",
                details=resultado,
                recommendation=(
                    "Verificar permisos y privilegios administrativos."
                )
            )

            return



        grupos_peligrosos = [

            "Everyone",
            "Todos",
            "Users",
            "Authenticated Users"

        ]


        vulnerable = False


        for grupo in grupos_peligrosos:

            if grupo in resultado:

                if (
                    ":(F)" in resultado
                    or
                    ":(M)" in resultado
                    or
                    ":(W)" in resultado
                ):

                    vulnerable = True
                    break



        if vulnerable:

            self.add_finding(
                title=f"File Permissions: {ruta}",
                status="FAIL",
                severity="HIGH",
                details=(
                    "Usuarios no privilegiados tienen permisos excesivos."
                ),
                recommendation=(
                    "Reducir permisos NTFS siguiendo mínimo privilegio."
                )
            )


        else:

            self.add_finding(
                title=f"File Permissions: {ruta}",
                status="PASS",
                severity="INFO",
                details=(
                    "Permisos NTFS correctamente restringidos."
                ),
                recommendation=(
                    "Mantener permisos mínimos necesarios."
                )
            )



    def _analizar_proteccion_archivo(
        self,
        ruta
    ):

        self.log(
            f"Verificando protección: {ruta}"
        )


        resultado = self._run_command(
            f'icacls "{ruta}"'
        )


        if (
            "Access is denied" in resultado
            or
            "Acceso denegado" in resultado
        ):

            self.add_finding(
                title=f"File Protection: {ruta}",
                status="PASS",
                severity="INFO",
                details=(
                    "El archivo está protegido contra acceso no autorizado."
                ),
                recommendation=(
                    "Mantener restricciones NTFS del sistema."
                )
            )

            return



        if resultado.upper().startswith("ERROR:"):

            self.add_finding(
                title=f"File Protection: {ruta}",
                status="WARNING",
                severity="MEDIUM",
                details=resultado,
                recommendation=(
                    "Revisar permisos del archivo."
                )
            )

            return



        self.add_finding(
            title=f"File Protection: {ruta}",
            status="FAIL",
            severity="CRITICAL",
            details=(
                "El archivo sensible puede ser leído."
            ),
            recommendation=(
                "Restringir acceso al archivo SAM inmediatamente."
            )
        )