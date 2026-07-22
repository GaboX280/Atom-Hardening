from atom_core.base_auditor import BaseAuditor


class LinuxFileAuditor(BaseAuditor):


    def ejecutar(self):

        self.log(
            "Iniciando auditoría de archivos críticos Linux..."
        )


        checks = [

            self.audit_passwd,

            self.audit_shadow,

            self.audit_sudoers

        ]


        return self.run_checks(checks)




    def audit_passwd(self):

        self._analizar_permisos_linux(
            "/etc/passwd"
        )



    def audit_shadow(self):

        self._analizar_permisos_linux(
            "/etc/shadow"
        )



    def audit_sudoers(self):

        self._analizar_permisos_linux(
            "/etc/sudoers"
        )




    def _analizar_permisos_linux(
        self,
        archivo
    ):


        self.log(
            f"Analizando permisos: {archivo}"
        )


        permisos = self._run_command(
            f"stat -c '%a' {archivo}"
        ).strip()



        if (
            "ERROR" in permisos.upper()
            or
            not permisos
        ):

            self.add_finding(
                title=f"File Permissions: {archivo}",
                status="ERROR",
                severity="HIGH",
                details=(
                    f"No se pudo obtener permisos: {permisos}"
                ),
                recommendation=(
                    "Ejecutar con privilegios suficientes."
                )
            )

            return




        others_permission = permisos[-1]



        if others_permission in [
            "2",
            "3",
            "6",
            "7"
        ]:


            self.add_finding(
                title=f"File Permissions: {archivo}",
                status="FAIL",
                severity="HIGH",
                details=(
                    f"Permisos peligrosos detectados: {permisos}"
                ),
                recommendation=(
                    "Restringir permisos para usuarios no privilegiados."
                )
            )


        else:


            self.add_finding(
                title=f"File Permissions: {archivo}",
                status="PASS",
                severity="INFO",
                details=(
                    f"Permisos seguros detectados: {permisos}"
                ),
                recommendation=(
                    "Mantener permisos mínimos necesarios."
                )
            )