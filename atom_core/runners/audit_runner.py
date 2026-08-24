"""Modulo para la ejecución de auditorías en ATOM.

Este módulo se encarga de coordinar la ejecución de auditorías,
la recopilación de resultados, el análisis de puntuaciones de seguridad
y la generación de reportes en diferentes formatos.

La clase AuditRunner actúa como el punto central para ejecutar auditorías
y manejar los resultados obtenidos.

La lógica de auditoría específica se delega a los auditores correspondientes
según el sistema operativo, mientras que el análisis y la generación de
reportes se manejan mediante módulos independientes.
"""

# Importacion de librerias necesarias
from atom_core.auditor_factory import AuditorFactory
from atom_core.core.security_score import SecurityScore
from atom_core.core.security_summary import SecuritySummary
from atom_core.reporters.console_reporter import ConsoleReporter
from atom_core.reporters.html_reporter import HTMLReporter
from atom_core.reporters.json_reporter import JsonReporter
from atom_core.reporters.text_reporter import TextReporter

# =====================================#
# Clase AuditRunner
# =====================================#


class AuditRunner:
    # ========================
    # METODO PARA EJECUTAR AUDITORIA
    # ========================

    def run(
        self,
        option: str = "1",
        fmt: str = "all",
        output_dir: str | None = None,
        quiet: bool = False,
    ) -> dict[str, str] | None:

        # Verifica que la opcion recibida
        # corresponda a una auditoria.

        if option != "1":
            print("[!] Auditoría inválida")

            return None

        # ==========================
        # CREACION DEL AUDITOR
        # ==========================

        # Crea el auditor correspondiente
        # mediante AuditorFactory.

        auditor = AuditorFactory.get_auditor()

        # ==========================
        # EJECUCION DE AUDITORIA
        # ==========================

        # Ejecuta todos los checks correspondientes
        # al sistema operativo actual.

        findings = auditor.ejecutar()

        # Verifica que el auditor haya generado
        # resultados antes de continuar con el análisis.

        if not findings:
            print("[!] El auditor no devolvió resultados.")

            return None

        # ==========================
        # ANALISIS DE RESULTADOS
        # ==========================

        # Calcula la puntuacion de seguridad
        # utilizando los resultados obtenidos.

        score = SecurityScore.calculate(findings)

        # Determina la clasificacion correspondiente
        # a la puntuacion obtenida.

        rating = SecurityScore.rating(score)

        # Genera un resumen de los resultados
        # encontrados durante la auditoria.

        summary = SecuritySummary.summarize(findings)

        # Agrega la puntuacion de seguridad
        # al resumen de la auditoria.

        summary["score"] = score

        # Agrega la clasificacion de seguridad
        # al resumen de la auditoria.

        summary["rating"] = rating

        # Guarda el nombre de la clase del auditor
        # utilizado durante la auditoria.

        summary["module"] = auditor.__class__.__name__

        # ==========================
        # REPORTES EN CONSOLA
        # ==========================

        # Muestra los resultados de la auditoria
        # directamente en la consola si no está en modo silencioso.

        if not quiet:
            ConsoleReporter.display(findings, score, rating)

        # ==========================
        # REPORTES EN ARCHIVOS
        # ==========================

        # Diccionario utilizado para almacenar
        # las rutas de los reportes generados.

        reports: dict[str, str] = {}
        target_fmt = fmt.lower()

        if target_fmt in ("all", "text", "txt"):
            reports["text"] = TextReporter.save(summary, findings, output_dir=output_dir)

        if target_fmt in ("all", "json"):
            reports["json"] = JsonReporter.save(summary, findings, output_dir=output_dir)

        if target_fmt in ("all", "html"):
            reports["html"] = HTMLReporter.save(summary, findings, output_dir=output_dir)

        # ==========================
        # INFORMACION DE REPORTES
        # ==========================

        if not quiet and reports:
            print("\n[+] Reportes generados:")
            for r_type, r_path in reports.items():
                print(f"    {r_type.upper():<4}: {r_path}")

        return reports
