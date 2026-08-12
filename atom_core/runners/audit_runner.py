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

    def run(self, option):

        # Verifica que la opcion recibida
        # corresponda a una auditoria.

        if option != "1":
            print("[!] Auditoría inválida")

            return

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

            return

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
        # directamente en la consola.

        ConsoleReporter.display(findings, score, rating)

        # ==========================
        # REPORTES EN ARCHIVOS
        # ==========================

        # Diccionario utilizado para almacenar
        # las rutas de los reportes generados.

        reports = {}

        # Genera el reporte en formato TXT.

        reports["text"] = TextReporter.save(summary, findings)

        # Genera el reporte en formato JSON.

        reports["json"] = JsonReporter.save(summary, findings)

        # Genera el reporte en formato HTML.

        reports["html"] = HTMLReporter.save(summary, findings)

        # ==========================
        # INFORMACION DE REPORTES
        # ==========================

        # Informa al usuario que los reportes
        # fueron generados correctamente.

        print("\n[+] Reportes generados:")

        # Muestra la ubicacion del reporte TXT.

        print(f"    TXT : {reports['text']}")

        # Muestra la ubicacion del reporte JSON.

        print(f"    JSON: {reports['json']}")

        # Muestra la ubicacion del reporte HTML.

        print(f"    HTML: {reports['html']}")

        # Devuelve las rutas de los reportes
        # para que puedan ser utilizadas por
        # otras partes de ATOM.

        return reports
