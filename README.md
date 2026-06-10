# Atom Hardening Tool

**Atom** es una herramienta de auditoría de seguridad automatizada diseñada para identificar vulnerabilidades de configuración en sistemas operativos (Windows/Linux). Proporciona a administradores de sistemas y profesionales de ciberseguridad una visibilidad clara sobre la superficie de ataque mediante un escaneo exhaustivo de configuraciones críticas.

---

## Características

* **Detección Automática:** Identificación del sistema operativo (Windows/Linux) para la ejecución del módulo de auditoría correspondiente.
* **Auditoría de 17 Puntos:** Evaluación integral de la postura de seguridad, incluyendo:
    * **Seguridad Perimetral:** Auditoría de Firewall y Windows Defender.
    * **Identidad y Accesos:** Verificación de políticas de contraseñas, cuentas nativas y restricciones LSA.
    * **Configuración del Sistema:** Auditoría de BitLocker, UAC, directivas de ejecución de scripts y servicios.
    * **Seguridad de Red:** Identificación de protocolos obsoletos (SMBv1), mitigación de LLMNR y configuración de DNS Seguro (DoH).
* **Reporte Consolidado:** Generación de diagnósticos con estados claros de cumplimiento (OK, AVISO, PELIGRO).

---

## Stack Tecnológico

* **Lenguaje:** Python 3.x
* **Integración:** PowerShell / Bash
* **Gestión de Versiones:** Git

---

## Instalación

1. Clonar el repositorio:
   ```bash
   git clone [https://github.com/GaboX280/Atom-Hardening.git](https://github.com/GaboX280/Atom-Hardening.git)

2. Acceder al directorio:
   cd Atom-Hardening

3. Ejecutar la herramienta (se requiere privilegios de Administrador/Root):
   python main.py

Roadmap
[ ] Implementar módulo de auditoría de permisos de archivos críticos.

[ ] Integrar análisis de configuración de servicios SSH.

[ ] Desarrollo de exportador de reportes en formatos PDF/TXT.