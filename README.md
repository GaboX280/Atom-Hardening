<div align="center">
  <h1>⚛ Atom Hardening Tool</h1>
  <p><b>Framework Automatizado de Auditoría y Hardening de Seguridad para Windows y Linux</b></p>

  [![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
  [![License](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
  [![Status](https://img.shields.io/badge/Status-Active-success.svg)]()
  [![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey.svg)]()
  [![CI](https://github.com/GaboX280/Atom-Hardening/actions/workflows/ci.yml/badge.svg)](https://github.com/GaboX280/Atom-Hardening/actions)
  [![Version](https://img.shields.io/badge/version-1.2.0-informational)]()
</div>

---

## 1. Descripción General

**Atom** es un framework modular de auditoría y hardening de seguridad diseñado para identificar debilidades de configuración y vulnerabilidades sistémicas en entornos **Windows** y **Linux**.

Realiza análisis automatizados de configuración en profundidad, genera hallazgos normalizados, aplica un **Security Score** estructurado y exporta telemetría en múltiples formatos (Consola, TXT, JSON, HTML). El framework opera mediante un diseño de módulos centrado en el SO, ejecutando verificaciones de seguridad dinámicamente según el entorno de ejecución.

---

## 2. Arquitectura del Framework

### Estructura de Directorios

```text
ATOM/
├── main.py                    # Punto de entrada principal (CLI + menú interactivo)
├── AtomHardening.spec         # Configuración de compilación PyInstaller
├── config.json                # Configuración del proyecto
├── pytest.ini                 # Configuración de pruebas
├── requirements.txt
├── atom_core/
│   ├── auditor_factory.py     # Detección automática del SO
│   ├── base_auditor.py        # Clase base compartida para todos los auditores
│   ├── core/
│   │   ├── security_score.py  # Cálculo del score de seguridad
│   │   └── security_summary.py
│   ├── interface/
│   │   └── interface.py       # Interfaz de usuario del menú
│   ├── models/
│   │   └── finding.py         # Modelo de dato: Finding
│   ├── reporters/
│   │   ├── console_reporter.py
│   │   ├── text_reporter.py
│   │   ├── json_reporter.py
│   │   └── html_reporter.py
│   ├── runners/
│   │   └── audit_runner.py    # Orquestador de auditorías
│   ├── utils/
│   │   └── distro.py
│   └── audits/
│       ├── windows/           # Auditor y checks de Windows
│       └── linux/             # Auditor y checks de Linux
├── tests/                     # Suite de pruebas unitarias (23 tests)
└── dist/
    └── AtomHardening.exe      # Ejecutable standalone (Windows)
```

### Pipeline de Ejecución

```text
[ START ] → main.py → AuditRunner → AuditorFactory
                                         |
              +--------------------------+
              |
              ▼
     [ OS DETECTADO ] → (WindowsAuditor | LinuxAuditor)
                                |
                                ▼
                        Security Checks
                                |
                                ▼
                        Finding Objects
                                |
              +-----------------+-----------------+
              |                                   |
              ▼                                   ▼
       SecurityScore                      SecuritySummary
              |                                   |
              +-----------------+-----------------+
                                |
                                ▼
               (Consola | TXT | JSON | HTML)
```

---

## 3. Capacidades de Auditoría

El framework detecta el sistema operativo automáticamente y carga el módulo de auditoría correspondiente.

### Verificaciones de Seguridad Soportadas

| Categoría | Windows | Linux |
| :--- | :--- | :--- |
| **Identidad del Sistema** | Cuentas Administrator y Guest | Usuarios y cuentas |
| **Control de Acceso** | UAC, PowerShell Policy, Contraseñas | Login Root, protocolos de autenticación |
| **Red y Comunicaciones** | Firewall, SMBv1, LLMNR | Firewall Linux, servicios de red |
| **Mecanismos de Defensa** | Windows Defender, BitLocker | Servicios del sistema |
| **Configuración** | Actualizaciones, DNS over HTTPS | Configuraciones críticas del sistema |
| **Seguridad de Archivos** | Permisos NTFS | Archivos sensibles, permisos |
| **SSH** | Configuración SSH | Estado y configuración del servicio SSH |

---

## 4. Telemetría y Reportes

Atom genera salidas estandarizadas en cuatro formatos. El directorio de salida por defecto es `~/Desktop/Atom Logs`, configurable con la bandera `--output-dir`.

| Tipo de Reporte | Uso Principal | Características |
| :--- | :--- | :--- |
| **Consola** | Operación en tiempo real | Colores por severidad (PASS, FAIL, WARNING) |
| **TXT** | Logging local | Archivo plano estructurado para logs persistentes |
| **JSON** | Automatización / SIEM | Esquema normalizado para ingesta en APIs/backends |
| **HTML** | Dashboards ejecutivos | Interfaz gráfica con tabla de hallazgos y score |

### Esquema de Hallazgo (Finding)

```json
{
    "title": "Windows Firewall",
    "status": "PASS",
    "severity": "INFO",
    "category": "Network Security",
    "module": "WindowsAuditor",
    "recommendation": "Mantener el firewall habilitado.",
    "reference": "CIS 1.2",
    "timestamp": "2026-10-15T10:30:00Z"
}
```

---

## 5. Security Score

El framework cuantifica la postura de seguridad del sistema mediante un algoritmo progresivo de **Security Score**. Las deducciones se aplican según la severidad de cada hallazgo.

> **SECURITY SCORE: 78/100**
> **STATUS: MODERATE**

| Nivel de Severidad | Deducción |
| :--- | :--- |
| **CRITICAL** | - 25 pts |
| **HIGH** | - 15 pts |
| **MEDIUM** | - 8 pts |
| **LOW** | - 3 pts |
| **INFO** | 0 pts |

---

## 6. Instalación y Ejecución

### Prerrequisitos
- **Windows**: Privilegios elevados (`Administrador`)
- **Linux**: Privilegios root (`sudo`)
- Python 3.10+

### Opción A — Ejecutable Standalone (recomendado)

Descarga directamente `AtomHardening.exe` desde `dist/` — **no requiere Python instalado**.

```powershell
# Windows: ejecutar escaneo completo
.\AtomHardening.exe --scan

# Guardar solo reporte JSON en carpeta personalizada
.\AtomHardening.exe --scan --format json --output-dir C:\mis-reportes
```

### Opción B — Desde el código fuente

```bash
git clone https://github.com/GaboX280/Atom-Hardening.git
cd Atom-Hardening
pip install pyfiglet
```

```bash
# Modo interactivo (menú)
python main.py

# Escaneo directo sin menú
python main.py --scan
```

---

## 7. Referencia de Banderas CLI

```text
usage: main.py [-h] [-s] [-f {all,json,html,text,txt}] [-o OUTPUT_DIR] [-q] [-v]
               {audit,list,config} ...

ATOM - Framework de Auditoría y Hardening de Seguridad Automatizado

Banderas principales:
  -s, --scan            Ejecutar escaneo directo sin menú interactivo
  -f, --format          Formato de reporte: all | json | html | text | txt  (defecto: all)
  -o, --output-dir      Carpeta personalizada para guardar reportes
  -q, --quiet           Modo silencioso (suprime banner y mensajes decorativos)
  -v, --version         Mostrar versión de ATOM y salir

Subcomandos:
  audit                 Ejecutar auditoría (modo automático o interactivo)
  list                  Listar auditorías disponibles
  config                Mostrar configuración actual (config.json)
```

### Ejemplos Rápidos

```bash
# Ver versión
python main.py --version
# → ATOM v1.2.0

# Listar auditorías disponibles
python main.py list

# Escaneo silencioso, solo HTML, en carpeta personalizada
python main.py --scan --format html --output-dir ./reportes --quiet

# Modo interactivo completo (por defecto)
python main.py
```

---

## 8. Visualización

| Fase | Vista |
| :--- | :--- |
| **Interfaz Principal** | ![Menu](docs/screenshots/menu_inicio.png) |
| **Ejecución de Auditoría** | ![Audit](docs/screenshots/Ejecucion_windows_audit.png) |
| **Security Score** | ![Score](docs/screenshots/Security_Score.png) |
| **Resumen en Terminal** | ![Results](docs/screenshots/Resultados_windows.png) |
| **Reporte TXT/JSON** | ![Report](docs/screenshots/Security_Report.png) |
| **Reporte HTML** | ![HTML](docs/screenshots/html.report.png) |

---

## 9. Pruebas Unitarias

La suite de tests cubre los componentes críticos del framework. Todos los tests corren en CI automáticamente en cada push.

```bash
# Ejecutar suite completa (23 tests)
python -m pytest

# Con cobertura de tipos
mypy .

# Verificación de estilo
ruff check .
```

| Archivo de Test | Cobertura |
| :--- | :--- |
| `test_cli.py` | Banderas CLI, `--scan`, `--version`, `--format` |
| `test_auditor_factory.py` | Detección de OS, `WindowsAuditor`, `LinuxAuditor` |
| `test_base_auditor.py` | `add_finding`, `clear_report`, `command_exists` |
| `test_finding.py` | Modelo Finding, `to_dict`, `__str__` |
| `test_reporters.py` | JSON, TXT, HTML, Console reporters |
| `test_security_summary.py` | Agregación de hallazgos por estado y severidad |
| `test_security_score.py` | Cálculo del score y clasificación |

---

## 10. Compilar el Ejecutable

Para generar `dist/AtomHardening.exe` desde el código fuente:

```bash
pip install pyinstaller
pyinstaller --clean AtomHardening.spec
```

El ejecutable resultante es completamente independiente — incluye todos los módulos de `atom_core`, los fonts de pyfiglet y `config.json`.

---

## 11. Roadmap

**Logros Completados:**
- ✅ Arquitectura modular centrada en el OS.
- ✅ Subsistemas de auditoría para Windows y Linux.
- ✅ Detección automática del OS.
- ✅ Reportes multi-formato (JSON, HTML, TXT, Consola).
- ✅ Modelo de dato centralizado (`Finding`).
- ✅ Suite de pruebas unitarias (23 tests, CI/CD con GitHub Actions).
- ✅ Banderas CLI completas (`--scan`, `--format`, `--output-dir`, `--quiet`, `--version`).
- ✅ Ejecutable standalone `AtomHardening.exe` vía PyInstaller.
- ✅ Traducción completa de comentarios a español.

**Pipeline de Desarrollo:**
- ⬜ Mapeo de benchmarks CIS.
- ⬜ Referencias cruzadas CVE/CIS por hallazgo.
- ⬜ Plugin sub-system para checks personalizados.
- ⬜ Dashboard web expandido.
- ⬜ Filtrado de auditorías por categoría.

---

## 12. Aviso Legal

**Atom** es un framework de código abierto desarrollado exclusivamente para investigación educativa y evaluación autorizada de la postura de seguridad. La ejecución de scripts de auditoría y hardening automatizados debe estar estrictamente limitada a infraestructura propia o entornos que operen bajo autorización explícita. El mantenedor del repositorio no asume ninguna responsabilidad por el uso no autorizado.