<div align="center">

# ⚛ Atom-Hardening

**Herramienta modular de auditoría de seguridad y evaluación de configuración para Windows y Linux.**

Automatiza comprobaciones locales, normaliza hallazgos y genera reportes para facilitar la revisión de la postura de seguridad.

[![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/GaboX280/Atom-Hardening/actions/workflows/ci.yml/badge.svg)](https://github.com/GaboX280/Atom-Hardening/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-1.3.0-blue)]()

</div>

---

## Contenido

- [Descripción](#descripción)
- [Características](#características)
- [Comprobaciones de seguridad](#comprobaciones-de-seguridad)
- [Requisitos e instalación](#requisitos-e-instalación)
- [Uso de la CLI](#uso-de-la-cli)
- [Reportes](#reportes)
- [Arquitectura](#arquitectura)
- [Pruebas y calidad](#pruebas-y-calidad)
- [Limitaciones conocidas](#limitaciones-conocidas)
- [Uso responsable](#uso-responsable)

## Descripción

**Atom-Hardening** es un proyecto de seguridad defensiva que audita configuraciones locales de Windows y Linux. Ejecuta comprobaciones específicas del sistema operativo, representa los resultados como hallazgos estructurados y calcula un *Security Score* para ofrecer una vista resumida de los resultados.

El proyecto está desarrollado en Python y organizado en módulos para separar la ejecución de auditorías, las comprobaciones, la lógica de puntuación y la generación de reportes.

## Características

- Detección del sistema operativo y selección del auditor correspondiente.
- Comprobaciones de configuración de seguridad para Windows y Linux.
- Hallazgos normalizados con estado, severidad, detalles y recomendación.
- Resumen de resultados y cálculo de *Security Score*.
- Exportación de reportes en TXT, JSON y HTML, además de resumen en consola.
- CLI con modo de escaneo directo, selección de formato, directorio de salida y modo silencioso.
- Pruebas automatizadas y controles de calidad en GitHub Actions.

## Comprobaciones de seguridad

Las comprobaciones disponibles dependen del sistema operativo y del entorno donde se ejecuta Atom.

| Área | Ejemplos de comprobaciones |
| --- | --- |
| Cuentas y acceso | Cuenta Administrator/Guest, política de contraseñas, UAC |
| Red | Firewall, SMBv1, LLMNR, configuración de red |
| Protección del sistema | Windows Defender, BitLocker, Windows Update |
| Servicios y permisos | Servicios de riesgo, permisos de archivos y cuentas privilegiadas |
| Linux | Firewall, inicios de sesión fallidos, cuentas root, servicios, permisos y archivos SUID |

> La cobertura funcional de cada control varía. Consultá los hallazgos y las recomendaciones generadas; no interpretés el resultado como una certificación completa de cumplimiento.

## Requisitos e instalación

- Python **3.10 o superior**.
- Git para clonar el repositorio.
- Ejecutar con permisos adecuados puede ser necesario para consultar determinadas configuraciones del sistema.

### 1. Clonar el repositorio

```bash
git clone https://github.com/GaboX280/Atom-Hardening.git
cd Atom-Hardening
```

### 2. Crear y activar un entorno virtual (recomendado)

**Windows PowerShell**

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

**Linux**

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Instalar dependencias

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## Uso de la CLI

Ejecutá los comandos desde la raíz del repositorio.

### Ayuda y versión

```bash
python main.py --help
python main.py --version
```

### Ejecutar una auditoría

```bash
# Escaneo directo, sin menú interactivo
python main.py --scan

# También se puede usar el subcomando audit en modo no interactivo
python main.py audit --audit 1 --no-gui

# Modo silencioso: --quiet funciona antes o después del subcomando
python main.py audit --audit 1 --no-gui --quiet
```

### Elegir el formato del reporte

```bash
# Generar todos los formatos disponibles
python main.py --scan --format all

# Generar únicamente JSON
python main.py --scan --format json

# Generar HTML en un directorio específico
python main.py --scan --format html --output-dir ./reports
```

Formatos aceptados: `all`, `json`, `html`, `text` y `txt`. El formato `all` genera TXT, JSON y HTML.

### Modo silencioso

```bash
python main.py --scan --format json --output-dir ./reports --quiet
```

La opción `--quiet` suprime el banner y la presentación de resultados en consola. Los reportes siguen generándose cuando la auditoría produce hallazgos.

### Listar opciones y consultar configuración

```bash
python main.py list
python main.py config
```

- `list`: muestra las opciones disponibles en el menú interactivo.
- `config`: imprime el contenido de `config.json`, si está disponible.

### Opciones disponibles

| Opción | Descripción |
| --- | --- |
| `-h`, `--help` | Mostrar la ayuda de la CLI |
| `-s`, `--scan` | Ejecutar una auditoría sin abrir el menú |
| `-f`, `--format` | Elegir `all`, `json`, `html`, `text` o `txt` |
| `-o`, `--output-dir` | Especificar el directorio de salida de los reportes |
| `-q`, `--quiet` | Suprimir la presentación interactiva y el resumen de consola |
| `-v`, `--version` | Mostrar la versión |
| `audit --no-gui` | Ejecutar el flujo de auditoría sin el menú |
| `audit --quiet` | Ejecutar el subcomando sin banner ni salida de consola |
| `list` | Listar las opciones del menú |
| `config` | Mostrar la configuración cargada |

## Reportes

Atom puede generar los siguientes formatos:

| Formato | Uso |
| --- | --- |
| Consola | Resumen de puntuación, estados y hallazgos durante la ejecución |
| TXT | Lectura humana y registro local |
| JSON | Integración y procesamiento automatizado |
| HTML | Revisión visual de los resultados |

Los reportes contienen el resumen de la auditoría y los hallazgos producidos por los controles ejecutados. El directorio de salida puede definirse con `--output-dir`; si no se especifica, se utiliza la ubicación predeterminada del generador de reportes.

## Arquitectura

```text
main.py
└── CLI y punto de entrada
    └── atom_core/
        ├── interface/    # Menú interactivo y presentación
        ├── runners/      # Orquestación de la auditoría
        ├── modules/      # Auditores y comprobaciones por SO
        ├── core/         # Security Score y resumen
        ├── models/       # Modelo de hallazgo
        └── reporters/    # Salidas de consola, TXT, JSON y HTML
```

Flujo general:

```text
CLI → AuditRunner → AuditorFactory → Comprobaciones del SO
    → Hallazgos → Resumen y Security Score → Reportes
```

## Pruebas y calidad

Para ejecutar la suite de pruebas:

```bash
python -m pip install pytest pytest-cov mypy ruff
python -m pytest
```

Para ejecutar las pruebas con reporte de cobertura:

```bash
python -m pytest --cov=atom_core --cov-report=term-missing
```

Para ejecutar los mismos tipos de comprobaciones estáticas usados por CI:

```bash
mypy .
ruff check .
```

La integración continua ejecuta las comprobaciones de tipos, el análisis de estilo y las pruebas automatizadas en GitHub Actions. La cantidad de pruebas y la cobertura pueden cambiar a medida que el proyecto evoluciona.

## Limitaciones conocidas

- Los controles disponibles y la información que puede obtenerse dependen del sistema operativo, los permisos y la configuración local.
- Una auditoría automatizada ayuda a identificar posibles problemas, pero no sustituye una revisión de seguridad completa ni una validación de cumplimiento.
- La CLI y los controles siguen en desarrollo; consultá la ayuda integrada con `python main.py --help` para conocer las opciones expuestas por la versión actual.

## Uso responsable

Atom-Hardening está destinado a aprendizaje, investigación y evaluación defensiva autorizada. Ejecutá la herramienta únicamente en equipos propios o en sistemas para los que tengas autorización explícita. Revisá los resultados antes de aplicar cambios manuales en la configuración del sistema.

---

<div align="center">

Desarrollado por **GaboX280** · [GitHub](https://github.com/GaboX280)

</div>
