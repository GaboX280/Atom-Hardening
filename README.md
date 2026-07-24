# Atom Hardening Tool

<p align="center">
  <b>Automated Security Auditing Framework for Windows and Linux</b>
</p>

---

## Descripción

**Atom** es una herramienta modular de auditoría de seguridad desarrollada en Python orientada a evaluar configuraciones críticas de sistemas Windows y Linux.

Su objetivo es identificar debilidades de hardening, generar hallazgos estructurados y proporcionar recomendaciones para mejorar la postura de seguridad del sistema.

Atom utiliza una arquitectura basada en módulos independientes, permitiendo agregar nuevos auditores sin modificar el núcleo principal de la aplicación.

---

# Características

## Auditoría de Sistemas

Evaluación de configuraciones críticas del sistema operativo:

### Windows

- Firewall de Windows
- Windows Defender
- Políticas de contraseñas
- Cuentas administrativas
- Cuenta Guest
- User Account Control (UAC)
- BitLocker
- Windows Update
- PowerShell Execution Policy
- SMBv1
- LLMNR
- Restricciones de acceso anónimo
- Servicios de riesgo
- DNS over HTTPS

---

## Auditoría de Archivos

Evaluación de protección sobre archivos sensibles:

- Permisos NTFS
- Protección de archivos críticos del sistema
- Archivos sensibles como SAM y hosts

---

## Auditoría SSH

Evaluación de configuraciones SSH:

- Estado del servicio SSH
- Existencia de configuración
- Root Login
- Password Authentication
- Exposición del servicio en red

---

# Arquitectura

Atom utiliza una arquitectura modular basada en auditores independientes.

```
ATOM

│
├── main.py
│
├── AuditRunner
│
├── AuditorFactory
│
├── BaseAuditor
│
├── SecurityScore
│
├── SecuritySummary
│
├── Reporters
│
└── Modules

    ├── Windows
    │
    ├── Linux
    │
    ├── File Audit
    │
    └── SSH
```

---

# Flujo de ejecución

```
Usuario

  |
  v

AuditRunner

  |
  v

AuditorFactory

  |
  v

Auditor seleccionado

  |
  v

Finding Objects

  |
  +------------+
  |            |
  v            v

Security     Reporters
Score
```

---

# Sistema de Findings

Cada hallazgo generado por Atom contiene:

| Campo | Descripción |
|---|---|
| Title | Nombre del hallazgo |
| Status | PASS / WARNING / FAIL / ERROR |
| Severity | Nivel de impacto |
| Category | Categoría de seguridad |
| Module | Auditor responsable |
| Recommendation | Acción recomendada |
| Timestamp | Fecha de detección |

---

# Security Score

Atom calcula una puntuación de seguridad basada en la severidad de los hallazgos encontrados.

Ejemplo:

```
Security Score: 78/100

Rating:
MODERATE
```

La puntuación considera:

| Severidad | Penalización |
|-|-|
| CRITICAL | -25 |
| HIGH | -15 |
| MEDIUM | -8 |
| LOW | -3 |
| INFO | 0 |

---

# Tecnologías utilizadas

- Python 3.x
- PowerShell
- Bash
- Git
- Programación Orientada a Objetos
- Arquitectura modular

---

# Instalación

Clonar repositorio:

```bash
git clone https://github.com/GaboX280/Atom-Hardening.git
```

Entrar al proyecto:

```bash
cd Atom-Hardening
```

Ejecutar:

```bash
python main.py
```

> Se requieren privilegios de Administrador en Windows o Root en Linux.

---

# Uso

Al iniciar Atom:

```
ATOM Security Auditor

1 - System Audit
2 - File Audit
3 - SSH Audit
```

Seleccionar el módulo deseado y esperar la generación del reporte.

---

# Roadmap

## Completado

- [x] Arquitectura modular
- [x] Auditoría Windows
- [x] Auditoría SSH
- [x] Auditoría de archivos
- [x] Sistema de Findings
- [x] Security Score
- [x] Reportes de consola

## Próximamente

- [ ] Reportes JSON
- [ ] Reportes HTML
- [ ] Tests automatizados
- [ ] Mapeo CIS Benchmark
- [ ] Empaquetado ejecutable Windows
- [ ] Empaquetado ejecutable Linux
- [ ] Sistema de plugins

---

# Disclaimer

Atom es una herramienta desarrollada con fines educativos y de investigación en seguridad informática.

Debe utilizarse únicamente en sistemas propios o con autorización explícita.