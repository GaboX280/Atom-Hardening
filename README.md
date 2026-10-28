<div align="center">

# ⚛ Atom-Hardening

**Automated security auditing and configuration assessment for Windows and Linux.**

Atom runs local security checks, normalizes findings, calculates a bounded Security Score, and produces reports that help analysts review endpoint posture.

[![Python](https://img.shields.io/badge/Python-3.11%2B-3776AB?logo=python&logoColor=white)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux-lightgrey)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![CI](https://github.com/GaboX280/Atom-Hardening/actions/workflows/ci.yml/badge.svg)](https://github.com/GaboX280/Atom-Hardening/actions/workflows/ci.yml)
[![Version](https://img.shields.io/badge/version-2.0.0--candidate-blue)]()

</div>

---

## Overview

Atom-Hardening is a modular defensive-security project. It evaluates selected local configuration controls on Windows and Linux and reports the results as structured findings. It is designed for auditing and visibility; **it does not automatically change system settings or apply hardening actions**.

## What's new in 2.0

- **Richer terminal UI:** colored Rich panels show the Security Score, check status counts and severity distribution side by side when the terminal is wide enough. Detailed findings appear beneath the summary.
- **Structured Windows checks:** PowerShell and registry-backed controls use structured output where implemented, reducing dependence on localized command-line text.
- **More predictable audit results:** findings use a common model, the Security Score is bounded to 0–100, and execution errors remain visible without being treated as confirmed security weaknesses.
- **Multi-format reporting:** TXT, JSON and HTML reports support human review and downstream automation.
- **Expanded tests:** core logic, CLI behavior, Windows checks and Linux checks have automated coverage.

> Version 2.0 is a release candidate until the full CI checks pass and the integrated behavior is verified.

## Security checks

The exact results depend on operating system, policy configuration, available commands and permissions.

| Area | Examples |
| --- | --- |
| Windows identity and access | Built-in Administrator and Guest accounts, UAC, password policy |
| Windows network security | Firewall profiles, SMBv1, LLMNR, Remote Desktop |
| Windows protection | BitLocker, Microsoft Defender, Windows Update and selected system policies |
| Linux configuration | Firewall state, failed logins, password policy, file permissions, root accounts, services and SUID files |

Some checks need elevated privileges or specific Windows PowerShell cmdlets to return complete results. A result of `ERROR` means the check could not reliably evaluate the control; it should not be read as a confirmed vulnerability. Review the details and recommendations before making operational decisions.

## Requirements

- Python **3.11 or newer**.
- Windows PowerShell for Windows-specific checks; compatible Linux utilities for Linux checks.
- Administrator/root permissions may be required for selected checks.

## Installation

```powershell
git clone https://github.com/GaboX280/Atom-Hardening.git
cd Atom-Hardening
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

On Linux, create and activate the virtual environment with `python3 -m venv .venv` and `source .venv/bin/activate`, then install `requirements.txt`.

## Usage

Run the interactive menu:

```bash
python main.py
```

In the interactive flow, option **1** runs the security audit; option **2** displays the last results after a completed audit.

Run an audit directly:

```bash
# Show version and supported commands
python main.py --version
python main.py --help
python main.py list

# Run an audit and generate all supported report formats
python main.py --scan

# Generate JSON only in a custom output directory
python main.py --scan --format json --output-dir ./reports

# Use the audit subcommand without the interactive menu
python main.py audit --audit 1 --no-gui
```

Supported output selections are `all`, `json`, `html`, `text` and `txt`. Use `--quiet` to suppress the decorative console output.

## Architecture

```text
main.py
└── CLI and interactive menu
    └── atom_core/
        ├── interface/    # Rich terminal interface
        ├── runners/      # Audit orchestration and result presentation
        ├── modules/      # Windows and Linux security checks
        ├── core/         # Security Score and summary aggregation
        ├── models/       # Normalized Finding model
        └── reporters/    # Console, TXT, JSON and HTML output
```

General execution flow:

```text
CLI → AuditRunner → OS-specific checks → Findings
    → SecuritySummary + SecurityScore → Reporters
```

## Tests and quality checks

Install the development tools and run the same checks used by CI:

```bash
python -m pip install pytest pytest-cov mypy ruff
python -m mypy .
python -m ruff check .
python -m pytest --cov=atom_core --cov-report=term-missing
```

## Responsible use

Use Atom only on systems you own or are authorized to assess. Review findings before changing a security policy, and validate any recommendation against the requirements of your environment.

## License

MIT. See [LICENSE](LICENSE).
