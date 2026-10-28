# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller specification for the Atom-Hardening Windows executable."""

import os

import pyfiglet
from PyInstaller.utils.hooks import collect_submodules

PROJECT_ROOT = os.path.dirname(os.path.abspath(SPEC))  # noqa: F821
PYFIGLET_FONTS = os.path.join(os.path.dirname(pyfiglet.__file__), "fonts")
CONFIG_FILE = os.path.join(PROJECT_ROOT, "config.json")
ATOM_ART_FILE = os.path.join(
    PROJECT_ROOT, "atom_core", "interface", "atom_art.txt"
)

for required_path in (PYFIGLET_FONTS, CONFIG_FILE, ATOM_ART_FILE):
    if not os.path.exists(required_path):
        raise FileNotFoundError(f"Required packaging resource is missing: {required_path}")

a = Analysis(
    ["main.py"],
    pathex=[PROJECT_ROOT],
    binaries=[],
    datas=[
        (PYFIGLET_FONTS, "pyfiglet/fonts"),
        (CONFIG_FILE, "."),
        (ATOM_ART_FILE, "atom_core/interface"),
    ],
    # Collect every Atom module, including OS-specific checks that are imported
    # through the auditor factory and may not be discovered by static analysis.
    hiddenimports=collect_submodules("atom_core") + ["pyfiglet"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "mypy", "ruff"],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)  # noqa: F821

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="AtomHardening",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
