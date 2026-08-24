# -*- mode: python ; coding: utf-8 -*-
import os
import sys

# ---------------------------------------------------------------------------
# Rutas dinámicas
# ---------------------------------------------------------------------------

# Raíz del proyecto
PROJECT_ROOT = os.path.dirname(os.path.abspath(SPEC))  # noqa: F821

# Busca los fonts de pyfiglet dentro del venv activo o en el Python del sistema
def find_pyfiglet_fonts():
    """Retorna la ruta a los fonts de pyfiglet."""
    try:
        import pyfiglet
        pkg_path = os.path.dirname(pyfiglet.__file__)
        fonts_path = os.path.join(pkg_path, "fonts")
        if os.path.isdir(fonts_path):
            return fonts_path
    except ImportError:
        pass
    # Fallback: busca manualmente en site-packages conocidas
    candidates = [
        os.path.join(sys.prefix, "Lib", "site-packages", "pyfiglet", "fonts"),
        r"C:/Python314/Lib/site-packages/pyfiglet/fonts",
    ]
    for c in candidates:
        if os.path.isdir(c):
            return c
    raise FileNotFoundError("No se encontraron los fonts de pyfiglet. Instala pyfiglet primero.")


PYFIGLET_FONTS = find_pyfiglet_fonts()

# ---------------------------------------------------------------------------
# Análisis de dependencias
# ---------------------------------------------------------------------------

a = Analysis(
    ['main.py'],
    pathex=[PROJECT_ROOT],
    binaries=[],
    datas=[
        # Fuentes de pyfiglet (necesarias para el banner ASCII)
        (PYFIGLET_FONTS, 'pyfiglet/fonts'),
        # Configuración del proyecto
        (os.path.join(PROJECT_ROOT, 'config.json'), '.'),
    ],
    hiddenimports=[
        # Asegura que todos los módulos de atom_core sean incluidos
        'atom_core',
        'atom_core.auditor_factory',
        'atom_core.base_auditor',
        'atom_core.core.security_score',
        'atom_core.core.security_summary',
        'atom_core.interface.interface',
        'atom_core.reporters.console_reporter',
        'atom_core.reporters.json_reporter',
        'atom_core.reporters.text_reporter',
        'atom_core.reporters.html_reporter',
        'atom_core.runners.audit_runner',
        'atom_core.utils.distro',
        'pyfiglet',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        # Excluye módulos de test y desarrollo para reducir tamaño
        'pytest',
        'mypy',
        'ruff',
    ],
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
    name='AtomHardening',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)
