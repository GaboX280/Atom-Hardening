from unittest.mock import patch

import pytest

from atom_core.auditor_factory import AuditorFactory
from atom_core.modules.linux.auditor import LinuxAuditor
from atom_core.modules.windows.auditor import WindowsAuditor


def test_get_auditor_windows() -> None:
    """Verifica que se instancie WindowsAuditor en el sistema Windows."""
    with patch("platform.system", return_value="Windows"):
        auditor = AuditorFactory.get_auditor()
        assert isinstance(auditor, WindowsAuditor)


def test_get_auditor_linux() -> None:
    """Verifica que se instancie LinuxAuditor en el sistema Linux."""
    with patch("platform.system", return_value="Linux"):
        auditor = AuditorFactory.get_auditor()
        assert isinstance(auditor, LinuxAuditor)


def test_get_auditor_unsupported_os() -> None:
    """Verifica que se lance NotImplementedError en un sistema operativo no soportado."""
    with patch("platform.system", return_value="FreeBSD"):
        with pytest.raises(NotImplementedError) as exc_info:
            AuditorFactory.get_auditor()
        assert "No hay auditor disponible" in str(exc_info.value)
