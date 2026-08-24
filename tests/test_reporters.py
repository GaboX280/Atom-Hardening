from pathlib import Path
from unittest.mock import patch

import pytest

from atom_core.models.finding import Finding
from atom_core.reporters.console_reporter import ConsoleReporter
from atom_core.reporters.html_reporter import HTMLReporter
from atom_core.reporters.json_reporter import JsonReporter
from atom_core.reporters.text_reporter import TextReporter


def test_json_reporter(tmp_path: Path) -> None:
    """Verifica la generación y contenido del archivo JSON del reporte."""
    summary = {
        "system": "Windows",
        "module": "DummyModule",
        "score": 85,
        "rating": "BUENO",
        "total": 1,
    }
    findings = [
        Finding(
            title="Firewall Check",
            status="PASS",
            severity="INFO",
            details="Activo",
        )
    ]

    with patch.object(JsonReporter, "_get_report_folder", return_value=str(tmp_path)):
        filepath = JsonReporter.save(summary, findings)
        assert Path(filepath).exists()
        content = Path(filepath).read_text(encoding="utf-8")
        assert "Firewall Check" in content
        assert "BUENO" in content


def test_text_reporter(tmp_path: Path) -> None:
    """Verifica la generación y contenido del archivo TXT del reporte."""
    summary = {
        "system": "Linux",
        "module": "DummyModule",
        "score": 100,
        "rating": "EXCELENTE",
        "total": 1,
    }
    findings = [
        Finding(
            title="SUID Check",
            status="PASS",
            severity="INFO",
            details="Permisos OK",
        )
    ]

    with patch.object(TextReporter, "_get_report_folder", return_value=str(tmp_path)):
        filepath = TextReporter.save(summary, findings)
        assert Path(filepath).exists()
        content = Path(filepath).read_text(encoding="utf-8")
        assert "ATOM SECURITY REPORT" in content
        assert "SUID Check" in content


def test_html_reporter(tmp_path: Path) -> None:
    """Verifica la generación y contenido del archivo HTML del reporte."""
    summary = {
        "system": "Linux",
        "module": "DummyModule",
        "score": 90,
        "rating": "EXCELENTE",
        "total": 1,
    }
    findings = [
        Finding(
            title="SSH Check",
            status="PASS",
            severity="INFO",
            details="Configuración segura",
        )
    ]

    with patch.object(HTMLReporter, "_get_report_folder", return_value=str(tmp_path)):
        filepath = HTMLReporter.save(summary, findings)
        assert Path(filepath).exists()
        content = Path(filepath).read_text(encoding="utf-8")
        assert "<title>" in content
        assert "SSH Check" in content


def test_console_reporter(capsys: pytest.CaptureFixture[str]) -> None:
    """Verifica que ConsoleReporter imprima correctamente los hallazgos en la salida estándar."""
    findings = [
        Finding(
            title="Consola Check",
            status="WARNING",
            severity="MEDIUM",
            details="Advertencia detectada",
        )
    ]

    ConsoleReporter.display(findings, score=75, rating="MODERADO")
    captured = capsys.readouterr()

    assert "ATOM SECURITY REPORT" in captured.out
    assert "Consola Check" in captured.out
    assert "Advertencia detectada" in captured.out


def test_console_reporter_empty(capsys: pytest.CaptureFixture[str]) -> None:
    """Verifica el comportamiento de ConsoleReporter cuando no hay hallazgos."""
    ConsoleReporter.display([], score=100, rating="EXCELENTE")
    captured = capsys.readouterr()

    assert "No se encontraron resultados" in captured.out
