from unittest.mock import patch

import pytest

from main import build_parser, main


def test_cli_parser_defaults() -> None:
    """Verifica los valores por defecto del parseador CLI."""
    parser = build_parser()
    args = parser.parse_args([])

    assert not args.scan
    assert args.format == "all"
    assert args.output_dir is None
    assert not args.quiet
    assert not args.version
    assert args.command is None


def test_cli_parser_scan_flags() -> None:
    """Verifica el parseo de banderas de escaneo directo y opciones."""
    parser = build_parser()
    args = parser.parse_args(["-s", "-f", "json", "-o", "./output_test", "-q"])

    assert args.scan
    assert args.format == "json"
    assert args.output_dir == "./output_test"
    assert args.quiet


def test_cli_parser_subcommands() -> None:
    """Verifica el parseo de subcomandos list, config y audit."""
    parser = build_parser()

    args_list = parser.parse_args(["list"])
    assert args_list.command == "list"

    args_config = parser.parse_args(["config"])
    assert args_config.command == "config"

    args_audit = parser.parse_args(["audit", "--no-gui"])
    assert args_audit.command == "audit"
    assert args_audit.no_gui


def test_main_version(capsys: pytest.CaptureFixture[str]) -> None:
    """Verifica la salida de la bandera --version."""
    with patch("sys.argv", ["main.py", "--version"]):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

    captured = capsys.readouterr()
    assert "ATOM v1.2.0" in captured.out


def test_main_scan_execution() -> None:
    """Verifica la ejecución directa en modo --scan sin UI interactiva."""
    with (
        patch("sys.argv", ["main.py", "--scan", "--quiet", "-f", "json"]),
        patch("atom_core.runners.audit_runner.AuditRunner.run") as mock_run,
    ):
        main()
        mock_run.assert_called_once_with(
            option="1",
            fmt="json",
            output_dir=None,
            quiet=True,
        )
