from unittest.mock import patch

import pytest

from main import build_parser, main


def test_cli_parser_defaults() -> None:
    """Verifica los valores por defecto del parseador CLI."""
    args = build_parser().parse_args([])

    assert not args.scan
    assert args.format == "all"
    assert args.output_dir is None
    assert not args.quiet
    assert not args.version
    assert args.command is None


def test_cli_parser_scan_flags() -> None:
    """Verifica el parseo de banderas de escaneo directo y opciones."""
    args = build_parser().parse_args(
        ["-s", "-f", "json", "-o", "./output_test", "-q"]
    )

    assert args.scan
    assert args.format == "json"
    assert args.output_dir == "./output_test"
    assert args.quiet


def test_cli_parser_subcommands() -> None:
    """Verifica el parseo de subcomandos list, config y audit."""
    parser = build_parser()

    assert parser.parse_args(["list"]).command == "list"
    assert parser.parse_args(["config"]).command == "config"

    args_audit = parser.parse_args(["audit", "--no-gui"])
    assert args_audit.command == "audit"
    assert args_audit.no_gui
    assert args_audit.audit == "1"


def test_cli_rejects_unsupported_audit_id() -> None:
    """Rechaza IDs de auditoría que aún no están implementados."""
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(["audit", "--audit", "2", "--no-gui"])

    assert exc_info.value.code == 2


def test_config_command_does_not_accept_redundant_show_flag() -> None:
    """El subcomando config muestra la configuración sin una bandera redundante."""
    with pytest.raises(SystemExit) as exc_info:
        build_parser().parse_args(["config", "--show"])

    assert exc_info.value.code == 2


def test_main_config_displays_json(capsys: pytest.CaptureFixture[str]) -> None:
    """Verifica que config muestre el contenido de configuración."""
    with (
        patch("sys.argv", ["main.py", "config"]),
        patch("main.load_config", return_value={"reports": {"format": "json"}}),
    ):
        main()

    captured = capsys.readouterr()
    assert '"reports"' in captured.out
    assert '"format": "json"' in captured.out


def test_main_version(capsys: pytest.CaptureFixture[str]) -> None:
    """Verifica la salida de la bandera --version."""
    with patch("sys.argv", ["main.py", "--version"]):
        with pytest.raises(SystemExit) as exc_info:
            main()
        assert exc_info.value.code == 0

    captured = capsys.readouterr()
    assert "ATOM v1.3.0" in captured.out


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


def test_main_audit_uses_selected_id() -> None:
    """Pasa al runner el ID elegido mediante audit --audit."""
    with (
        patch(
            "sys.argv",
            ["main.py", "audit", "--audit", "1", "--no-gui", "--quiet"],
        ),
        patch("atom_core.runners.audit_runner.AuditRunner.run") as mock_run,
    ):
        main()

    mock_run.assert_called_once_with(
        option="1",
        fmt="all",
        output_dir=None,
        quiet=True,
    )
