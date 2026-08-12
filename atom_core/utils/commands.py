def command_exists(auditor, command):

    resultado = auditor._run_command(f"command -v {command}")

    return bool(resultado)
