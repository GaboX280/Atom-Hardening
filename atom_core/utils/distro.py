from atom_core.base_auditor import BaseAuditor


def detect_distro(auditor: BaseAuditor) -> str: # [TIPADO AÑADIDO]

    resultado_comando = auditor._run_command("cat /etc/os-release")

    if resultado_comando.error is not None or resultado_comando.returncode != 0:
        auditor.log("No fue posible detectar la distribución Linux.", level="ERROR")
        return "unknown"

    resultado = resultado_comando.stdout.lower()

    if "ubuntu" in resultado:
        return "ubuntu"

    if "debian" in resultado:
        return "debian"

    if "fedora" in resultado:
        return "fedora"

    if "rhel" in resultado or "red hat" in resultado:
        return "rhel"

    if "arch" in resultado:
        return "arch"

    if "kali" in resultado:
        return "kali"

    return "unknown"
