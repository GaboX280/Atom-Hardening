from atom_core.base_auditor import BaseAuditor

def detect_distro(auditor: BaseAuditor) -> str: # [TYPING ADDED]

    resultado = auditor._run_command("cat /etc/os-release").lower()

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
