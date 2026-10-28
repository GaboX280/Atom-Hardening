import re

from atom_core.base_auditor import BaseAuditor


def audit_firewall(auditor: BaseAuditor) -> None:
    """Evaluate available Linux firewall backends without stopping at an inactive one."""
    auditor.log(f"Evaluando firewall Linux ({auditor.distro})...")

    inactive_backends: list[str] = []
    detected_backend = False

    # UFW
    if auditor.command_exists("ufw"):
        detected_backend = True
        result = auditor._run_command("ufw status")
        if auditor._record_command_error(result, "Linux Firewall Check"):
            return

        if "status: active" in result.stdout.lower():
            auditor.add_finding(
                title="Linux Firewall UFW",
                status="PASS",
                severity="INFO",
                category="Network Security",
                details="UFW está instalado y activo.",
                recommendation="Mantener reglas restrictivas y actualizadas.",
                reference="UFW Documentation",
                impact="El tráfico no autorizado puede ser filtrado por UFW.",
                compliance=["CIS Linux Benchmark"],
            )
            return

        inactive_backends.append("UFW está instalado pero deshabilitado.")

    # nftables
    if auditor.command_exists("nft"):
        detected_backend = True
        result = auditor._run_command("nft list ruleset")
        if auditor._record_command_error(result, "Linux Firewall Check"):
            return

        ruleset = result.stdout.strip()
        has_restrictive_rule = any(
            re.search(r"\b(drop|reject)\b", line, re.IGNORECASE)
            for line in ruleset.splitlines()
        )
        if has_restrictive_rule:
            auditor.add_finding(
                title="Linux Firewall nftables",
                status="PASS",
                severity="INFO",
                category="Network Security",
                details="Se detectaron políticas o reglas drop/reject en nftables.",
                recommendation="Revisar periódicamente que las reglas filtren el tráfico según la política esperada.",
                reference="nftables Documentation",
                impact="Las políticas y reglas de rechazo reducen el tráfico no autorizado.",
                compliance=["CIS Linux Benchmark"],
            )
            return

        inactive_backends.append(
            "nftables no presenta reglas drop/reject explícitas; su filtrado efectivo no está confirmado."
        )

    # firewalld
    if auditor.command_exists("firewall-cmd"):
        detected_backend = True
        result = auditor._run_command("firewall-cmd --state")
        if auditor._record_command_error(
            result, "Linux Firewall Check", allowed_returncodes=(0, 252)
        ):
            return

        state = result.stdout.lower()
        if "running" in state and "not running" not in state:
            auditor.add_finding(
                title="Linux Firewall Firewalld",
                status="PASS",
                severity="INFO",
                category="Network Security",
                details="Firewalld está activo.",
                recommendation="Mantener zonas y reglas actualizadas.",
                compliance=["CIS Linux Benchmark"],
            )
            return

        inactive_backends.append("Firewalld está instalado pero detenido.")

    # iptables heredado. La presencia de cadenas no demuestra que sus políticas
    # filtren tráfico; por eso se informa como hallazgo que requiere revisión.
    if auditor.command_exists("iptables"):
        detected_backend = True
        result = auditor._run_command("iptables -L -n")
        if auditor._record_command_error(result, "Linux Firewall Check"):
            return

        if result.stdout.strip() and "Chain" in result.stdout:
            inactive_backends.append(
                "iptables está disponible; sus políticas y reglas requieren revisión."
            )
        else:
            inactive_backends.append("iptables está disponible, pero no se detectaron reglas.")

    if inactive_backends:
        auditor.add_finding(
            title="Linux Firewall",
            status="WARNING",
            severity="MEDIUM",
            category="Network Security",
            details="No se confirmó un firewall activo entre los backends revisados: "
            + " ".join(inactive_backends),
            recommendation="Verificar qué backend administra el filtrado del sistema y confirmar sus reglas efectivas.",
            reference="CIS Linux Benchmark",
            impact="No se pudo confirmar una política efectiva de filtrado del tráfico.",
            confidence="MEDIUM",
            compliance=["CIS Linux Benchmark"],
        )
        return

    if not detected_backend:
        auditor.add_finding(
            title="Linux Firewall",
            status="WARNING",
            severity="MEDIUM",
            category="Network Security",
            details="No se detectó una solución firewall disponible mediante UFW, nftables, firewalld o iptables.",
            recommendation="Configurar una solución de firewall adecuada para el escenario.",
            reference="CIS Linux Benchmark",
            impact="La máquina podría aceptar tráfico no filtrado.",
            compliance=["CIS Linux Benchmark"],
        )
