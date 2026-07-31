# linux/audits/__init__.py

from .checks.failed_logins import audit_failed_logins
from .checks.firewall import audit_firewall
from .checks.network import audit_network
from .checks.password_policy import audit_password_policy
from .checks.permissions import audit_permissions
from .checks.root_accounts import audit_root_accounts
from .checks.services import audit_services
from .checks.suid import audit_suid

LINUX_AUDITS = [
    audit_firewall,
    audit_services,
    audit_failed_logins,
    audit_root_accounts,
    audit_suid,
    audit_permissions,
    audit_password_policy,
    audit_network,
]