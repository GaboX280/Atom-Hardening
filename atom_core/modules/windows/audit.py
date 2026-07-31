from .checks.admin_account import audit_admin_account
from .checks.anonymous_lookup import audit_anonymous_lookup
from .checks.bitlocker import audit_bitlocker
from .checks.doh_settings import audit_doh_settings
from .checks.firewall import audit_firewall
from .checks.guest_account import audit_guest_account
from .checks.llmnr import audit_llmnr
from .checks.password_policy import audit_password_policy
from .checks.powershell_policy import audit_powershell_policy
from .checks.remote_desktop import audit_remote_desktop
from .checks.risky_services import audit_risky_services
from .checks.smbv1 import audit_smbv1
from .checks.uac import audit_uac
from .checks.windows_defender import audit_windows_defender
from .checks.windows_update import audit_windows_update

WINDOWS_CHECKS = [
    audit_firewall,
    audit_windows_defender,
    audit_password_policy,
    audit_guest_account,
    audit_remote_desktop,
    audit_uac,
    audit_bitlocker,
    audit_powershell_policy,
    audit_windows_update,
    audit_admin_account,
    audit_smbv1,
    audit_llmnr,
    audit_anonymous_lookup,
    audit_risky_services,
    audit_doh_settings,
]