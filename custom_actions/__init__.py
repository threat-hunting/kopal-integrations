"""SOCLib remote registry for Kopal (tools.soclib.ad and others)."""
__version__ = "0.1.0"

# Import so UDFs are registered when the package is loaded
from custom_actions import ad_ldap  # noqa: F401
from custom_actions import winrm  # noqa: F401
from custom_actions import wmi  # noqa: F401
from custom_actions import splunkes  # noqa: F401
from custom_actions import telegram  # noqa: F401
from custom_actions import telegram_phase234  # noqa: F401
from custom_actions import b17_lab  # noqa: F401
