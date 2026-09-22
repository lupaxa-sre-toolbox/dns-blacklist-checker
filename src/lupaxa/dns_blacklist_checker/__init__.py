"""lupaxa.dns_blacklist_checker — DNS blacklist lookups."""

from __future__ import annotations

from .lookup import (
    DEFAULT_TIMEOUT,
    DEFAULT_ZONES,
    AddressResult,
    CheckResult,
    ZoneResult,
    check,
    check_mail_exchangers,
    dnsbl_qname,
    resolve_ipv4,
    spamhaus_query_zone,
)
from .version import __version__, get_version

__all__ = [
    "DEFAULT_TIMEOUT",
    "DEFAULT_ZONES",
    "AddressResult",
    "CheckResult",
    "ZoneResult",
    "__version__",
    "check",
    "check_mail_exchangers",
    "dnsbl_qname",
    "get_version",
    "resolve_ipv4",
    "spamhaus_query_zone",
]
