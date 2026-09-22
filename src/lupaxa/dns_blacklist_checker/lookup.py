"""DNS blacklist lookups for IP addresses and hostnames."""

from __future__ import annotations

import ipaddress
import math
from collections.abc import Callable, Sequence
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from typing import Protocol

import dns.exception
import dns.resolver

DEFAULT_TIMEOUT = 5.0

# Zones that answer IPv6 nibble queries. Other default zones are IPv4 only.
IPV6_ZONES: frozenset[str] = frozenset(
    {
        "zen.spamhaus.org",
        "sbl.spamhaus.org",
        "xbl.spamhaus.org",
        "pbl.spamhaus.org",
        "combined.mail.abusix.zone",
    }
)

# Dropped from the original script: SORBS (shut down), separate Spamhaus
# zones already covered by ZEN, CBL (included in ZEN), and UCEPROTECT levels
# 2 and 3 (whole netblocks).
DEFAULT_ZONES: tuple[str, ...] = (
    "zen.spamhaus.org",
    "combined.mail.abusix.zone",
    "bl.spamcop.net",
    "b.barracudacentral.org",
    "dnsbl.dronebl.org",
    "dnsbl-1.uceprotect.net",
    "ix.dnsbl.manitu.net",
    "psbl.surriel.com",
    "rbl.spamlab.com",
    "ubl.unsubscore.com",
    "virus.rbl.jp",
    "spamrbl.imp.ch",
    "virbl.dnsbl.bit.nl",
    "rbl.efnetrbl.org",
    "blackholes.five-ten-sg.com",
    "dnsbl.inps.de",
    "ipbl.mailboxtools.com",
    "bl.spamcannibal.org",
    "dnsbl.justspam.org",
    "dnsbl.kempt.net",
)

_IPV4_ONLY_ZONES: frozenset[str] = frozenset(
    zone for zone in DEFAULT_ZONES if zone not in IPV6_ZONES
)

_SPAMHAUS_NOTES = {
    "127.255.255.252": "typing error in zone name",
    "127.255.255.254": "query via public resolver",
    "127.255.255.255": "excessive number of queries",
}

_ABUSIX_POLICY = {
    "127.0.0.11": "policy: generic reverse DNS",
    "127.0.0.12": "policy: missing reverse DNS",
}


class NameResolver(Protocol):
    """Minimal resolver surface used by :func:`check`."""

    def resolve(self, qname: str, rdtype: str) -> object:
        """Resolve ``qname`` for ``rdtype`` or raise a resolver error."""


ResolveAddress = Callable[[str], str]


@dataclass(frozen=True)
class ZoneResult:
    """Outcome of one DNSBL zone query."""

    zone: str
    listed: bool
    detail: str
    return_codes: tuple[str, ...] = ()
    reason: str = ""


@dataclass(frozen=True)
class AddressResult:
    """Zone results for one resolved address."""

    address: str
    zones: tuple[ZoneResult, ...] = ()
    error: str | None = None

    @property
    def listed(self) -> bool:
        """Return whether any zone listed this address."""
        return any(zone.listed for zone in self.zones)


@dataclass(frozen=True)
class CheckResult:
    """Outcome of checking one target."""

    query: str
    addresses: tuple[AddressResult, ...] = ()
    error: str | None = None
    exchanger: str | None = None

    @property
    def address(self) -> str | None:
        """Return the first resolved address, if any."""
        if not self.addresses:
            return None
        return self.addresses[0].address

    @property
    def zones(self) -> tuple[ZoneResult, ...]:
        """Return zone results for the first address."""
        if not self.addresses:
            return ()
        return self.addresses[0].zones

    @property
    def listed(self) -> bool:
        """Return whether any address was listed."""
        return any(item.listed for item in self.addresses)


def dnsbl_qname(address: str, zone: str) -> str:
    """Return the reversed query name for ``zone``.

    IPv4 uses reversed octets. IPv6 uses reversed nibbles, the same form as
    ``ip6.arpa``.
    """
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError as exc:
        raise ValueError(f"not an IP address: {address}") from exc
    if isinstance(parsed, ipaddress.IPv4Address):
        reversed_name = ".".join(reversed(str(parsed).split(".")))
    else:
        nibbles = parsed.exploded.replace(":", "")
        reversed_name = ".".join(reversed(nibbles))
    return reversed_name + "." + zone.strip().strip(".")


def spamhaus_query_zone(zone: str, key: str | None) -> str:
    """Return the zone name to query, applying a Spamhaus DQS key when set."""
    cleaned = (key or "").strip()
    if not cleaned or not zone.endswith(".spamhaus.org"):
        return zone
    label = zone[: -len(".spamhaus.org")]
    if not label:
        return zone
    return f"{cleaned}.{label}.dq.spamhaus.net"


def check(
    target: str,
    *,
    zones: Sequence[str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    resolver: NameResolver | None = None,
    resolve_address: ResolveAddress | None = None,
    spamhaus_key: str | None = None,
    query_name: str | None = None,
    exchanger: str | None = None,
) -> CheckResult:
    """Check ``target`` against DNSBL zones.

    A hostname is resolved to every A and AAAA address. Each address is
    checked against the zones that support that family. A ``127.0.0.0/8``
    answer is a listing, except Spamhaus ``127.255.255.0/24`` responses and
    Abusix policy codes ``127.0.0.11`` and ``127.0.0.12``.

    Parameters
    ----------
    target:
        IP address or hostname. Leading and trailing whitespace is ignored.
    zones:
        Zone names to query. ``None`` uses :data:`DEFAULT_ZONES`.
    timeout:
        Per-zone resolver timeout and lifetime, in seconds.
    resolver:
        Resolver used for lookups. The default is a ``dnspython`` resolver.
    resolve_address:
        Optional callable that returns one address and skips host lookup.
    spamhaus_key:
        Spamhaus Data Query Service key. Spamhaus zones are queried as
        ``<key>.<zone>.dq.spamhaus.net``.
    query_name:
        Name to show as the query. Defaults to ``target``.
    exchanger:
        Mail exchanger this check belongs to, when walking MX records.

    Returns
    -------
    CheckResult
        One result per resolved address.

    Raises
    ------
    ValueError
        If ``target`` is empty, ``timeout`` is not greater than zero, or no
        zone names remain after normalisation.
    """
    if not math.isfinite(timeout) or timeout <= 0:
        raise ValueError("timeout must be greater than 0")
    subject = target.strip()
    if not subject:
        raise ValueError("target must not be empty")
    query = (query_name or subject).strip()
    chosen = _normalise_zones(DEFAULT_ZONES if zones is None else zones)
    if not chosen:
        raise ValueError("at least one zone is required")

    try:
        addresses = _addresses_for(subject, resolver, resolve_address, timeout)
    except ValueError as exc:
        return CheckResult(query=query, error=str(exc), exchanger=exchanger)

    blocks = tuple(
        _check_address(address, chosen, resolver, timeout, spamhaus_key) for address in addresses
    )
    return CheckResult(query=query, addresses=blocks, exchanger=exchanger)


def check_mail_exchangers(
    domain: str,
    *,
    zones: Sequence[str] | None = None,
    timeout: float = DEFAULT_TIMEOUT,
    resolver: NameResolver | None = None,
    spamhaus_key: str | None = None,
) -> tuple[CheckResult, ...]:
    """Check every address of each MX host for ``domain``.

    Exchangers are ordered by MX preference. A domain with no MX records
    produces one result whose ``error`` is ``no mail exchangers``. An IP
    address produces ``mail exchanger lookup requires a domain``.
    """
    name = domain.strip()
    if not name:
        raise ValueError("target must not be empty")
    try:
        ipaddress.ip_address(name)
    except ValueError:
        pass
    else:
        return (CheckResult(query=name, error="mail exchanger lookup requires a domain"),)
    active: NameResolver = resolver if resolver is not None else _BoundResolver(timeout)
    try:
        hosts = resolve_mx_hosts(name, active)
    except ValueError as exc:
        return (CheckResult(query=name, error=str(exc)),)
    return tuple(
        check(
            host,
            zones=zones,
            timeout=timeout,
            resolver=resolver,
            spamhaus_key=spamhaus_key,
            query_name=name,
            exchanger=host,
        )
        for host in hosts
    )


def resolve_ipv4(target: str) -> str:
    """Return the first IPv4 address for ``target``.

    Raises
    ------
    ValueError
        If ``target`` is an IPv6 address or the name cannot be resolved.
    """
    import socket

    try:
        parsed = ipaddress.ip_address(target)
    except ValueError:
        parsed = None
    if isinstance(parsed, ipaddress.IPv6Address):
        raise ValueError("IPv6 addresses are not supported")
    if isinstance(parsed, ipaddress.IPv4Address):
        return str(parsed)
    try:
        infos = socket.getaddrinfo(target, None, socket.AF_INET, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise ValueError("name resolution failed") from exc
    if not infos:
        raise ValueError("name resolution failed")
    address = infos[0][4][0]
    if not isinstance(address, str):
        raise ValueError("name resolution failed")
    return address


def resolve_mx_hosts(domain: str, resolver: NameResolver) -> tuple[str, ...]:
    """Return MX hostnames for ``domain``, lowest preference first."""
    try:
        answer = resolver.resolve(domain, "MX")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as exc:
        raise ValueError("no mail exchangers") from exc
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        raise ValueError("name resolution failed") from exc
    ranked: list[tuple[int, str]] = []
    for record in _iter_records(answer):
        exchange = getattr(record, "exchange", None)
        if exchange is None:
            continue
        preference = int(getattr(record, "preference", 0))
        host = str(exchange).rstrip(".")
        if host:
            ranked.append((preference, host))
    if not ranked:
        raise ValueError("no mail exchangers")
    seen: set[str] = set()
    hosts: list[str] = []
    for _preference, host in sorted(ranked):
        if host in seen:
            continue
        seen.add(host)
        hosts.append(host)
    return tuple(hosts)


def _addresses_for(
    target: str,
    resolver: NameResolver | None,
    resolve_address: ResolveAddress | None,
    timeout: float,
) -> tuple[str, ...]:
    if resolve_address is not None:
        return (resolve_address(target),)
    try:
        parsed = ipaddress.ip_address(target)
    except ValueError:
        parsed = None
    if parsed is not None:
        return (str(parsed),)
    active: NameResolver = resolver if resolver is not None else _BoundResolver(timeout)
    found: list[str] = []
    seen: set[str] = set()
    for rdtype in ("A", "AAAA"):
        try:
            answer = active.resolve(target, rdtype)
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
            continue
        except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
            raise ValueError("name resolution failed") from exc
        for record in _iter_records(answer):
            address = _record_address(record)
            if address and address not in seen:
                seen.add(address)
                found.append(address)
    if not found:
        raise ValueError("name resolution failed")
    return tuple(found)


def _check_address(
    address: str,
    zones: Sequence[str],
    resolver: NameResolver | None,
    timeout: float,
    spamhaus_key: str | None,
) -> AddressResult:
    selected = tuple(zone for zone in zones if _zone_supports(zone, address))
    if not selected:
        family = "IPv6" if ipaddress.ip_address(address).version == 6 else "IPv4"
        return AddressResult(address=address, error=f"no zones support {family}")

    def query(zone: str) -> ZoneResult:
        return _query_zone(resolver, address, zone, timeout, spamhaus_key)

    hits: tuple[ZoneResult, ...]
    if len(selected) == 1:
        hits = (query(selected[0]),)
    else:
        with ThreadPoolExecutor(max_workers=min(32, len(selected))) as pool:
            hits = tuple(pool.map(query, selected))
    return AddressResult(address=address, zones=hits)


def _zone_supports(zone: str, address: str) -> bool:
    """Return whether ``zone`` should be queried for ``address``.

    Known IPv4-only default zones are skipped for IPv6. Every other zone,
    including a name passed with ``--zone``, is queried for both families.
    """
    if isinstance(ipaddress.ip_address(address), ipaddress.IPv4Address):
        return True
    return zone not in _IPV4_ONLY_ZONES


def _normalise_zones(zones: Sequence[str]) -> tuple[str, ...]:
    seen: set[str] = set()
    chosen: list[str] = []
    for zone in zones:
        name = zone.strip().strip(".")
        if not name or name in seen:
            continue
        seen.add(name)
        chosen.append(name)
    return tuple(chosen)


class _BoundResolver:
    """dnspython resolver with one timeout for both timeout and lifetime."""

    def __init__(self, timeout: float) -> None:
        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout

    def resolve(self, qname: str, rdtype: str) -> object:
        """Resolve ``qname`` for ``rdtype``."""
        return self._resolver.resolve(qname, rdtype)


def _query_zone(
    resolver: NameResolver | None,
    address: str,
    zone: str,
    timeout: float,
    spamhaus_key: str | None,
) -> ZoneResult:
    active: NameResolver = resolver if resolver is not None else _BoundResolver(timeout)
    query_zone = spamhaus_query_zone(zone, spamhaus_key)
    qname = dnsbl_qname(address, query_zone)
    try:
        answer = active.resolve(qname, "A")
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
        return ZoneResult(zone=zone, listed=False, detail="not listed")
    except (dns.exception.Timeout, dns.resolver.NoNameservers) as exc:
        return ZoneResult(zone=zone, listed=False, detail=f"query failed: {exc}")
    except Exception as exc:
        return ZoneResult(zone=zone, listed=False, detail=f"query failed: {exc}")
    codes = _addresses_in(answer)
    listed, detail, kept = _interpret_codes(zone, codes)
    reason = _lookup_reason(active, qname) if listed or kept else ""
    return ZoneResult(
        zone=zone,
        listed=listed,
        detail=detail,
        return_codes=tuple(kept),
        reason=reason,
    )


def _interpret_codes(zone: str, codes: Sequence[str]) -> tuple[bool, str, list[str]]:
    listings: list[str] = []
    notes: list[str] = []
    loopback = ipaddress.ip_network("127.0.0.0/8")
    for code in codes:
        note = _policy_note(zone, code)
        if note:
            notes.append(note)
            continue
        try:
            parsed = ipaddress.ip_address(code)
        except ValueError:
            continue
        if parsed in loopback:
            listings.append(code)
    if listings:
        return True, "listed", listings
    if notes:
        return False, "; ".join(notes), []
    return False, "not listed", []


def _policy_note(zone: str, code: str) -> str | None:
    try:
        parsed = ipaddress.ip_address(code)
    except ValueError:
        return None
    if parsed in ipaddress.ip_network("127.255.255.0/24"):
        return _SPAMHAUS_NOTES.get(code, f"resolver policy {code}")
    if "abusix.zone" in zone and code in _ABUSIX_POLICY:
        return _ABUSIX_POLICY[code]
    return None


def _lookup_reason(resolver: NameResolver, qname: str) -> str:
    try:
        answer = resolver.resolve(qname, "TXT")
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.exception.Timeout,
        dns.resolver.NoNameservers,
    ):
        return ""
    except Exception:
        return ""
    parts = [text for text in (_record_text(record) for record in _iter_records(answer)) if text]
    return " ".join(parts)


def _iter_records(answer: object) -> list[object]:
    if answer is None:
        return []
    rrset = getattr(answer, "rrset", None)
    if rrset is not None:
        return list(rrset)
    if isinstance(answer, (list, tuple)):
        return list(answer)
    return [answer]


def _addresses_in(answer: object) -> list[str]:
    found: list[str] = []
    for record in _iter_records(answer):
        address = _record_address(record)
        if address:
            found.append(address)
    return found


def _record_address(record: object) -> str | None:
    if isinstance(record, str):
        return record
    address = getattr(record, "address", None)
    if isinstance(address, str):
        return address
    return None


def _record_text(record: object) -> str:
    if isinstance(record, str):
        return record
    strings = getattr(record, "strings", None)
    if strings is None:
        return ""
    chunks: list[str] = []
    for item in strings:
        if isinstance(item, bytes):
            chunks.append(item.decode("utf-8", errors="replace"))
        else:
            chunks.append(str(item))
    return "".join(chunks)
