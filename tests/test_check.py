"""DNSBL query behaviour."""

from __future__ import annotations

import ipaddress
import socket
import threading

import dns.exception
import dns.resolver
import pytest

import lupaxa.dns_blacklist_checker.lookup as lookup_mod
from lupaxa.dns_blacklist_checker.lookup import (
    DEFAULT_ZONES,
    check,
    check_mail_exchangers,
    dnsbl_qname,
    resolve_ipv4,
    spamhaus_query_zone,
)


class FakeResolver:
    def __init__(self, answers: dict[object, object]) -> None:
        self.answers = answers
        self.queries: list[tuple[str, str]] = []
        self._lock = threading.Lock()

    def resolve(self, qname: str, rdtype: str) -> object:
        with self._lock:
            self.queries.append((qname, rdtype))
            if (qname, rdtype) in self.answers:
                outcome = self.answers[(qname, rdtype)]
            elif rdtype == "A" and qname in self.answers:
                outcome = self.answers[qname]
            else:
                outcome = dns.resolver.NXDOMAIN()
        if isinstance(outcome, BaseException):
            raise outcome
        return outcome


class _Mx:
    def __init__(self, preference: int, exchange: str) -> None:
        self.preference = preference
        self.exchange = exchange


class _Text:
    def __init__(self, strings: tuple[bytes, ...]) -> None:
        self.strings = strings


class _Address:
    def __init__(self, address: str) -> None:
        self.address = address


class _Answer:
    def __init__(self, records: list[object]) -> None:
        self.rrset = records


def test_default_zones_are_unique_and_include_spamhaus() -> None:
    assert len(DEFAULT_ZONES) == len(set(DEFAULT_ZONES))
    assert "zen.spamhaus.org" in DEFAULT_ZONES
    assert "combined.mail.abusix.zone" in DEFAULT_ZONES
    assert "dnsbl-1.uceprotect.net" in DEFAULT_ZONES
    dropped = (
        "dnsbl.sorbs.net",
        "spam.dnsbl.sorbs.net",
        "sbl.spamhaus.org",
        "xbl.spamhaus.org",
        "pbl.spamhaus.org",
        "cbl.abuseat.org",
        "dnsbl-2.uceprotect.net",
        "dnsbl-3.uceprotect.net",
    )
    for name in dropped:
        assert name not in DEFAULT_ZONES


def test_dnsbl_qname_reverses_ipv4() -> None:
    assert dnsbl_qname("203.0.113.9", "zen.spamhaus.org") == "9.113.0.203.zen.spamhaus.org"
    with pytest.raises(ValueError, match="not an IP address"):
        dnsbl_qname("not-an-ip", "zen.spamhaus.org")


def test_dnsbl_qname_reverses_ipv6() -> None:
    address = "2001:db8::1"
    nibbles = ipaddress.IPv6Address(address).exploded.replace(":", "")
    expected = ".".join(reversed(nibbles)) + ".zen.spamhaus.org"
    assert dnsbl_qname(address, "zen.spamhaus.org") == expected


def test_check_reports_listed_and_clear_zones() -> None:
    listed = "9.113.0.203.zen.spamhaus.org"
    resolver = FakeResolver({listed: ["127.0.0.2"]})
    result = check(
        "203.0.113.9",
        zones=("zen.spamhaus.org", "bl.spamcop.net"),
        resolver=resolver,
    )
    assert result.error is None
    assert result.address == "203.0.113.9"
    assert result.listed is True
    assert result.zones[0].listed is True
    assert result.zones[0].detail == "listed"
    assert result.zones[0].return_codes == ("127.0.0.2",)
    assert result.zones[1].listed is False
    assert result.zones[1].detail == "not listed"
    assert (listed, "A") in resolver.queries


def test_check_records_no_answer_and_unexpected_errors() -> None:
    resolver = FakeResolver(
        {
            "1.2.0.192.bl.spamcop.net": dns.resolver.NoAnswer(),
            "1.2.0.192.zen.spamhaus.org": dns.resolver.NoNameservers(),
            "1.2.0.192.dnsbl.sorbs.net": RuntimeError("boom"),
        }
    )
    result = check(
        "192.0.2.1",
        zones=("bl.spamcop.net", "zen.spamhaus.org", "dnsbl.sorbs.net"),
        resolver=resolver,
    )
    assert result.zones[0].detail == "not listed"
    assert result.zones[1].detail.startswith("query failed:")
    assert result.zones[2].detail == "query failed: boom"


def test_default_resolver_honours_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    created: dict[str, object] = {}

    class _Resolver:
        def __init__(self) -> None:
            self.timeout = 0.0
            self.lifetime = 0.0
            created["resolver"] = self

        def resolve(self, _qname: str, _rdtype: str) -> object:
            raise dns.resolver.NXDOMAIN

    monkeypatch.setattr(lookup_mod.dns.resolver, "Resolver", _Resolver)
    result = check("192.0.2.1", zones=("zen.spamhaus.org",), timeout=2)
    resolver = created["resolver"]
    assert isinstance(resolver, _Resolver)
    assert resolver.timeout == 2
    assert resolver.lifetime == 2
    assert result.zones[0].detail == "not listed"


def test_check_records_query_failure_without_stopping() -> None:
    resolver = FakeResolver(
        {
            "1.2.0.192.bl.spamcop.net": dns.exception.Timeout(),
        }
    )
    result = check(
        "192.0.2.1",
        zones=("bl.spamcop.net", "zen.spamhaus.org"),
        resolver=resolver,
    )
    assert result.listed is False
    assert result.zones[0].detail.startswith("query failed:")
    assert result.zones[1].detail == "not listed"


def test_check_returns_resolution_error() -> None:
    def _fail(_target: str) -> str:
        raise ValueError("name resolution failed")

    result = check("missing.example", zones=("zen.spamhaus.org",), resolve_address=_fail)
    assert result.address is None
    assert result.error == "name resolution failed"
    assert result.zones == ()


def test_check_rejects_empty_target_and_timeout() -> None:
    with pytest.raises(ValueError, match="empty"):
        check("   ")
    with pytest.raises(ValueError, match="timeout"):
        check("192.0.2.1", timeout=0)


def test_check_rejects_empty_zone_list() -> None:
    with pytest.raises(ValueError, match="zone"):
        check("192.0.2.1", zones=(" ", ""))


def test_check_drops_duplicate_zones() -> None:
    resolver = FakeResolver({})
    result = check(
        "192.0.2.1",
        zones=("zen.spamhaus.org", " zen.spamhaus.org ", "bl.spamcop.net"),
        resolver=resolver,
    )
    assert [zone.zone for zone in result.zones] == ["zen.spamhaus.org", "bl.spamcop.net"]


def test_resolve_ipv4_literal_and_ipv6() -> None:
    assert resolve_ipv4("192.0.2.10") == "192.0.2.10"
    with pytest.raises(ValueError, match="IPv6"):
        resolve_ipv4("2001:db8::1")


def _addrinfo(*_args: object, **_kwargs: object) -> list[object]:
    return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("192.0.2.20", 0))]


def _addrinfo_fail(*_args: object, **_kwargs: object) -> list[object]:
    raise socket.gaierror("no such host")


def test_resolve_ipv4_hostname(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _addrinfo)
    assert resolve_ipv4("example.test") == "192.0.2.20"


def _empty_addrinfo(*_args: object, **_kwargs: object) -> list[object]:
    return []


def test_resolve_ipv4_empty_or_non_string(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _empty_addrinfo)
    with pytest.raises(ValueError, match="name resolution failed"):
        resolve_ipv4("empty.test")

    def _non_string(*_args: object, **_kwargs: object) -> list[object]:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (None, 0))]

    monkeypatch.setattr(socket, "getaddrinfo", _non_string)
    with pytest.raises(ValueError, match="name resolution failed"):
        resolve_ipv4("odd.test")


def test_resolve_ipv4_hostname_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(socket, "getaddrinfo", _addrinfo_fail)
    with pytest.raises(ValueError, match="name resolution failed"):
        resolve_ipv4("missing.test")


def test_check_queries_every_address() -> None:
    resolver = FakeResolver(
        {
            ("mail.example", "A"): ["192.0.2.1", "192.0.2.2"],
            ("mail.example", "AAAA"): ["2001:db8::1"],
            "1.2.0.192.zen.spamhaus.org": ["127.0.0.2"],
        }
    )
    result = check(
        "mail.example",
        zones=("zen.spamhaus.org", "bl.spamcop.net"),
        resolver=resolver,
    )
    assert [item.address for item in result.addresses] == [
        "192.0.2.1",
        "192.0.2.2",
        "2001:db8::1",
    ]
    assert result.listed is True
    assert [zone.zone for zone in result.addresses[2].zones] == ["zen.spamhaus.org"]


def test_ipv6_skips_known_ipv4_zones_and_queries_custom_zones() -> None:
    resolver = FakeResolver({})
    result = check(
        "2001:db8::1",
        zones=("bl.spamcop.net", "lists.example"),
        resolver=resolver,
    )
    assert [zone.zone for zone in result.zones] == ["lists.example"]
    assert result.zones[0].detail == "not listed"
    skipped = check("2001:db8::1", zones=("bl.spamcop.net",), resolver=resolver)
    assert skipped.addresses[0].error == "no zones support IPv6"
    assert skipped.listed is False


def test_policy_codes_are_notes() -> None:
    spamhaus = dnsbl_qname("203.0.113.9", "zen.spamhaus.org")
    abusix = dnsbl_qname("192.0.2.2", "combined.mail.abusix.zone")
    resolver = FakeResolver(
        {
            spamhaus: ["127.255.255.254", "127.0.0.2"],
            abusix: ["127.0.0.12"],
        }
    )
    listed = check("203.0.113.9", zones=("zen.spamhaus.org",), resolver=resolver)
    assert listed.listed is True
    assert listed.zones[0].return_codes == ("127.0.0.2",)
    policy = check("192.0.2.2", zones=("combined.mail.abusix.zone",), resolver=resolver)
    assert policy.listed is False
    assert policy.zones[0].detail == "policy: missing reverse DNS"


def test_public_resolver_code_is_not_a_listing() -> None:
    qname = dnsbl_qname("203.0.113.9", "zen.spamhaus.org")
    resolver = FakeResolver({qname: ["127.255.255.254"]})
    result = check("203.0.113.9", zones=("zen.spamhaus.org",), resolver=resolver)
    assert result.listed is False
    assert result.zones[0].detail == "query via public resolver"
    assert result.zones[0].return_codes == ()


def test_txt_reason_is_recorded() -> None:
    qname = dnsbl_qname("203.0.113.9", "zen.spamhaus.org")
    resolver = FakeResolver(
        {
            (qname, "A"): _Answer([_Address("127.0.0.2"), _Address("127.0.0.4")]),
            (qname, "TXT"): _Answer([_Text((b"https://www.spamhaus.org/sbl/query/SBL123",))]),
        }
    )
    result = check("203.0.113.9", zones=("zen.spamhaus.org",), resolver=resolver)
    assert result.zones[0].return_codes == ("127.0.0.2", "127.0.0.4")
    assert "SBL123" in result.zones[0].reason


def test_txt_failure_does_not_drop_a_listing() -> None:
    qname = dnsbl_qname("203.0.113.9", "zen.spamhaus.org")
    resolver = FakeResolver(
        {
            (qname, "A"): ["127.0.0.2"],
            (qname, "TXT"): RuntimeError("txt down"),
        }
    )
    result = check("203.0.113.9", zones=("zen.spamhaus.org",), resolver=resolver)
    assert result.listed is True
    assert result.zones[0].reason == ""


def test_spamhaus_key_rewrites_the_query_name() -> None:
    qname = "9.113.0.203.secret.zen.dq.spamhaus.net"
    resolver = FakeResolver({qname: ["127.0.0.2"]})
    result = check(
        "203.0.113.9",
        zones=("zen.spamhaus.org", "bl.spamcop.net"),
        resolver=resolver,
        spamhaus_key=" secret ",
    )
    assert result.zones[0].zone == "zen.spamhaus.org"
    assert (qname, "A") in resolver.queries
    assert ("9.113.0.203.bl.spamcop.net", "A") in resolver.queries
    assert spamhaus_query_zone("bl.spamcop.net", "secret") == "bl.spamcop.net"
    assert spamhaus_query_zone("zen.spamhaus.org", "  ") == "zen.spamhaus.org"
    assert spamhaus_query_zone(".spamhaus.org", "secret") == ".spamhaus.org"


def test_hostname_resolution_failure() -> None:
    resolver = FakeResolver({("missing.example", "A"): dns.exception.Timeout()})
    result = check("missing.example", zones=("zen.spamhaus.org",), resolver=resolver)
    assert result.address is None
    assert result.error == "name resolution failed"


def test_check_mail_exchangers_orders_by_preference() -> None:
    resolver = FakeResolver(
        {
            ("example.com", "MX"): [
                _Mx(20, "b.example."),
                _Mx(10, "a.example"),
                _Mx(10, "a.example"),
            ],
            ("a.example", "A"): ["192.0.2.1"],
            ("b.example", "A"): ["192.0.2.2"],
        }
    )
    results = check_mail_exchangers(
        "example.com",
        zones=("zen.spamhaus.org",),
        resolver=resolver,
    )
    assert [item.exchanger for item in results] == ["a.example", "b.example"]
    assert results[0].query == "example.com"
    assert results[0].address == "192.0.2.1"
    assert results[1].address == "192.0.2.2"


def test_check_mail_exchangers_errors() -> None:
    missing = check_mail_exchangers(
        "example.com",
        zones=("zen.spamhaus.org",),
        resolver=FakeResolver({}),
    )
    assert missing[0].error == "no mail exchangers"
    address = check_mail_exchangers("192.0.2.1", zones=("zen.spamhaus.org",))
    assert address[0].error == "mail exchanger lookup requires a domain"
    with pytest.raises(ValueError, match="empty"):
        check_mail_exchangers("  ")
    failed = check_mail_exchangers(
        "example.com",
        zones=("zen.spamhaus.org",),
        resolver=FakeResolver({("example.com", "MX"): dns.resolver.NoNameservers()}),
    )
    assert failed[0].error == "name resolution failed"
    timed_out = check_mail_exchangers(
        "example.com",
        zones=("zen.spamhaus.org",),
        resolver=FakeResolver({("example.com", "MX"): dns.exception.Timeout()}),
    )
    assert timed_out[0].error == "name resolution failed"

    class _Bare:
        pass

    empty = check_mail_exchangers(
        "example.com",
        zones=("zen.spamhaus.org",),
        resolver=FakeResolver({("example.com", "MX"): [_Bare(), _Mx(1, "")]}),
    )
    assert empty[0].error == "no mail exchangers"


def test_hostname_with_no_records_and_duplicate_addresses() -> None:
    missing = check("missing.example", zones=("zen.spamhaus.org",), resolver=FakeResolver({}))
    assert missing.error == "name resolution failed"

    class _Numeric:
        def __init__(self) -> None:
            self.address = 7

    class _Plain:
        pass

    class _Mixed:
        def __init__(self) -> None:
            self.strings = ("plain",)

    qname = dnsbl_qname("192.0.2.1", "zen.spamhaus.org")
    resolver = FakeResolver(
        {
            ("mail.example", "A"): ["192.0.2.1", "192.0.2.1", _Numeric()],
            ("mail.example", "AAAA"): dns.resolver.NoAnswer(),
            (qname, "A"): [None, "", "127.0.0.2"],
            (qname, "TXT"): "SBL CSS",
        }
    )
    result = check("mail.example", zones=("zen.spamhaus.org",), resolver=resolver)
    assert [item.address for item in result.addresses] == ["192.0.2.1"]
    assert result.zones[0].reason == "SBL CSS"

    literal = dnsbl_qname("203.0.113.9", "zen.spamhaus.org")
    quiet = FakeResolver({(literal, "A"): ["127.0.0.3"], (literal, "TXT"): [_Plain(), _Mixed()]})
    listed = check("203.0.113.9", zones=("zen.spamhaus.org",), resolver=quiet)
    assert listed.listed is True
    assert listed.zones[0].reason == "plain"
    empty = check(
        "203.0.113.9",
        zones=("zen.spamhaus.org",),
        resolver=FakeResolver({(literal, "A"): None}),
    )
    assert empty.zones[0].detail == "not listed"


def test_non_loopback_answers_are_not_listings() -> None:
    qname = dnsbl_qname("203.0.113.9", "zen.spamhaus.org")
    resolver = FakeResolver({qname: ["192.0.2.9", "not-an-address"]})
    result = check("203.0.113.9", zones=("zen.spamhaus.org",), resolver=resolver)
    assert result.listed is False
    assert result.zones[0].detail == "not listed"
    unknown = FakeResolver({qname: ["127.255.255.1", "127.255.255.252", "127.255.255.255"]})
    noted = check("203.0.113.9", zones=("zen.spamhaus.org",), resolver=unknown)
    assert noted.listed is False
    assert "resolver policy 127.255.255.1" in noted.zones[0].detail
    assert "typing error" in noted.zones[0].detail
    assert "excessive number of queries" in noted.zones[0].detail
    abusix = dnsbl_qname("192.0.2.8", "combined.mail.abusix.zone")
    policy = check(
        "192.0.2.8",
        zones=("combined.mail.abusix.zone",),
        resolver=FakeResolver({abusix: ["127.0.0.11", "127.0.0.200"]}),
    )
    assert policy.listed is True
    assert policy.zones[0].return_codes == ("127.0.0.200",)
