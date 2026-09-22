"""Command-line interface."""

from __future__ import annotations

import pytest

from lupaxa.dns_blacklist_checker import AddressResult, CheckResult, ZoneResult
from lupaxa.dns_blacklist_checker.cli import format_result, main


def _result(
    query: str,
    address: str | None,
    zones: tuple[ZoneResult, ...] = (),
    error: str | None = None,
    exchanger: str | None = None,
) -> CheckResult:
    addresses = () if address is None else (AddressResult(address, zones),)
    return CheckResult(query=query, addresses=addresses, error=error, exchanger=exchanger)


def test_format_listed_clear_and_errors() -> None:
    listed = _result(
        "203.0.113.9",
        "203.0.113.9",
        (
            ZoneResult("zen.spamhaus.org", True, "listed"),
            ZoneResult("bl.spamcop.net", False, "not listed"),
            ZoneResult("dnsbl.sorbs.net", False, "query failed: timed out"),
        ),
    )
    assert (
        format_result(listed)
        == "203.0.113.9 (203.0.113.9) is blacklisted on: zen.spamhaus.org (1 zone query failed)"
    )
    clear = _result(
        "192.0.2.1",
        "192.0.2.1",
        (ZoneResult("zen.spamhaus.org", False, "not listed"),),
    )
    assert format_result(clear) == "192.0.2.1 (192.0.2.1) is not blacklisted."
    plural = _result(
        "192.0.2.1",
        "192.0.2.1",
        (
            ZoneResult("a.example", False, "query failed: one"),
            ZoneResult("b.example", False, "query failed: two"),
        ),
    )
    assert format_result(plural).endswith("(2 zone queries failed)")
    failed = _result("missing.example", None, error="name resolution failed")
    assert format_result(failed) == "missing.example error: name resolution failed"


def test_help_and_missing_target(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--help"]) == 0
    assert "TARGET" in capsys.readouterr().out
    assert main([]) == 2


def test_bad_timeout_is_usage_error() -> None:
    assert main(["192.0.2.1", "--timeout", "0"]) == 2
    assert main(["192.0.2.1", "--timeout", "nope"]) == 2


def test_version(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--version"]) == 0
    assert capsys.readouterr().out.strip()


def test_clear_exit_zero(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "lupaxa.dns_blacklist_checker.cli.check",
        lambda *_args, **_kwargs: _result(
            "192.0.2.1",
            "192.0.2.1",
            (ZoneResult("zen.spamhaus.org", False, "not listed"),),
        ),
    )
    assert main(["192.0.2.1", "-z", "zen.spamhaus.org", "--timeout", "2"]) == 0
    assert "is not blacklisted" in capsys.readouterr().out


def test_listed_exit_one(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "lupaxa.dns_blacklist_checker.cli.check",
        lambda *_args, **_kwargs: _result(
            "203.0.113.9",
            "203.0.113.9",
            (ZoneResult("zen.spamhaus.org", True, "listed"),),
        ),
    )
    assert main(["203.0.113.9"]) == 1
    assert "blacklisted on: zen.spamhaus.org" in capsys.readouterr().out


def test_resolution_error_exit_two(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "lupaxa.dns_blacklist_checker.cli.check",
        lambda *_args, **_kwargs: _result("missing.example", None, error="name resolution failed"),
    )
    assert main(["missing.example"]) == 2
    assert "error: name resolution failed" in capsys.readouterr().out


def test_listed_wins_over_resolution_error(monkeypatch: pytest.MonkeyPatch) -> None:
    results = iter(
        [
            _result(
                "203.0.113.9",
                "203.0.113.9",
                (ZoneResult("zen.spamhaus.org", True, "listed"),),
            ),
            _result("missing.example", None, error="name resolution failed"),
        ]
    )
    monkeypatch.setattr(
        "lupaxa.dns_blacklist_checker.cli.check",
        lambda *_args, **_kwargs: next(results),
    )
    assert main(["203.0.113.9", "missing.example"]) == 1


def _boom(*_args: object, **_kwargs: object) -> None:
    raise ValueError("timeout must be greater than 0")


def test_library_value_error_prints_to_stderr(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr("lupaxa.dns_blacklist_checker.cli.check", _boom)
    assert main(["192.0.2.1"]) == 1
    captured = capsys.readouterr()
    assert "timeout must be greater than 0" in captured.err


def test_format_codes_notes_mx_and_several_addresses() -> None:
    coded = _result(
        "203.0.113.9",
        "203.0.113.9",
        (ZoneResult("zen.spamhaus.org", True, "listed", ("127.0.0.2",), "SBL123"),),
    )
    assert (
        format_result(coded)
        == "203.0.113.9 (203.0.113.9) is blacklisted on: zen.spamhaus.org [127.0.0.2] SBL123"
    )
    noted = _result(
        "192.0.2.1",
        "192.0.2.1",
        (ZoneResult("zen.spamhaus.org", False, "query via public resolver"),),
    )
    assert "zen.spamhaus.org: query via public resolver" in format_result(noted)
    exchanged = _result(
        "example.com",
        "192.0.2.10",
        (ZoneResult("zen.spamhaus.org", False, "not listed"),),
        exchanger="mail.example",
    )
    assert format_result(exchanged).startswith("example.com mx=mail.example (192.0.2.10)")
    several = CheckResult(
        query="mail.example",
        addresses=(
            AddressResult("192.0.2.1", (ZoneResult("zen.spamhaus.org", False, "not listed"),)),
            AddressResult("192.0.2.2", (ZoneResult("zen.spamhaus.org", True, "listed"),)),
        ),
    )
    lines = format_result(several).splitlines()
    assert lines[0].endswith("is not blacklisted.")
    assert "192.0.2.2" in lines[1]
    assert "blacklisted on: zen.spamhaus.org" in lines[1]


def test_address_error_exits_two(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(
        "lupaxa.dns_blacklist_checker.cli.check",
        lambda *_args, **_kwargs: CheckResult(
            query="2001:db8::1",
            addresses=(AddressResult("2001:db8::1", error="no zones support IPv6"),),
        ),
    )
    assert main(["2001:db8::1"]) == 2
    assert "no zones support IPv6" in capsys.readouterr().out


def test_spamhaus_key_and_mx_are_forwarded(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, object] = {}

    def _check(*_args: object, **kwargs: object) -> CheckResult:
        seen["key"] = kwargs.get("spamhaus_key")
        return _result(
            "192.0.2.1",
            "192.0.2.1",
            (ZoneResult("zen.spamhaus.org", False, "not listed"),),
        )

    def _mx(*_args: object, **kwargs: object) -> tuple[CheckResult, ...]:
        seen["mx_key"] = kwargs.get("spamhaus_key")
        return (
            _result(
                "example.com",
                "192.0.2.1",
                (ZoneResult("zen.spamhaus.org", False, "not listed"),),
                exchanger="mail.example",
            ),
        )

    monkeypatch.setattr("lupaxa.dns_blacklist_checker.cli.check", _check)
    monkeypatch.setattr("lupaxa.dns_blacklist_checker.cli.check_mail_exchangers", _mx)
    monkeypatch.setenv("SPAMHAUS_DQS_KEY", "from-env")
    assert main(["192.0.2.1"]) == 0
    assert seen["key"] == "from-env"
    assert main(["192.0.2.1", "--spamhaus-key", "from-flag"]) == 0
    assert seen["key"] == "from-flag"
    assert main(["example.com", "--mx", "--spamhaus-key", "mx-key"]) == 0
    assert seen["mx_key"] == "mx-key"
