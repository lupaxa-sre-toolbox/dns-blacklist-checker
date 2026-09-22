"""Command-line interface for DNS blacklist checks."""

from __future__ import annotations

import argparse
import math
import os
import sys

from .lookup import (
    DEFAULT_TIMEOUT,
    DEFAULT_ZONES,
    AddressResult,
    CheckResult,
    ZoneResult,
    check,
    check_mail_exchangers,
)
from .version import get_version


def _positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("timeout must be a number") from exc
    if not math.isfinite(timeout) or timeout <= 0:
        raise argparse.ArgumentTypeError("timeout must be greater than 0")
    return timeout


def _exit_code(exc: SystemExit) -> int:
    code = exc.code
    if code is None:
        return 0
    return code if isinstance(code, int) else 1


def _program_name(argv0: str) -> str:
    name = os.path.basename(argv0)
    return "dns-blacklist-checker" if name == "__main__.py" else name


def build_parser() -> argparse.ArgumentParser:
    """Build the ``dns-blacklist-checker`` argument parser."""
    parser = argparse.ArgumentParser(
        description=("Check whether an IP address or hostname is listed on DNS blacklists."),
    )
    parser.add_argument(
        "targets",
        nargs="+",
        metavar="TARGET",
        help="IPv4 address, IPv6 address, or hostname",
    )
    parser.add_argument(
        "-t",
        "--timeout",
        type=_positive_timeout,
        default=DEFAULT_TIMEOUT,
        metavar="SECONDS",
        help=f"Per-zone DNS timeout in seconds (default: {DEFAULT_TIMEOUT:g})",
    )
    parser.add_argument(
        "-z",
        "--zone",
        action="append",
        dest="zones",
        metavar="ZONE",
        help="DNSBL zone to query (repeatable; default: the built-in zone list)",
    )
    parser.add_argument(
        "--mx",
        action="store_true",
        help="Check every address of each mail exchanger for a domain",
    )
    parser.add_argument(
        "--spamhaus-key",
        default=None,
        metavar="KEY",
        help="Spamhaus DQS key (default: the SPAMHAUS_DQS_KEY environment variable)",
    )
    parser.add_argument("--version", action="version", version=get_version())
    return parser


def _prefix(result: CheckResult) -> str:
    if result.exchanger:
        return f"{result.query} mx={result.exchanger}"
    return result.query


def _zone_label(zone: ZoneResult) -> str:
    label = zone.zone
    if zone.return_codes:
        label += f" [{', '.join(zone.return_codes)}]"
    if zone.reason:
        label += f" {zone.reason}"
    return label


def _format_address(result: CheckResult, item: AddressResult) -> str:
    subject = f"{_prefix(result)} ({item.address})"
    if item.error:
        return f"{subject} error: {item.error}"
    listed = [_zone_label(zone) for zone in item.zones if zone.listed]
    failed = sum(1 for zone in item.zones if zone.detail.startswith("query failed"))
    notes = [
        f"{zone.zone}: {zone.detail}"
        for zone in item.zones
        if not zone.listed
        and zone.detail != "not listed"
        and not zone.detail.startswith("query failed")
    ]
    if listed:
        line = f"{subject} is blacklisted on: {', '.join(listed)}"
    else:
        line = f"{subject} is not blacklisted."
    if notes:
        line += f" ({'; '.join(notes)})"
    if failed:
        noun = "zone query" if failed == 1 else "zone queries"
        line += f" ({failed} {noun} failed)"
    return line


def format_result(result: CheckResult) -> str:
    """Return the output for one target, one line per address."""
    if not result.addresses:
        message = result.error or "name resolution failed"
        return f"{_prefix(result)} error: {message}"
    return "\n".join(_format_address(result, item) for item in result.addresses)


def main(argv: list[str] | None = None) -> int:
    """Run the CLI and return a process exit code."""
    parser = build_parser()
    try:
        args = parser.parse_args(argv)
    except SystemExit as exc:
        return _exit_code(exc)

    listed = False
    failed = False
    zones = tuple(args.zones) if args.zones else DEFAULT_ZONES
    spamhaus_key = args.spamhaus_key or os.environ.get("SPAMHAUS_DQS_KEY")
    for target in args.targets:
        try:
            if args.mx:
                results = check_mail_exchangers(
                    target,
                    zones=zones,
                    timeout=args.timeout,
                    spamhaus_key=spamhaus_key,
                )
            else:
                results = (
                    check(
                        target,
                        zones=zones,
                        timeout=args.timeout,
                        spamhaus_key=spamhaus_key,
                    ),
                )
        except ValueError as exc:
            print(f"{_program_name(sys.argv[0])}: {exc}", file=sys.stderr)
            return 1
        for result in results:
            print(format_result(result))
            if result.listed:
                listed = True
            if result.error or any(item.error for item in result.addresses):
                failed = True
    if listed:
        return 1
    if failed:
        return 2
    return 0
