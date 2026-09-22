# Reference

## Commands

| Command                                  | Role                                     |
| :--------------------------------------- | :--------------------------------------- |
| `dns-blacklist-checker`                  | The installed command                    |
| `dnsbl`                                  | Alias for `dns-blacklist-checker`        |
| `python -m lupaxa.dns_blacklist_checker` | The same program, run as a Python module |

`dnsbl` accepts the same flags and prints the same output as
`dns-blacklist-checker`.

## CLI arguments

| Flag              | Default              | Description                                      |
| :---------------- | :------------------- | :----------------------------------------------- |
| `TARGET`          | required, repeatable | IPv4 address, IPv6 address, or hostname          |
| `--timeout`, `-t` | `5`                  | Per-zone DNS timeout in seconds                  |
| `--zone`, `-z`    | built-in zone list   | DNSBL zone; repeat to replace the built-in list  |
| `--mx`            | off                  | Check every address of each mail exchanger       |
| `--spamhaus-key`  | `SPAMHAUS_DQS_KEY`   | Spamhaus Data Query Service key                  |
| `--version`       | —                    | Print the package version and exit               |

`--timeout` must be greater than `0`. It sets both the resolver timeout and
the resolver lifetime for each zone, and for hostname and MX lookups.

## Exit codes

| Code | When                                                              |
| :--- | :---------------------------------------------------------------- |
| `0`  | Help, version, or every address resolved and none were listed     |
| `1`  | At least one address is listed, or library input was invalid      |
| `2`  | Usage failed, a target could not be resolved, or no zone applied  |

When one target is listed and another cannot be resolved, the command exits
`1`.

## Library

| Name                    | Meaning                                                      |
| :---------------------- | :----------------------------------------------------------- |
| `check`                 | Look up one target and return a `CheckResult`                |
| `check_mail_exchangers` | Look up each MX host and return one `CheckResult` per host   |
| `dnsbl_qname`           | Build the reversed IPv4 or IPv6 query name for a zone        |
| `spamhaus_query_zone`   | Rewrite a Spamhaus zone when a DQS key is set                |
| `resolve_ipv4`          | Resolve a hostname to its first IPv4 address                 |
| `CheckResult`           | Frozen result: query, addresses, error, and exchanger        |
| `AddressResult`         | Frozen result for one address and its zone outcomes          |
| `ZoneResult`            | One zone: `zone`, `listed`, `detail`, return codes, reason   |
| `DEFAULT_ZONES`         | Built-in DNSBL zone names                                    |
| `DEFAULT_TIMEOUT`       | Default per-zone timeout (`5.0`)                             |
| `get_version()`         | Return the package version string                            |

`CheckResult.address` and `CheckResult.zones` are the first address.
`listed` is true when any address was listed. `exchanger` is set for MX
checks.

`detail` is `listed`, `not listed`, a policy note, or `query failed: ...`.
A query failure is not a listing. `return_codes` holds the loopback codes
that counted as a listing, and `reason` is the TXT record when one was
returned.

`DEFAULT_ZONES` starts with `zen.spamhaus.org` and
`combined.mail.abusix.zone`. It does not include SORBS, the separate
Spamhaus SBL, XBL, and PBL zones, CBL, or UCEPROTECT levels 2 and 3.
IPv6 queries skip the built-in zones that publish IPv4 data only.
`b.barracudacentral.org` answers after the querying address is registered
with Barracuda.

A name that does not resolve sets `error` and leaves `addresses` empty. An
empty target, a bad timeout, or an empty zone list raises `ValueError`.
