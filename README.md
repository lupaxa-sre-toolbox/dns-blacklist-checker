<p align="center">
  <a href="https://github.com/lupaxa-sre-toolbox">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/organisations/sre-toolbox/readme-logo.png" alt="SRE Toolbox" />
  </a>
</p>

<h1 align="center">DNS Blacklist Checker</h1>

Check whether an IP address or hostname is listed on DNS blacklists.

Each hostname is resolved to every IPv4 and IPv6 address. Each address is
reversed and queried against the built-in DNSBL zones in parallel. A loopback
answer is a listing, and the line includes the return code and TXT reason when
the zone provides them. Spamhaus `127.255.255.0/24` answers and Abusix
`127.0.0.11` / `127.0.0.12` are notes, not listings. A zone timeout is not a
listing.

## Install

Requires Python 3.13 or newer. `dnspython` is installed with the package.

```bash
pip install lupaxa-dns-blacklist-checker
dns-blacklist-checker --help
```

## CLI

`dns-blacklist-checker` is the command. `dnsbl` is an alias for that same
command: same flags, same output. `python -m lupaxa.dns_blacklist_checker`
runs that same program. Examples use the full command name.

```bash
dns-blacklist-checker 192.0.2.1 example.com
dns-blacklist-checker 2001:db8::1
dns-blacklist-checker 203.0.113.9 --zone zen.spamhaus.org --timeout 2
dns-blacklist-checker example.com --mx
dns-blacklist-checker 203.0.113.9 --spamhaus-key "$SPAMHAUS_DQS_KEY"
```

| Flag              | Default              | Description                                      |
| :---------------- | :------------------- | :----------------------------------------------- |
| `TARGET`          | required, repeatable | IPv4 address, IPv6 address, or hostname          |
| `--timeout`, `-t` | `5`                  | Per-zone DNS timeout in seconds                  |
| `--zone`, `-z`    | built-in zone list   | DNSBL zone; repeat to replace the built-in list  |
| `--mx`            | off                  | Check every address of each mail exchanger       |
| `--spamhaus-key`  | `SPAMHAUS_DQS_KEY`   | Spamhaus Data Query Service key                  |
| `--version`       | —                    | Print the package version and exit               |

`--timeout` must be greater than `0`. It bounds each zone query, and hostname
and MX lookups.

`--zone` replaces the built-in list. Repeat the flag for each zone. Whitespace
and a trailing dot are ignored, and duplicate names are queried once.

`--mx` requires a domain. Exchangers are ordered by preference, and every
address of each one is checked. An IP address with `--mx` is an error.

`--spamhaus-key` rewrites Spamhaus zones to `<key>.<zone>.dq.spamhaus.net`.
The printed zone name stays the public name. When the flag is omitted, the
command reads `SPAMHAUS_DQS_KEY`.

### Exit Codes

| Code | When                                                             |
| :--- | :--------------------------------------------------------------- |
| `0`  | Help, version, or every address resolved and none were listed    |
| `1`  | At least one address is listed, or library input was invalid     |
| `2`  | Usage failed, a target could not be resolved, or no zone applied |

When one target is listed and another cannot be resolved, the command exits
`1`.

## Output

Each address is one line.

```text
192.0.2.1 (192.0.2.1) is not blacklisted.
203.0.113.9 (203.0.113.9) is blacklisted on: zen.spamhaus.org [127.0.0.2] SBL123
example.com (192.0.2.10) is not blacklisted.
example.com (2001:db8::10) is not blacklisted.
example.com mx=mail.example (192.0.2.10) is not blacklisted.
missing.example error: name resolution failed
203.0.113.9 (203.0.113.9) is not blacklisted. (zen.spamhaus.org: query via public resolver)
192.0.2.1 (192.0.2.1) is not blacklisted. (1 zone query failed)
2001:db8::1 (2001:db8::1) error: no zones support IPv6
```

IPv6 queries use nibble names. Built-in zones that publish IPv4 data only are
skipped for IPv6. A zone passed with `--zone` is queried for both families.
If none of the selected zones apply, that address is an error.

## Zones

The built-in list starts with `zen.spamhaus.org` and
`combined.mail.abusix.zone`. It does not include SORBS, the separate Spamhaus
SBL, XBL, and PBL zones, CBL, or UCEPROTECT levels 2 and 3.
`b.barracudacentral.org` answers after the querying address is registered
with Barracuda.

## Library

```python
from lupaxa.dns_blacklist_checker import check

result = check("203.0.113.9", zones=("zen.spamhaus.org",), timeout=5.0)
if result.error:
    print(result.query, result.error)
else:
    for item in result.addresses:
        print(item.address, item.listed)
        for zone in item.zones:
            if zone.listed:
                print(zone.zone, zone.return_codes, zone.reason)
```

`check` returns a result when a name does not resolve. It raises `ValueError`
for an empty target, a non-positive timeout, or a zone list that is empty
after normalisation. `listed` is true when any address was listed.
`check_mail_exchangers` checks each MX host. `dnsbl_qname` builds the
reversed query name.

## Development

```bash
make init
make python-install-dev
make python-check
```

<a href="https://github.com/the-lupaxa-project">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>
