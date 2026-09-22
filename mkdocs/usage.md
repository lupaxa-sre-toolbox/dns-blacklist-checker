# Usage

## Output

A clear address:

```text
192.0.2.1 (192.0.2.1) is not blacklisted.
```

A listed address names the zone, the return code, and the TXT reason:

```text
203.0.113.9 (203.0.113.9) is blacklisted on: zen.spamhaus.org [127.0.0.2] SBL123
```

A hostname is resolved to every A and AAAA address. Each address is one line:

```text
example.com (192.0.2.10) is not blacklisted.
example.com (2001:db8::10) is not blacklisted.
```

`--mx` resolves the domain's mail exchangers, then checks every address of
each exchanger:

```text
example.com mx=mail.example (192.0.2.10) is not blacklisted.
```

A name that does not resolve:

```text
missing.example error: name resolution failed
```

Spamhaus answers in `127.255.255.0/24`, and Abusix `127.0.0.11` / `127.0.0.12`,
are notes rather than listings:

```text
203.0.113.9 (203.0.113.9) is not blacklisted. (zen.spamhaus.org: query via public resolver)
```

IPv6 addresses are checked with nibble queries. Built-in zones that only
publish IPv4 data are skipped. A zone you pass with `--zone` is queried for
both families. If none of the selected zones can be queried:

```text
2001:db8::1 (2001:db8::1) error: no zones support IPv6
```

A zone that times out or returns a resolver error is not a listing. The line
counts those failures:

```text
192.0.2.1 (192.0.2.1) is not blacklisted. (1 zone query failed)
```

## CLI

`dns-blacklist-checker` is the command. `dnsbl` is an alias for that same
command: same flags, same output.

```bash
dns-blacklist-checker 192.0.2.1 203.0.113.9
dns-blacklist-checker example.com --timeout 2
dns-blacklist-checker 203.0.113.9 --zone zen.spamhaus.org --zone bl.spamcop.net
dns-blacklist-checker example.com --mx
dns-blacklist-checker 203.0.113.9 --spamhaus-key "$SPAMHAUS_DQS_KEY"
```

`--zone` replaces the built-in list. Repeat the flag for each zone you want.
Whitespace and a trailing dot are ignored, and duplicate names are queried
once.

`--mx` requires a domain. It orders exchangers by preference and checks every
address of each one. Passing a bare address with `--mx` is an error.

`--spamhaus-key` rewrites Spamhaus zones to
`<key>.<zone>.dq.spamhaus.net`. The printed zone name stays the public name.
When the flag is omitted, the command reads `SPAMHAUS_DQS_KEY`.

## Library

```python
from lupaxa.dns_blacklist_checker import check

result = check("203.0.113.9", timeout=5.0)
if result.error:
    print(result.query, result.error)
else:
    for item in result.addresses:
        print(item.address, item.listed)
        for zone in item.zones:
            if zone.listed:
                print(zone.zone, zone.return_codes, zone.reason)
```

`check` returns a result for name-resolution failures. It raises `ValueError`
for an empty target, a non-positive timeout, or a zone list that is empty
after normalisation.
