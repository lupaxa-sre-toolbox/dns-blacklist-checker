# DNS Blacklist Checker

`lupaxa-dns-blacklist-checker` looks up an IP address or hostname on DNS
blacklists (DNSBLs). It reverses each address, queries each zone, and reports
which zones listed it.

```bash
pip install lupaxa-dns-blacklist-checker
dns-blacklist-checker 192.0.2.1
```

`dnsbl` is an alias for `dns-blacklist-checker`. Both commands accept the same
flags and print the same output.

A listed address names the zones that answered, with the return code and TXT
reason when the zone provides them. A clear address prints that it is not
blacklisted. Hostnames are checked on every IPv4 and IPv6 address they
resolve to.

## Next steps

- [Getting started](getting-started.md) — install and first run
- [Usage](usage.md) — output, CLI flags, and the library API
- [Reference](reference.md) — defaults, exit codes, and API names
- [Examples](examples.md) — common lookup recipes
