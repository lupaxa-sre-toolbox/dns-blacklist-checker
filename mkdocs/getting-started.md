# Getting started

## Requirements

- Python 3.13 or newer
- An IPv4 address, IPv6 address, or hostname you are allowed to look up
- DNS resolution for the DNSBL zones you query
- The `dnspython` package, installed with this distribution

## Install

```bash
pip install lupaxa-dns-blacklist-checker
dns-blacklist-checker --help
```

## First run

```bash
dns-blacklist-checker 192.0.2.1 example.com
```

Each address prints one line. A listing names the zones that returned an
answer.

`dnsbl` is an alias for `dns-blacklist-checker`. Both commands accept the same
flags and print the same output. The examples on this site use the full
command name.

Module entry point:

```bash
python -m lupaxa.dns_blacklist_checker --version
```

### From source (development)

```bash
make init
make python-install-dev
dns-blacklist-checker --version
```

## Makefile helpers

```bash
make python-check
make mkdocs-serve
```
