<!-- markdownlint-disable -->
<p align="center">
  <a href="https://github.com/lupaxa-sre-toolbox">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/organisations/sre-toolbox/readme-logo.png" alt="Project Logo" width="256"/><br/>
  </a>
</p>
<h3 align="center">
  The Lupaxa SRE Toolbox<br />
  Part of The Lupaxa Project
</h3>

<br />

# lupaxa-dns-blacklist-checker

Check whether an IP address or hostname is listed on DNS blacklists.

## Features

- Query a built-in list of DNSBL zones in parallel
- Accept IPv4 addresses, IPv6 addresses, and hostnames
- Check every address a hostname resolves to
- Check every address of each mail exchanger with `--mx`
- Report the return code and TXT reason for a listing
- Treat Spamhaus and Abusix policy codes as notes, not listings
- Use a Spamhaus Data Query Service key with `--spamhaus-key` or `SPAMHAUS_DQS_KEY`
- Record a zone query failure without treating it as a listing
- Override the zone list and the per-zone timeout
- Install `dns-blacklist-checker`, with `dnsbl` as an alias for the same command
- Use the `check` library API
- Depend only on `dnspython` at runtime

## Installation

### From PyPI

```bash
pip install lupaxa-dns-blacklist-checker
```

### From source (development mode)

```bash
pip install -e ".[dev]"
```

Requires Python 3.13+.

## Library quick start

```python
from lupaxa.dns_blacklist_checker import check

result = check("203.0.113.9", zones=("zen.spamhaus.org", "bl.spamcop.net"))
for item in result.addresses:
    print(item.address, item.listed)
    for zone in item.zones:
        print(zone.zone, zone.detail, zone.return_codes, zone.reason)
```

## CLI quick start

```bash
dns-blacklist-checker --help
dns-blacklist-checker 192.0.2.1 example.com
dns-blacklist-checker 203.0.113.1 --zone zen.spamhaus.org --timeout 5
```

`dnsbl` is an alias for `dns-blacklist-checker`. Both commands accept the same
flags and print the same output.

You can also run the CLI as a module:

```bash
python -m lupaxa.dns_blacklist_checker --help
python -m lupaxa.dns_blacklist_checker --version
```

## Options

- `TARGET`: one or more IPv4 addresses, IPv6 addresses, or hostnames
- `--timeout`, `-t`: per-zone DNS timeout in seconds; default `5`
- `--zone`, `-z`: DNSBL zone to query; repeat to replace the built-in list
- `--mx`: check every address of each mail exchanger for a domain
- `--spamhaus-key`: Spamhaus Data Query Service key; default `SPAMHAUS_DQS_KEY`
- `--version`: print the package version

## Documentation

Online documentation:

[Documentation](https://dns-blacklist-checker.thelupaxaproject.org/)

Source repository:

[GitHub](https://github.com/lupaxa-sre-toolbox/dns-blacklist-checker)

### Serve docs locally

From a clone of the repository:

```bash
make mkdocs-serve
```

Then open the local URL printed by MkDocs in your browser.

## Development

Clone the repository and install with Make:

```bash
make init                # first-time makefile-skills checkout
make python-install-dev  # editable install with [dev]
make python-check        # lint, type-check, and test
```

<a href="https://github.com/the-lupaxa-project">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>
