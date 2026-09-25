<p align="center">
  <a href="https://github.com/lupaxa-sre-toolbox">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/organisations/sre-toolbox/readme-logo.png" alt="SRE Toolbox" />
  </a>
</p>

<h1 align="center">DNS Blacklist Checker</h1>

Check whether an IP address or hostname is listed on DNS blacklists.

## Install

```bash
pip install lupaxa-dns-blacklist-checker
dns-blacklist-checker --help
```

## CLI

```bash
dns-blacklist-checker 192.0.2.1 example.com
dns-blacklist-checker 203.0.113.1 --zone zen.spamhaus.org --timeout 5
python -m lupaxa.dns_blacklist_checker --version
```

`dnsbl` is an alias for `dns-blacklist-checker`. Both commands accept the same
flags and print the same output. `python -m lupaxa.dns_blacklist_checker` runs
that same program.

The tool resolves each hostname to every IPv4 and IPv6 address, reverses the
address, and queries the built-in DNSBL zones. A loopback answer means the
address is listed. Spamhaus and Abusix policy codes are reported as notes.

## Library

```python
from lupaxa.dns_blacklist_checker import check

result = check("203.0.113.9", zones=("zen.spamhaus.org",))
print(result.listed, [item.address for item in result.addresses])
```

## Development

```bash
make init
make python-install-dev
make python-check
make mkdocs-serve
```

## Documentation

The published guide is at
<https://dns-blacklist-checker.thelupaxaproject.org/>.

Site Markdown lives in `mkdocs/`.

<a href="https://github.com/the-lupaxa-project">
    <img src="https://raw.githubusercontent.com/the-lupaxa-project/brand-assets/master/logos/components/footer-for-child-orgs.svg" alt="The Lupaxa Project Footer" width="100%" />
</a>
