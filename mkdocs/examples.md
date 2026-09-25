# Examples

`dnsbl` is an alias for `dns-blacklist-checker`. The shell examples below use
the full command name. Swap in `dnsbl` anywhere you would type
`dns-blacklist-checker`.

## One Address, Built-in Zones

```bash
dns-blacklist-checker 203.0.113.9
```

## Several Targets

```bash
dns-blacklist-checker 192.0.2.1 198.51.100.8 mail.example.com
```

## One Zone and a Shorter Timeout

```bash
dns-blacklist-checker 203.0.113.9 --zone zen.spamhaus.org --timeout 2
```

## Library, Selected Zones

```python
from lupaxa.dns_blacklist_checker import check

result = check(
    "mail.example.com",
    zones=("zen.spamhaus.org", "bl.spamcop.net"),
    timeout=2.0,
)
for item in result.addresses:
    print(result.query, item.address, item.listed)
```

## IPv6 Address

```bash
dns-blacklist-checker 2001:db8::1
```

## Mail Exchangers

```bash
dns-blacklist-checker example.com --mx
```

## Spamhaus Data Query Service

```bash
export SPAMHAUS_DQS_KEY=your-key
dns-blacklist-checker 203.0.113.9 --spamhaus-key "$SPAMHAUS_DQS_KEY"
```

## Query Name

```python
from lupaxa.dns_blacklist_checker import dnsbl_qname

print(dnsbl_qname("203.0.113.9", "zen.spamhaus.org"))
# 9.113.0.203.zen.spamhaus.org
```
