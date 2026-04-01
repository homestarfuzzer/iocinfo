# iocinfo

> IOC enrichment from the command line. Look up IPs, domains, and hashes against multiple threat intel sources — color-coded, clearly labeled, no browser required.

```
$ iocinfo 1.2.3.4

────────────────── iocinfo · 1.2.3.4 (ip) ──────────────────

 🌐  Geolocation  [ip-api.com]
 ╭──────────────────────────────────────────────────────╮
 │ IP           1.2.3.4                                 │
 │ Location     Amsterdam, North Holland, Netherlands   │
 │ ISP          Some Provider BV                        │
 │ ASN          AS12345 Some-ASN                        │
 │ Flags        HOSTING/VPS                             │
 ╰──────────────────────────────────────────────────────╯

 🚨  AbuseIPDB  [score: 87/100]          (shown in red)
 ╭──────────────────────────────────────────────────────╮
 │ Abuse Score  87/100                                  │
 │ Reports      412                                     │
 │ Last Report  2026-04-01T03:00:00Z                    │
 ╰──────────────────────────────────────────────────────╯
```

---

## Install

```bash
pip install git+https://github.com/homestarfuzzer/iocinfo.git
```

That's it. `iocinfo` is now a command on your system.

> **Coming soon:** `pip install iocinfo` once published to PyPI.

---

## Quick Start

```bash
# Look up an IP (type is auto-detected)
iocinfo 8.8.8.8

# Look up a domain
iocinfo evil-domain.com

# Look up a hash (MD5, SHA1, or SHA256)
iocinfo d41d8cd98f00b204e9800998ecf8427e

# Query specific sources only
iocinfo 1.2.3.4 --source abuseipdb

# Query multiple specific sources
iocinfo 1.2.3.4 --source vt abuseipdb shodan

# See all options
iocinfo --help
```

---

## Sources

### Free — no API key needed

| Source | What it provides | Types |
|---|---|---|
| [ip-api.com](https://ip-api.com) | Geolocation, ASN, ISP, proxy/hosting flags | IP |
| [ipinfo.io](https://ipinfo.io) | Hostname, org, ASN | IP |
| [ThreatFox](https://threatfox.abuse.ch) | Malware family, confidence score, tags | IP, Domain, Hash |
| [URLhaus](https://urlhaus.abuse.ch) | Malware URLs, file type, signatures | Domain, Hash |
| DNS | Live DNS resolution | Domain |

### Paid — free API keys available

| Service | What it provides | Types | Free Tier |
|---|---|---|---|
| [VirusTotal](https://www.virustotal.com) | Detection ratio across 90+ AV engines | IP, Domain, Hash | 500 req/day |
| [AbuseIPDB](https://www.abuseipdb.com) | Abuse confidence score, report history | IP | 1,000 req/day |
| [Shodan](https://shodan.io) | Open ports, banners, CVEs, hostnames | IP | Free (limited) |
| [GreyNoise](https://greynoise.io) | Internet noise classification | IP | Community tier |
| [AlienVault OTX](https://otx.alienvault.com) | Pulse count, threat actor tagging | IP, Domain, Hash | Free |

---

## API Key Setup

Run the setup wizard once:

```bash
iocinfo --setup
```

This walks you through each source, shows where to get a free key, and saves to `~/.iocinfo/config.ini`. Skip any source you don't have — free sources work with zero config.

### Manual config

```ini
[virustotal]
api_key = YOUR_VT_KEY_HERE

[abuseipdb]
api_key = YOUR_ABUSEIPDB_KEY_HERE

[shodan]
api_key = YOUR_SHODAN_KEY_HERE

[greynoise]
api_key = YOUR_GREYNOISE_KEY_HERE

[otx]
api_key = YOUR_OTX_KEY_HERE

[ipinfo]
token = YOUR_IPINFO_TOKEN_HERE
```

---

## Output Colors

| Color | Meaning |
|---|---|
| 🟢 Green | Clean / not flagged |
| 🟡 Yellow | Low risk / suspicious |
| 🟠 Orange | Medium risk |
| 🔴 Red | High risk / malicious |

VirusTotal: based on detection ratio (7/94 → red, 0/94 → green).
AbuseIPDB: based on confidence score (0 → green, 75+ → red).

---

## Source Flags

```bash
iocinfo 1.2.3.4 --source virustotal
iocinfo 1.2.3.4 --source abuseipdb shodan
iocinfo evil.com --source vt threatfox urlhaus
iocinfo <hash> --source vt urlhaus threatfox otx
```

All flags: `vt` / `virustotal`, `abuseipdb`, `shodan`, `greynoise`, `otx`, `ipapi`, `ipinfo`, `urlhaus`, `threatfox`, `dns`

---

## Requirements

- Python 3.8+
- `rich` (installed automatically)
- API keys optional — free sources work out of the box

---

## Getting Free API Keys

| Service | Signup | Daily Limit |
|---|---|---|
| VirusTotal | https://www.virustotal.com/gui/join-us | 500 |
| AbuseIPDB | https://www.abuseipdb.com/register | 1,000 |
| Shodan | https://account.shodan.io/register | Limited |
| GreyNoise | https://viz.greynoise.io/signup | Community |
| AlienVault OTX | https://otx.alienvault.com/accounts/signup | Free |

---

## License

MIT — do whatever you want with it.

Built by [homestarfuzzer](https://homestarfuzzer.github.io) · [GitHub](https://github.com/homestarfuzzer/iocinfo)
