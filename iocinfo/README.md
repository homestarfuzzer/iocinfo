# iocinfo

> IOC enrichment from the command line. Look up IPs, domains, and hashes against multiple threat intel sources — color-coded, clearly labeled, no browser required.

```
$ iocinfo 1.2.3.4

══════════════════════ iocinfo · 1.2.3.4 (ip) ══════════════════════

 🌐  Geolocation  [ip-api.com]
  ┌──────────────────────────────────────────────────────────────┐
  │ IP           1.2.3.4                                         │
  │ Location     Amsterdam, North Holland, Netherlands           │
  │ ISP          Some Provider BV                                │
  │ ASN          AS12345 Some-ASN                                │
  │ Flags        HOSTING/VPS                                     │
  └──────────────────────────────────────────────────────────────┘

 🚨  AbuseIPDB  [score: 87/100]
  ┌──────────────────────────────────────────────────────────────┐
  │ Abuse Score  87/100                                          │  ← red
  │ Reports      412                                             │
  │ Last Report  2026-04-01T03:00:00Z                            │
  └──────────────────────────────────────────────────────────────┘
```

---

## Install

```bash
pip install iocinfo
```

Or with pipx (recommended — keeps it isolated):

```bash
pipx install iocinfo
```

That's it. `iocinfo` is now a command on your system.

---

## Quick Start

```bash
# Look up an IP (auto-detects type)
iocinfo 8.8.8.8

# Look up a domain
iocinfo evil-domain.com

# Look up a hash (MD5, SHA1, or SHA256)
iocinfo d41d8cd98f00b204e9800998ecf8427e

# Query specific sources only
iocinfo 1.2.3.4 --sources abuseipdb shodan

# Force indicator type
iocinfo 1.2.3.4 --type ip
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

| Source | What it provides | Types | Free Tier |
|---|---|---|---|
| [VirusTotal](https://www.virustotal.com) | Detection ratio across 90+ AV engines | IP, Domain, Hash | 500 req/day |
| [AbuseIPDB](https://www.abuseipdb.com) | Abuse confidence score, report history | IP | 1,000 req/day |
| [Shodan](https://shodan.io) | Open ports, banners, CVEs, hostnames | IP | Free (limited) |
| [GreyNoise](https://greynoise.io) | Internet noise classification | IP | Community tier |
| [AlienVault OTX](https://otx.alienvault.com) | Pulse count, threat actor tagging | IP, Domain, Hash | Free |

---

## API Key Setup

Run the setup wizard once to configure your keys:

```bash
iocinfo --setup
```

This walks you through each source, shows you where to get a free API key, and saves everything to `~/.iocinfo/config.ini`.

You can skip any source you don't want — the tool still runs using free sources only.

### Manual config (optional)

Edit `~/.iocinfo/config.ini` directly:

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

Results are color-coded based on verdict:

| Color | Meaning |
|---|---|
| 🟢 Green | Clean / not flagged |
| 🟡 Yellow | Low risk / suspicious |
| 🟠 Orange | Medium risk |
| 🔴 Red | High risk / malicious |

VirusTotal colors are based on detection ratio (e.g. 7/94 = red, 0/94 = green).
AbuseIPDB colors are based on abuse confidence score.

---

## Source Flags

Use `--sources` to query specific sources:

```bash
iocinfo 1.2.3.4 --sources virustotal abuseipdb
iocinfo 1.2.3.4 --sources shodan greynoise
iocinfo evil.com --sources vt threatfox urlhaus
iocinfo <hash> --sources vt urlhaus threatfox otx
```

Available source flags: `virustotal` (or `vt`), `abuseipdb`, `shodan`, `greynoise`, `otx`, `ipapi`, `ipinfo`, `urlhaus`, `threatfox`, `dns`

---

## Requirements

- Python 3.8+
- `rich` (installed automatically)
- Internet access
- API keys for paid sources (optional but recommended)

---

## Getting Free API Keys

| Service | Signup | Daily Limit |
|---|---|---|
| VirusTotal | https://www.virustotal.com/gui/join-us | 500 lookups |
| AbuseIPDB | https://www.abuseipdb.com/register | 1,000 lookups |
| Shodan | https://account.shodan.io/register | Limited free |
| GreyNoise | https://viz.greynoise.io/signup | Community tier |
| AlienVault OTX | https://otx.alienvault.com/accounts/signup | Free |

All free tiers are more than enough for personal SOC/CTF use.

---

## License

MIT — do whatever you want with it.

Built by [homestarfuzzer](https://homestarfuzzer.github.io) · [GitHub](https://github.com/homestarfuzzer/iocinfo)
