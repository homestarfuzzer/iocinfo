# iocinfo

IOC enrichment from the command line. Drop in an IP, domain, or hash and get threat intel back instantly, color-coded and clearly labeled. No browser needed, no dashboards to navigate.

Built for SOC analysts and threat hunters who want answers fast.

```
pip install git+https://github.com/homestarfuzzer/iocinfo.git
```

---

## Demo

```
$ iocinfo 185.220.101.35

 ⠄ ⢀⡀ ⢀⣀ ⠄ ⣀⡀ ⣰⡁ ⢀⡀
 ⠇ ⠣⠜ ⠣⠤ ⠇ ⠇⠸ ⢸  ⠣⠜  v1.1

  185.220.101.35  (ip)

  🚨 AbuseIPDB 100/100  ·  🦠 VT 8/94  ·  📡 GreyNoise malicious  ·  ☠️ ThreatFox: TrickBot

 ╭─── 🌐  Geolocation  [ip-api.com] ─────────────────────────────╮
 │ IP          185.220.101.35                                     │
 │ Location    Frankfurt, Hesse, Germany                          │
 │ ISP         Tor Project                                        │
 │ ASN         AS60729 Relayon UG                                 │
 │ Flags       HOSTING/VPS                                        │
 ╰────────────────────────────────────────────────────────────────╯

 ╭─── 🏢  RDAP / WHOIS  [rdap.org] ──────────────────────────────╮
 │ Network     RELAYON                                            │
 │ CIDR        185.220.96.0/21                                    │
 │ Country     DE                                                 │
 │ Registered  2019-04-05                                         │
 │ Org         Relayon UG                                         │
 │ Abuse Email abuse@relayon.org                                  │
 ╰────────────────────────────────────────────────────────────────╯

 ╭─── 🚨  AbuseIPDB  [score: 100/100] ───────────────────────────╮  (red)
 │ Abuse Score    100/100                                         │
 │ Total Reports  4,821                                           │
 │ Distinct Users 312                                             │
 │ Last Reported  2026-04-18T06:12:00Z                            │
 │ Usage Type     Tor Exit Node                                   │
 │ ISP            Tor Project                                     │
 │ Tor Node       Yes                                             │
 ╰────────────────────────────────────────────────────────────────╯

 ╭─── 🦠  VirusTotal  [8/94 engines] ────────────────────────────╮  (red)
 │ Detections  8/94                                               │
 │ Malicious   8                                                  │
 │ Suspicious  0                                                  │
 │ Undetected  86                                                 │
 │ Country     DE                                                 │
 │ Network     185.220.96.0/21                                    │
 │ AS Owner    Relayon UG                                         │
 ╰────────────────────────────────────────────────────────────────╯

 ╭─── 📡  GreyNoise  [malicious] ────────────────────────────────╮  (red)
 │ Noise          Yes                                             │
 │ Classification malicious                                       │
 │ Last Seen      2026-04-17                                      │
 ╰────────────────────────────────────────────────────────────────╯

 ╭─── 🛰️  Shodan ─────────────────────────────────────────────────╮
 │ Open Ports  443, 9001, 9030                                    │
 │ Tags        tor                                                │
 │ Last Update 2026-04-17T21:30:00                                │
 ╰────────────────────────────────────────────────────────────────╯

──────────────────────────────────────────────────────────────────
```

Sections only appear when a source has data. Empty sources are silently skipped.

---

## Install

```bash
pip install git+https://github.com/homestarfuzzer/iocinfo.git
```

On Kali Linux and other systems with externally-managed Python environments, use `pipx` instead:

```bash
pipx install git+https://github.com/homestarfuzzer/iocinfo.git
```

To upgrade or reinstall:

```bash
pipx install --force git+https://github.com/homestarfuzzer/iocinfo.git
```

Python 3.8+ and `rich` are the only requirements. `rich` is installed automatically.

After install, verify everything is working:

```bash
iocinfo --help
```

---

## Quick Start

Type is auto-detected. Just pass the indicator:

```bash
iocinfo 185.220.101.35         # IP
iocinfo evil-domain.com        # domain
iocinfo d41d8cd98f00b204e9800998ecf8427e   # hash (MD5, SHA1, or SHA256)
```

Query specific sources only:

```bash
iocinfo 1.2.3.4 --source abuseipdb
iocinfo 1.2.3.4 --source vt abuseipdb shodan
iocinfo evil.com --source vt threatfox urlhaus crtsh
```

Run the setup wizard once to configure API keys:

```bash
iocinfo --setup
```

---

## Output

Sections are color-coded by severity:

| Color | Meaning |
|---|---|
| Green | Clean or not flagged |
| Yellow | Low risk or suspicious |
| Orange | Medium risk |
| Red | High risk or confirmed malicious |

A compact verdict line appears at the top when any source flags the indicator. Sections only render when a source returned actual data, so you never see empty panels or "not found" noise.

---

## Sources

### Free: no API key needed

| Source | What it provides | Types |
|---|---|---|
| [ip-api.com](https://ip-api.com) | Geolocation, ASN, ISP, proxy/hosting flags | IP |
| [ipinfo.io](https://ipinfo.io) | Hostname, org, ASN | IP |
| [rdap.org](https://rdap.org) | RDAP/WHOIS registration data, abuse contacts | IP, Domain |
| [dns.google](https://dns.google) | Full DNS records: A, MX, NS, TXT | Domain |
| [crt.sh](https://crt.sh) | Certificate Transparency logs, issuer history | Domain |
| [ThreatFox](https://threatfox.abuse.ch) | Malware family, confidence score, tags | IP, Domain, Hash |
| [URLhaus](https://urlhaus.abuse.ch) | Malware URLs, file type, signatures | Domain, Hash |

### Paid: free API keys available

| Service | What it provides | Types | Free Tier |
|---|---|---|---|
| [VirusTotal](https://www.virustotal.com) | Detection ratio across 90+ AV engines | IP, Domain, Hash | 500 req/day |
| [AbuseIPDB](https://www.abuseipdb.com) | Abuse confidence score, report history | IP | 1,000 req/day |
| [Shodan](https://shodan.io) | Open ports, banners, CVEs, hostnames | IP | Free (limited) |
| [GreyNoise](https://greynoise.io) | Internet noise classification | IP | Community tier |
| [AlienVault OTX](https://otx.alienvault.com) | Pulse count, threat actor tagging | IP, Domain, Hash | Free |

---

## API Key Setup

```bash
iocinfo --setup
```

The wizard walks through each service, shows the signup URL, and saves to `~/.iocinfo/config.ini`. Skip any you don't have yet. Free sources work with zero config.

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

### Free signup links

| Service | Signup | Daily Limit |
|---|---|---|
| VirusTotal | https://www.virustotal.com/gui/join-us | 500 |
| AbuseIPDB | https://www.abuseipdb.com/register | 1,000 |
| Shodan | https://account.shodan.io/register | Limited |
| GreyNoise | https://viz.greynoise.io/signup | Community |
| AlienVault OTX | https://otx.alienvault.com/accounts/signup | Free |

---

## Source Flags

```bash
iocinfo 185.220.101.35 --source virustotal
iocinfo 185.220.101.35 --source abuseipdb shodan
iocinfo evil.com --source vt threatfox urlhaus crtsh
iocinfo <hash> --source vt urlhaus threatfox otx
```

All source names: `vt` / `virustotal`, `abuseipdb`, `shodan`, `greynoise`, `otx`, `ipapi`, `ipinfo`, `rdap` / `whois`, `dns`, `crtsh`, `urlhaus`, `threatfox`

---

## License

MIT. Do whatever you want with it.

Built by [homestarfuzzer](https://homestarfuzzer.github.io) · [GitHub](https://github.com/homestarfuzzer/iocinfo)
