#!/usr/bin/env python3
"""
iocinfo -- IOC enrichment tool
Lookup IPs, domains, and hashes against free and paid threat intel sources.
"""

import argparse
import configparser
import ipaddress
import json
import re
import sys
import urllib.parse
import urllib.request
import urllib.error
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.rule import Rule
    RICH = True
except ImportError:
    RICH = False

CONFIG_DIR = Path.home() / ".iocinfo"
CONFIG_FILE = CONFIG_DIR / "config.ini"
console = Console() if RICH else None
VERSION = "1.1.0"

BANNER = (
    " ⠄ ⢀⡀ ⢀⣀ ⠄ ⣀⡀ ⣰⡁ ⢀⡀\n"
    " ⠇ ⠣⠜ ⠣⠤ ⠇ ⠇⠸ ⢸  ⠣⠜"
)


# ─── Helpers ─────────────────────────────────────────────────────────────────

def detect_type(indicator: str) -> str:
    """Auto-detect whether input is an IP, domain, hash, or URL."""
    indicator = indicator.strip()
    if re.fullmatch(r"[a-fA-F0-9]{32}", indicator):
        return "md5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", indicator):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", indicator):
        return "sha256"
    try:
        ipaddress.ip_address(indicator)
        return "ip"
    except ValueError:
        pass
    if re.match(r"^https?://", indicator):
        return "url"
    return "domain"


def fetch_json(url: str, headers: dict = None, timeout: int = 10) -> dict:
    """HTTP GET returning parsed JSON."""
    req = urllib.request.Request(url, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"_error": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:
        return {"_error": str(e)}


def fetch_post(url: str, data: bytes,
               content_type: str = "application/x-www-form-urlencoded",
               timeout: int = 10) -> dict:
    """HTTP POST returning parsed JSON."""
    req = urllib.request.Request(url, data=data)
    req.add_header("Content-Type", content_type)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        return {"_error": f"HTTP {e.code}: {e.reason}"}
    except Exception as e:
        return {"_error": str(e)}


def load_config() -> configparser.ConfigParser:
    cfg = configparser.ConfigParser()
    if CONFIG_FILE.exists():
        cfg.read(CONFIG_FILE)
    return cfg


def get_key(cfg: configparser.ConfigParser, section: str, key: str) -> str:
    try:
        return cfg[section][key].strip()
    except (KeyError, TypeError):
        return ""


def _clean(d: dict) -> dict:
    """Strip empty, None, 'None', 'Unknown', and 'N/A' values."""
    skip = {"", "None", "Unknown", "N/A", "none", "unknown", "n/a"}
    return {k: v for k, v in d.items() if v is not None and str(v).strip() not in skip}


# ─── RDAP helpers ─────────────────────────────────────────────────────────────

def _rdap_fn(entities: list, *roles) -> str:
    """Extract the fn (name) from the first entity matching any of the given roles."""
    for e in entities:
        if any(r in e.get("roles", []) for r in roles):
            vc = e.get("vcardArray", [])
            props = vc[1] if len(vc) >= 2 else []
            for item in props:
                if item and item[0] == "fn":
                    return item[3]
    return ""


def _rdap_email(entities: list, *roles) -> str:
    """Extract email from the first entity matching any of the given roles."""
    for e in entities:
        if any(r in e.get("roles", []) for r in roles):
            vc = e.get("vcardArray", [])
            props = vc[1] if len(vc) >= 2 else []
            for item in props:
                if item and item[0] == "email":
                    return item[3]
    return ""


def _rdap_event(events: list, action: str) -> str:
    """Return the date (YYYY-MM-DD) of the first event matching the given action."""
    for e in events:
        if e.get("eventAction") == action:
            return e.get("eventDate", "")[:10]
    return ""


# ─── Verdict coloring ─────────────────────────────────────────────────────────

def verdict_color(score: int, total: int) -> str:
    if total == 0:
        return "dim"
    ratio = score / total
    if ratio == 0:
        return "green"
    if ratio < 0.1:
        return "yellow"
    if ratio < 0.3:
        return "dark_orange"
    return "red"


def abuse_color(score: int) -> str:
    if score == 0:
        return "green"
    if score < 25:
        return "yellow"
    if score < 75:
        return "dark_orange"
    return "red"


# ─── Display ─────────────────────────────────────────────────────────────────

def print_section(title: str, data: dict, color: str = "cyan"):
    if not RICH:
        print(f"\n=== {title} ===")
        for k, v in data.items():
            if not k.startswith("_"):
                print(f"  {k}: {v}")
        return

    # Dynamic key column width: just wide enough for the longest key
    display_keys = [k for k in data if not k.startswith("_")]
    key_width = max((len(k) for k in display_keys), default=8) + 2

    table = Table(box=None, show_header=False, padding=(0, 1))
    table.add_column("Key", style="bold white", min_width=key_width, max_width=key_width + 4)
    table.add_column("Value", style="white")

    for k, v in data.items():
        if k.startswith("_"):
            continue
        table.add_row(k, str(v))

    # OSC 8 hyperlink in title (supported by most modern terminals)
    url = data.get("_url", "")
    if url:
        panel_title = f"[bold {color}][link={url}]{title}[/link][/]"
    else:
        panel_title = f"[bold {color}]{title}[/]"

    console.print(Panel(table, title=panel_title,
                        border_style=color, expand=False, width=72))


def print_error(source: str, msg: str):
    if RICH:
        console.print(f"  [dim red]x {source}:[/] [dim]{msg}[/]")
    else:
        print(f"  [ERROR] {source}: {msg}")


def print_header(indicator: str, itype: str):
    if RICH:
        console.print()
        console.print(f"[bold cyan]{BANNER}[/]  [dim]v{VERSION}[/]")
        console.print()
        console.print(f"  [bold white]{indicator}[/]  [dim]({itype})[/]")
        console.print()
    else:
        print(f"\n{'='*60}")
        print(f"  iocinfo v{VERSION}  |  {indicator}  ({itype})")
        print(f"{'='*60}")


def print_verdict_summary(verdicts: list):
    """Print a compact one-line summary of scored sources (only called when verdicts exist)."""
    if not verdicts:
        return
    if RICH:
        parts = []
        for emoji, label, color in verdicts:
            parts.append(f"[{color}]{emoji} {label}[/{color}]")
        console.print("  " + "  [dim]·[/]  ".join(parts))
        console.print()
    else:
        parts = [f"{emoji} {label}" for emoji, label, _ in verdicts]
        print("  " + "  ·  ".join(parts))


# ─── Free Sources ─────────────────────────────────────────────────────────────

def lookup_ip_api(ip: str) -> dict:
    """ip-api.com -- free geo/ASN, no key needed."""
    data = fetch_json(
        f"http://ip-api.com/json/{ip}"
        "?fields=status,message,country,regionName,city,isp,org,as,proxy,hosting,query"
    )
    if data.get("_error") or data.get("status") != "success":
        return {}

    flags = []
    if data.get("proxy"):
        flags.append("PROXY")
    if data.get("hosting"):
        flags.append("HOSTING/VPS")

    result = {
        "IP":       data.get("query", ""),
        "Location": ", ".join(filter(None, [
            data.get("city", ""), data.get("regionName", ""), data.get("country", "")
        ])),
        "ISP":  data.get("isp", ""),
        "Org":  data.get("org", ""),
        "ASN":  data.get("as", ""),
    }
    if flags:
        result["Flags"] = ", ".join(flags)
    return _clean(result)


def lookup_ipinfo(ip: str, token: str = "") -> dict:
    """ipinfo.io -- hostname/org/abuse, free tier."""
    url = f"https://ipinfo.io/{ip}/json"
    if token:
        url += f"?token={token}"
    data = fetch_json(url)
    if data.get("_error") or "bogon" in data:
        return {}
    result = {}
    if data.get("hostname"):
        result["Hostname"] = data["hostname"]
    if data.get("org"):
        result["Org/ASN"] = data["org"]
    if data.get("abuse", {}).get("email"):
        result["Abuse Contact"] = data["abuse"]["email"]
    return _clean(result)


def lookup_rdap_ip(ip: str) -> dict:
    """RDAP/WHOIS for IPs via rdap.org -- free, no key."""
    data = fetch_json(f"https://rdap.org/ip/{ip}", timeout=12)
    if data.get("_error"):
        return {}
    entities = data.get("entities", [])
    events   = data.get("events", [])

    # Prefer CIDR notation from cidr0_cidrs if available
    cidrs = data.get("cidr0_cidrs", [])
    if cidrs:
        c = cidrs[0]
        prefix = c.get("v4prefix") or c.get("v6prefix", "")
        length = c.get("length", "")
        cidr_str = f"{prefix}/{length}" if prefix and length else ""
    else:
        start = data.get("startAddress", "")
        end   = data.get("endAddress", "")
        cidr_str = f"{start} - {end}" if start and end else ""

    result = {
        "Network":     data.get("name", ""),
        "CIDR":        cidr_str,
        "Country":     data.get("country", ""),
        "Registered":  _rdap_event(events, "registration"),
        "Org":         _rdap_fn(entities, "registrant", "administrative", "technical"),
        "Abuse Email": _rdap_email(entities, "abuse"),
    }
    return _clean(result)


def lookup_dns_full(domain: str) -> dict:
    """Full DNS enrichment via Google DoH -- free, no key."""
    result = {}
    type_map = [("A", 1), ("MX", 15), ("NS", 2), ("TXT", 16)]
    for rtype, rnum in type_map:
        url = f"https://dns.google/resolve?name={urllib.parse.quote(domain)}&type={rtype}"
        data = fetch_json(url, timeout=5)
        if data.get("_error") or data.get("Status", 3) != 0:
            continue
        answers = [a["data"] for a in data.get("Answer", []) if a.get("type") == rnum]
        if not answers:
            continue
        if rtype == "A":
            result["A Records"] = ", ".join(answers[:6])
        elif rtype == "MX":
            hosts = [v.split()[-1].rstrip(".") for v in answers[:4]]
            result["MX Records"] = ", ".join(hosts)
        elif rtype == "NS":
            result["NS Records"] = ", ".join(v.rstrip(".") for v in answers[:4])
        elif rtype == "TXT":
            txts = [v.strip('"')[:80] for v in answers[:2]]
            result["TXT Records"] = " | ".join(txts)
    return result


def lookup_rdap_domain(domain: str) -> dict:
    """RDAP/WHOIS for domains via rdap.org -- free, no key."""
    data = fetch_json(f"https://rdap.org/domain/{domain}", timeout=12)
    if data.get("_error"):
        return {}
    entities    = data.get("entities", [])
    events      = data.get("events", [])
    nameservers = [ns.get("ldhName", "") for ns in data.get("nameservers", [])]
    status      = [s for s in data.get("status", []) if s]

    result = {
        "Registrar":    _rdap_fn(entities, "registrar"),
        "Registered":   _rdap_event(events, "registration"),
        "Expires":      _rdap_event(events, "expiration"),
        "Last Changed": _rdap_event(events, "last changed"),
        "Nameservers":  ", ".join(ns for ns in nameservers[:4] if ns),
        "Status":       ", ".join(status[:3]),
    }
    return _clean(result)


def lookup_crtsh(domain: str) -> dict:
    """Certificate Transparency logs via crt.sh -- free, no key."""
    url = "https://crt.sh/?q=%25." + urllib.parse.quote(domain) + "&output=json"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            raw = resp.read().decode("utf-8", errors="ignore")
        certs = json.loads(raw)
    except Exception:
        return {}

    if not isinstance(certs, list) or not certs:
        return {}

    sample = certs[:500]
    total  = len(sample)
    dates  = sorted(c.get("not_before", "")[:10] for c in sample if c.get("not_before"))
    # Extract org from issuer_name "C=US, O=Let's Encrypt, CN=R3" -> "Let's Encrypt"
    issuers = []
    seen    = set()
    for c in sample:
        raw_issuer = c.get("issuer_name", "")
        for part in raw_issuer.split(","):
            part = part.strip()
            if part.startswith("O="):
                name = part[2:].strip()
                if name and name not in seen:
                    seen.add(name)
                    issuers.append(name)
                break

    result = {
        "Certs Found":  str(total) + ("+" if total == 500 else ""),
        "Earliest":     dates[0] if dates else "",
        "Most Recent":  dates[-1] if dates else "",
        "Issuers":      ", ".join(issuers[:3]),
    }
    return _clean(result)


def lookup_urlhaus_hash(hash_val: str) -> dict:
    """URLhaus hash lookup -- free, no key."""
    if len(hash_val) == 32:
        body = f"md5_hash={hash_val}".encode()
    else:
        body = f"sha256_hash={hash_val}".encode()
    data = fetch_post("https://urlhaus-api.abuse.ch/v1/payload/", body)
    if data.get("_error") or data.get("query_status") == "no_results":
        return {}
    result = {
        "File Type":  data.get("file_type", ""),
        "File Size":  f"{data.get('file_size')} bytes" if data.get("file_size") else "",
        "Signature":  data.get("signature", ""),
        "First Seen": data.get("firstseen", ""),
        "Last Seen":  data.get("lastseen", ""),
        "Downloads":  str(data.get("download_count", "")) if data.get("download_count") else "",
        "URLs Seen":  str(len(data.get("urls", []))) if data.get("urls") else "",
    }
    return _clean(result)


def lookup_urlhaus_url(val: str) -> dict:
    """URLhaus URL/domain/IP lookup -- free, no key."""
    if val.startswith("http"):
        endpoint = "https://urlhaus-api.abuse.ch/v1/url/"
        body = f"url={urllib.parse.quote(val)}".encode()
    else:
        endpoint = "https://urlhaus-api.abuse.ch/v1/host/"
        body = f"host={val}".encode()
    data = fetch_post(endpoint, body)
    if data.get("_error") or data.get("query_status") in ("no_results", "invalid_url"):
        return {}
    result = {
        "Status": data.get("query_status", ""),
        "Threat": data.get("threat", ""),
        "Added":  data.get("date_added", ""),
        "URLs":   str(len(data.get("urls", []))) if data.get("urls") else "",
    }
    return _clean(result)


def lookup_threatfox_hash(hash_val: str) -> dict:
    """ThreatFox hash lookup -- free, no key."""
    payload = json.dumps({"query": "search_ioc", "search_term": hash_val}).encode()
    data = fetch_post("https://threatfox-api.abuse.ch/api/v1/", payload, "application/json")
    if data.get("_error") or data.get("query_status") == "no_results":
        return {}
    iocs = data.get("data", [])
    if not iocs:
        return {}
    ioc  = iocs[0]
    tags = [t for t in (ioc.get("tags") or []) if t]
    result = {
        "Malware":    ioc.get("malware_printable", ""),
        "IOC Type":   ioc.get("ioc_type_desc", ""),
        "Confidence": f"{ioc.get('confidence_level', '')}%",
        "Reporter":   ioc.get("reporter", ""),
        "First Seen": ioc.get("first_seen", ""),
    }
    if tags:
        result["Tags"] = ", ".join(tags)
    return _clean(result)


def lookup_threatfox_ip_domain(indicator: str) -> dict:
    """ThreatFox IP/domain lookup -- free, no key."""
    payload = json.dumps({"query": "search_ioc", "search_term": indicator}).encode()
    data = fetch_post("https://threatfox-api.abuse.ch/api/v1/", payload, "application/json")
    if data.get("_error") or data.get("query_status") == "no_results":
        return {}
    iocs = data.get("data", [])
    if not iocs:
        return {}
    ioc  = iocs[0]
    tags = [t for t in (ioc.get("tags") or []) if t]
    result = {
        "Malware":    ioc.get("malware_printable", ""),
        "Confidence": f"{ioc.get('confidence_level', '')}%",
        "First Seen": ioc.get("first_seen", ""),
    }
    if tags:
        result["Tags"] = ", ".join(tags)
    return _clean(result)


# ─── Paid Sources ─────────────────────────────────────────────────────────────

def lookup_virustotal(indicator: str, itype: str, api_key: str) -> dict:
    """VirusTotal -- requires free API key."""
    if itype == "ip":
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{indicator}"
    elif itype == "domain":
        url = f"https://www.virustotal.com/api/v3/domains/{indicator}"
    elif itype in ("md5", "sha1", "sha256"):
        url = f"https://www.virustotal.com/api/v3/files/{indicator}"
    else:
        return {}

    data = fetch_json(url, headers={"x-apikey": api_key})
    if data.get("_error"):
        return {"_error": data["_error"]}

    attrs = data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    malicious  = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total      = sum(stats.values())
    detected   = malicious + suspicious

    result = {
        "Detections": f"{detected}/{total}",
        "Malicious":  str(malicious),
        "Suspicious": str(suspicious),
        "Undetected": str(stats.get("undetected", 0)),
    }

    if itype in ("md5", "sha1", "sha256"):
        if attrs.get("type_description"):
            result["File Type"] = attrs["type_description"]
        if attrs.get("size"):
            result["File Size"] = f"{attrs['size']} bytes"
        if attrs.get("magic"):
            result["Magic"] = attrs["magic"]
        if attrs.get("first_submission_date"):
            result["First Seen"] = str(attrs["first_submission_date"])
        if attrs.get("times_submitted"):
            result["Times Submitted"] = str(attrs["times_submitted"])
    elif itype == "domain":
        if attrs.get("registrar"):
            result["Registrar"] = attrs["registrar"]
        cats = list(attrs.get("categories", {}).values())
        if cats:
            result["Categories"] = ", ".join(cats)
    elif itype == "ip":
        if attrs.get("country"):
            result["Country"] = attrs["country"]
        if attrs.get("network"):
            result["Network"] = attrs["network"]
        if attrs.get("as_owner"):
            result["AS Owner"] = attrs["as_owner"]

    result["_detected"] = detected
    result["_total"]    = total
    return result


def lookup_abuseipdb(ip: str, api_key: str) -> dict:
    """AbuseIPDB -- requires free API key."""
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose"
    data = fetch_json(url, headers={"Key": api_key, "Accept": "application/json"})
    if data.get("_error"):
        return {"_error": data["_error"]}

    d     = data.get("data", {})
    score = d.get("abuseConfidenceScore", 0)
    last  = d.get("lastReportedAt") or ""

    result = {
        "Abuse Score":    f"{score}/100",
        "Total Reports":  str(d.get("totalReports", 0)),
        "Distinct Users": str(d.get("numDistinctUsers", 0)),
        "Usage Type":     d.get("usageType", ""),
        "ISP":            d.get("isp", ""),
        "Domain":         d.get("domain", ""),
    }
    if last:
        result["Last Reported"] = last
    # Only surface positive boolean flags
    if d.get("isTor"):
        result["Tor Node"] = "Yes"
    if d.get("isWhitelisted"):
        result["Whitelisted"] = "Yes"

    result["_score"] = score
    # Clean non-internal keys
    cleaned = {k: v for k, v in result.items()
               if k.startswith("_") or (v is not None and str(v).strip() not in {"", "None", "N/A"})}
    return cleaned


def lookup_shodan(ip: str, api_key: str) -> dict:
    """Shodan -- requires API key."""
    data = fetch_json(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}")
    if data.get("_error"):
        return {"_error": data["_error"]}

    ports     = data.get("ports", [])
    hostnames = data.get("hostnames", [])
    tags      = data.get("tags", [])
    vulns     = list(data.get("vulns", {}).keys())
    os_val    = data.get("os")

    result = {}
    if ports:
        result["Open Ports"] = ", ".join(str(p) for p in sorted(ports))
    if hostnames:
        result["Hostnames"] = ", ".join(hostnames)
    if os_val:
        result["OS"] = os_val
    if tags:
        result["Tags"] = ", ".join(tags)
    if data.get("last_update"):
        result["Last Update"] = data["last_update"]
    if vulns:
        cve_str = ", ".join(vulns[:10])
        if len(vulns) > 10:
            cve_str += f" (+{len(vulns) - 10} more)"
        result["CVEs"] = cve_str
    return result


def lookup_greynoise(ip: str, api_key: str) -> dict:
    """GreyNoise -- requires API key (free community tier)."""
    headers = {"key": api_key} if api_key else {}
    data = fetch_json(f"https://api.greynoise.io/v3/community/{ip}", headers=headers)
    if data.get("_error"):
        return {"_error": data["_error"]}

    result = {}
    if data.get("noise"):
        result["Noise"] = "Yes"
    if data.get("riot"):
        result["RIOT"] = "Yes"
    cls = data.get("classification", "")
    if cls:
        result["Classification"] = cls
    name = data.get("name", "")
    if name and name.lower() not in ("unknown", ""):
        result["Name"] = name
    if data.get("last_seen"):
        result["Last Seen"] = data["last_seen"]
    return result


def lookup_otx(indicator: str, itype: str, api_key: str) -> dict:
    """AlienVault OTX -- requires free API key."""
    type_map = {"ip": "IPv4", "domain": "domain", "md5": "file",
                "sha1": "file", "sha256": "file", "url": "URL"}
    otx_type = type_map.get(itype, "")
    if not otx_type:
        return {}

    section = "reputation" if itype == "ip" else "general"
    url = f"https://otx.alienvault.com/api/v1/indicators/{otx_type}/{indicator}/{section}"
    data = fetch_json(url, headers={"X-OTX-API-KEY": api_key})
    if data.get("_error"):
        return {"_error": data["_error"]}

    pulses = data.get("pulse_info", {}).get("count", 0)
    result = {"Pulse Count": str(pulses)}

    if itype == "ip":
        rep = data.get("reputation", {})
        if rep.get("threat_score"):
            result["Threat Score"] = str(rep["threat_score"])
        acts = list(rep.get("activities", {}).keys())
        if acts:
            result["Activities"] = ", ".join(acts)

    result["_pulses"] = pulses
    return result


# ─── Main lookup orchestrator ─────────────────────────────────────────────────

def run_lookup(indicator: str, itype: str, cfg: configparser.ConfigParser,
               sources: list, verbose: bool = False):

    vt_key       = get_key(cfg, "virustotal", "api_key")
    abuse_key    = get_key(cfg, "abuseipdb",  "api_key")
    shodan_key   = get_key(cfg, "shodan",     "api_key")
    grey_key     = get_key(cfg, "greynoise",  "api_key")
    otx_key      = get_key(cfg, "otx",        "api_key")
    ipinfo_token = get_key(cfg, "ipinfo",     "token")

    run_all = not sources or "all" in sources

    # Collect results before printing so we can show the verdict summary up top
    sections = []   # list of (title, data, color)
    verdicts = []   # list of (emoji, label, color)
    errors   = []   # list of (source, msg)

    def want(*names) -> bool:
        return run_all or any(n in sources for n in names)

    def explicit(*names) -> bool:
        """True only when the user explicitly passed these source names via --source."""
        return any(n in sources for n in names)

    tf_url  = lambda i: f"https://threatfox.abuse.ch/browse/?search=ioc%3A{urllib.parse.quote(i)}"
    uh_url  = lambda i: f"https://urlhaus.abuse.ch/browse.php?search={urllib.parse.quote(i)}"

    # ── IP ───────────────────────────────────────────────────────────────────
    if itype == "ip":

        if want("ipapi"):
            d = lookup_ip_api(indicator)
            if d:
                color = "red" if d.get("Flags") else "green"
                sections.append(("🌐  Geolocation  [ip-api.com]", d, color))

        if want("ipinfo"):
            d = lookup_ipinfo(indicator, ipinfo_token)
            if d:
                d["_url"] = f"https://ipinfo.io/{indicator}"
                sections.append(("🔍  IP Info  [ipinfo.io]", d, "cyan"))

        if want("rdap", "whois"):
            d = lookup_rdap_ip(indicator)
            if d:
                sections.append(("🏢  RDAP / WHOIS  [rdap.org]", d, "cyan"))

        if want("threatfox"):
            d = lookup_threatfox_ip_domain(indicator)
            if d:
                malware = d.get("Malware", "")
                color   = "red" if malware else "green"
                d["_url"] = tf_url(indicator)
                sections.append(("☠️  ThreatFox  [abuse.ch]", d, color))
                if malware:
                    verdicts.append(("☠️", f"ThreatFox: {malware}", "red"))

        if want("urlhaus"):
            d = lookup_urlhaus_url(indicator)
            if d:
                color = "red" if "online" in str(d).lower() else "yellow"
                d["_url"] = uh_url(indicator)
                sections.append(("🔗  URLhaus  [abuse.ch]", d, color))

        if abuse_key and want("abuseipdb"):
            d = lookup_abuseipdb(indicator, abuse_key)
            if "_error" in d:
                errors.append(("AbuseIPDB", d["_error"]))
            elif d:
                score = d.pop("_score", 0)
                color = abuse_color(score)
                d["_url"] = f"https://www.abuseipdb.com/check/{indicator}"
                sections.append((f"🚨  AbuseIPDB  [score: {score}/100]", d, color))
                if score > 0:
                    verdicts.append(("🚨", f"AbuseIPDB {score}/100", color))
        elif not abuse_key and explicit("abuseipdb"):
            errors.append(("AbuseIPDB", "No API key -- run: iocinfo --setup"))

        if vt_key and want("virustotal", "vt"):
            d = lookup_virustotal(indicator, itype, vt_key)
            if "_error" in d:
                errors.append(("VirusTotal", d["_error"]))
            elif d:
                detected = d.pop("_detected", 0)
                total    = d.pop("_total", 0)
                color    = verdict_color(detected, total)
                d["_url"] = f"https://www.virustotal.com/gui/ip-address/{indicator}"
                sections.append((f"🦠  VirusTotal  [{detected}/{total} engines]", d, color))
                if detected > 0:
                    verdicts.append(("🦠", f"VT {detected}/{total}", color))
        elif not vt_key and explicit("virustotal", "vt"):
            errors.append(("VirusTotal", "No API key -- run: iocinfo --setup"))

        if shodan_key and want("shodan"):
            d = lookup_shodan(indicator, shodan_key)
            if "_error" in d:
                errors.append(("Shodan", d["_error"]))
            elif d:
                color = "red" if "CVEs" in d else "blue"
                d["_url"] = f"https://www.shodan.io/host/{indicator}"
                sections.append(("🛰️  Shodan", d, color))
        elif not shodan_key and explicit("shodan"):
            errors.append(("Shodan", "No API key -- run: iocinfo --setup"))

        if grey_key and want("greynoise"):
            d = lookup_greynoise(indicator, grey_key)
            if "_error" in d:
                errors.append(("GreyNoise", d["_error"]))
            elif d:
                cls   = d.get("Classification", "")
                color = "red" if cls == "malicious" else "green" if cls == "benign" else "yellow"
                d["_url"] = f"https://viz.greynoise.io/ip/{indicator}"
                sections.append((f"📡  GreyNoise  [{cls}]", d, color))
                if cls == "malicious":
                    verdicts.append(("📡", "GreyNoise malicious", "red"))
                elif d.get("Noise") == "Yes":
                    verdicts.append(("📡", "GreyNoise noise", "yellow"))
        elif not grey_key and explicit("greynoise"):
            errors.append(("GreyNoise", "No API key -- run: iocinfo --setup"))

        if otx_key and want("otx"):
            d = lookup_otx(indicator, itype, otx_key)
            if "_error" in d:
                errors.append(("OTX", d["_error"]))
            elif d:
                pulses = d.pop("_pulses", 0)
                color  = "red" if pulses > 0 else "green"
                d["_url"] = f"https://otx.alienvault.com/indicator/ip/{indicator}"
                sections.append((f"👁️  AlienVault OTX  [{pulses} pulses]", d, color))
                if pulses > 0:
                    verdicts.append(("👁️", f"OTX {pulses} pulses", color))

    # ── Domain ───────────────────────────────────────────────────────────────
    elif itype == "domain":

        if want("dns"):
            d = lookup_dns_full(indicator)
            if d:
                sections.append(("🌐  DNS Records  [dns.google]", d, "cyan"))

        if want("rdap", "whois"):
            d = lookup_rdap_domain(indicator)
            if d:
                sections.append(("🏢  WHOIS  [rdap.org]", d, "cyan"))

        if want("crtsh"):
            d = lookup_crtsh(indicator)
            if d:
                d["_url"] = f"https://crt.sh/?q={urllib.parse.quote(indicator)}"
                sections.append(("🔏  Cert Transparency  [crt.sh]", d, "cyan"))

        if want("threatfox"):
            d = lookup_threatfox_ip_domain(indicator)
            if d:
                malware = d.get("Malware", "")
                color   = "red" if malware else "green"
                d["_url"] = tf_url(indicator)
                sections.append(("☠️  ThreatFox  [abuse.ch]", d, color))
                if malware:
                    verdicts.append(("☠️", f"ThreatFox: {malware}", "red"))

        if want("urlhaus"):
            d = lookup_urlhaus_url(indicator)
            if d:
                d["_url"] = uh_url(indicator)
                sections.append(("🔗  URLhaus  [abuse.ch]", d, "yellow"))

        if vt_key and want("virustotal", "vt"):
            d = lookup_virustotal(indicator, itype, vt_key)
            if "_error" in d:
                errors.append(("VirusTotal", d["_error"]))
            elif d:
                detected = d.pop("_detected", 0)
                total    = d.pop("_total", 0)
                color    = verdict_color(detected, total)
                d["_url"] = f"https://www.virustotal.com/gui/domain/{indicator}"
                sections.append((f"🦠  VirusTotal  [{detected}/{total} engines]", d, color))
                if detected > 0:
                    verdicts.append(("🦠", f"VT {detected}/{total}", color))
        elif not vt_key and explicit("virustotal", "vt"):
            errors.append(("VirusTotal", "No API key -- run: iocinfo --setup"))

        if otx_key and want("otx"):
            d = lookup_otx(indicator, itype, otx_key)
            if "_error" in d:
                errors.append(("OTX", d["_error"]))
            elif d:
                pulses = d.pop("_pulses", 0)
                color  = "red" if pulses > 0 else "green"
                d["_url"] = f"https://otx.alienvault.com/indicator/domain/{indicator}"
                sections.append((f"👁️  AlienVault OTX  [{pulses} pulses]", d, color))
                if pulses > 0:
                    verdicts.append(("👁️", f"OTX {pulses} pulses", color))

    # ── Hash ─────────────────────────────────────────────────────────────────
    elif itype in ("md5", "sha1", "sha256"):

        if want("urlhaus"):
            d = lookup_urlhaus_hash(indicator)
            if d:
                color = "red" if "malware" in str(d).lower() else "yellow"
                d["_url"] = f"https://urlhaus.abuse.ch/browse.php?search={indicator}"
                sections.append(("🔗  URLhaus  [abuse.ch]", d, color))

        if want("threatfox"):
            d = lookup_threatfox_hash(indicator)
            if d:
                malware = d.get("Malware", "")
                color   = "red" if malware else "green"
                d["_url"] = tf_url(indicator)
                sections.append(("☠️  ThreatFox  [abuse.ch]", d, color))
                if malware:
                    verdicts.append(("☠️", f"ThreatFox: {malware}", "red"))

        if vt_key and want("virustotal", "vt"):
            d = lookup_virustotal(indicator, itype, vt_key)
            if "_error" in d:
                errors.append(("VirusTotal", d["_error"]))
            elif d:
                detected = d.pop("_detected", 0)
                total    = d.pop("_total", 0)
                color    = verdict_color(detected, total)
                d["_url"] = f"https://www.virustotal.com/gui/file/{indicator}"
                sections.append((f"🦠  VirusTotal  [{detected}/{total} engines]", d, color))
                if detected > 0:
                    verdicts.append(("🦠", f"VT {detected}/{total}", color))
        elif not vt_key and explicit("virustotal", "vt"):
            errors.append(("VirusTotal", "No API key -- run: iocinfo --setup"))

        if otx_key and want("otx"):
            d = lookup_otx(indicator, itype, otx_key)
            if "_error" in d:
                errors.append(("OTX", d["_error"]))
            elif d:
                pulses = d.pop("_pulses", 0)
                color  = "red" if pulses > 0 else "green"
                d["_url"] = f"https://otx.alienvault.com/indicator/file/{indicator}"
                sections.append((f"👁️  AlienVault OTX  [{pulses} pulses]", d, color))
                if pulses > 0:
                    verdicts.append(("👁️", f"OTX {pulses} pulses", color))

    # ── Output ───────────────────────────────────────────────────────────────
    print_header(indicator, itype)
    print_verdict_summary(verdicts)

    for title, data, color in sections:
        print_section(title, data, color)

    for source, msg in errors:
        print_error(source, msg)

    if RICH:
        console.print(Rule(style="bright_black"))
        console.print()


# ─── Setup wizard ─────────────────────────────────────────────────────────────

def setup_wizard():
    print("\n  iocinfo -- API Key Setup")
    print("  " + "-" * 40)
    print("  Press ENTER to skip any key you don't have yet.\n")

    keys = {
        "virustotal": ("VirusTotal",       "api_key", "https://www.virustotal.com/gui/join-us"),
        "abuseipdb":  ("AbuseIPDB",        "api_key", "https://www.abuseipdb.com/register"),
        "shodan":     ("Shodan",           "api_key", "https://account.shodan.io/register"),
        "greynoise":  ("GreyNoise",        "api_key", "https://viz.greynoise.io/signup"),
        "otx":        ("AlienVault OTX",   "api_key", "https://otx.alienvault.com/accounts/signup"),
        "ipinfo":     ("ipinfo.io (opt.)", "token",   "https://ipinfo.io/signup"),
    }

    cfg = configparser.ConfigParser()
    if CONFIG_FILE.exists():
        cfg.read(CONFIG_FILE)

    for section, (name, key, signup_url) in keys.items():
        existing = get_key(cfg, section, key)
        prompt   = f"  {name}\n  Signup: {signup_url}\n  Key"
        if existing:
            prompt += f" (current: {existing[:6]}...  ENTER to keep)"
        val = input(f"{prompt}: ").strip()
        if val:
            if section not in cfg:
                cfg[section] = {}
            cfg[section][key] = val
        print()

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        cfg.write(f)
    print(f"  Config saved to {CONFIG_FILE}\n")


# ─── Help screen ─────────────────────────────────────────────────────────────

def print_help():
    if not RICH:
        print(f"""
iocinfo v{VERSION} -- IOC enrichment CLI

USAGE:
  iocinfo <indicator> [options]
  iocinfo --setup
  iocinfo --help

ARGUMENTS:
  indicator       IP address, domain, or hash (auto-detected)

OPTIONS:
  --source        One or more sources to query (default: all configured)
  --type          Force type: ip, domain, md5, sha1, sha256
  --setup         Configure API keys
  --version       Show version
  -h, --help      Show this help

FREE SOURCES (no API key needed):
  ipapi           Geolocation, ASN, ISP, proxy/hosting flags     [IP]
  ipinfo          Hostname, org, abuse contact                   [IP]
  rdap / whois    RDAP/WHOIS registration data                   [IP, Domain]
  dns             Full DNS records (A, MX, NS, TXT)              [Domain]
  crtsh           Certificate Transparency logs                  [Domain]
  threatfox       Malware family, confidence, tags               [IP, Domain, Hash]
  urlhaus         Malware URLs, signatures, file type            [Domain, Hash]

PAID SOURCES (free API keys available):
  vt / virustotal Detection ratio across 90+ AV engines          [IP, Domain, Hash]
  abuseipdb       Abuse score, report history                    [IP]
  shodan          Open ports, banners, CVEs                      [IP]
  greynoise       Internet noise classification                  [IP]
  otx             Pulse count, threat actor tagging              [IP, Domain, Hash]

EXAMPLES:
  iocinfo 185.220.101.35
  iocinfo evil.com
  iocinfo d41d8cd98f00b204e9800998ecf8427e
  iocinfo 1.2.3.4 --source abuseipdb
  iocinfo 1.2.3.4 --source vt abuseipdb shodan
  iocinfo --setup
""")
        return

    console.print()
    console.print(f"[bold cyan]{BANNER}[/]  [dim]v{VERSION}[/]")
    console.print()

    console.print("  [bold cyan]USAGE[/]")
    console.print("    [white]iocinfo[/] [green]<indicator>[/] [dim]\\[options][/]")
    console.print("    [white]iocinfo[/] [yellow]--setup[/]")
    console.print()

    console.print("  [bold cyan]OPTIONS[/]")
    opts = [
        ("--source",   "One or more sources to query [dim](default: all)[/]"),
        ("--type",     "Force type: [dim]ip, domain, md5, sha1, sha256[/]"),
        ("--setup",    "Configure API keys interactively"),
        ("--version",  "Show version"),
        ("-h, --help", "Show this help screen"),
    ]
    for flag, desc in opts:
        console.print(f"    [yellow]{flag:<18}[/] {desc}")
    console.print()

    console.print("  [bold green]FREE SOURCES[/] [dim]-- no API key needed[/]")
    free = [
        ("ipapi",        "Geolocation, ASN, ISP, proxy/hosting flags",    "IP"),
        ("ipinfo",       "Hostname, org, abuse contact",                  "IP"),
        ("rdap / whois", "RDAP/WHOIS registration data",                  "IP · Domain"),
        ("dns",          "Full DNS records (A, MX, NS, TXT)",             "Domain"),
        ("crtsh",        "Certificate Transparency logs",                 "Domain"),
        ("threatfox",    "Malware family, confidence score, tags",        "IP · Domain · Hash"),
        ("urlhaus",      "Malware URLs, signatures, file type",           "Domain · Hash"),
    ]
    for name, desc, types in free:
        console.print(f"    [bold green]{name:<18}[/] {desc:<46} [dim cyan]{types}[/]")
    console.print()

    console.print("  [bold yellow]PAID SOURCES[/] [dim]-- free keys available  ->  run: iocinfo --setup[/]")
    paid = [
        ("vt / virustotal", "Detection ratio across 90+ AV engines",      "IP · Domain · Hash"),
        ("abuseipdb",       "Abuse confidence score, report history",      "IP"),
        ("shodan",          "Open ports, banners, CVEs, hostnames",        "IP"),
        ("greynoise",       "Internet noise classification",               "IP"),
        ("otx",             "Pulse count, threat actor tagging",           "IP · Domain · Hash"),
    ]
    for name, desc, types in paid:
        console.print(f"    [bold yellow]{name:<18}[/] {desc:<46} [dim cyan]{types}[/]")
    console.print()

    console.print("  [bold cyan]EXAMPLES[/]")
    examples = [
        "iocinfo 185.220.101.35",
        "iocinfo evil.com",
        "iocinfo d41d8cd98f00b204e9800998ecf8427e",
        "iocinfo 1.2.3.4 --source abuseipdb",
        "iocinfo 1.2.3.4 --source vt abuseipdb shodan",
        "iocinfo evil.com --source vt threatfox urlhaus",
        "iocinfo --setup",
    ]
    for ex in examples:
        console.print(f"    [dim]$[/] [white]{ex}[/]")
    console.print()


# ─── CLI entry point ─────────────────────────────────────────────────────────

def main():
    if "-h" in sys.argv or "--help" in sys.argv:
        print_help()
        return

    parser = argparse.ArgumentParser(prog="iocinfo", add_help=False)
    parser.add_argument("indicator", nargs="?")
    parser.add_argument("--source", nargs="+", metavar="SOURCE")
    parser.add_argument("--type", choices=["ip", "domain", "md5", "sha1", "sha256"])
    parser.add_argument("--setup", action="store_true")
    parser.add_argument("--version", action="version", version=f"iocinfo {VERSION}")
    parser.add_argument("-h", "--help", action="store_true", default=False)

    args = parser.parse_args()

    if args.setup:
        setup_wizard()
        return

    if not args.indicator:
        print_help()
        return

    indicator = args.indicator.strip()
    itype     = args.type or detect_type(indicator)
    sources   = [s.lower() for s in args.source] if args.source else []
    cfg       = load_config()

    if not RICH:
        print("\n  Tip: Install 'rich' for colored output:  pip install rich\n")

    run_lookup(indicator, itype, cfg, sources)


if __name__ == "__main__":
    main()
