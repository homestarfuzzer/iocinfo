#!/usr/bin/env python3
"""
iocinfo — IOC enrichment tool
Lookup IPs, domains, and hashes against free and paid threat intel sources.
"""

import argparse
import configparser
import ipaddress
import json
import os
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path

try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
    from rich.text import Text
    from rich.rule import Rule
    from rich.columns import Columns
    RICH = True
except ImportError:
    RICH = False

CONFIG_DIR = Path.home() / ".iocinfo"
CONFIG_FILE = CONFIG_DIR / "config.ini"

console = Console() if RICH else None


# ─── Helpers ────────────────────────────────────────────────────────────────

def detect_type(indicator: str) -> str:
    """Auto-detect whether input is an IP, domain, or hash."""
    indicator = indicator.strip()
    # Hash detection
    if re.fullmatch(r"[a-fA-F0-9]{32}", indicator):
        return "md5"
    if re.fullmatch(r"[a-fA-F0-9]{40}", indicator):
        return "sha1"
    if re.fullmatch(r"[a-fA-F0-9]{64}", indicator):
        return "sha256"
    # IP detection
    try:
        ipaddress.ip_address(indicator)
        return "ip"
    except ValueError:
        pass
    # Domain/URL fallback
    if re.match(r"^(https?://)", indicator):
        return "url"
    return "domain"


def fetch_json(url: str, headers: dict = None, timeout: int = 10) -> dict:
    """Simple HTTP GET returning parsed JSON."""
    req = urllib.request.Request(url, headers=headers or {})
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


# ─── Verdict coloring ───────────────────────────────────────────────────────

def verdict_color(score: int, total: int) -> str:
    """Return rich color string based on detection ratio."""
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


def print_section(title: str, data: dict, color: str = "cyan"):
    """Print a labeled section panel."""
    if not RICH:
        print(f"\n=== {title} ===")
        for k, v in data.items():
            print(f"  {k}: {v}")
        return

    table = Table(box=None, show_header=False, padding=(0, 1))
    table.add_column("Key", style="bold white", min_width=22)
    table.add_column("Value", style="white")

    for k, v in data.items():
        if isinstance(v, str) and v.startswith("["):
            table.add_row(k, Text(v, style="dim"))
        else:
            table.add_row(k, str(v))

    console.print(Panel(table, title=f"[bold {color}]{title}[/]",
                        border_style=color, expand=False, width=72))


def print_error(source: str, msg: str):
    if RICH:
        console.print(f"  [dim red]✗ {source}:[/] [dim]{msg}[/]")
    else:
        print(f"  [ERROR] {source}: {msg}")


def print_header(indicator: str, itype: str):
    if RICH:
        console.print()
        console.print(Rule(f"[bold white] iocinfo [/][dim]·[/] [bold cyan]{indicator}[/] [dim]({itype})[/]",
                           style="bright_black"))
        console.print()
    else:
        print(f"\n{'='*60}")
        print(f"  iocinfo  |  {indicator}  ({itype})")
        print(f"{'='*60}")


def print_verdict(label: str, score_str: str, color: str):
    if RICH:
        console.print(f"  [bold]Verdict:[/] [{color}]{label}[/]  [dim]{score_str}[/]")
        console.print()
    else:
        print(f"  Verdict: {label}  {score_str}")


# ─── Free Sources (no API key) ──────────────────────────────────────────────

def lookup_ip_api(ip: str) -> dict:
    """ip-api.com — free geo/ASN, no key needed."""
    data = fetch_json(f"http://ip-api.com/json/{ip}?fields=status,message,country,regionName,city,isp,org,as,proxy,hosting,query")
    if data.get("_error"):
        return {}
    if data.get("status") != "success":
        return {}
    result = {
        "IP":       data.get("query", ""),
        "Location": f"{data.get('city', '')}, {data.get('regionName', '')}, {data.get('country', '')}",
        "ISP":      data.get("isp", ""),
        "Org":      data.get("org", ""),
        "ASN":      data.get("as", ""),
    }
    flags = []
    if data.get("proxy"):
        flags.append("PROXY")
    if data.get("hosting"):
        flags.append("HOSTING/VPS")
    result["Flags"] = ", ".join(flags) if flags else "None"
    return result


def lookup_ipinfo(ip: str, token: str = "") -> dict:
    """ipinfo.io — geo/ASN/org, free tier no key for basic."""
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
    return result


def lookup_urlhaus_hash(hash_val: str) -> dict:
    """URLhaus hash lookup — free, no key."""
    url = "https://urlhaus-api.abuse.ch/v1/payload/"
    data_bytes = f"md5_hash={hash_val}".encode() if len(hash_val) == 32 else f"sha256_hash={hash_val}".encode()
    req = urllib.request.Request(url, data=data_bytes)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return {}

    if data.get("query_status") == "no_results":
        return {"URLhaus": "No results found (not in URLhaus database)"}

    result = {
        "URLhaus Status": data.get("query_status", ""),
        "File Type":      data.get("file_type", ""),
        "File Size":      f"{data.get('file_size', '')} bytes" if data.get("file_size") else "",
        "Signature":      data.get("signature") or "Unknown",
        "First Seen":     data.get("firstseen", ""),
        "Last Seen":      data.get("lastseen", ""),
        "Downloads":      str(data.get("download_count", "")),
    }
    urls = data.get("urls", [])
    if urls:
        result["Associated URLs"] = str(len(urls))
    return {k: v for k, v in result.items() if v}


def lookup_urlhaus_url(url_val: str) -> dict:
    """URLhaus URL/domain lookup — free, no key."""
    data_bytes = f"url={urllib.parse.quote(url_val)}".encode() if "http" in url_val else f"host={url_val}".encode()

    endpoint = "https://urlhaus-api.abuse.ch/v1/url/" if "http" in url_val else "https://urlhaus-api.abuse.ch/v1/host/"
    req = urllib.request.Request(endpoint, data=data_bytes)
    req.add_header("Content-Type", "application/x-www-form-urlencoded")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return {}

    if data.get("query_status") in ("no_results", "invalid_url"):
        return {"URLhaus": "Not found in URLhaus database"}

    result = {
        "URLhaus Status": data.get("query_status", ""),
        "Threat":         data.get("threat", ""),
        "Date Added":     data.get("date_added", ""),
        "URLs (host)":    str(len(data.get("urls", []))),
    }
    return {k: v for k, v in result.items() if v}


def lookup_dns(domain: str) -> dict:
    """Basic DNS resolution using socket — no API needed."""
    import socket
    result = {}
    try:
        addrs = socket.getaddrinfo(domain, None)
        ips = list(dict.fromkeys([a[4][0] for a in addrs]))
        result["Resolves To"] = ", ".join(ips[:5])
    except Exception:
        result["DNS"] = "Could not resolve"
    return result


def lookup_threatfox_hash(hash_val: str) -> dict:
    """ThreatFox hash lookup — free, no key."""
    payload = json.dumps({"query": "search_ioc", "search_term": hash_val}).encode()
    req = urllib.request.Request("https://threatfox-api.abuse.ch/api/v1/", data=payload)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return {}

    if data.get("query_status") == "no_results":
        return {"ThreatFox": "Not found in ThreatFox database"}

    iocs = data.get("data", [])
    if not iocs:
        return {}

    ioc = iocs[0]
    return {
        "ThreatFox Malware":  ioc.get("malware_printable", ""),
        "ThreatFox IOC Type": ioc.get("ioc_type_desc", ""),
        "Confidence":         f"{ioc.get('confidence_level', '')}%",
        "Reporter":           ioc.get("reporter", ""),
        "First Seen":         ioc.get("first_seen", ""),
        "Tags":               ", ".join(ioc.get("tags") or []) or "None",
    }


def lookup_threatfox_ip_domain(indicator: str) -> dict:
    """ThreatFox IP/domain lookup — free, no key."""
    payload = json.dumps({"query": "search_ioc", "search_term": indicator}).encode()
    req = urllib.request.Request("https://threatfox-api.abuse.ch/api/v1/", data=payload)
    req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())
    except Exception:
        return {}

    if data.get("query_status") == "no_results":
        return {"ThreatFox": "Not found"}

    iocs = data.get("data", [])
    if not iocs:
        return {}

    ioc = iocs[0]
    return {
        "ThreatFox Malware":  ioc.get("malware_printable", ""),
        "Confidence":         f"{ioc.get('confidence_level', '')}%",
        "First Seen":         ioc.get("first_seen", ""),
        "Tags":               ", ".join(ioc.get("tags") or []) or "None",
    }


# ─── Paid Sources (API key required) ────────────────────────────────────────

def lookup_virustotal(indicator: str, itype: str, api_key: str) -> dict:
    """VirusTotal — requires free API key."""
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
        "Detections":  f"{detected}/{total}",
        "Malicious":   str(malicious),
        "Suspicious":  str(suspicious),
        "Undetected":  str(stats.get("undetected", 0)),
    }

    if itype in ("md5", "sha1", "sha256"):
        result["File Type"]    = attrs.get("type_description", "")
        result["File Size"]    = f"{attrs.get('size', '')} bytes" if attrs.get("size") else ""
        result["Magic"]        = attrs.get("magic", "")
        result["First Seen"]   = attrs.get("first_submission_date", "")
        result["Times Submitted"] = str(attrs.get("times_submitted", ""))
    elif itype == "domain":
        result["Registrar"]    = attrs.get("registrar", "")
        result["Creation Date"] = attrs.get("creation_date", "")
        result["Categories"]   = ", ".join(attrs.get("categories", {}).values()) or "None"
    elif itype == "ip":
        result["Country"]      = attrs.get("country", "")
        result["Network"]      = attrs.get("network", "")
        result["AS Owner"]     = attrs.get("as_owner", "")

    result["_detected"] = detected
    result["_total"]    = total
    return result


def lookup_abuseipdb(ip: str, api_key: str) -> dict:
    """AbuseIPDB — requires free API key."""
    url = f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}&maxAgeInDays=90&verbose"
    data = fetch_json(url, headers={"Key": api_key, "Accept": "application/json"})
    if data.get("_error"):
        return {"_error": data["_error"]}

    d = data.get("data", {})
    score = d.get("abuseConfidenceScore", 0)
    return {
        "Abuse Score":      f"{score}/100",
        "Total Reports":    str(d.get("totalReports", 0)),
        "Distinct Users":   str(d.get("numDistinctUsers", 0)),
        "Last Reported":    d.get("lastReportedAt", "Never") or "Never",
        "Usage Type":       d.get("usageType", ""),
        "ISP":              d.get("isp", ""),
        "Domain":           d.get("domain", ""),
        "Tor Node":         "Yes" if d.get("isTor") else "No",
        "Whitelisted":      "Yes" if d.get("isWhitelisted") else "No",
        "_score":           score,
    }


def lookup_shodan(ip: str, api_key: str) -> dict:
    """Shodan — requires API key."""
    data = fetch_json(f"https://api.shodan.io/shodan/host/{ip}?key={api_key}")
    if data.get("_error"):
        return {"_error": data["_error"]}

    ports     = data.get("ports", [])
    hostnames = data.get("hostnames", [])
    tags      = data.get("tags", [])
    vulns     = list(data.get("vulns", {}).keys())

    result = {
        "Open Ports":  ", ".join(str(p) for p in sorted(ports)) or "None",
        "Hostnames":   ", ".join(hostnames) or "None",
        "OS":          data.get("os", "Unknown") or "Unknown",
        "Tags":        ", ".join(tags) or "None",
        "Last Update": data.get("last_update", ""),
    }
    if vulns:
        result["CVEs"] = ", ".join(vulns[:10])
        if len(vulns) > 10:
            result["CVEs"] += f" (+{len(vulns)-10} more)"
    return result


def lookup_greynoise(ip: str, api_key: str) -> dict:
    """GreyNoise — requires API key (free community tier available)."""
    data = fetch_json(
        f"https://api.greynoise.io/v3/community/{ip}",
        headers={"key": api_key}
    )
    if data.get("_error"):
        # Try community endpoint without key for basic verdict
        data = fetch_json(f"https://api.greynoise.io/v3/community/{ip}")
        if data.get("_error"):
            return {"_error": data["_error"]}

    result = {
        "Noise":        "Yes" if data.get("noise") else "No",
        "RIOT":         "Yes" if data.get("riot") else "No",
        "Classification": data.get("classification", "unknown"),
        "Name":         data.get("name", ""),
        "Link":         data.get("link", ""),
        "Last Seen":    data.get("last_seen", ""),
        "Message":      data.get("message", ""),
    }
    return {k: v for k, v in result.items() if v}


def lookup_otx(indicator: str, itype: str, api_key: str) -> dict:
    """AlienVault OTX — requires free API key."""
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
    result = {
        "OTX Pulse Count": str(pulses),
    }
    if itype == "ip":
        rep = data.get("reputation", {})
        if rep:
            result["Reputation Score"] = str(rep.get("threat_score", ""))
            result["Activities"]       = ", ".join(rep.get("activities", {}).keys()) or "None"
    return result


# ─── Main lookup orchestrator ────────────────────────────────────────────────

import urllib.parse


def run_lookup(indicator: str, itype: str, cfg: configparser.ConfigParser,
               sources: list, verbose: bool = False):

    print_header(indicator, itype)

    vt_key       = get_key(cfg, "virustotal",  "api_key")
    abuse_key    = get_key(cfg, "abuseipdb",   "api_key")
    shodan_key   = get_key(cfg, "shodan",      "api_key")
    grey_key     = get_key(cfg, "greynoise",   "api_key")
    otx_key      = get_key(cfg, "otx",         "api_key")
    ipinfo_token = get_key(cfg, "ipinfo",      "token")

    run_all = not sources or "all" in sources

    # ── IP enrichment ────────────────────────────────────────────────────────
    if itype == "ip":

        # Free: ip-api.com
        if run_all or "ipapi" in sources:
            data = lookup_ip_api(indicator)
            if data:
                flags = data.get("Flags", "None")
                color = "red" if flags != "None" else "green"
                print_section("🌐  Geolocation  [ip-api.com]", data, color)
            else:
                print_error("ip-api.com", "No data returned")

        # Free: ipinfo.io
        if run_all or "ipinfo" in sources:
            data = lookup_ipinfo(indicator, ipinfo_token)
            if data:
                print_section("🔍  IP Info  [ipinfo.io]", data, "cyan")

        # Free: ThreatFox
        if run_all or "threatfox" in sources:
            data = lookup_threatfox_ip_domain(indicator)
            if data:
                color = "red" if "ThreatFox Malware" in data else "green"
                print_section("☠️   ThreatFox  [abuse.ch]", data, color)

        # Free: URLhaus host lookup
        if run_all or "urlhaus" in sources:
            data = lookup_urlhaus_url(indicator)
            if data:
                color = "red" if "online" in str(data).lower() else "dim"
                print_section("🔗  URLhaus  [abuse.ch]", data, color)

        # Paid: AbuseIPDB
        if (run_all or "abuseipdb" in sources) and abuse_key:
            data = lookup_abuseipdb(indicator, abuse_key)
            if "_error" in data:
                print_error("AbuseIPDB", data["_error"])
            elif data:
                score = data.pop("_score", 0)
                color = abuse_color(score)
                print_section(f"🚨  AbuseIPDB  [score: {score}/100]", data, color)
        elif "abuseipdb" in sources and not abuse_key:
            print_error("AbuseIPDB", "No API key configured — run: iocinfo --setup")

        # Paid: VirusTotal
        if (run_all or "virustotal" in sources or "vt" in sources) and vt_key:
            data = lookup_virustotal(indicator, itype, vt_key)
            if "_error" in data:
                print_error("VirusTotal", data["_error"])
            elif data:
                detected = data.pop("_detected", 0)
                total    = data.pop("_total", 0)
                color    = verdict_color(detected, total)
                print_section(f"🦠  VirusTotal  [{detected}/{total} engines]", data, color)
        elif ("virustotal" in sources or "vt" in sources) and not vt_key:
            print_error("VirusTotal", "No API key configured — run: iocinfo --setup")

        # Paid: Shodan
        if (run_all or "shodan" in sources) and shodan_key:
            data = lookup_shodan(indicator, shodan_key)
            if "_error" in data:
                print_error("Shodan", data["_error"])
            elif data:
                has_vulns = "CVEs" in data
                color = "red" if has_vulns else "blue"
                print_section("🛰️   Shodan", data, color)
        elif "shodan" in sources and not shodan_key:
            print_error("Shodan", "No API key configured — run: iocinfo --setup")

        # Paid: GreyNoise
        if (run_all or "greynoise" in sources) and grey_key:
            data = lookup_greynoise(indicator, grey_key)
            if "_error" in data:
                print_error("GreyNoise", data["_error"])
            elif data:
                cls = data.get("Classification", "unknown")
                color = "red" if cls == "malicious" else "green" if cls == "benign" else "yellow"
                print_section(f"📡  GreyNoise  [{cls}]", data, color)
        elif "greynoise" in sources and not grey_key:
            print_error("GreyNoise", "No API key configured — run: iocinfo --setup")

        # Paid: OTX
        if (run_all or "otx" in sources) and otx_key:
            data = lookup_otx(indicator, itype, otx_key)
            if "_error" in data:
                print_error("OTX", data["_error"])
            elif data:
                pulses = int(data.get("OTX Pulse Count", 0))
                color  = "red" if pulses > 0 else "green"
                print_section(f"👁️   AlienVault OTX  [{pulses} pulses]", data, color)

    # ── Domain enrichment ────────────────────────────────────────────────────
    elif itype == "domain":

        # Free: DNS resolution
        if run_all or "dns" in sources:
            data = lookup_dns(indicator)
            if data:
                print_section("🌐  DNS Resolution", data, "cyan")

        # Free: ThreatFox
        if run_all or "threatfox" in sources:
            data = lookup_threatfox_ip_domain(indicator)
            if data:
                color = "red" if "ThreatFox Malware" in data else "green"
                print_section("☠️   ThreatFox  [abuse.ch]", data, color)

        # Free: URLhaus
        if run_all or "urlhaus" in sources:
            data = lookup_urlhaus_url(indicator)
            if data:
                print_section("🔗  URLhaus  [abuse.ch]", data, "yellow")

        # Paid: VirusTotal
        if (run_all or "virustotal" in sources or "vt" in sources) and vt_key:
            data = lookup_virustotal(indicator, itype, vt_key)
            if "_error" in data:
                print_error("VirusTotal", data["_error"])
            elif data:
                detected = data.pop("_detected", 0)
                total    = data.pop("_total", 0)
                color    = verdict_color(detected, total)
                print_section(f"🦠  VirusTotal  [{detected}/{total} engines]", data, color)

        # Paid: OTX
        if (run_all or "otx" in sources) and otx_key:
            data = lookup_otx(indicator, itype, otx_key)
            if "_error" in data:
                print_error("OTX", data["_error"])
            elif data:
                pulses = int(data.get("OTX Pulse Count", 0))
                color  = "red" if pulses > 0 else "green"
                print_section(f"👁️   AlienVault OTX  [{pulses} pulses]", data, color)

    # ── Hash enrichment ──────────────────────────────────────────────────────
    elif itype in ("md5", "sha1", "sha256"):

        # Free: URLhaus
        if run_all or "urlhaus" in sources:
            data = lookup_urlhaus_hash(indicator)
            if data:
                color = "red" if "malware" in str(data).lower() else "dim"
                print_section("🔗  URLhaus  [abuse.ch]", data, color)

        # Free: ThreatFox
        if run_all or "threatfox" in sources:
            data = lookup_threatfox_hash(indicator)
            if data:
                color = "red" if "ThreatFox Malware" in data else "green"
                print_section("☠️   ThreatFox  [abuse.ch]", data, color)

        # Paid: VirusTotal
        if (run_all or "virustotal" in sources or "vt" in sources) and vt_key:
            data = lookup_virustotal(indicator, itype, vt_key)
            if "_error" in data:
                print_error("VirusTotal", data["_error"])
            elif data:
                detected = data.pop("_detected", 0)
                total    = data.pop("_total", 0)
                color    = verdict_color(detected, total)
                print_section(f"🦠  VirusTotal  [{detected}/{total} engines]", data, color)

        # Paid: OTX
        if (run_all or "otx" in sources) and otx_key:
            data = lookup_otx(indicator, itype, otx_key)
            if "_error" in data:
                print_error("OTX", data["_error"])
            elif data:
                pulses = int(data.get("OTX Pulse Count", 0))
                color  = "red" if pulses > 0 else "green"
                print_section(f"👁️   AlienVault OTX  [{pulses} pulses]", data, color)

    if RICH:
        console.print(Rule(style="bright_black"))
        console.print()


# ─── Setup wizard ────────────────────────────────────────────────────────────

def setup_wizard():
    print("\n  iocinfo — API Key Setup")
    print("  " + "─" * 40)
    print("  Press ENTER to skip any key you don't have yet.\n")

    keys = {
        "virustotal":  ("VirusTotal",       "api_key",  "https://www.virustotal.com/gui/join-us"),
        "abuseipdb":   ("AbuseIPDB",        "api_key",  "https://www.abuseipdb.com/register"),
        "shodan":      ("Shodan",           "api_key",  "https://account.shodan.io/register"),
        "greynoise":   ("GreyNoise",        "api_key",  "https://viz.greynoise.io/signup"),
        "otx":         ("AlienVault OTX",   "api_key",  "https://otx.alienvault.com/accounts/signup"),
        "ipinfo":      ("ipinfo.io (opt.)", "token",    "https://ipinfo.io/signup"),
    }

    cfg = configparser.ConfigParser()
    if CONFIG_FILE.exists():
        cfg.read(CONFIG_FILE)

    for section, (name, key, signup_url) in keys.items():
        existing = get_key(cfg, section, key)
        prompt = f"  {name} [{signup_url}]\n  Key"
        if existing:
            prompt += f" (current: {existing[:6]}...{'ENTER to keep'})"
        val = input(f"{prompt}: ").strip()
        if val:
            if section not in cfg:
                cfg[section] = {}
            cfg[section][key] = val
        elif existing:
            pass  # keep existing

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    with open(CONFIG_FILE, "w") as f:
        cfg.write(f)

    print(f"\n  ✓ Config saved to {CONFIG_FILE}\n")


# ─── CLI entry point ─────────────────────────────────────────────────────────

def print_help():
    """Rich color-coded help screen."""
    if not RICH:
        print("""
iocinfo v1.0.0 — IOC enrichment CLI

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
  dns             Live DNS resolution                            [Domain]
  threatfox       Malware family, confidence, tags               [IP, Domain, Hash]
  urlhaus         Malware URLs, signatures, file type            [Domain, Hash]

PAID SOURCES (free API keys available):
  vt / virustotal Detection ratio across 90+ AV engines          [IP, Domain, Hash]
  abuseipdb       Abuse score, report history                    [IP]
  shodan          Open ports, banners, CVEs                      [IP]
  greynoise       Internet noise classification                  [IP]
  otx             Pulse count, threat actor tagging              [IP, Domain, Hash]

EXAMPLES:
  iocinfo 8.8.8.8
  iocinfo evil.com
  iocinfo d41d8cd98f00b204e9800998ecf8427e
  iocinfo 1.2.3.4 --source abuseipdb
  iocinfo 1.2.3.4 --source vt abuseipdb shodan
  iocinfo --setup
""")
        return

    console.print()
    console.print(Panel.fit(
        "[bold white]iocinfo[/] [dim]v1.0.0[/]  ·  [dim]IOC enrichment CLI[/]",
        border_style="bright_black"
    ))
    console.print()

    console.print("  [bold cyan]USAGE[/]")
    console.print("    [white]iocinfo[/] [green]<indicator>[/] [dim]\\[options][/]")
    console.print("    [white]iocinfo[/] [yellow]--setup[/]")
    console.print("    [white]iocinfo[/] [yellow]--help[/]")
    console.print()

    console.print("  [bold cyan]ARGUMENTS[/]")
    console.print(f"    [green]{'indicator':<18}[/] IP address, domain, or hash [dim](auto-detected)[/]")
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

    console.print("  [bold green]FREE SOURCES[/] [dim]— no API key needed[/]")
    free = [
        ("ipapi",     "Geolocation, ASN, ISP, proxy/hosting flags",  "IP"),
        ("ipinfo",    "Hostname, org, abuse contact",                 "IP"),
        ("dns",       "Live DNS resolution",                          "Domain"),
        ("threatfox", "Malware family, confidence score, tags",       "IP · Domain · Hash"),
        ("urlhaus",   "Malware URLs, signatures, file type",          "Domain · Hash"),
    ]
    for name, desc, types in free:
        console.print(f"    [bold green]{name:<18}[/] {desc:<44} [dim cyan]{types}[/]")
    console.print()

    console.print("  [bold yellow]PAID SOURCES[/] [dim]— free keys available  →  run: iocinfo --setup[/]")
    paid = [
        ("vt / virustotal", "Detection ratio across 90+ AV engines",     "IP · Domain · Hash"),
        ("abuseipdb",       "Abuse confidence score, report history",     "IP"),
        ("shodan",          "Open ports, banners, CVEs, hostnames",       "IP"),
        ("greynoise",       "Internet noise classification",              "IP"),
        ("otx",             "Pulse count, threat actor tagging",          "IP · Domain · Hash"),
    ]
    for name, desc, types in paid:
        console.print(f"    [bold yellow]{name:<18}[/] {desc:<44} [dim cyan]{types}[/]")
    console.print()

    console.print("  [bold cyan]EXAMPLES[/]")
    examples = [
        "iocinfo 8.8.8.8",
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


def main():
    if "-h" in sys.argv or "--help" in sys.argv:
        print_help()
        return

    parser = argparse.ArgumentParser(prog="iocinfo", add_help=False)
    parser.add_argument("indicator", nargs="?")
    parser.add_argument("--source", nargs="+", metavar="SOURCE")
    parser.add_argument("--type", choices=["ip", "domain", "md5", "sha1", "sha256"])
    parser.add_argument("--setup", action="store_true")
    parser.add_argument("--version", action="version", version="iocinfo 1.0.0")
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
        print("\n  Tip: Install \'rich\' for colored output: pip install rich\n")

    run_lookup(indicator, itype, cfg, sources)


if __name__ == "__main__":
    main()
