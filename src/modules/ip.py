"""
Passive IP OSINT module.
All lookups query third-party databases — zero direct contact with the target.
"""

from typing import Any

import requests

from .utils import console, print_result, print_section
from .. import config


def _get(url: str, **kwargs) -> requests.Response | None:
    try:
        r = requests.get(url, headers=config.HEADERS, timeout=config.TIMEOUT, **kwargs)
        r.raise_for_status()
        return r
    except Exception as e:
        console.print(f"  [dim red]  request failed: {e}[/dim red]")
        return None


# ---------------------------------------------------------------------------
# ip-api.com — free, no key, 45 req/min
# ---------------------------------------------------------------------------

def lookup_ip_geo(ip: str) -> dict[str, Any]:
    print_section("IP Geolocation (ip-api.com)", "cyan")
    r = _get(
        f"https://ip-api.com/json/{ip}",
        params={"fields": "status,country,countryCode,regionName,city,zip,lat,lon,isp,org,as,asname,proxy,hosting,timezone,query"},
    )
    if not r:
        return {}
    try:
        data = r.json()
        if data.get("status") != "success":
            console.print("  [dim]No data.[/dim]")
            return {}
        print_result("IP",      data.get("query"))
        print_result("country", f"{data.get('country')} ({data.get('countryCode')})")
        print_result("region",  data.get("regionName"))
        print_result("city",    data.get("city"))
        print_result("ISP",     data.get("isp"))
        print_result("org",     data.get("org"))
        print_result("AS",      data.get("as"))
        print_result("proxy/VPN", data.get("proxy"))
        print_result("hosting", data.get("hosting"))
        print_result("timezone", data.get("timezone"))
        return data
    except Exception as e:
        console.print(f"  [red]Parse error: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# ipinfo.io — free, no key, 50k/month
# ---------------------------------------------------------------------------

def lookup_ipinfo(ip: str) -> dict[str, Any]:
    print_section("IPInfo.io", "cyan")
    r = _get(f"https://ipinfo.io/{ip}/json")
    if not r:
        return {}
    try:
        data = r.json()
        print_result("hostname", data.get("hostname"))
        print_result("org",      data.get("org"))
        print_result("city",     data.get("city"))
        print_result("region",   data.get("region"))
        print_result("country",  data.get("country"))
        print_result("loc",      data.get("loc"))
        print_result("timezone", data.get("timezone"))
        return data
    except Exception as e:
        console.print(f"  [red]Parse error: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# BGPView — free, no key, ASN + routing info
# ---------------------------------------------------------------------------

def lookup_bgpview(ip: str) -> dict[str, Any]:
    print_section("BGPView (ASN / routing)", "cyan")
    r = _get(f"https://api.bgpview.io/ip/{ip}")
    if not r:
        return {}
    try:
        data = r.json().get("data", {})
        prefixes = data.get("prefixes", [])
        asns = []
        prefix_list = []
        for p in prefixes:
            prefix_list.append(p.get("prefix"))
            asn_info = p.get("asn", {})
            asns.append({
                "asn":         asn_info.get("asn"),
                "name":        asn_info.get("name"),
                "description": asn_info.get("description"),
                "country":     asn_info.get("country_code"),
            })
        for asn in asns:
            print_result(f"ASN {asn.get('asn')}", asn.get("description") or asn.get("name"))
        print_result("prefixes", prefix_list)
        rir = data.get("rir_allocation", {})
        print_result("RIR", rir.get("rir_name"))
        return {"prefixes": prefix_list, "asns": asns, "rir": rir}
    except Exception as e:
        console.print(f"  [red]Parse error: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# HackerTarget — free, 100/day, no key — reverse IP lookup
# ---------------------------------------------------------------------------

def lookup_hackertarget_ip(ip: str) -> dict[str, Any]:
    print_section("HackerTarget (reverse IP)", "cyan")
    r = _get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
    if not r:
        return {}
    lines = [l.strip() for l in r.text.strip().splitlines() if l.strip() and "error" not in l.lower()]
    print_result("hosted domains", lines[:20])
    return {"hosted_domains": lines}


# ---------------------------------------------------------------------------
# GreyNoise — community tier free, no key needed
# ---------------------------------------------------------------------------

def lookup_greynoise(ip: str) -> dict[str, Any]:
    print_section("GreyNoise (noise / malicious)", "cyan")
    headers = {**config.HEADERS}
    if config.GREYNOISE_API_KEY:
        headers["key"] = config.GREYNOISE_API_KEY
    r = _get(f"https://api.greynoise.io/v3/community/{ip}", headers=headers)
    if not r:
        return {}
    try:
        data = r.json()
        if data.get("message") == "This IP is not in our database.":
            console.print("  [dim]Not in GreyNoise database.[/dim]")
            return {"noise": False, "riot": False, "classification": "unknown"}
        print_result("noise",          data.get("noise"))
        print_result("riot (trusted)", data.get("riot"))
        print_result("classification", data.get("classification"))
        print_result("name",           data.get("name"))
        print_result("link",           data.get("link"))
        return data
    except Exception as e:
        console.print(f"  [red]Parse error: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# ThreatFox — abuse.ch, free, no key
# ---------------------------------------------------------------------------

def lookup_threatfox_ip(ip: str) -> dict[str, Any]:
    print_section("ThreatFox (IOC database)", "cyan")
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": ip},
            headers=config.HEADERS,
            timeout=config.TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("query_status") == "no_result":
            console.print("  [dim green]Not found in ThreatFox.[/dim green]")
            return {"found": False}
        iocs = data.get("data", [])
        console.print(f"  [bold red]Found {len(iocs)} IOC(s)![/bold red]")
        result = []
        for ioc in iocs[:5]:
            entry = {
                "ioc":         ioc.get("ioc_value"),
                "threat_type": ioc.get("threat_type"),
                "malware":     ioc.get("malware"),
                "confidence":  ioc.get("confidence_level"),
                "first_seen":  ioc.get("first_seen"),
            }
            result.append(entry)
            print_result(ioc.get("ioc_value"), f"{ioc.get('threat_type')} / {ioc.get('malware')}")
        return {"found": True, "iocs": result}
    except Exception as e:
        console.print(f"  [red]ThreatFox error: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# AbuseIPDB — free key, 1000 checks/day
# ---------------------------------------------------------------------------

def lookup_abuseipdb(ip: str) -> dict[str, Any]:
    print_section("AbuseIPDB (reputation)", "cyan")
    if not config.ABUSEIPDB_API_KEY:
        console.print("  [dim]ABUSEIPDB_API_KEY not set — skipping.[/dim]")
        return {}
    r = _get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={**config.HEADERS, "Key": config.ABUSEIPDB_API_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
    )
    if not r:
        return {}
    try:
        data = r.json().get("data", {})
        score = data.get("abuseConfidenceScore", 0)
        print_result("abuse score",   f"{score}%")
        print_result("country",       data.get("countryCode"))
        print_result("ISP",           data.get("isp"))
        print_result("domain",        data.get("domain"))
        print_result("total reports", data.get("totalReports"))
        print_result("last reported", data.get("lastReportedAt"))
        print_result("hostnames",     data.get("hostnames"))
        return data
    except Exception as e:
        console.print(f"  [red]Parse error: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# VirusTotal IP reputation — free key (4 req/min)
# ---------------------------------------------------------------------------

def lookup_virustotal_ip(ip: str) -> dict[str, Any]:
    print_section("VirusTotal (IP reputation)", "cyan")
    if not config.VIRUSTOTAL_API_KEY:
        console.print("  [dim]VIRUSTOTAL_API_KEY not set — skipping.[/dim]")
        return {}
    r = _get(
        f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
        headers={**config.HEADERS, "x-apikey": config.VIRUSTOTAL_API_KEY},
    )
    if not r:
        return {}
    try:
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        print_result("malicious",  stats.get("malicious", 0))
        print_result("suspicious", stats.get("suspicious", 0))
        print_result("harmless",   stats.get("harmless", 0))
        print_result("country",    data.get("country"))
        print_result("ASN",        data.get("asn"))
        print_result("AS owner",   data.get("as_owner"))
        return data
    except Exception as e:
        console.print(f"  [red]Parse error: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# Shodan — paid key
# ---------------------------------------------------------------------------

def lookup_shodan_ip(ip: str) -> dict[str, Any]:
    print_section("Shodan (scan data)", "cyan")
    if not config.SHODAN_API_KEY:
        console.print("  [dim]SHODAN_API_KEY not set — skipping.[/dim]")
        return {}
    r = _get(f"https://api.shodan.io/shodan/host/{ip}?key={config.SHODAN_API_KEY}")
    if not r:
        return {}
    try:
        data = r.json()
        print_result("org",        data.get("org"))
        print_result("isp",        data.get("isp"))
        print_result("os",         data.get("os"))
        print_result("open ports", data.get("ports", []))
        vulns = list(data.get("vulns", {}).keys())
        if vulns:
            print_result("CVEs", vulns)
        return data
    except Exception as e:
        console.print(f"  [red]Parse error: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def scan_ip(ip: str, tools: set[str] | None = None, use_cache: bool = True) -> dict[str, Any]:
    from .cache import get_cache
    console.print(f"\n[bold white]Target IP:[/bold white] [bold cyan]{ip}[/bold cyan]")

    cache = get_cache()
    if use_cache:
        cached = cache.get("ip", ip)
        if cached:
            console.print("  [dim cyan][cache hit — use --no-cache to refresh][/dim cyan]")
            return cached

    steps = [
        ("ip_geo",       lookup_ip_geo),
        ("ipinfo",       lookup_ipinfo),
        ("bgpview",      lookup_bgpview),
        ("hackertarget", lookup_hackertarget_ip),
        ("greynoise",    lookup_greynoise),
        ("threatfox",    lookup_threatfox_ip),
        ("abuseipdb",    lookup_abuseipdb),
        ("virustotal",   lookup_virustotal_ip),
        ("shodan",       lookup_shodan_ip),
    ]

    result: dict[str, Any] = {}
    for name, fn in steps:
        if tools and name not in tools:
            continue
        result[name] = fn(ip)

    if use_cache:
        cache.set("ip", ip, result)
    return result
