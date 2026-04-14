"""
Passive domain/URL OSINT module.
All lookups go through third-party APIs or public databases — zero direct
contact with the target host.
"""

import json
import re
import socket
from datetime import datetime
from typing import Any

import dns.resolver
import requests
import whois

from .. import config
from .utils import console, extract_domain, is_ip, print_result, print_section

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get(url: str, **kwargs) -> requests.Response | None:
    try:
        r = requests.get(
            url,
            headers=config.HEADERS,
            timeout=config.TIMEOUT,
            **kwargs,
        )
        r.raise_for_status()
        return r
    except Exception as e:
        console.print(f"  [dim red]  request failed: {e}[/dim red]")
        return None


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

def lookup_whois(domain: str) -> dict[str, Any]:
    print_section("WHOIS", "yellow")
    try:
        w = whois.whois(domain)
        data = {
            "registrar": w.registrar,
            "created": str(w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date),
            "expires": str(w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date),
            "updated": str(w.updated_date[0] if isinstance(w.updated_date, list) else w.updated_date),
            "name_servers": w.name_servers,
            "status": w.status if isinstance(w.status, list) else [w.status],
            "emails": w.emails if isinstance(w.emails, list) else ([w.emails] if w.emails else []),
            "country": w.country,
            "org": w.org,
        }
        for k, v in data.items():
            print_result(k, v)
        return data
    except Exception as e:
        console.print(f"  [red]WHOIS lookup failed: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# DNS (passive — querying public resolvers, not the target)
# ---------------------------------------------------------------------------

def lookup_dns(domain: str) -> dict[str, list[str]]:
    print_section("DNS Records (passive)", "yellow")
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]
    results: dict[str, list[str]] = {}
    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1"]  # Google & Cloudflare — not the target

    for rtype in record_types:
        try:
            answers = resolver.resolve(domain, rtype, lifetime=8)
            records = [str(r) for r in answers]
            results[rtype] = records
            print_result(rtype, records)
        except Exception:
            results[rtype] = []

    return results


# ---------------------------------------------------------------------------
# Certificate Transparency — crt.sh (passive)
# ---------------------------------------------------------------------------

def lookup_crtsh(domain: str) -> list[str]:
    print_section("Certificate Transparency (crt.sh)", "yellow")
    r = _get(f"https://crt.sh/?q=%.{domain}&output=json")
    if not r:
        return []

    try:
        entries = r.json()
        subdomains: set[str] = set()
        for entry in entries:
            name = entry.get("name_value", "")
            for line in name.splitlines():
                line = line.strip().lstrip("*.")
                if line.endswith(domain):
                    subdomains.add(line)
        subs = sorted(subdomains)
        print_result("subdomains found", subs)
        return subs
    except Exception as e:
        console.print(f"  [red]crt.sh parse error: {e}[/red]")
        return []


# ---------------------------------------------------------------------------
# Wayback Machine (passive archive)
# ---------------------------------------------------------------------------

def lookup_wayback(domain: str) -> dict[str, Any]:
    print_section("Wayback Machine (archive.org)", "yellow")
    url = f"https://archive.org/wayback/available?url={domain}"
    r = _get(url)
    if not r:
        return {}
    data = r.json()
    snapshot = data.get("archived_snapshots", {}).get("closest", {})
    if snapshot:
        print_result("available", snapshot.get("available"))
        print_result("timestamp", snapshot.get("timestamp"))
        print_result("url", snapshot.get("url"))
        print_result("status", snapshot.get("status"))
    else:
        console.print("  [dim]No snapshot found.[/dim]")

    # CDX API — count of captures
    cdx = _get(
        "https://web.archive.org/cdx/search/cdx",
        params={"url": domain, "output": "json", "fl": "timestamp", "limit": "5", "collapse": "timestamp:6"},
    )
    if cdx:
        try:
            rows = cdx.json()
            if len(rows) > 1:
                timestamps = [r[0] for r in rows[1:]]
                print_result("recent captures", timestamps)
        except Exception:
            pass
    return snapshot


# ---------------------------------------------------------------------------
# Shodan (requires API key)
# ---------------------------------------------------------------------------

def lookup_shodan(query: str) -> dict[str, Any]:
    print_section("Shodan (passive scan data)", "yellow")
    if not config.SHODAN_API_KEY:
        console.print("  [dim]SHODAN_API_KEY not set — skipping.[/dim]")
        return {}

    endpoint = (
        f"https://api.shodan.io/shodan/host/{query}?key={config.SHODAN_API_KEY}"
        if is_ip(query)
        else f"https://api.shodan.io/dns/resolve?hostnames={query}&key={config.SHODAN_API_KEY}"
    )
    r = _get(endpoint)
    if not r:
        return {}

    try:
        data = r.json()
        if not is_ip(query):
            ip = data.get(query, "")
            print_result("resolved IP", ip)
            if ip:
                r2 = _get(f"https://api.shodan.io/shodan/host/{ip}?key={config.SHODAN_API_KEY}")
                data = r2.json() if r2 else {}

        print_result("org", data.get("org"))
        print_result("isp", data.get("isp"))
        print_result("country", data.get("country_name"))
        print_result("city", data.get("city"))
        print_result("os", data.get("os"))
        open_ports = data.get("ports", [])
        print_result("open ports", open_ports)
        vulns = list(data.get("vulns", {}).keys())
        if vulns:
            print_result("CVEs detected", vulns)
        return data
    except Exception as e:
        console.print(f"  [red]Shodan parse error: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# VirusTotal (passive reputation)
# ---------------------------------------------------------------------------

def lookup_virustotal(domain: str) -> dict[str, Any]:
    print_section("VirusTotal (passive reputation)", "yellow")
    if not config.VIRUSTOTAL_API_KEY:
        console.print("  [dim]VIRUSTOTAL_API_KEY not set — skipping.[/dim]")
        return {}

    r = _get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers={**config.HEADERS, "x-apikey": config.VIRUSTOTAL_API_KEY},
    )
    if not r:
        return {}

    try:
        data = r.json().get("data", {}).get("attributes", {})
        stats = data.get("last_analysis_stats", {})
        print_result("malicious votes", stats.get("malicious", 0))
        print_result("suspicious votes", stats.get("suspicious", 0))
        print_result("harmless votes", stats.get("harmless", 0))
        print_result("reputation", data.get("reputation"))
        cats = data.get("categories", {})
        print_result("categories", list(cats.values()))
        print_result("creation date", data.get("creation_date"))
        return data
    except Exception as e:
        console.print(f"  [red]VirusTotal parse error: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# Hunter.io — email discovery from domain
# ---------------------------------------------------------------------------

def lookup_hunter(domain: str) -> list[str]:
    print_section("Hunter.io (email discovery)", "yellow")
    if not config.HUNTER_API_KEY:
        console.print("  [dim]HUNTER_API_KEY not set — skipping.[/dim]")
        return []

    r = _get(
        "https://api.hunter.io/v2/domain-search",
        params={"domain": domain, "api_key": config.HUNTER_API_KEY, "limit": 20},
    )
    if not r:
        return []

    try:
        data = r.json().get("data", {})
        emails = [e["value"] for e in data.get("emails", [])]
        print_result("organization", data.get("organization"))
        print_result("emails found", emails)
        return emails
    except Exception as e:
        console.print(f"  [red]Hunter parse error: {e}[/red]")
        return []


# ---------------------------------------------------------------------------
# URLScan.io (passive scan database)
# ---------------------------------------------------------------------------

def lookup_urlscan(domain: str) -> list[dict]:
    print_section("URLScan.io (passive scan history)", "yellow")
    r = _get(
        "https://urlscan.io/api/v1/search/",
        params={"q": f"domain:{domain}", "size": 5},
        headers={**config.HEADERS, "API-Key": config.URLSCAN_API_KEY or ""},
    )
    if not r:
        return []

    try:
        results = r.json().get("results", [])
        for res in results:
            page = res.get("page", {})
            console.print(
                f"  [green]•[/green] {page.get('url', '')} "
                f"[dim]({res.get('task', {}).get('time', '')})[/dim]"
            )
        print_result("total scans found", r.json().get("total", 0))
        return results
    except Exception as e:
        console.print(f"  [red]URLScan parse error: {e}[/red]")
        return []


# ---------------------------------------------------------------------------
# IP Geolocation (ip-api.com — free, passive)
# ---------------------------------------------------------------------------

def lookup_ip_geo(ip_or_domain: str) -> dict[str, Any]:
    print_section("IP Geolocation (ip-api.com)", "yellow")
    # Resolve domain to IP without touching target (public DNS)
    target = ip_or_domain
    if not is_ip(ip_or_domain):
        try:
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ["8.8.8.8"]
            answers = resolver.resolve(ip_or_domain, "A", lifetime=8)
            target = str(answers[0])
            console.print(f"  [dim]Resolved {ip_or_domain} → {target}[/dim]")
        except Exception:
            console.print("  [red]Could not resolve domain.[/red]")
            return {}

    r = _get(f"https://ip-api.com/json/{target}?fields=status,country,countryCode,regionName,city,zip,lat,lon,isp,org,as,asname,proxy,hosting,timezone,query")
    if not r:
        return {}

    try:
        data = r.json()
        print_result("IP", data.get("query"))
        print_result("country", f"{data.get('country')} ({data.get('countryCode')})")
        print_result("region", data.get("regionName"))
        print_result("city", data.get("city"))
        print_result("zip", data.get("zip"))
        print_result("lat/lon", f"{data.get('lat')}, {data.get('lon')}")
        print_result("ISP", data.get("isp"))
        print_result("org", data.get("org"))
        print_result("AS", data.get("as"))
        print_result("ASN", data.get("asname"))
        print_result("proxy/VPN", data.get("proxy"))
        print_result("hosting", data.get("hosting"))
        print_result("timezone", data.get("timezone"))
        return data
    except Exception as e:
        console.print(f"  [red]IP geo parse error: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# HackerTarget — free, 100/day, no key
# ---------------------------------------------------------------------------

def lookup_hackertarget(domain: str) -> dict[str, Any]:
    print_section("HackerTarget (DNS history + reverse IP)", "yellow")
    dns_r = _get(f"https://api.hackertarget.com/dnslookup/?q={domain}")
    # Resolve to IP for reverse lookup
    ip = ""
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8"]
        answers = resolver.resolve(domain, "A", lifetime=8)
        ip = str(answers[0])
    except Exception:
        pass

    hosted: list[str] = []
    if ip:
        rev_r = _get(f"https://api.hackertarget.com/reverseiplookup/?q={ip}")
        if rev_r and "error" not in rev_r.text.lower():
            hosted = [l.strip() for l in rev_r.text.strip().splitlines() if l.strip()]

    dns_lines: list[str] = []
    if dns_r and "error" not in dns_r.text.lower():
        dns_lines = [l.strip() for l in dns_r.text.strip().splitlines() if l.strip()]

    print_result("resolved IP",     ip)
    print_result("co-hosted domains", hosted[:15])
    print_result("dns records",     dns_lines[:15])
    return {"ip": ip, "hosted_domains": hosted, "dns_records": dns_lines}


# ---------------------------------------------------------------------------
# ThreatFox — abuse.ch, free, no key
# ---------------------------------------------------------------------------

def lookup_threatfox(domain: str) -> dict[str, Any]:
    print_section("ThreatFox (IOC database)", "yellow")
    try:
        r = requests.post(
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "search_ioc", "search_term": domain},
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
# URLHaus — abuse.ch, free, no key
# ---------------------------------------------------------------------------

def lookup_urlhaus(domain: str) -> dict[str, Any]:
    print_section("URLHaus (malware URL database)", "yellow")
    try:
        r = requests.post(
            "https://urlhaus-api.abuse.ch/v1/host/",
            data={"host": domain},
            headers=config.HEADERS,
            timeout=config.TIMEOUT,
        )
        r.raise_for_status()
        data = r.json()
        if data.get("query_status") == "no_results":
            console.print("  [dim green]Not found in URLHaus.[/dim green]")
            return {"found": False}
        urls = data.get("urls", [])
        console.print(f"  [bold red]Found {len(urls)} malicious URL(s)![/bold red]")
        result = [
            {
                "url":        u.get("url"),
                "status":     u.get("url_status"),
                "threat":     u.get("threat"),
                "date_added": u.get("date_added"),
            }
            for u in urls[:5]
        ]
        for u in result:
            print_result(u["url"], u["threat"])
        return {"found": True, "total": len(urls), "urls": result}
    except Exception as e:
        console.print(f"  [red]URLHaus error: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# AlienVault OTX — free key (register at otx.alienvault.com)
# ---------------------------------------------------------------------------

def lookup_alienvault(domain: str) -> dict[str, Any]:
    print_section("AlienVault OTX (threat intel)", "yellow")
    if not config.ALIENVAULT_API_KEY:
        console.print("  [dim]ALIENVAULT_API_KEY not set — skipping.[/dim]")
        return {}
    r = _get(
        f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/general",
        headers={**config.HEADERS, "X-OTX-API-KEY": config.ALIENVAULT_API_KEY},
    )
    if not r:
        return {}
    try:
        data = r.json()
        pulse_info = data.get("pulse_info", {})
        pulses     = pulse_info.get("pulses", [])
        tags: list[str] = []
        for p in pulses[:10]:
            tags.extend(p.get("tags", []))
        tags = sorted(set(tags))
        print_result("pulse count", pulse_info.get("count", 0))
        print_result("reputation",  data.get("reputation", 0))
        print_result("alexa rank",  data.get("alexa"))
        print_result("tags",        tags[:10])
        return {
            "pulse_count": pulse_info.get("count", 0),
            "reputation":  data.get("reputation", 0),
            "tags":        tags,
            "pulses":      [{"name": p.get("name"), "created": p.get("created")} for p in pulses[:5]],
        }
    except Exception as e:
        console.print(f"  [red]AlienVault parse error: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# SecurityTrails — free key, 50 queries/month
# ---------------------------------------------------------------------------

def lookup_securitytrails(domain: str) -> dict[str, Any]:
    print_section("SecurityTrails (DNS history)", "yellow")
    if not config.SECURITYTRAILS_API_KEY:
        console.print("  [dim]SECURITYTRAILS_API_KEY not set — skipping.[/dim]")
        return {}
    r = _get(
        f"https://api.securitytrails.com/v1/domain/{domain}",
        headers={**config.HEADERS, "APIKEY": config.SECURITYTRAILS_API_KEY},
    )
    if not r:
        return {}
    try:
        data = r.json()
        current = data.get("current_dns", {})
        print_result("hostname",      data.get("hostname"))
        print_result("apex_domain",   data.get("apex_domain"))
        print_result("A records",     [v.get("ip")    for v in current.get("a",  {}).get("values", [])])
        print_result("MX records",    [v.get("value") for v in current.get("mx", {}).get("values", [])])
        print_result("NS records",    [v.get("value") for v in current.get("ns", {}).get("values", [])])
        print_result("subdomain count", data.get("subdomain_count", 0))
        return data
    except Exception as e:
        console.print(f"  [red]SecurityTrails parse error: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# Censys — free key, 250 queries/month (register at censys.io)
# ---------------------------------------------------------------------------

def lookup_censys(domain: str) -> dict[str, Any]:
    print_section("Censys (internet scan)", "yellow")
    if not config.CENSYS_API_ID or not config.CENSYS_API_SECRET:
        console.print("  [dim]CENSYS_API_ID/SECRET not set — skipping.[/dim]")
        return {}
    r = _get(
        "https://search.censys.io/api/v2/hosts/search",
        params={"q": f"dns.names: {domain}", "per_page": 5},
        auth=(config.CENSYS_API_ID, config.CENSYS_API_SECRET),
    )
    if not r:
        return {}
    try:
        hits = r.json().get("result", {}).get("hits", [])
        result = []
        for h in hits:
            entry = {
                "ip":       h.get("ip"),
                "services": [f"{s.get('port')}/{s.get('transport_protocol','tcp')}" for s in h.get("services", [])],
                "labels":   h.get("labels", []),
            }
            result.append(entry)
            print_result(h.get("ip"), entry["services"])
        total = r.json().get("result", {}).get("total", 0)
        print_result("total hosts", total)
        return {"total": total, "hosts": result}
    except Exception as e:
        console.print(f"  [red]Censys parse error: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# Full domain scan orchestrator
# ---------------------------------------------------------------------------

def scan_domain(target: str, tools: set[str] | None = None, use_cache: bool = True) -> dict[str, Any]:
    from .cache import get_cache
    domain = extract_domain(target)
    console.print(f"\n[bold white]Target:[/bold white] [bold green]{domain}[/bold green]")

    cache = get_cache()
    if use_cache:
        cached = cache.get("domain", domain)
        if cached:
            console.print("  [dim cyan][cache hit — use --no-cache to refresh][/dim cyan]")
            # Re-print key findings from cache
            for section, data in cached.items():
                if isinstance(data, dict) and data:
                    print_section(section, "yellow")
                    for k, v in data.items():
                        print_result(k, v)
                elif isinstance(data, list) and data:
                    print_section(section, "yellow")
                    print_result("results", data)
            return cached

    steps = [
        ("whois",          lambda d: lookup_whois(d)),
        ("dns",            lambda d: lookup_dns(d)),
        ("crtsh",          lambda d: {"subdomains": lookup_crtsh(d)}),
        ("wayback",        lambda d: lookup_wayback(d)),
        ("ip_geo",         lambda d: lookup_ip_geo(d)),
        ("hackertarget",   lambda d: lookup_hackertarget(d)),
        ("urlscan",        lambda d: {"results": [r.get("page", {}).get("url") for r in lookup_urlscan(d)]}),
        ("threatfox",      lambda d: lookup_threatfox(d)),
        ("urlhaus",        lambda d: lookup_urlhaus(d)),
        ("alienvault",     lambda d: lookup_alienvault(d)),
        ("virustotal",     lambda d: lookup_virustotal(d)),
        ("censys",         lambda d: lookup_censys(d)),
        ("securitytrails", lambda d: lookup_securitytrails(d)),
        ("shodan",         lambda d: lookup_shodan(d)),
        ("hunter",         lambda d: {"emails": lookup_hunter(d)}),
    ]

    result: dict[str, Any] = {}
    for name, fn in steps:
        if tools and name not in tools:
            continue
        result[name] = fn(domain)

    if use_cache:
        cache.set("domain", domain, result)

    return result
