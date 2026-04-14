"""
Passive email OSINT module — profile enrichment (separate from breach checks).
Zero direct contact with the target.
"""

import hashlib
import time
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
# EmailRep.io — free, no key, 10 req/day
# ---------------------------------------------------------------------------

def lookup_emailrep(email: str) -> dict[str, Any]:
    print_section("EmailRep.io (reputation)", "yellow")
    r = _get(
        f"https://emailrep.io/{email}",
        headers={**config.HEADERS, "User-Agent": "ultimate-osint"},
    )
    if not r:
        return {}
    try:
        data = r.json()
        details = data.get("details", {})
        print_result("reputation",          data.get("reputation"))
        print_result("suspicious",          data.get("suspicious"))
        print_result("references",          data.get("references"))
        print_result("blacklisted",         details.get("blacklisted"))
        print_result("malicious_activity",  details.get("malicious_activity"))
        print_result("credentials_leaked",  details.get("credentials_leaked"))
        print_result("data_breach",         details.get("data_breach"))
        print_result("profiles",            details.get("profiles", []))
        print_result("first_seen",          details.get("first_seen"))
        print_result("last_seen",           details.get("last_seen"))
        return data
    except Exception as e:
        console.print(f"  [red]Parse error: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# Gravatar — free, no key
# ---------------------------------------------------------------------------

def lookup_gravatar(email: str) -> dict[str, Any]:
    print_section("Gravatar (avatar / profile)", "yellow")
    h = hashlib.md5(email.lower().strip().encode()).hexdigest()
    try:
        r = requests.get(
            f"https://www.gravatar.com/avatar/{h}?d=404",
            headers=config.HEADERS,
            timeout=10,
        )
        found = r.status_code == 200
        avatar_url  = f"https://www.gravatar.com/avatar/{h}" if found else None
        profile_url = f"https://en.gravatar.com/{h}.json"    if found else None
        print_result("avatar found", found)
        if found:
            print_result("avatar url",  avatar_url)
            print_result("profile url", profile_url)
        return {"found": found, "hash": h, "avatar_url": avatar_url, "profile_url": profile_url}
    except Exception as e:
        console.print(f"  [red]Gravatar error: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# Hunter.io email verifier — free key, 25 verifications/month
# ---------------------------------------------------------------------------

def lookup_hunter_email(email: str) -> dict[str, Any]:
    print_section("Hunter.io (email verification)", "yellow")
    if not config.HUNTER_API_KEY:
        console.print("  [dim]HUNTER_API_KEY not set — skipping.[/dim]")
        return {}
    r = _get(
        "https://api.hunter.io/v2/email-verifier",
        params={"email": email, "api_key": config.HUNTER_API_KEY},
    )
    if not r:
        return {}
    try:
        data = r.json().get("data", {})
        print_result("status",     data.get("status"))
        print_result("result",     data.get("result"))
        print_result("score",      data.get("score"))
        print_result("disposable", data.get("disposable"))
        print_result("webmail",    data.get("webmail"))
        print_result("gibberish",  data.get("gibberish"))
        return data
    except Exception as e:
        console.print(f"  [red]Parse error: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# Intelligence X — free API key (limited)
# ---------------------------------------------------------------------------

def lookup_intelx_email(email: str) -> dict[str, Any]:
    print_section("Intelligence X (leak search)", "yellow")
    if not config.INTELX_API_KEY:
        console.print("  [dim]INTELX_API_KEY not set — skipping.[/dim]")
        return {}
    try:
        r = requests.post(
            "https://2.intelx.io/intelligent/search",
            json={"term": email, "maxresults": 10, "media": 0, "sort": 4, "terminate": []},
            headers={**config.HEADERS, "x-key": config.INTELX_API_KEY},
            timeout=config.TIMEOUT,
        )
        if not r.ok:
            return {}
        search_id = r.json().get("id")
        if not search_id:
            return {}
        time.sleep(2)
        r2 = requests.get(
            f"https://2.intelx.io/intelligent/search/result?id={search_id}&limit=5",
            headers={**config.HEADERS, "x-key": config.INTELX_API_KEY},
            timeout=config.TIMEOUT,
        )
        records = r2.json().get("records", []) if r2.ok else []
        print_result("results found", len(records))
        return {"results": records[:5]}
    except Exception as e:
        console.print(f"  [red]Parse error: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------

def scan_email(email: str, tools: set[str] | None = None, use_cache: bool = True) -> dict[str, Any]:
    from .cache import get_cache
    console.print(f"\n[bold white]Target email:[/bold white] [bold yellow]{email}[/bold yellow]")

    cache = get_cache()
    if use_cache:
        cached = cache.get("email_osint", email)
        if cached:
            console.print("  [dim cyan][cache hit — use --no-cache to refresh][/dim cyan]")
            return cached

    steps = [
        ("emailrep",     lookup_emailrep),
        ("gravatar",     lookup_gravatar),
        ("hunter_email", lookup_hunter_email),
        ("intelx",       lookup_intelx_email),
    ]

    result: dict[str, Any] = {}
    for name, fn in steps:
        if tools and name not in tools:
            continue
        result[name] = fn(email)

    if use_cache:
        cache.set("email_osint", email, result)
    return result
