"""
Passive person OSINT module (name / surname).
Uses public search APIs and data aggregators — no direct contact with targets.
"""

from typing import Any
from urllib.parse import quote_plus

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
# Search engine dork links (passive — opens no session with target)
# ---------------------------------------------------------------------------

def generate_dorks(first: str, last: str) -> dict[str, str]:
    print_section("Search Engine Dorks (passive links)", "green")
    full = f"{first} {last}"
    encoded = quote_plus(full)

    dorks = {
        "Google — general":         f"https://www.google.com/search?q={quote_plus(f'\"{full}\"')}",
        "Google — LinkedIn":        f"https://www.google.com/search?q={quote_plus(f'site:linkedin.com \"{full}\"')}",
        "Google — GitHub":          f"https://www.google.com/search?q={quote_plus(f'site:github.com \"{full}\"')}",
        "Google — email leak":      f"https://www.google.com/search?q={quote_plus(f'\"{full}\" email OR contact OR @')}",
        "Google — social media":    f"https://www.google.com/search?q={quote_plus(f'\"{full}\" site:twitter.com OR site:instagram.com OR site:facebook.com')}",
        "Bing — general":           f"https://www.bing.com/search?q={encoded}",
        "DuckDuckGo":               f"https://duckduckgo.com/?q={encoded}",
        "PeopleLookup":             f"https://www.peoplelookup.com/results/first={quote_plus(first)}&last={quote_plus(last)}",
        "Spokeo":                   f"https://www.spokeo.com/{quote_plus(first)}-{quote_plus(last)}",
        "TruePeopleSearch":         f"https://www.truepeoplesearch.com/results?name={encoded}",
        "FastPeopleSearch":         f"https://www.fastpeoplesearch.com/name/{quote_plus(full)}",
        "Pipl":                     f"https://pipl.com/search/?q={encoded}",
        "Intelius":                 f"https://intelius.com/people/{quote_plus(first)}-{quote_plus(last)}",
        "WhitePages":               f"https://www.whitepages.com/name/{quote_plus(full)}",
        "ZabaSearch":               f"https://www.zabasearch.com/people/{quote_plus(full)}/",
        "411.com":                  f"https://www.411.com/name/{quote_plus(first)}-{quote_plus(last)}",
        "PeekYou":                  f"https://www.peekyou.com/{quote_plus(first.lower())}_{quote_plus(last.lower())}",
        "Webmii":                   f"https://webmii.com/people?n={encoded}",
    }

    for label, url in dorks.items():
        console.print(f"  [dim cyan]{label:<30}[/dim cyan] [blue]{url}[/blue]")

    return dorks


# ---------------------------------------------------------------------------
# Gravatar MD5 hash check (email permutations → avatar = account exists)
# ---------------------------------------------------------------------------

def check_gravatar_permutations(first: str, last: str) -> list[str]:
    print_section("Gravatar Email Permutations (passive)", "green")
    import hashlib

    first_l = first.lower().strip()
    last_l = last.lower().strip()

    domains = ["gmail.com", "yahoo.com", "hotmail.com", "outlook.com", "protonmail.com"]
    permutations = [
        f"{first_l}.{last_l}",
        f"{first_l}{last_l}",
        f"{last_l}.{first_l}",
        f"{last_l}{first_l}",
        f"{first_l[0]}{last_l}",
        f"{first_l}{last_l[0]}",
        f"{first_l[0]}.{last_l}",
    ]

    found = []
    for local in permutations:
        for domain in domains:
            email = f"{local}@{domain}"
            md5 = hashlib.md5(email.lower().encode()).hexdigest()
            url = f"https://www.gravatar.com/avatar/{md5}?d=404"
            try:
                r = requests.get(url, headers=config.HEADERS, timeout=8)
                if r.status_code == 200:
                    found.append(email)
                    console.print(f"  [bold green][FOUND][/bold green] {email} → https://www.gravatar.com/{md5}")
            except Exception:
                pass

    if not found:
        console.print("  [dim]No Gravatar matches found.[/dim]")
    return found


# ---------------------------------------------------------------------------
# Dehashed — breach data lookup
# ---------------------------------------------------------------------------

def lookup_dehashed(first: str, last: str) -> list[dict]:
    print_section("Dehashed (breach data)", "green")
    if not config.DEHASHED_API_KEY or not config.DEHASHED_EMAIL:
        console.print("  [dim]DEHASHED_API_KEY or DEHASHED_EMAIL not set — skipping.[/dim]")
        return []

    full = f"{first} {last}"
    r = _get(
        "https://api.dehashed.com/search",
        params={"query": full, "size": 10},
        auth=(config.DEHASHED_EMAIL, config.DEHASHED_API_KEY),
        headers={**config.HEADERS, "Accept": "application/json"},
    )
    if not r:
        return []

    try:
        data = r.json()
        entries = data.get("entries", []) or []
        print_result("total hits", data.get("total", 0))
        for entry in entries[:10]:
            console.print(
                f"  [green]•[/green] "
                f"[white]{entry.get('email', '')}[/white] | "
                f"[dim]{entry.get('database_name', '')}[/dim] | "
                f"username: [cyan]{entry.get('username', '')}[/cyan]"
            )
        return entries
    except Exception as e:
        console.print(f"  [red]Dehashed parse error: {e}[/red]")
        return []


# ---------------------------------------------------------------------------
# Username variants generator
# ---------------------------------------------------------------------------

def generate_username_variants(first: str, last: str) -> list[str]:
    print_section("Common Username Variants", "green")
    f = first.lower().strip()
    l = last.lower().strip()
    variants = sorted(set([
        f"{f}{l}",
        f"{f}.{l}",
        f"{f}_{l}",
        f"{f[0]}{l}",
        f"{f[0]}.{l}",
        f"{f[0]}_{l}",
        f"{l}{f}",
        f"{l}.{f}",
        f"{l}_{f}",
        f"{l}{f[0]}",
        f"{f}{l[0]}",
        f"{f}-{l}",
        f"{l}-{f}",
    ]))
    for v in variants:
        console.print(f"  [cyan]•[/cyan] {v}")
    return variants


# ---------------------------------------------------------------------------
# Full person scan orchestrator
# ---------------------------------------------------------------------------

def scan_person(first: str, last: str) -> None:
    console.print(f"\n[bold white]Target:[/bold white] [bold green]{first} {last}[/bold green]")
    generate_dorks(first, last)
    generate_username_variants(first, last)
    check_gravatar_permutations(first, last)
    lookup_dehashed(first, last)
