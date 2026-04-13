"""
Passive breach / leak OSINT module.
Checks emails against public breach databases — no contact with the target.
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
    except requests.exceptions.HTTPError as e:
        if e.response.status_code == 404:
            return None  # not found = clean
        console.print(f"  [dim red]  HTTP {e.response.status_code}: {e}[/dim red]")
        return None
    except Exception as e:
        console.print(f"  [dim red]  request failed: {e}[/dim red]")
        return None


def lookup_hibp(email: str) -> list[dict]:
    """HaveIBeenPwned — requires API key ($3.50/month or free for personal use)."""
    print_section("HaveIBeenPwned (breach check)", "red")
    if not config.HIBP_API_KEY:
        console.print("  [dim]HIBP_API_KEY not set — skipping.[/dim]")
        console.print("  [dim]Get a key at: https://haveibeenpwned.com/API/Key[/dim]")
        return []

    r = _get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
        headers={
            **config.HEADERS,
            "hibp-api-key": config.HIBP_API_KEY,
            "user-agent": "ultimate-osint-cli",
        },
        params={"truncateResponse": "false"},
    )

    if r is None:
        console.print("  [green]No breaches found.[/green]")
        return []

    try:
        breaches = r.json()
        console.print(f"  [bold red]Found in {len(breaches)} breach(es):[/bold red]")
        for b in breaches:
            console.print(
                f"  [red]•[/red] [white]{b.get('Name')}[/white] "
                f"[dim]({b.get('BreachDate')})[/dim] — "
                f"{b.get('PwnCount', 0):,} accounts — "
                f"data: [cyan]{', '.join(b.get('DataClasses', [])[:5])}[/cyan]"
            )
        return breaches
    except Exception as e:
        console.print(f"  [red]HIBP parse error: {e}[/red]")
        return []


def lookup_hibp_pastes(email: str) -> list[dict]:
    """HaveIBeenPwned paste check."""
    print_section("HaveIBeenPwned (paste check)", "red")
    if not config.HIBP_API_KEY:
        console.print("  [dim]HIBP_API_KEY not set — skipping.[/dim]")
        return []

    r = _get(
        f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}",
        headers={
            **config.HEADERS,
            "hibp-api-key": config.HIBP_API_KEY,
            "user-agent": "ultimate-osint-cli",
        },
    )

    if r is None:
        console.print("  [green]No pastes found.[/green]")
        return []

    try:
        pastes = r.json()
        console.print(f"  [bold red]Found in {len(pastes)} paste(s):[/bold red]")
        for p in pastes:
            console.print(
                f"  [red]•[/red] [white]{p.get('Source')}[/white] "
                f"[dim]({p.get('Date', 'unknown date')})[/dim] — "
                f"title: [cyan]{p.get('Title', 'n/a')}[/cyan]"
            )
        return pastes
    except Exception as e:
        console.print(f"  [red]HIBP paste parse error: {e}[/red]")
        return []


def scan_breach(email: str, use_cache: bool = True) -> dict[str, Any]:
    from .cache import get_cache
    console.print(f"\n[bold white]Target:[/bold white] [bold red]{email}[/bold red]")

    cache = get_cache()
    if use_cache:
        cached = cache.get("breach", email)
        if cached:
            console.print("  [dim cyan][cache hit — use --no-cache to refresh][/dim cyan]")
            return cached

    result: dict[str, Any] = {
        "breaches": lookup_hibp(email),
        "pastes":   lookup_hibp_pastes(email),
    }

    if use_cache:
        # Breach data — shorter TTL (6h) since it can change
        cache.set("breach", email, result, ttl=21600)

    return result
