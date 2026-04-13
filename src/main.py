"""
Ultimate OSINT CLI — Passive Intelligence Gathering
"""

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import typer

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.modules.utils import banner, console
from src.modules.domain import scan_domain
from src.modules.phone import scan_phone
from src.modules.username import scan_username
from src.modules.person import scan_person
from src.modules.breach import scan_breach
from src.modules.reporter import write_report

app = typer.Typer(
    name="osint",
    help="[bold red]Ultimate OSINT CLI[/bold red] — Passive intelligence gathering. No direct contact with targets.",
    rich_markup_mode="rich",
    add_completion=False,
)


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# domain
# ---------------------------------------------------------------------------

@app.command("domain")
def cmd_domain(
    target: str = typer.Argument(..., help="Domain or URL to investigate (e.g. example.com)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save report to file (.json or .html)"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass cache and force fresh lookups"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Skip the banner"),
):
    """
    [bold]Passive domain/URL OSINT.[/bold]

    Runs: WHOIS · DNS · crt.sh · Wayback Machine · IP geo · Shodan · VirusTotal · Hunter.io · URLScan.io

    Zero requests sent to the target host.
    """
    if not no_banner:
        banner()
    result = scan_domain(target, use_cache=not no_cache)
    if output:
        write_report(output, {
            "target": target,
            "generated_at": _ts(),
            "modules_run": ["domain"],
            "results": {"domain": result},
        })


# ---------------------------------------------------------------------------
# phone
# ---------------------------------------------------------------------------

@app.command("phone")
def cmd_phone(
    number: str = typer.Argument(..., help="Phone number in E.164 format (e.g. +33612345678)"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save report to file (.json or .html)"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass cache"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Skip the banner"),
):
    """
    [bold]Passive phone number OSINT.[/bold]

    Runs: local format parsing · carrier/country detection · NumVerify · AbstractAPI · OpenCNAM

    Include the country code: +33612345678, +14155552671, etc.
    """
    if not no_banner:
        banner()
    result = scan_phone(number, use_cache=not no_cache)
    if output:
        write_report(output, {
            "target": number,
            "generated_at": _ts(),
            "modules_run": ["phone"],
            "results": {"phone": result},
        })


# ---------------------------------------------------------------------------
# username
# ---------------------------------------------------------------------------

@app.command("username")
def cmd_username(
    username: str = typer.Argument(..., help="Username to hunt across platforms"),
    concurrency: int = typer.Option(40, "--concurrency", "-c", help="Max simultaneous async connections"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save report to file (.json or .html)"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass cache"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Skip the banner"),
):
    """
    [bold]Username hunt across 35+ platforms (async httpx).[/bold]

    Checks Twitter/X · Instagram · GitHub · Reddit · TikTok · Steam · LinkedIn ·
    Telegram · Keybase · PyPI · NPM · DockerHub · Bluesky and more.
    """
    if not no_banner:
        banner()
    results = scan_username(username, concurrency=concurrency, use_cache=not no_cache)
    if output:
        write_report(output, {
            "target": username,
            "generated_at": _ts(),
            "modules_run": ["username"],
            "results": {"username": [r.to_dict() for r in results]},
        })


# ---------------------------------------------------------------------------
# person
# ---------------------------------------------------------------------------

@app.command("person")
def cmd_person(
    first: str = typer.Argument(..., help="First name"),
    last: str = typer.Argument(..., help="Last name"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save report to file (.json or .html)"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass cache"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Skip the banner"),
):
    """
    [bold]Passive person OSINT (first name + last name).[/bold]

    Generates search dorks · username variants · Gravatar permutations · Dehashed breach data.
    """
    if not no_banner:
        banner()
    result = scan_person(first, last, use_cache=not no_cache)
    if output:
        write_report(output, {
            "target": f"{first} {last}",
            "generated_at": _ts(),
            "modules_run": ["person"],
            "results": {"person": result},
        })


# ---------------------------------------------------------------------------
# breach
# ---------------------------------------------------------------------------

@app.command("breach")
def cmd_breach(
    email: str = typer.Argument(..., help="Email address to check against breach databases"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save report to file (.json or .html)"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass cache"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Skip the banner"),
):
    """
    [bold]Email breach / leak check.[/bold]

    Queries HaveIBeenPwned for breaches and paste leaks.
    Requires HIBP_API_KEY in .env.
    """
    if not no_banner:
        banner()
    result = scan_breach(email, use_cache=not no_cache)
    if output:
        write_report(output, {
            "target": email,
            "generated_at": _ts(),
            "modules_run": ["breach"],
            "results": {"breach": result},
        })


# ---------------------------------------------------------------------------
# full — run all modules
# ---------------------------------------------------------------------------

@app.command("full")
def cmd_full(
    target: str = typer.Argument(..., help="Main target (domain/URL)"),
    username: Optional[str] = typer.Option(None, "--username", "-u", help="Also hunt this username"),
    first: Optional[str] = typer.Option(None, "--first", "-f", help="First name for person lookup"),
    last: Optional[str] = typer.Option(None, "--last", "-l", help="Last name for person lookup"),
    phone: Optional[str] = typer.Option(None, "--phone", "-p", help="Phone number to analyze"),
    email: Optional[str] = typer.Option(None, "--email", "-e", help="Email for breach check"),
    output: Optional[str] = typer.Option(None, "--output", "-o", help="Save combined report (.json or .html)"),
    no_cache: bool = typer.Option(False, "--no-cache", help="Bypass cache for all modules"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Skip the banner"),
):
    """
    [bold]Full passive OSINT sweep.[/bold]

    Combines domain + username + person + phone + breach in one command.

    Example:
        osint full example.com -u johndoe -f John -l Doe -p +33612345678 -e john@example.com -o report.html
    """
    if not no_banner:
        banner()

    report: dict = {
        "target": target,
        "generated_at": _ts(),
        "modules_run": [],
        "results": {},
    }
    use_cache = not no_cache

    domain_result = scan_domain(target, use_cache=use_cache)
    report["modules_run"].append("domain")
    report["results"]["domain"] = domain_result

    if username:
        u_results = scan_username(username, use_cache=use_cache)
        report["modules_run"].append("username")
        report["results"]["username"] = [r.to_dict() for r in u_results]

    if first and last:
        p_result = scan_person(first, last, use_cache=use_cache)
        report["modules_run"].append("person")
        report["results"]["person"] = p_result

    if phone:
        ph_result = scan_phone(phone, use_cache=use_cache)
        report["modules_run"].append("phone")
        report["results"]["phone"] = ph_result

    if email:
        b_result = scan_breach(email, use_cache=use_cache)
        report["modules_run"].append("breach")
        report["results"]["breach"] = b_result

    if output:
        write_report(output, report)


# ---------------------------------------------------------------------------
# cache — manage local cache
# ---------------------------------------------------------------------------

@app.command("cache")
def cmd_cache(
    clear: bool = typer.Option(False, "--clear", help="Clear all cached results"),
    module: Optional[str] = typer.Option(None, "--module", "-m", help="Clear only this module (domain/phone/username/person/breach)"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Clear only this target"),
    stats: bool = typer.Option(False, "--stats", help="Show cache statistics"),
):
    """
    [bold]Manage the local SQLite result cache.[/bold]

    Examples:
        osint cache --stats
        osint cache --clear
        osint cache --clear --module domain --target example.com
    """
    from src.modules.cache import get_cache
    c = get_cache()

    if stats or (not clear):
        s = c.stats()
        console.print(f"\n[bold]Cache stats:[/bold]")
        console.print(f"  entries  : [cyan]{s['entries']}[/cyan]")
        if s["entries"]:
            from datetime import datetime
            oldest = datetime.fromtimestamp(s["oldest"]).strftime("%Y-%m-%d %H:%M") if s["oldest"] else "—"
            console.print(f"  oldest   : [dim]{oldest}[/dim]")
        console.print(f"  location : [dim]{c.conn.database if hasattr(c.conn, 'database') else '~/.cache/ultimate-osint/cache.db'}[/dim]")

    if clear:
        deleted = c.invalidate(module=module, target=target)
        label = f"{module}:{target}" if module and target else (module or "all")
        console.print(f"\n  [green]Cleared[/green] {deleted} entr{'y' if deleted == 1 else 'ies'} [{label}]")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
