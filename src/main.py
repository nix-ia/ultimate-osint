"""
Ultimate OSINT CLI — Passive Intelligence Gathering
"""

import sys
from pathlib import Path
from typing import Optional

import typer
from rich.console import Console

# Allow running directly or as a package
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.modules.utils import banner, console
from src.modules.domain import scan_domain
from src.modules.phone import scan_phone
from src.modules.username import scan_username
from src.modules.person import scan_person
from src.modules.breach import scan_breach

app = typer.Typer(
    name="osint",
    help="[bold red]Ultimate OSINT CLI[/bold red] — Passive intelligence gathering. No direct contact with targets.",
    rich_markup_mode="rich",
    add_completion=False,
)


# ---------------------------------------------------------------------------
# domain
# ---------------------------------------------------------------------------

@app.command("domain")
def cmd_domain(
    target: str = typer.Argument(..., help="Domain or URL to investigate (e.g. example.com)"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Skip the banner"),
):
    """
    [bold]Passive domain/URL OSINT.[/bold]

    Runs: WHOIS, DNS, crt.sh subdomains, Wayback Machine, IP geolocation,
    Shodan, VirusTotal, Hunter.io, URLScan.io.

    Zero requests sent to the target host.
    """
    if not no_banner:
        banner()
    scan_domain(target)


# ---------------------------------------------------------------------------
# phone
# ---------------------------------------------------------------------------

@app.command("phone")
def cmd_phone(
    number: str = typer.Argument(..., help="Phone number in E.164 format (e.g. +33612345678)"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Skip the banner"),
):
    """
    [bold]Passive phone number OSINT.[/bold]

    Runs: local format parsing, carrier/country lookup, line type detection,
    NumVerify, AbstractAPI, OpenCNAM.

    Include the country code: +33612345678, +14155552671, etc.
    """
    if not no_banner:
        banner()
    scan_phone(number)


# ---------------------------------------------------------------------------
# username
# ---------------------------------------------------------------------------

@app.command("username")
def cmd_username(
    username: str = typer.Argument(..., help="Username to hunt across platforms"),
    workers: int = typer.Option(20, "--workers", "-w", help="Number of concurrent threads"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Skip the banner"),
):
    """
    [bold]Username hunt across 35+ platforms.[/bold]

    Checks Twitter/X, Instagram, GitHub, Reddit, TikTok, Steam, LinkedIn,
    Telegram, Keybase, PyPI, NPM, DockerHub and many more.
    """
    if not no_banner:
        banner()
    scan_username(username, workers=workers)


# ---------------------------------------------------------------------------
# person
# ---------------------------------------------------------------------------

@app.command("person")
def cmd_person(
    first: str = typer.Argument(..., help="First name"),
    last: str = typer.Argument(..., help="Last name"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Skip the banner"),
):
    """
    [bold]Passive person OSINT (first name + last name).[/bold]

    Generates search dorks, username variants, checks Gravatar permutations,
    and queries Dehashed breach database.
    """
    if not no_banner:
        banner()
    scan_person(first, last)


# ---------------------------------------------------------------------------
# breach
# ---------------------------------------------------------------------------

@app.command("breach")
def cmd_breach(
    email: str = typer.Argument(..., help="Email address to check against breach databases"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Skip the banner"),
):
    """
    [bold]Email breach / leak check.[/bold]

    Queries HaveIBeenPwned for breaches and paste leaks.
    Requires HIBP_API_KEY in .env.
    """
    if not no_banner:
        banner()
    scan_breach(email)


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
    no_banner: bool = typer.Option(False, "--no-banner", help="Skip the banner"),
):
    """
    [bold]Full passive OSINT sweep.[/bold]

    Combine domain + username + person + phone + breach in one command.

    Example:
        osint full example.com -u johndoe -f John -l Doe -p +33612345678 -e john@example.com
    """
    if not no_banner:
        banner()

    scan_domain(target)

    if username:
        scan_username(username)

    if first and last:
        scan_person(first, last)

    if phone:
        scan_phone(phone)

    if email:
        scan_breach(email)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    app()
