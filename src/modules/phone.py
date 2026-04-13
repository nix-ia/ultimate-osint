"""
Passive phone number OSINT module.
Uses phonenumbers lib for format analysis and public APIs for enrichment.
Zero direct contact with the target.
"""

from typing import Any

import phonenumbers
from phonenumbers import geocoder, carrier, timezone

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
# phonenumbers library — local parsing (no network)
# ---------------------------------------------------------------------------

def parse_phone_local(number: str) -> dict[str, Any]:
    print_section("Phone Number Analysis (local)", "magenta")
    try:
        parsed = phonenumbers.parse(number, None)
        valid = phonenumbers.is_valid_number(parsed)
        possible = phonenumbers.is_possible_number(parsed)

        data = {
            "input": number,
            "valid": valid,
            "possible": possible,
            "international_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.INTERNATIONAL),
            "national_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            "e164_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            "country_code": f"+{parsed.country_code}",
            "national_number": str(parsed.national_number),
            "country": geocoder.description_for_number(parsed, "en"),
            "carrier": carrier.name_for_number(parsed, "en"),
            "timezones": list(timezone.time_zones_for_number(parsed)),
            "line_type": phonenumbers.PhoneNumberType.to_string(phonenumbers.number_type(parsed)),
        }

        for k, v in data.items():
            print_result(k, v)

        return data
    except phonenumbers.NumberParseException as e:
        console.print(f"  [red]Parse error: {e}[/red]")
        console.print("  [dim]Tip: include country code, e.g. +33612345678[/dim]")
        return {}


# ---------------------------------------------------------------------------
# NumVerify API
# ---------------------------------------------------------------------------

def lookup_numverify(number: str) -> dict[str, Any]:
    print_section("NumVerify (carrier/line type)", "magenta")
    if not config.NUMVERIFY_API_KEY:
        console.print("  [dim]NUMVERIFY_API_KEY not set — skipping.[/dim]")
        return {}

    clean = number.lstrip("+")
    r = _get(
        "http://apilayer.net/api/validate",
        params={"access_key": config.NUMVERIFY_API_KEY, "number": clean, "format": 1},
    )
    if not r:
        return {}

    try:
        data = r.json()
        print_result("valid", data.get("valid"))
        print_result("number", data.get("number"))
        print_result("local_format", data.get("local_format"))
        print_result("international_format", data.get("international_format"))
        print_result("country", f"{data.get('country_name')} ({data.get('country_code')})")
        print_result("location", data.get("location"))
        print_result("carrier", data.get("carrier"))
        print_result("line_type", data.get("line_type"))
        return data
    except Exception as e:
        console.print(f"  [red]NumVerify parse error: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# AbstractAPI Phone Validation
# ---------------------------------------------------------------------------

def lookup_abstractapi(number: str) -> dict[str, Any]:
    print_section("AbstractAPI Phone Validation", "magenta")
    if not config.ABSTRACTAPI_PHONE_KEY:
        console.print("  [dim]ABSTRACTAPI_PHONE_KEY not set — skipping.[/dim]")
        return {}

    r = _get(
        "https://phonevalidation.abstractapi.com/v1/",
        params={"api_key": config.ABSTRACTAPI_PHONE_KEY, "phone": number},
    )
    if not r:
        return {}

    try:
        data = r.json()
        print_result("valid", data.get("valid"))
        print_result("format_international", data.get("format", {}).get("international"))
        print_result("format_local", data.get("format", {}).get("local"))
        country = data.get("country", {})
        print_result("country", f"{country.get('name')} ({country.get('code')})")
        print_result("phone_type", data.get("type"))
        carrier_info = data.get("carrier", "")
        print_result("carrier", carrier_info)
        return data
    except Exception as e:
        console.print(f"  [red]AbstractAPI parse error: {e}[/red]")
        return {}


# ---------------------------------------------------------------------------
# Opencnam (caller ID lookup — free tier)
# ---------------------------------------------------------------------------

def lookup_opencnam(number: str) -> None:
    print_section("OpenCNAM (caller ID)", "magenta")
    e164 = number if number.startswith("+") else f"+{number}"
    r = _get(f"https://api.opencnam.com/v3/phone/{e164}?format=json")
    if not r:
        return
    try:
        data = r.json()
        print_result("name", data.get("name", "n/a"))
    except Exception:
        console.print("  [dim]No CNAM data available.[/dim]")


# ---------------------------------------------------------------------------
# Full phone scan orchestrator
# ---------------------------------------------------------------------------

def scan_phone(number: str, use_cache: bool = True) -> dict[str, Any]:
    from .cache import get_cache
    console.print(f"\n[bold white]Target:[/bold white] [bold magenta]{number}[/bold magenta]")

    cache = get_cache()
    if use_cache:
        cached = cache.get("phone", number)
        if cached:
            console.print("  [dim cyan][cache hit — use --no-cache to refresh][/dim cyan]")
            for k, v in cached.items():
                print_result(k, v)
            return cached

    result: dict[str, Any] = {}
    result.update(parse_phone_local(number))
    result["numverify"]   = lookup_numverify(number)
    result["abstractapi"] = lookup_abstractapi(number)

    if use_cache:
        cache.set("phone", number, result)

    return result
