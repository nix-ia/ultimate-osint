"""
Passive username OSINT module.
Checks username availability/existence across social platforms using
public profile URLs and lightweight HEAD/GET probes — NOT the target's
own infrastructure.
"""

import concurrent.futures
from dataclasses import dataclass, field
from typing import Any

import requests

from .utils import console, print_section
from .. import config

# ---------------------------------------------------------------------------
# Platform definitions
# Each entry: (name, url_template, expected_status_if_found, not_found_string)
# ---------------------------------------------------------------------------

PLATFORMS: list[dict] = [
    # Social
    {"name": "Twitter/X",       "url": "https://twitter.com/{u}",                  "found_status": 200, "not_found_text": "this account doesn't exist"},
    {"name": "Instagram",       "url": "https://www.instagram.com/{u}/",            "found_status": 200, "not_found_text": "Page Not Found"},
    {"name": "Facebook",        "url": "https://www.facebook.com/{u}",              "found_status": 200, "not_found_text": ""},
    {"name": "TikTok",          "url": "https://www.tiktok.com/@{u}",               "found_status": 200, "not_found_text": "couldn't find this account"},
    {"name": "Snapchat",        "url": "https://www.snapchat.com/add/{u}",          "found_status": 200, "not_found_text": ""},
    # Dev
    {"name": "GitHub",          "url": "https://github.com/{u}",                   "found_status": 200, "not_found_text": "Not Found"},
    {"name": "GitLab",          "url": "https://gitlab.com/{u}",                   "found_status": 200, "not_found_text": ""},
    {"name": "Bitbucket",       "url": "https://bitbucket.org/{u}",                "found_status": 200, "not_found_text": ""},
    {"name": "HackerNews",      "url": "https://news.ycombinator.com/user?id={u}", "found_status": 200, "not_found_text": "No such user"},
    {"name": "Replit",          "url": "https://replit.com/@{u}",                  "found_status": 200, "not_found_text": ""},
    # Professional
    {"name": "LinkedIn",        "url": "https://www.linkedin.com/in/{u}",          "found_status": 200, "not_found_text": ""},
    {"name": "DevTo",           "url": "https://dev.to/{u}",                       "found_status": 200, "not_found_text": "404"},
    {"name": "Medium",          "url": "https://medium.com/@{u}",                  "found_status": 200, "not_found_text": "404"},
    {"name": "Hashnode",        "url": "https://hashnode.com/@{u}",                "found_status": 200, "not_found_text": ""},
    # Gaming
    {"name": "Steam",           "url": "https://steamcommunity.com/id/{u}",        "found_status": 200, "not_found_text": "The specified profile could not be found"},
    {"name": "Twitch",          "url": "https://www.twitch.tv/{u}",                "found_status": 200, "not_found_text": ""},
    {"name": "Xbox",            "url": "https://xboxgamertag.com/search/{u}",      "found_status": 200, "not_found_text": ""},
    {"name": "Chess.com",       "url": "https://www.chess.com/member/{u}",         "found_status": 200, "not_found_text": ""},
    # Creative
    {"name": "Reddit",          "url": "https://www.reddit.com/user/{u}",          "found_status": 200, "not_found_text": "page not found"},
    {"name": "Pinterest",       "url": "https://www.pinterest.com/{u}/",           "found_status": 200, "not_found_text": ""},
    {"name": "Flickr",          "url": "https://www.flickr.com/people/{u}",        "found_status": 200, "not_found_text": ""},
    {"name": "Behance",         "url": "https://www.behance.net/{u}",              "found_status": 200, "not_found_text": ""},
    {"name": "Dribbble",        "url": "https://dribbble.com/{u}",                 "found_status": 200, "not_found_text": "Whoops"},
    {"name": "SoundCloud",      "url": "https://soundcloud.com/{u}",               "found_status": 200, "not_found_text": ""},
    {"name": "Spotify",         "url": "https://open.spotify.com/user/{u}",        "found_status": 200, "not_found_text": ""},
    # Other
    {"name": "ProductHunt",     "url": "https://www.producthunt.com/@{u}",         "found_status": 200, "not_found_text": ""},
    {"name": "Keybase",         "url": "https://keybase.io/{u}",                   "found_status": 200, "not_found_text": ""},
    {"name": "AboutMe",         "url": "https://about.me/{u}",                     "found_status": 200, "not_found_text": ""},
    {"name": "Pastebin",        "url": "https://pastebin.com/u/{u}",               "found_status": 200, "not_found_text": ""},
    {"name": "DockerHub",       "url": "https://hub.docker.com/u/{u}",             "found_status": 200, "not_found_text": ""},
    {"name": "NPM",             "url": "https://www.npmjs.com/~{u}",               "found_status": 200, "not_found_text": ""},
    {"name": "PyPI",            "url": "https://pypi.org/user/{u}/",               "found_status": 200, "not_found_text": ""},
    {"name": "Gravatar",        "url": "https://en.gravatar.com/{u}",              "found_status": 200, "not_found_text": ""},
    {"name": "Mastodon",        "url": "https://mastodon.social/@{u}",             "found_status": 200, "not_found_text": ""},
    {"name": "Telegram",        "url": "https://t.me/{u}",                         "found_status": 200, "not_found_text": ""},
]


@dataclass
class PlatformResult:
    name: str
    url: str
    found: bool
    status_code: int = 0
    error: str = ""


def _check_platform(username: str, platform: dict) -> PlatformResult:
    url = platform["url"].format(u=username)
    try:
        r = requests.get(
            url,
            headers={**config.HEADERS, "Accept-Language": "en-US,en;q=0.9"},
            timeout=10,
            allow_redirects=True,
        )
        found = r.status_code == platform["found_status"]
        # Secondary check: if not_found_text is set, verify content doesn't contain it
        if found and platform.get("not_found_text"):
            if platform["not_found_text"].lower() in r.text.lower():
                found = False
        return PlatformResult(name=platform["name"], url=url, found=found, status_code=r.status_code)
    except requests.exceptions.Timeout:
        return PlatformResult(name=platform["name"], url=url, found=False, error="timeout")
    except Exception as e:
        return PlatformResult(name=platform["name"], url=url, found=False, error=str(e)[:60])


def scan_username(username: str, workers: int = 20) -> list[PlatformResult]:
    print_section(f"Username Hunt: @{username}", "blue")
    console.print(f"  [dim]Checking {len(PLATFORMS)} platforms with {workers} threads...[/dim]\n")

    results: list[PlatformResult] = []
    found_count = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
        futures = {
            executor.submit(_check_platform, username, p): p for p in PLATFORMS
        }
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            if result.found:
                found_count += 1
                console.print(f"  [bold green][FOUND][/bold green] {result.name:<20} {result.url}")
            elif result.error:
                console.print(f"  [dim red][ERROR][/dim red] {result.name:<20} [dim]{result.error}[/dim]")
            else:
                console.print(f"  [dim][    ][/dim] [dim]{result.name:<20}[/dim] [dim grey50]{result.url}[/dim grey50]")

    console.print(f"\n  [bold]Found on {found_count}/{len(PLATFORMS)} platforms.[/bold]")
    return results
