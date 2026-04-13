"""
Passive username OSINT module — async with httpx.
Checks username existence across 35+ platforms with connection pooling.
Zero contact with target infrastructure.
"""

import asyncio
from dataclasses import dataclass

import httpx

from .utils import console, print_section
from .. import config

# ---------------------------------------------------------------------------
# Platform definitions
# name, url template, HTTP status expected when found, text that signals 404
# ---------------------------------------------------------------------------

PLATFORMS: list[dict] = [
    # Social
    {"name": "Twitter/X",    "url": "https://twitter.com/{u}",                   "found_status": 200, "not_found_text": "this account doesn't exist"},
    {"name": "Instagram",    "url": "https://www.instagram.com/{u}/",             "found_status": 200, "not_found_text": "Page Not Found"},
    {"name": "Facebook",     "url": "https://www.facebook.com/{u}",               "found_status": 200, "not_found_text": ""},
    {"name": "TikTok",       "url": "https://www.tiktok.com/@{u}",                "found_status": 200, "not_found_text": "couldn't find this account"},
    {"name": "Snapchat",     "url": "https://www.snapchat.com/add/{u}",           "found_status": 200, "not_found_text": ""},
    {"name": "Bluesky",      "url": "https://bsky.app/profile/{u}",               "found_status": 200, "not_found_text": "Profile not found"},
    # Dev
    {"name": "GitHub",       "url": "https://github.com/{u}",                    "found_status": 200, "not_found_text": "Not Found"},
    {"name": "GitLab",       "url": "https://gitlab.com/{u}",                    "found_status": 200, "not_found_text": ""},
    {"name": "Bitbucket",    "url": "https://bitbucket.org/{u}",                 "found_status": 200, "not_found_text": ""},
    {"name": "HackerNews",   "url": "https://news.ycombinator.com/user?id={u}",  "found_status": 200, "not_found_text": "No such user"},
    {"name": "Replit",       "url": "https://replit.com/@{u}",                   "found_status": 200, "not_found_text": ""},
    {"name": "Codepen",      "url": "https://codepen.io/{u}",                    "found_status": 200, "not_found_text": ""},
    # Professional
    {"name": "LinkedIn",     "url": "https://www.linkedin.com/in/{u}",           "found_status": 200, "not_found_text": ""},
    {"name": "DevTo",        "url": "https://dev.to/{u}",                        "found_status": 200, "not_found_text": "404"},
    {"name": "Medium",       "url": "https://medium.com/@{u}",                   "found_status": 200, "not_found_text": "404"},
    {"name": "Hashnode",     "url": "https://hashnode.com/@{u}",                 "found_status": 200, "not_found_text": ""},
    # Gaming
    {"name": "Steam",        "url": "https://steamcommunity.com/id/{u}",         "found_status": 200, "not_found_text": "The specified profile could not be found"},
    {"name": "Twitch",       "url": "https://www.twitch.tv/{u}",                 "found_status": 200, "not_found_text": ""},
    {"name": "Xbox",         "url": "https://xboxgamertag.com/search/{u}",       "found_status": 200, "not_found_text": ""},
    {"name": "Chess.com",    "url": "https://www.chess.com/member/{u}",          "found_status": 200, "not_found_text": ""},
    # Creative
    {"name": "Reddit",       "url": "https://www.reddit.com/user/{u}",           "found_status": 200, "not_found_text": "page not found"},
    {"name": "Pinterest",    "url": "https://www.pinterest.com/{u}/",            "found_status": 200, "not_found_text": ""},
    {"name": "Flickr",       "url": "https://www.flickr.com/people/{u}",         "found_status": 200, "not_found_text": ""},
    {"name": "Behance",      "url": "https://www.behance.net/{u}",               "found_status": 200, "not_found_text": ""},
    {"name": "Dribbble",     "url": "https://dribbble.com/{u}",                  "found_status": 200, "not_found_text": "Whoops"},
    {"name": "SoundCloud",   "url": "https://soundcloud.com/{u}",                "found_status": 200, "not_found_text": ""},
    {"name": "Spotify",      "url": "https://open.spotify.com/user/{u}",         "found_status": 200, "not_found_text": ""},
    # Other
    {"name": "ProductHunt",  "url": "https://www.producthunt.com/@{u}",          "found_status": 200, "not_found_text": ""},
    {"name": "Keybase",      "url": "https://keybase.io/{u}",                    "found_status": 200, "not_found_text": ""},
    {"name": "AboutMe",      "url": "https://about.me/{u}",                      "found_status": 200, "not_found_text": ""},
    {"name": "Pastebin",     "url": "https://pastebin.com/u/{u}",                "found_status": 200, "not_found_text": ""},
    {"name": "DockerHub",    "url": "https://hub.docker.com/u/{u}",              "found_status": 200, "not_found_text": ""},
    {"name": "NPM",          "url": "https://www.npmjs.com/~{u}",                "found_status": 200, "not_found_text": ""},
    {"name": "PyPI",         "url": "https://pypi.org/user/{u}/",                "found_status": 200, "not_found_text": ""},
    {"name": "Gravatar",     "url": "https://en.gravatar.com/{u}",               "found_status": 200, "not_found_text": ""},
    {"name": "Mastodon",     "url": "https://mastodon.social/@{u}",              "found_status": 200, "not_found_text": ""},
    {"name": "Telegram",     "url": "https://t.me/{u}",                          "found_status": 200, "not_found_text": ""},
]


@dataclass
class PlatformResult:
    name: str
    url: str
    found: bool
    status_code: int = 0
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "url": self.url,
            "found": self.found,
            "status_code": self.status_code,
            "error": self.error,
        }


# ---------------------------------------------------------------------------
# Async core
# ---------------------------------------------------------------------------

async def _check_platform_async(
    client: httpx.AsyncClient,
    username: str,
    platform: dict,
    semaphore: asyncio.Semaphore,
) -> PlatformResult:
    url = platform["url"].format(u=username)
    async with semaphore:
        try:
            r = await client.get(url, follow_redirects=True, timeout=10)
            found = r.status_code == platform["found_status"]
            if found and platform.get("not_found_text"):
                if platform["not_found_text"].lower() in r.text.lower():
                    found = False
            return PlatformResult(name=platform["name"], url=url, found=found, status_code=r.status_code)
        except httpx.TimeoutException:
            return PlatformResult(name=platform["name"], url=url, found=False, error="timeout")
        except Exception as e:
            return PlatformResult(name=platform["name"], url=url, found=False, error=str(e)[:60])


async def _run_all(username: str, concurrency: int) -> list[PlatformResult]:
    semaphore = asyncio.Semaphore(concurrency)
    headers = {**config.HEADERS, "Accept-Language": "en-US,en;q=0.9"}
    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)

    async with httpx.AsyncClient(headers=headers, limits=limits) as client:
        tasks = [
            _check_platform_async(client, username, p, semaphore)
            for p in PLATFORMS
        ]
        results = []
        for coro in asyncio.as_completed(tasks):
            result = await coro
            results.append(result)
            if result.found:
                console.print(f"  [bold green][FOUND][/bold green] {result.name:<20} {result.url}")
            elif result.error:
                console.print(f"  [dim red][ERROR][/dim red] {result.name:<20} [dim]{result.error}[/dim]")
            else:
                console.print(
                    f"  [dim][    ][/dim] [dim]{result.name:<20}[/dim] "
                    f"[dim grey50]{result.url}[/dim grey50]"
                )
        return results


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def scan_username(username: str, concurrency: int = 40, use_cache: bool = True) -> list[PlatformResult]:
    """
    Check `username` across all platforms using async httpx.
    `concurrency` controls the number of simultaneous open connections.
    """
    from .cache import get_cache
    print_section(f"Username Hunt: @{username}", "blue")

    cache = get_cache()
    if use_cache:
        cached = cache.get("username", username)
        if cached:
            console.print("  [dim cyan][cache hit — use --no-cache to refresh][/dim cyan]\n")
            results = [PlatformResult(**r) for r in cached]
            found = [r for r in results if r.found]
            for r in found:
                console.print(f"  [bold green][FOUND][/bold green] {r.name:<20} {r.url}")
            console.print(f"\n  [bold]Found on {len(found)}/{len(results)} platforms.[/bold]")
            return results

    console.print(
        f"  [dim]Checking {len(PLATFORMS)} platforms "
        f"(async, up to {concurrency} concurrent connections)...[/dim]\n"
    )

    results = asyncio.run(_run_all(username, concurrency))
    found = [r for r in results if r.found]

    console.print(f"\n  [bold]Found on {len(found)}/{len(PLATFORMS)} platforms.[/bold]")
    if found:
        console.print("\n  [bold green]Summary:[/bold green]")
        for r in found:
            console.print(f"  [green]•[/green] {r.name:<20} {r.url}")

    if use_cache:
        cache.set("username", username, [r.to_dict() for r in results])

    return results
