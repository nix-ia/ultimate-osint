"""
Ultimate OSINT — Web interface (Flask + SSE streaming)
"""

import json
import sys
from pathlib import Path

from flask import Flask, Response, render_template, request, stream_with_context

sys.path.insert(0, str(Path(__file__).parent.parent))

import src.config as config
from src.modules.cache import get_cache

app = Flask(__name__)


# ---------------------------------------------------------------------------
# SSE helpers
# ---------------------------------------------------------------------------

def _sse(event_type: str, data: dict) -> str:
    payload = json.dumps({"type": event_type, **data}, default=str)
    return f"data: {payload}\n\n"

def _section(name: str) -> str:
    return _sse("section", {"name": name, "status": "running"})

def _result(name: str, data) -> str:
    return _sse("result", {"name": name, "data": data})

def _error(name: str, msg: str) -> str:
    return _sse("error", {"name": name, "msg": msg})

def _done(summary: dict = None) -> str:
    return _sse("done", {"summary": summary or {}})


# ---------------------------------------------------------------------------
# Tools param helper
# ---------------------------------------------------------------------------

def _parse_tools(raw: str) -> set[str] | None:
    if not raw:
        return None
    parts = {t.strip() for t in raw.split(",") if t.strip()}
    return parts if parts else None


# ---------------------------------------------------------------------------
# Generic step runner for stream functions
# ---------------------------------------------------------------------------

def _run_steps(steps, tools, result, cache_fn=None):
    """Yield SSE events for each step, filtered by tools set."""
    for name, fn, arg in steps:
        if tools and name not in tools:
            continue
        yield _section(name)
        try:
            data = fn(arg)
            result[name] = data
            yield _result(name, data)
        except Exception as e:
            yield _error(name, str(e))
            result[name] = {}


# ---------------------------------------------------------------------------
# Stream generators
# ---------------------------------------------------------------------------

def stream_domain(target: str, use_cache: bool = True, tools: set[str] | None = None):
    from src.modules.utils import extract_domain
    from src.modules.domain import (
        lookup_whois, lookup_dns, lookup_crtsh, lookup_wayback,
        lookup_ip_geo, lookup_shodan, lookup_virustotal,
        lookup_hunter, lookup_urlscan, lookup_hackertarget,
        lookup_threatfox, lookup_urlhaus, lookup_alienvault,
        lookup_securitytrails, lookup_censys,
    )

    domain = extract_domain(target)
    yield _sse("start", {"target": domain, "module": "domain"})

    cache = get_cache()
    if use_cache:
        cached = cache.get("domain", domain)
        if cached:
            yield _sse("cache_hit", {"target": domain})
            for sn, sd in cached.items():
                yield _result(sn, sd)
            yield _done({"domain": domain, "cache": True})
            return

    result = {}
    steps = [
        ("whois",          lookup_whois,         domain),
        ("dns",            lookup_dns,           domain),
        ("crtsh",          lambda d: {"subdomains": lookup_crtsh(d)}, domain),
        ("wayback",        lookup_wayback,       domain),
        ("ip_geo",         lookup_ip_geo,        domain),
        ("hackertarget",   lookup_hackertarget,  domain),
        ("urlscan",        lambda d: {"results": [r.get("page", {}).get("url") for r in lookup_urlscan(d)]}, domain),
        ("threatfox",      lookup_threatfox,     domain),
        ("urlhaus",        lookup_urlhaus,       domain),
        ("alienvault",     lookup_alienvault,    domain),
        ("virustotal",     lookup_virustotal,    domain),
        ("censys",         lookup_censys,        domain),
        ("securitytrails", lookup_securitytrails, domain),
        ("shodan",         lookup_shodan,        domain),
        ("hunter",         lambda d: {"emails": lookup_hunter(d)}, domain),
    ]

    yield from _run_steps(steps, tools, result)

    if use_cache:
        cache.set("domain", domain, result)
    yield _done({"domain": domain})


def stream_ip(ip: str, use_cache: bool = True, tools: set[str] | None = None):
    from src.modules.ip import (
        lookup_ip_geo, lookup_ipinfo, lookup_bgpview, lookup_hackertarget_ip,
        lookup_greynoise, lookup_threatfox_ip, lookup_abuseipdb,
        lookup_virustotal_ip, lookup_shodan_ip,
    )

    yield _sse("start", {"target": ip, "module": "ip"})

    cache = get_cache()
    if use_cache:
        cached = cache.get("ip", ip)
        if cached:
            yield _sse("cache_hit", {"target": ip})
            for sn, sd in cached.items():
                yield _result(sn, sd)
            yield _done({"ip": ip, "cache": True})
            return

    result = {}
    steps = [
        ("ip_geo",       lookup_ip_geo,          ip),
        ("ipinfo",       lookup_ipinfo,          ip),
        ("bgpview",      lookup_bgpview,         ip),
        ("hackertarget", lookup_hackertarget_ip, ip),
        ("greynoise",    lookup_greynoise,       ip),
        ("threatfox",    lookup_threatfox_ip,    ip),
        ("abuseipdb",    lookup_abuseipdb,       ip),
        ("virustotal",   lookup_virustotal_ip,   ip),
        ("shodan",       lookup_shodan_ip,       ip),
    ]

    yield from _run_steps(steps, tools, result)

    if use_cache:
        cache.set("ip", ip, result)
    yield _done({"ip": ip})


def stream_email(email: str, use_cache: bool = True, tools: set[str] | None = None):
    from src.modules.email_osint import (
        lookup_emailrep, lookup_gravatar, lookup_hunter_email, lookup_intelx_email,
    )

    yield _sse("start", {"target": email, "module": "email"})

    cache = get_cache()
    if use_cache:
        cached = cache.get("email_osint", email)
        if cached:
            yield _sse("cache_hit", {"target": email})
            for sn, sd in cached.items():
                yield _result(sn, sd)
            yield _done({"email": email, "cache": True})
            return

    result = {}
    steps = [
        ("emailrep",     lookup_emailrep,     email),
        ("gravatar",     lookup_gravatar,     email),
        ("hunter_email", lookup_hunter_email, email),
        ("intelx",       lookup_intelx_email, email),
    ]

    yield from _run_steps(steps, tools, result)

    if use_cache:
        cache.set("email_osint", email, result)
    yield _done({"email": email})


def stream_phone(number: str, use_cache: bool = True, tools: set[str] | None = None):
    from src.modules.phone import parse_phone_local, lookup_numverify, lookup_abstractapi

    yield _sse("start", {"target": number, "module": "phone"})

    cache = get_cache()
    if use_cache:
        cached = cache.get("phone", number)
        if cached:
            yield _sse("cache_hit", {"target": number})
            yield _result("phone", cached)
            yield _done()
            return

    result = {}
    steps = [
        ("local",       parse_phone_local,  number),
        ("numverify",   lookup_numverify,   number),
        ("abstractapi", lookup_abstractapi, number),
    ]

    yield from _run_steps(steps, tools, result)

    if use_cache:
        cache.set("phone", number, result)
    yield _done()


def stream_username(username: str, use_cache: bool = True, tools: set[str] | None = None):
    from src.modules.username import scan_username

    yield _sse("start", {"target": username, "module": "username"})

    cache = get_cache()
    if use_cache:
        cached = cache.get("username", username)
        if cached:
            yield _sse("cache_hit", {"target": username})
            yield _result("username", cached)
            yield _done()
            return

    yield _section("platforms")
    try:
        results = scan_username(username, use_cache=False)
        data    = [r.to_dict() for r in results]
        found   = [r for r in data if r.get("found")]
        if use_cache:
            cache.set("username", username, data)
        yield _result("username", data)
        yield _done({"found": len(found), "total": len(data)})
    except Exception as e:
        yield _error("username", str(e))
        yield _done()


def stream_person(first: str, last: str, use_cache: bool = True, tools: set[str] | None = None):
    from src.modules.person import scan_person

    target = f"{first} {last}"
    yield _sse("start", {"target": target, "module": "person"})

    cache = get_cache()
    if use_cache:
        cached = cache.get("person", target)
        if cached:
            yield _sse("cache_hit", {"target": target})
            yield _result("person", cached)
            yield _done()
            return

    yield _section("person")
    try:
        result = scan_person(first, last, use_cache=False)
        if use_cache:
            cache.set("person", target, result)
        yield _result("person", result)
        yield _done()
    except Exception as e:
        yield _error("person", str(e))
        yield _done()


def stream_breach(email: str, use_cache: bool = True, tools: set[str] | None = None):
    from src.modules.breach import lookup_hibp, lookup_hibp_pastes

    yield _sse("start", {"target": email, "module": "breach"})

    cache = get_cache()
    if use_cache:
        cached = cache.get("breach", email)
        if cached:
            yield _sse("cache_hit", {"target": email})
            for sn, sd in cached.items():
                yield _result(sn, sd)
            yield _done()
            return

    result = {}
    steps = [
        ("hibp",        lookup_hibp,        email),
        ("hibp_pastes", lookup_hibp_pastes, email),
    ]

    yield from _run_steps(steps, tools, result)

    if use_cache:
        cache.set("breach", email, result, ttl=21600)
    yield _done()


def stream_full(params: dict):
    target   = params.get("target", "")
    ip       = params.get("ip", "")
    email    = params.get("email", "")
    username = params.get("username", "")
    first    = params.get("first", "")
    last     = params.get("last", "")
    phone    = params.get("phone", "")
    use_cache = not params.get("no_cache", False)

    yield _sse("start", {"target": target or ip or email or username, "module": "full"})

    if target:
        yield from stream_domain(target, use_cache)
    if ip:
        yield from stream_ip(ip, use_cache)
    if email:
        yield from stream_email(email, use_cache)
        yield from stream_breach(email, use_cache)
    if username:
        yield from stream_username(username, use_cache)
    if first and last:
        yield from stream_person(first, last, use_cache)
    if phone:
        yield from stream_phone(phone, use_cache)

    yield _done()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    api_keys = {
        "SHODAN":         bool(config.SHODAN_API_KEY),
        "VIRUSTOTAL":     bool(config.VIRUSTOTAL_API_KEY),
        "HUNTER":         bool(config.HUNTER_API_KEY),
        "URLSCAN":        bool(config.URLSCAN_API_KEY),
        "NUMVERIFY":      bool(config.NUMVERIFY_API_KEY),
        "ABSTRACTAPI":    bool(config.ABSTRACTAPI_PHONE_KEY),
        "HIBP":           bool(config.HIBP_API_KEY),
        "ABUSEIPDB":      bool(config.ABUSEIPDB_API_KEY),
        "GREYNOISE":      bool(config.GREYNOISE_API_KEY),
        "ALIENVAULT":     bool(config.ALIENVAULT_API_KEY),
        "CENSYS":         bool(config.CENSYS_API_ID),
        "SECURITYTRAILS": bool(config.SECURITYTRAILS_API_KEY),
        "INTELX":         bool(config.INTELX_API_KEY),
    }
    return render_template("index.html", api_keys=api_keys)


def _sse_response(gen):
    return Response(
        stream_with_context(gen),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/stream/domain")
def api_domain():
    target   = request.args.get("target", "").strip()
    no_cache = request.args.get("no_cache") == "1"
    tools    = _parse_tools(request.args.get("tools", ""))
    if not target:
        return "Missing target", 400
    return _sse_response(stream_domain(target, use_cache=not no_cache, tools=tools))


@app.route("/stream/ip")
def api_ip():
    ip       = request.args.get("ip", "").strip()
    no_cache = request.args.get("no_cache") == "1"
    tools    = _parse_tools(request.args.get("tools", ""))
    if not ip:
        return "Missing ip", 400
    return _sse_response(stream_ip(ip, use_cache=not no_cache, tools=tools))


@app.route("/stream/email")
def api_email():
    email    = request.args.get("email", "").strip()
    no_cache = request.args.get("no_cache") == "1"
    tools    = _parse_tools(request.args.get("tools", ""))
    if not email:
        return "Missing email", 400
    return _sse_response(stream_email(email, use_cache=not no_cache, tools=tools))


@app.route("/stream/phone")
def api_phone():
    number   = request.args.get("number", "").strip()
    no_cache = request.args.get("no_cache") == "1"
    tools    = _parse_tools(request.args.get("tools", ""))
    if not number:
        return "Missing number", 400
    return _sse_response(stream_phone(number, use_cache=not no_cache, tools=tools))


@app.route("/stream/username")
def api_username():
    username = request.args.get("username", "").strip()
    no_cache = request.args.get("no_cache") == "1"
    if not username:
        return "Missing username", 400
    return _sse_response(stream_username(username, use_cache=not no_cache))


@app.route("/stream/person")
def api_person():
    first    = request.args.get("first", "").strip()
    last     = request.args.get("last", "").strip()
    no_cache = request.args.get("no_cache") == "1"
    if not first or not last:
        return "Missing first/last", 400
    return _sse_response(stream_person(first, last, use_cache=not no_cache))


@app.route("/stream/breach")
def api_breach():
    email    = request.args.get("email", "").strip()
    no_cache = request.args.get("no_cache") == "1"
    tools    = _parse_tools(request.args.get("tools", ""))
    if not email:
        return "Missing email", 400
    return _sse_response(stream_breach(email, use_cache=not no_cache, tools=tools))


@app.route("/stream/full")
def api_full():
    params = {
        "target":   request.args.get("target", "").strip(),
        "ip":       request.args.get("ip", "").strip(),
        "email":    request.args.get("email", "").strip(),
        "username": request.args.get("username", "").strip(),
        "first":    request.args.get("first", "").strip(),
        "last":     request.args.get("last", "").strip(),
        "phone":    request.args.get("phone", "").strip(),
        "no_cache": request.args.get("no_cache") == "1",
    }
    return _sse_response(stream_full(params))


@app.route("/api/cache", methods=["GET"])
def cache_stats():
    return get_cache().stats()


@app.route("/api/cache", methods=["DELETE"])
def cache_clear():
    module  = request.args.get("module")
    target  = request.args.get("target")
    deleted = get_cache().invalidate(module=module, target=target)
    return {"deleted": deleted}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888, debug=False)
