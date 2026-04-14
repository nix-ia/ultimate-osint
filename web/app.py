"""
Ultimate OSINT — Web interface (Flask + SSE streaming)
"""

import json
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from queue import Queue, Empty

from flask import Flask, Response, render_template, request, stream_with_context

# Make src importable
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


def _section(name: str, status: str = "running") -> str:
    return _sse("section", {"name": name, "status": status})


def _result(name: str, data) -> str:
    return _sse("result", {"name": name, "data": data})


def _error(name: str, msg: str) -> str:
    return _sse("error", {"name": name, "msg": msg})


def _done(summary: dict = None) -> str:
    return _sse("done", {"summary": summary or {}})


# ---------------------------------------------------------------------------
# Stream generators — one per module
# ---------------------------------------------------------------------------

def stream_domain(target: str, use_cache: bool = True):
    from src.modules.utils import extract_domain
    from src.modules.domain import (
        lookup_whois, lookup_dns, lookup_crtsh, lookup_wayback,
        lookup_ip_geo, lookup_shodan, lookup_virustotal,
        lookup_hunter, lookup_urlscan
    )

    domain = extract_domain(target)
    yield _sse("start", {"target": domain, "module": "domain"})

    cache = get_cache()
    if use_cache:
        cached = cache.get("domain", domain)
        if cached:
            yield _sse("cache_hit", {"target": domain})
            for section_name, section_data in cached.items():
                yield _result(section_name, section_data)
            yield _done({"domain": domain, "cache": True})
            return

    result = {}

    steps = [
        ("whois",       lookup_whois,       domain),
        ("dns",         lookup_dns,         domain),
        ("crtsh",       lambda d: {"subdomains": lookup_crtsh(d)}, domain),
        ("wayback",     lookup_wayback,     domain),
        ("ip_geo",      lookup_ip_geo,      domain),
        ("shodan",      lookup_shodan,      domain),
        ("virustotal",  lookup_virustotal,  domain),
        ("hunter",      lambda d: {"emails": lookup_hunter(d)}, domain),
        ("urlscan",     lambda d: {"results": [r.get("page", {}).get("url") for r in lookup_urlscan(d)]}, domain),
    ]

    for name, fn, arg in steps:
        yield _section(name)
        try:
            data = fn(arg)
            result[name] = data
            yield _result(name, data)
        except Exception as e:
            yield _error(name, str(e))
            result[name] = {}

    if use_cache:
        cache.set("domain", domain, result)

    yield _done({"domain": domain})


def stream_phone(number: str, use_cache: bool = True):
    from src.modules.phone import scan_phone

    yield _sse("start", {"target": number, "module": "phone"})

    cache = get_cache()
    if use_cache:
        cached = cache.get("phone", number)
        if cached:
            yield _sse("cache_hit", {"target": number})
            yield _result("phone", cached)
            yield _done()
            return

    yield _section("phone")
    try:
        result = scan_phone(number, use_cache=False)
        yield _result("phone", result)
        yield _done()
    except Exception as e:
        yield _error("phone", str(e))
        yield _done()


def stream_username(username: str, use_cache: bool = True):
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
        data = [r.to_dict() for r in results]
        found = [r for r in data if r.get("found")]
        if use_cache:
            cache.set("username", username, data)
        yield _result("username", data)
        yield _done({"found": len(found), "total": len(data)})
    except Exception as e:
        yield _error("username", str(e))
        yield _done()


def stream_person(first: str, last: str, use_cache: bool = True):
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


def stream_breach(email: str, use_cache: bool = True):
    from src.modules.breach import scan_breach

    yield _sse("start", {"target": email, "module": "breach"})

    cache = get_cache()
    if use_cache:
        cached = cache.get("breach", email)
        if cached:
            yield _sse("cache_hit", {"target": email})
            yield _result("breach", cached)
            yield _done()
            return

    yield _section("breach")
    try:
        result = scan_breach(email, use_cache=False)
        if use_cache:
            cache.set("breach", email, result)
        yield _result("breach", result)
        yield _done()
    except Exception as e:
        yield _error("breach", str(e))
        yield _done()


def stream_full(params: dict):
    """Run all enabled modules and stream results."""
    target  = params.get("target", "")
    username = params.get("username", "")
    first   = params.get("first", "")
    last    = params.get("last", "")
    phone   = params.get("phone", "")
    email   = params.get("email", "")
    no_cache = params.get("no_cache", False)
    use_cache = not no_cache

    yield _sse("start", {"target": target, "module": "full"})

    if target:
        yield from stream_domain(target, use_cache)
    if username:
        yield from stream_username(username, use_cache)
    if first and last:
        yield from stream_person(first, last, use_cache)
    if phone:
        yield from stream_phone(phone, use_cache)
    if email:
        yield from stream_breach(email, use_cache)

    yield _done()


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.route("/")
def index():
    api_keys = {
        "SHODAN_API_KEY":       bool(config.SHODAN_API_KEY),
        "VIRUSTOTAL_API_KEY":   bool(config.VIRUSTOTAL_API_KEY),
        "HUNTER_API_KEY":       bool(config.HUNTER_API_KEY),
        "URLSCAN_API_KEY":      bool(config.URLSCAN_API_KEY),
        "NUMVERIFY_API_KEY":    bool(config.NUMVERIFY_API_KEY),
        "ABSTRACTAPI_PHONE_KEY":bool(config.ABSTRACTAPI_PHONE_KEY),
        "HIBP_API_KEY":         bool(config.HIBP_API_KEY),
        "DEHASHED_API_KEY":     bool(config.DEHASHED_API_KEY),
    }
    return render_template("index.html", api_keys=api_keys)


@app.route("/stream/domain")
def api_domain():
    target   = request.args.get("target", "").strip()
    no_cache = request.args.get("no_cache") == "1"
    if not target:
        return "Missing target", 400

    def generate():
        yield from stream_domain(target, use_cache=not no_cache)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/stream/phone")
def api_phone():
    number   = request.args.get("number", "").strip()
    no_cache = request.args.get("no_cache") == "1"
    if not number:
        return "Missing number", 400

    def generate():
        yield from stream_phone(number, use_cache=not no_cache)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/stream/username")
def api_username():
    username = request.args.get("username", "").strip()
    no_cache = request.args.get("no_cache") == "1"
    if not username:
        return "Missing username", 400

    def generate():
        yield from stream_username(username, use_cache=not no_cache)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/stream/person")
def api_person():
    first    = request.args.get("first", "").strip()
    last     = request.args.get("last", "").strip()
    no_cache = request.args.get("no_cache") == "1"
    if not first or not last:
        return "Missing first/last", 400

    def generate():
        yield from stream_person(first, last, use_cache=not no_cache)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/stream/breach")
def api_breach():
    email    = request.args.get("email", "").strip()
    no_cache = request.args.get("no_cache") == "1"
    if not email:
        return "Missing email", 400

    def generate():
        yield from stream_breach(email, use_cache=not no_cache)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/stream/full")
def api_full():
    params = {
        "target":   request.args.get("target", "").strip(),
        "username": request.args.get("username", "").strip(),
        "first":    request.args.get("first", "").strip(),
        "last":     request.args.get("last", "").strip(),
        "phone":    request.args.get("phone", "").strip(),
        "email":    request.args.get("email", "").strip(),
        "no_cache": request.args.get("no_cache") == "1",
    }

    def generate():
        yield from stream_full(params)

    return Response(
        stream_with_context(generate()),
        mimetype="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.route("/api/cache", methods=["GET"])
def cache_stats():
    c = get_cache()
    return c.stats()


@app.route("/api/cache", methods=["DELETE"])
def cache_clear():
    module = request.args.get("module")
    target = request.args.get("target")
    c = get_cache()
    deleted = c.invalidate(module=module, target=target)
    return {"deleted": deleted}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8888, debug=False)
