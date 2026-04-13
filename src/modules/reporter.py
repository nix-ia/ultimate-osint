"""
Report exporter — writes OSINT results to JSON or standalone HTML.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any

from .utils import console


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def write_json(path: Path, report: dict[str, Any]) -> None:
    path.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
    console.print(f"\n[bold green]JSON report saved →[/bold green] {path}")


# ---------------------------------------------------------------------------
# HTML
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>OSINT Report — {title}</title>
<style>
  :root {{
    --bg: #0d1117; --bg2: #161b22; --bg3: #21262d;
    --border: #30363d; --text: #c9d1d9; --muted: #8b949e;
    --green: #3fb950; --red: #f85149; --yellow: #d29922;
    --blue: #58a6ff; --purple: #bc8cff; --cyan: #39d353;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: 'Segoe UI', system-ui, monospace; font-size: 14px; line-height: 1.6; }}
  header {{ background: var(--bg2); border-bottom: 1px solid var(--border); padding: 24px 32px; }}
  header h1 {{ font-size: 22px; color: var(--red); letter-spacing: 2px; }}
  header p {{ color: var(--muted); font-size: 12px; margin-top: 4px; }}
  .badge {{ display: inline-block; background: var(--bg3); border: 1px solid var(--border);
            border-radius: 20px; padding: 2px 10px; font-size: 11px; margin: 4px 4px 0 0; color: var(--blue); }}
  main {{ max-width: 1100px; margin: 0 auto; padding: 24px 32px; }}
  .section {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px;
              margin-bottom: 20px; overflow: hidden; }}
  .section-header {{ padding: 12px 20px; background: var(--bg3); border-bottom: 1px solid var(--border);
                     cursor: pointer; display: flex; justify-content: space-between; align-items: center; }}
  .section-header h2 {{ font-size: 14px; color: var(--yellow); text-transform: uppercase; letter-spacing: 1px; }}
  .section-header .count {{ background: var(--bg); border: 1px solid var(--border);
                             border-radius: 12px; padding: 1px 8px; font-size: 11px; color: var(--muted); }}
  .section-body {{ padding: 16px 20px; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ text-align: left; color: var(--muted); font-weight: 600; padding: 6px 10px;
        border-bottom: 1px solid var(--border); font-size: 11px; text-transform: uppercase; }}
  td {{ padding: 6px 10px; border-bottom: 1px solid var(--border); vertical-align: top; word-break: break-all; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: var(--bg3); }}
  .found {{ color: var(--green); font-weight: 600; }}
  .notfound {{ color: var(--muted); }}
  .error {{ color: var(--red); }}
  a {{ color: var(--blue); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .tag {{ display: inline-block; background: var(--bg3); border-radius: 4px;
          padding: 1px 6px; font-size: 11px; margin: 1px; color: var(--cyan); }}
  .kv-row {{ display: flex; gap: 12px; padding: 4px 0; border-bottom: 1px solid var(--border); }}
  .kv-row:last-child {{ border-bottom: none; }}
  .kv-key {{ color: var(--muted); min-width: 180px; flex-shrink: 0; font-size: 12px; }}
  .kv-val {{ color: var(--text); word-break: break-all; }}
  .pill-found {{ background: rgba(63,185,80,.15); color: var(--green);
                 border: 1px solid rgba(63,185,80,.3); border-radius: 4px; padding: 1px 8px; font-size: 11px; }}
  .pill-skip {{ background: rgba(139,148,158,.1); color: var(--muted);
                border: 1px solid var(--border); border-radius: 4px; padding: 1px 8px; font-size: 11px; }}
  details summary {{ list-style: none; }}
  details summary::-webkit-details-marker {{ display: none; }}
  .toggle {{ color: var(--muted); font-size: 18px; transition: transform .2s; }}
  details[open] .toggle {{ transform: rotate(90deg); }}
</style>
</head>
<body>
<header>
  <h1>&#9679; ULTIMATE OSINT — REPORT</h1>
  <p>Generated: {generated} &nbsp;|&nbsp; Target: <strong>{title}</strong></p>
  {badges}
</header>
<main>
{sections}
</main>
<script>
  document.querySelectorAll('.section-header').forEach(h => {{
    h.addEventListener('click', () => {{
      const body = h.nextElementSibling;
      body.style.display = body.style.display === 'none' ? '' : 'none';
    }});
  }});
</script>
</body>
</html>
"""


def _kv_table(data: dict) -> str:
    if not data:
        return "<p style='color:var(--muted);font-size:12px'>No data.</p>"
    rows = []
    for k, v in data.items():
        if isinstance(v, list):
            val = " ".join(f'<span class="tag">{x}</span>' for x in v) if v else '<span style="color:var(--muted)">—</span>'
        elif v is None or v == "":
            val = '<span style="color:var(--muted)">—</span>'
        else:
            val = str(v)
        rows.append(f'<div class="kv-row"><div class="kv-key">{k}</div><div class="kv-val">{val}</div></div>')
    return "\n".join(rows)


def _username_table(results: list[dict]) -> str:
    if not results:
        return "<p style='color:var(--muted)'>No results.</p>"
    rows = []
    for r in sorted(results, key=lambda x: (not x.get("found"), x.get("name", ""))):
        found = r.get("found")
        status = '<span class="pill-found">FOUND</span>' if found else '<span class="pill-skip">—</span>'
        url = r.get("url", "")
        link = f'<a href="{url}" target="_blank">{url}</a>' if found else f'<span class="notfound">{url}</span>'
        rows.append(f"<tr><td>{r.get('name','')}</td><td>{status}</td><td>{link}</td></tr>")
    return f"<table><tr><th>Platform</th><th>Status</th><th>URL</th></tr>{''.join(rows)}</table>"


def _make_section(title: str, content_html: str, count: str = "") -> str:
    return f"""
<div class="section">
  <div class="section-header">
    <h2>{title}</h2>
    <span class="count">{count}</span>
  </div>
  <div class="section-body">
    {content_html}
  </div>
</div>"""


def _render_module(module: str, data: Any) -> str:
    if module == "username":
        found = [r for r in (data or []) if r.get("found")]
        return _make_section("Username Hunt", _username_table(data or []), f"{len(found)} found / {len(data or [])} checked")
    if module == "domain":
        if not data:
            return ""
        parts = []
        for sub, sub_data in data.items():
            if not sub_data:
                continue
            if isinstance(sub_data, dict):
                parts.append(f"<h3 style='color:var(--yellow);margin:12px 0 6px;font-size:12px;text-transform:uppercase'>{sub}</h3>" + _kv_table(sub_data))
            elif isinstance(sub_data, list):
                tags = " ".join(f'<span class="tag">{x}</span>' for x in sub_data)
                parts.append(f"<h3 style='color:var(--yellow);margin:12px 0 6px;font-size:12px;text-transform:uppercase'>{sub}</h3>{tags}")
        return _make_section("Domain Intelligence", "\n".join(parts), f"{len(data)} sources")
    if module == "phone":
        return _make_section("Phone Intelligence", _kv_table(data or {}))
    if module == "person":
        parts = []
        for k, v in (data or {}).items():
            if k == "dorks" and isinstance(v, dict):
                links = "".join(f'<div style="margin:2px 0"><a href="{url}" target="_blank">{label}</a></div>' for label, url in v.items())
                parts.append(f"<h3 style='color:var(--yellow);margin:12px 0 6px;font-size:12px;text-transform:uppercase'>Search Dorks</h3>{links}")
            elif k == "username_variants" and isinstance(v, list):
                tags = " ".join(f'<span class="tag">{x}</span>' for x in v)
                parts.append(f"<h3 style='color:var(--yellow);margin:12px 0 6px;font-size:12px;text-transform:uppercase'>Username Variants</h3>{tags}")
            elif k == "gravatar_found" and isinstance(v, list) and v:
                tags = " ".join(f'<span class="tag found">{x}</span>' for x in v)
                parts.append(f"<h3 style='color:var(--yellow);margin:12px 0 6px;font-size:12px;text-transform:uppercase'>Gravatar Matches</h3>{tags}")
        return _make_section("Person Intelligence", "\n".join(parts) if parts else "<p style='color:var(--muted)'>No data.</p>")
    if module == "breach":
        breaches = data.get("breaches", []) if isinstance(data, dict) else []
        if not breaches:
            return _make_section("Breach Check", "<p style='color:var(--green)'>No breaches found.</p>")
        rows = "".join(
            f"<tr><td>{b.get('Name','')}</td><td>{b.get('BreachDate','')}</td>"
            f"<td>{b.get('PwnCount',0):,}</td><td>{', '.join(b.get('DataClasses',[])[:4])}</td></tr>"
            for b in breaches
        )
        table = f"<table><tr><th>Name</th><th>Date</th><th>Accounts</th><th>Data types</th></tr>{rows}</table>"
        return _make_section("Breach Check", table, f"{len(breaches)} breach(es)")
    return ""


def write_html(path: Path, report: dict[str, Any]) -> None:
    title = report.get("target", "unknown")
    generated = report.get("generated_at", datetime.utcnow().isoformat())

    badges_html = ""
    for mod in report.get("modules_run", []):
        badges_html += f'<span class="badge">{mod}</span>'

    sections_html = ""
    for mod, data in report.get("results", {}).items():
        sections_html += _render_module(mod, data)

    html = _HTML_TEMPLATE.format(
        title=title,
        generated=generated,
        badges=badges_html,
        sections=sections_html,
    )
    path.write_text(html, encoding="utf-8")
    console.print(f"\n[bold green]HTML report saved →[/bold green] {path}")


# ---------------------------------------------------------------------------
# Unified writer
# ---------------------------------------------------------------------------

def write_report(output: str, report: dict[str, Any]) -> None:
    path = Path(output)
    if path.suffix.lower() == ".html":
        write_html(path, report)
    else:
        write_json(path, report)
