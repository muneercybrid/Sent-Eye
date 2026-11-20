import base64
import html
import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List


_CSS = """
body{font-family:system-ui,-apple-system,sans-serif;margin:0;background:#0f172a;color:#e2e8f0;}
.container{max-width:1200px;margin:0 auto;padding:40px 20px;}
h1{color:#38bdf8;margin:0 0 8px 0;}
h2{color:#7dd3fc;margin-top:40px;border-bottom:1px solid #1e293b;padding-bottom:8px;}
h3{color:#bae6fd;font-size:1em;margin:0 0 8px 0;}
table{width:100%;border-collapse:collapse;margin-top:12px;}
td,th{padding:8px 12px;text-align:left;border-bottom:1px solid #1e293b;vertical-align:top;}
th{background:#1e293b;color:#94a3b8;font-weight:600;}
code{background:#1e293b;padding:2px 6px;border-radius:4px;font-size:0.9em;color:#7dd3fc;}
a{color:#38bdf8;text-decoration:none;}
a:hover{text-decoration:underline;}
.card{background:#1e293b;border-radius:8px;padding:16px;margin:12px 0;}
.error{color:#fca5a5;margin:4px 0;}
.meta-table td:first-child{width:220px;color:#94a3b8;font-family:monospace;font-size:0.9em;}
.result-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:12px;margin-top:16px;}
.result-card{background:#1e293b;border-radius:8px;padding:12px;display:flex;flex-direction:column;}
.result-card img{width:100%;height:120px;object-fit:cover;border-radius:4px;margin-bottom:8px;background:#0f172a;}
.result-card small{color:#94a3b8;margin-top:auto;font-size:0.8em;padding-top:8px;}
iframe{border:0;border-radius:8px;margin-top:12px;background:#fff;}
.summary-bar{background:#1e293b;padding:12px 20px;border-radius:8px;margin:12px 0;}
.meta-group{background:#0f172a;border-radius:6px;padding:8px 16px;margin:8px 0;}
.meta-group summary{cursor:pointer;padding:6px 0;color:#bae6fd;font-size:0.95em;}
.meta-group summary:hover{color:#7dd3fc;}
.meta-group[open] summary{margin-bottom:8px;}
.meta-group table{margin:0;}
.warning{color:#facc15;margin:4px 0;}
"""

_STATUS_COLORS = {
    "success": "#22c55e",
    "partial": "#eab308",
    "failed": "#ef4444",
    "skipped": "#64748b",
}


def _esc(value: Any) -> str:
    if value is None:
        return "-"
    return html.escape(str(value))


def _status_badge(status: str) -> str:
    color = _STATUS_COLORS.get(status, "#64748b")
    return (
        f'<span style="background:{color};color:#fff;padding:3px 10px;'
        f'border-radius:12px;font-size:0.75em;font-weight:700;letter-spacing:0.03em;">'
        f"{_esc(status.upper())}</span>"
    )



def _load_image_as_data_uri(path):
    """Load an image as a base64 data URI, or None on failure."""
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except Exception:
        return None
    ext = Path(path).suffix.lower()
    mime = {
        ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
        ".png": "image/png", ".webp": "image/webp", ".bmp": "image/bmp",
    }.get(ext, "image/jpeg")
    return f"data:{mime};base64,{base64.b64encode(data).decode('ascii')}"


def _get_image_dimensions(path):
    """Return (width, height) for an image, or None on failure."""
    try:
        from PIL import Image
        with Image.open(path) as im:
            return im.size
    except Exception:
        return None


class HTMLReporter:
    """Renders a Sent Eye JSON report as a self-contained HTML dossier."""

    def __init__(self, report: Dict[str, Any]):
        self.report = report

    def render(self) -> str:
        results = self.report.get("results", {})
        summary_rows = self._render_summary_rows(results)
        sections = "\n".join(
            self._render_module(name, data) for name, data in results.items()
        )
        target = self.report.get("target", "")
        target_name = Path(target).name if target else "(unknown)"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sent Eye Report - {_esc(target_name)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="container">
<h1>Sent Eye Intelligence Report</h1>
<div class="summary-bar">
  <p style="margin:0 0 6px 0;">Target: <code>{_esc(target)}</code></p>
  <p style="margin:0 0 6px 0;">Type: <code>{_esc(self.report.get('target_type', 'image'))}</code></p>
  <p style="margin:0 0 6px 0;">Generated: {_esc(timestamp)}</p>
  <p style="margin:0;">Modules run: {_esc(self.report.get("modules_run"))}</p>
</div>
<h2>Summary</h2>
<table>
<tr><th>Module</th><th>Status</th><th>Findings</th><th>Errors</th></tr>
{summary_rows}
</table>
{sections}
</div>
</body>
</html>"""

    def _render_summary_rows(self, results: Dict[str, Dict]) -> str:
        rows = []
        for name, data in results.items():
            rows.append(
                f"<tr><td><code>{_esc(name)}</code></td>"
                f"<td>{_status_badge(data.get('status', 'unknown'))}</td>"
                f"<td>{len(data.get('findings', []))}</td>"
                f"<td>{len(data.get('errors', []))}</td></tr>"
            )
        return "\n".join(rows)

    def _render_module(self, name: str, data: Dict[str, Any], target=None, header="h2") -> str:
        status = data.get("status", "unknown")
        findings = data.get("findings", [])
        errors = data.get("errors", [])
        warnings = data.get("warnings", [])

        parts = [f"<{header}>{_esc(name)}</{header}>"]
        parts.append(f"<p style='color:#94a3b8;'>{_esc(data.get('description', ''))}</p>")

        # Only failed modules show a red error card. For partial/skipped/success,
        # errors (if any) get demoted to warnings so nothing looks scarier than it is.
        if status == "failed" and errors:
            parts.append('<div class="card" style="border-left:4px solid #ef4444;"><h3>Errors</h3>')
            for err in errors:
                parts.append(f'<p class="error">* {_esc(err)}</p>')
            parts.append("</div>")
        elif errors:
            warnings = list(warnings) + list(errors)
            errors = []

        if warnings:
            parts.append(
                f'<details class="meta-group"><summary style="color:#eab308;">'
                f'Warnings ({len(warnings)})</summary>'
            )
            for w in warnings:
                parts.append(f'<p class="warning">* {_esc(w)}</p>')
            parts.append('</details>')

        if name == "metadata_extraction":
            parts.append(self._render_metadata(findings, status=status))
        elif name == "geolocation":
            parts.append(self._render_geolocation(findings, status=status))
        elif name == "reverse_image_search":
            parts.append(self._render_reverse_search(findings))
        elif name == "face_analysis":
            parts.append(self._render_face_analysis(findings, target=target, status=status))
        elif name == "username_enumeration":
            parts.append(self._render_username_enumeration(findings, status=status))
        elif name == "email_intel":
            parts.append(self._render_email_intel(findings, status=status))
        elif name == "vin_decode":
            parts.append(self._render_vin_decode(findings, status=status))
        else:
            parts.append(self._render_generic(findings))

        return "\n".join(parts)

    def _render_value(self, value):
        if not isinstance(value, str):
            return _esc(value)
        if len(value) <= 200:
            return _esc(value)
        return (
            f'<details><summary>{_esc(value[:180])}...</summary>'
            f'<pre style="white-space:pre-wrap;font-size:0.9em;">{_esc(value)}</pre></details>'
        )

    def _render_metadata(self, findings: List[Dict], status=None) -> str:
        if not findings:
            return "<p>No displayable metadata fields.</p>"

        from .metadata_categories import categorize, category_labels

        merged = {}
        for finding in findings:
            for k, v in finding.get("metadata", {}).items():
                if k == "SourceFile":
                    continue
                merged[k] = v

        highlights, categorized, other = categorize(merged)
        parts = []

        if highlights:
            parts.append(
                '<div class="card" style="border-left:4px solid #38bdf8;">'
                '<h4 style="margin:0 0 12px 0;color:#38bdf8;">Highlights</h4>'
            )
            parts.append('<table class="meta-table">')
            for k, v in highlights.items():
                parts.append(f"<tr><td>{_esc(k)}</td><td>{self._render_value(v)}</td></tr>")
            parts.append("</table></div>")

        for cat_key, label in category_labels():
            items = categorized.get(cat_key, {})
            if not items:
                continue
            parts.append(
                f'<details class="meta-group" open><summary><strong>{label}</strong> '
                f'<span style="color:#64748b;">({len(items)})</span></summary>'
            )
            parts.append('<table class="meta-table">')
            for k, v in items.items():
                parts.append(f"<tr><td>{_esc(k)}</td><td>{self._render_value(v)}</td></tr>")
            parts.append("</table></details>")

        if other:
            parts.append(
                f'<details class="meta-group"><summary><strong>Other</strong> '
                f'<span style="color:#64748b;">({len(other)})</span></summary>'
            )
            parts.append('<table class="meta-table">')
            for k, v in other.items():
                parts.append(f"<tr><td>{_esc(k)}</td><td>{self._render_value(v)}</td></tr>")
            parts.append("</table></details>")

        return "\n".join(parts)

    def _render_geolocation(self, findings: List[Dict], status=None) -> str:
        if not findings:
            return '<p style="color:#94a3b8;">No GPS coordinates found in metadata.</p>'
        parts = []
        for f in findings:
            lat = f.get("latitude")
            lon = f.get("longitude")
            address = f.get("address", "Coordinates")
            parts.append('<div class="card">')
            parts.append(f"<h3>{_esc(address)}</h3>")
            parts.append(
                f"<p>Latitude: <code>{_esc(lat)}</code> | "
                f"Longitude: <code>{_esc(lon)}</code></p>"
            )
            links = []
            if f.get("google_maps"):
                links.append(f'<a href="{_esc(f["google_maps"])}" target="_blank">Google Maps</a>')
            if f.get("openstreetmap"):
                links.append(f'<a href="{_esc(f["openstreetmap"])}" target="_blank">OpenStreetMap</a>')
            if links:
                parts.append(f"<p>{' | '.join(links)}</p>")
            if lat is not None and lon is not None:
                bbox = f"{float(lon)-0.005},{float(lat)-0.005},{float(lon)+0.005},{float(lat)+0.005}"
                parts.append(
                    f'<iframe width="100%" height="360" '
                    f'src="https://www.openstreetmap.org/export/embed.html'
                    f'?bbox={bbox}&layer=mapnik&marker={lat},{lon}"></iframe>'
                )
            if f.get("geocoding_error"):
                parts.append(f'<p class="error">Geocoding error: {_esc(f["geocoding_error"])}</p>')
            parts.append("</div>")
        return "\n".join(parts)

    def _render_reverse_search(self, findings: List[Dict]) -> str:
        if not findings:
            return "<p>No reverse image search results.</p>"
        cards = []
        for f in findings:
            thumb = f.get("thumbnail")
            img_tag = f'<img src="{_esc(thumb)}" alt="" loading="lazy">' if thumb else ""
            title = f.get("title") or f.get("url") or "(untitled)"
            url = f.get("url", "#")
            source = f.get("source", "")
            cards.append(
                f'<div class="result-card">{img_tag}'
                f'<a href="{_esc(url)}" target="_blank">{_esc(title)}</a>'
                f'<small>{_esc(source)}</small></div>'
            )
        return f'<div class="result-grid">{"".join(cards)}</div>'

    def _render_face_analysis(self, findings, target=None, status=None):
        if status == "skipped":
            return '<p style="color:#94a3b8;">Face analysis was not enabled for this run.</p>'
        if not findings:
            return '<p style="color:#94a3b8;">No faces detected in the image.</p>' 

        if target is None:
            target = self.report.get("target", "")
        data_uri = _load_image_as_data_uri(target) if target else None
        dims = _get_image_dimensions(target) if target else None

        parts = []

        if data_uri and dims:
            width, height = dims
            shapes = []
            for f in findings:
                loc = f.get("location", {})
                top = loc.get("top", 0)
                left = loc.get("left", 0)
                right = loc.get("right", 0)
                bottom = loc.get("bottom", 0)
                color = "#22c55e" if f.get("has_match") else "#38bdf8"
                shapes.append(
                    f'<rect x="{left}" y="{top}" '
                    f'width="{right - left}" height="{bottom - top}" '
                    f'fill="none" stroke="{color}" stroke-width="4"/>'
                )
                shapes.append(
                    f'<text x="{left}" y="{max(top - 8, 20)}" '
                    f'fill="{color}" font-size="20" font-weight="bold">'
                    f'Face {f.get("face_index")}</text>'
                )
            parts.append(
                '<div class="card" style="text-align:center;">'
                f'<svg viewBox="0 0 {width} {height}" '
                'style="max-width:100%;height:auto;max-height:600px;">'
                f'<image href="{data_uri}" width="{width}" height="{height}"/>'
                f'{"".join(shapes)}</svg>'
                '</div>'
            )

        for f in findings:
            parts.append(f'<div class="card"><h3>Face {f.get("face_index")}</h3>')
            matches = f.get("matches", [])
            if not matches:
                parts.append('<p style="color:#94a3b8;">No matches (no reference database configured).</p>')
            else:
                parts.append('<table><tr><th>Reference</th><th>Distance</th><th>Result</th></tr>')
                for m in matches:
                    dist = m["distance"]
                    pct = max(0, min(100, int((1 - dist) * 100)))
                    is_match = m["is_match"]
                    color = "#22c55e" if is_match else "#64748b"
                    label = "MATCH" if is_match else "no match"
                    parts.append(
                        f'<tr><td>{_esc(m["file"])}</td>'
                        '<td><div style="background:#0f172a;border-radius:4px;overflow:hidden;margin-bottom:4px;">'
                        f'<div style="width:{pct}%;background:{color};height:12px;"></div></div>'
                        f'<span style="font-size:0.8em;color:#94a3b8;">{dist:.4f}</span></td>'
                        f'<td><span style="color:{color};font-weight:700;">{label}</span></td></tr>'
                    )
                parts.append('</table>')
            parts.append('</div>')

        return "\n".join(parts)

    def _render_username_enumeration(self, findings, status=None):
        if not findings:
            return '<p style="color:#94a3b8;">No sites were checked.</p>'

        claimed_high = [f for f in findings if f.get("status") == "claimed" and f.get("confidence") == "high"]
        claimed_low = [f for f in findings if f.get("status") == "claimed" and f.get("confidence") == "low"]
        available = [f for f in findings if f.get("status") == "available"]
        ambiguous = [f for f in findings if f.get("status") in ("ambiguous", "error")]
        blocked = [f for f in ambiguous if f.get("http_code") in (403, 429)]

        parts = []
        parts.append(
            '<div class="stats">'
            f'<div class="stat"><div class="stat-value">{len(claimed_high)}</div>'
            f'<div class="stat-label">Confirmed</div></div>'
            f'<div class="stat"><div class="stat-value">{len(claimed_low)}</div>'
            f'<div class="stat-label">Unverified</div></div>'
            f'<div class="stat"><div class="stat-value">{len(available)}</div>'
            f'<div class="stat-label">Available</div></div>'
            f'<div class="stat"><div class="stat-value">{len(ambiguous)}</div>'
            f'<div class="stat-label">Ambiguous</div></div>'
            '</div>'
        )

        if blocked:
            parts.append(
                f'<div class="card" style="border-left:4px solid #eab308;">'
                f'<p style="margin:0;color:#facc15;">'
                f'<strong>{len(blocked)} site(s) returned 403/429</strong> — likely cloud-IP blocking '
                f'(AWS/GCP ranges are blocked by Cloudflare/Akamai). '
                f'Run Sent Eye locally for full accuracy.</p></div>'
            )

        if claimed_high:
            parts.append('<h4 style="color:#22c55e;margin:20px 0 8px 0;">Confirmed Profiles (API / reliable)</h4>')
            parts.append('<table><tr><th>Site</th><th>Category</th><th>Profile</th></tr>')
            for f in sorted(claimed_high, key=lambda x: x.get("name", "")):
                parts.append(
                    f'<tr><td><strong>{_esc(f.get("name", ""))}</strong></td>'
                    f'<td>{_esc(f.get("category", ""))}</td>'
                    f'<td><a href="{_esc(f.get("url", "#"))}" target="_blank">'
                    f'{_esc(f.get("url", ""))}</a></td></tr>'
                )
            parts.append('</table>')

        if claimed_low:
            parts.append('<h4 style="color:#eab308;margin:20px 0 8px 0;">Unverified Profiles (verify manually)</h4>')
            parts.append(
                '<p style="color:#94a3b8;font-size:0.9em;margin:0 0 8px 0;">'
                'These sites return HTTP 200 for any handle — open each link to confirm.</p>'
            )
            parts.append('<table><tr><th>Site</th><th>Category</th><th>Profile</th></tr>')
            for f in sorted(claimed_low, key=lambda x: x.get("name", "")):
                parts.append(
                    f'<tr><td><strong>{_esc(f.get("name", ""))}</strong></td>'
                    f'<td>{_esc(f.get("category", ""))}</td>'
                    f'<td><a href="{_esc(f.get("url", "#"))}" target="_blank">'
                    f'{_esc(f.get("url", ""))}</a></td></tr>'
                )
            parts.append('</table>')

        if not claimed_high and not claimed_low:
            parts.append(
                '<p style="color:#94a3b8;margin-top:16px;">'
                'No profiles found — username appears unclaimed across all checked sites.'
                '</p>'
            )

        if available:
            parts.append(
                f'<details class="meta-group"><summary><strong>Available '
                f'<span style="color:#64748b;">({len(available)})</span></summary>'
            )
            parts.append('<table><tr><th>Site</th><th>URL</th></tr>')
            for f in sorted(available, key=lambda x: x.get("name", "")):
                parts.append(
                    f'<tr><td>{_esc(f.get("name", ""))}</td>'
                    f'<td><a href="{_esc(f.get("url", "#"))}" target="_blank">'
                    f'{_esc(f.get("url", ""))}</a></td></tr>'
                )
            parts.append('</table></details>')

        if ambiguous:
            parts.append(
                f'<details class="meta-group"><summary><strong>Ambiguous / Errors '
                f'<span style="color:#64748b;">({len(ambiguous)})</span></summary>'
            )
            parts.append('<table><tr><th>Site</th><th>Status</th><th>Detail</th></tr>')
            for f in sorted(ambiguous, key=lambda x: x.get("name", "")):
                detail = f.get("error") or f'HTTP {f.get("http_code")}'
                parts.append(
                    f'<tr><td>{_esc(f.get("name", ""))}</td>'
                    f'<td>{_esc(f.get("status", ""))}</td>'
                    f'<td>{_esc(detail)}</td></tr>'
                )
            parts.append('</table></details>')

        return "\n".join(parts)

    def _render_email_intel(self, findings, status=None):
        if not findings:
            return '<p style="color:#94a3b8;">No checks were run.</p>'

        by_cat: Dict[str, List[Dict[str, Any]]] = {}
        for f in findings:
            by_cat.setdefault(f.get("category", "other"), []).append(f)

        parts = []

        hibp = next((f for f in findings if f.get("check") == "hibp"), None)
        if hibp:
            if hibp.get("status") == "breached":
                parts.append(
                    '<div class="card" style="border-left:4px solid #ef4444;">'
                    f'<h3 style="margin:0 0 8px 0;color:#fca5a5;">'
                    f'{_esc(hibp.get("detail", ""))}</h3>'
                    '<p style="color:#94a3b8;margin:0;">Review the breach list below.</p>'
                    '</div>'
                )
            elif hibp.get("status") == "ok":
                parts.append(
                    '<div class="card" style="border-left:4px solid #22c55e;">'
                    '<h3 style="margin:0;color:#86efac;">No known breaches</h3></div>'
                )

        if "validation" in by_cat:
            parts.append('<h4 style="color:#38bdf8;margin:20px 0 8px 0;">Validation</h4>')
            parts.append('<table><tr><th>Check</th><th>Status</th><th>Detail</th></tr>')
            for f in by_cat["validation"]:
                color = {
                    "ok": "#86efac", "detected": "#fde047",
                    "warning": "#fde047", "error": "#fca5a5",
                }.get(f.get("status"), "#e2e8f0")
                parts.append(
                    f'<tr><td>{_esc(f.get("check", ""))}</td>'
                    f'<td style="color:{color};font-weight:600;">{_esc(f.get("status", ""))}</td>'
                    f'<td>{_esc(f.get("detail", ""))}</td></tr>'
                )
            parts.append('</table>')

        if "domain" in by_cat:
            parts.append('<h4 style="color:#38bdf8;margin:20px 0 8px 0;">Domain</h4>')
            for f in by_cat["domain"]:
                parts.append('<div class="card">')
                parts.append(
                    f'<p style="margin:0 0 8px 0;"><strong>{_esc(f.get("check", ""))}</strong> — '
                    f'{_esc(f.get("detail", ""))}</p>'
                )
                records = f.get("records") or []
                if records:
                    parts.append('<table><tr><th>Priority</th><th>Host</th></tr>')
                    for r in records:
                        parts.append(
                            f'<tr><td>{_esc(r.get("priority"))}</td>'
                            f'<td><code>{_esc(r.get("host"))}</code></td></tr>'
                        )
                    parts.append('</table>')
                parts.append('</div>')

        if "profile" in by_cat:
            parts.append('<h4 style="color:#38bdf8;margin:20px 0 8px 0;">Profile (Gravatar)</h4>')
            for f in by_cat["profile"]:
                if f.get("status") == "none":
                    parts.append(
                        '<p style="color:#94a3b8;">No Gravatar profile found.</p>'
                    )
                    continue
                if f.get("status") == "error":
                    parts.append(f'<p class="error">{_esc(f.get("detail", ""))}</p>')
                    continue
                parts.append('<div class="card">')
                parts.append('<div style="display:flex;gap:16px;align-items:flex-start;">')
                avatar_url = f.get("url")
                if avatar_url:
                    parts.append(
                        f'<img src="{_esc(avatar_url)}" alt="Avatar" '
                        f'style="width:96px;height:96px;border-radius:8px;background:#0f172a;flex-shrink:0;">'
                    )
                parts.append('<div style="flex:1;">')
                if f.get("display_name"):
                    parts.append(f'<p style="margin:0 0 4px 0;"><strong>Display name:</strong> {_esc(f["display_name"])}</p>')
                if f.get("full_name"):
                    parts.append(f'<p style="margin:0 0 4px 0;"><strong>Full name:</strong> {_esc(f["full_name"])}</p>')
                if f.get("about"):
                    parts.append(f'<p style="margin:0 0 4px 0;"><strong>About:</strong> {_esc(f["about"])}</p>')
                urls = f.get("urls") or []
                if urls:
                    parts.append('<p style="margin:0 0 4px 0;"><strong>Linked URLs:</strong></p>')
                    parts.append('<ul style="margin:0 0 8px 20px;">')
                    for u in urls:
                        parts.append(f'<li><a href="{_esc(u)}" target="_blank">{_esc(u)}</a></li>')
                    parts.append('</ul>')
                parts.append('</div></div></div>')

        if "breaches" in by_cat:
            for f in by_cat["breaches"]:
                if f.get("status") != "breached":
                    continue
                breaches = f.get("breaches") or []
                parts.append('<h4 style="color:#fca5a5;margin:20px 0 8px 0;">Breach History</h4>')
                parts.append('<table><tr><th>Breach</th><th>Date</th><th>Accounts</th><th>Data leaked</th></tr>')
                for b in breaches:
                    data_classes = ", ".join(b.get("data_classes", []))[:120]
                    parts.append(
                        f'<tr><td><strong>{_esc(b.get("title") or b.get("name", ""))}</strong></td>'
                        f'<td>{_esc(b.get("date", ""))}</td>'
                        f'<td>{_esc(b.get("pwn_count", ""))}</td>'
                        f'<td style="font-size:0.85em;">{_esc(data_classes)}</td></tr>'
                    )
                parts.append('</table>')

        if hibp and hibp.get("status") == "skipped":
            parts.append(
                f'<p style="color:#94a3b8;margin-top:16px;">'
                f'{_esc(hibp.get("detail", ""))}</p>'
            )

        return "\n".join(parts)

    def _render_vin_decode(self, findings, status=None):
        if not findings:
            return '<p style="color:#94a3b8;">VIN was not decoded.</p>'

        decode = next((f for f in findings if f.get("category") == "decode"), None)
        recalls = next((f for f in findings if f.get("category") == "recalls"), None)

        parts = []

        if decode and decode.get("status") == "ok":
            decoded = decode.get("decoded", {})
            parts.append(
                '<div class="card" style="border-left:4px solid #38bdf8;">'
                '<h3 style="margin:0 0 12px 0;color:#38bdf8;">Vehicle Identity</h3>'
                '<table class="meta-table">'
            )
            ordered_keys = [
                "Make", "Model", "ModelYear", "Series", "Trim", "BodyClass",
                "VehicleType", "Doors", "DriveType", "EngineCylinders",
                "DisplacementL", "EngineHP", "FuelTypePrimary",
                "TransmissionStyle", "TransmissionSpeeds", "GVWR",
                "SeatBeltsAll", "BrakeSystemType",
                "PlantCity", "PlantState", "PlantCountry", "PlantCompanyName",
                "Manufacturer",
            ]
            for key in ordered_keys:
                if key in decoded:
                    parts.append(
                        f'<tr><td>{_esc(key)}</td><td>{_esc(decoded[key])}</td></tr>'
                    )
            picture = decoded.get("VehiclePicture")
            if picture:
                parts.append('</table>')
                parts.append(
                    f'<p style="margin-top:12px;"><img src="{_esc(picture)}" '
                    f'alt="Vehicle" style="max-width:320px;border-radius:8px;background:#0f172a;"></p>'
                )
            else:
                parts.append('</table>')
            parts.append('</div>')
        elif decode:
            parts.append(
                f'<div class="card" style="border-left:4px solid #eab308;">'
                f'<p style="margin:0;color:#facc15;">'
                f'{_esc(decode.get("detail", "Decode incomplete."))}</p></div>'
            )

        if decode:
            all_fields = decode.get("all_fields", {})
            if all_fields:
                parts.append(
                    f'<details class="meta-group"><summary><strong>All vPIC fields '
                    f'<span style="color:#64748b;">({len(all_fields)})</span></summary>'
                    '<table class="meta-table">'
                )
                for k in sorted(all_fields.keys()):
                    v = all_fields[k]
                    if isinstance(v, str) and len(v) > 200:
                        v = v[:200] + "..."
                    parts.append(
                        f'<tr><td>{_esc(k)}</td><td>{_esc(v)}</td></tr>'
                    )
                parts.append('</table></details>')

        if recalls:
            count = len(recalls.get("recalls") or [])
            if count == 0:
                parts.append(
                    '<h4 style="color:#22c55e;margin:20px 0 8px 0;">'
                    'Recalls — No Open Recalls</h4>'
                    '<p style="color:#94a3b8;">'
                    'NHTSA has no open recalls on file for this vehicle.</p>'
                )
            else:
                parts.append(
                    f'<h4 style="color:#fca5a5;margin:20px 0 8px 0;">'
                    f'Recalls — {count} on File</h4>'
                )
                parts.append(
                    '<table><tr><th>Campaign</th><th>Component</th><th>Summary</th></tr>'
                )
                for r in recalls["recalls"]:
                    parts.append(
                        f'<tr><td><code>{_esc(r.get("campaign", ""))}</code></td>'
                        f'<td><strong>{_esc(r.get("component", ""))}</strong></td>'
                        f'<td style="font-size:0.9em;">{_esc(r.get("summary", ""))}</td></tr>'
                    )
                parts.append('</table>')

        return "\n".join(parts)

    def _render_generic(self, findings: List[Dict]) -> str:
        if not findings:
            return "<p>No findings.</p>"
        return f"<pre>{_esc(json.dumps(findings, indent=2, default=str))}</pre>"
