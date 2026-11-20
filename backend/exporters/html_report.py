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
    """Renders a Sent-Eye JSON report as a self-contained HTML dossier."""

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
<title>Sent-Eye Report - {_esc(target_name)}</title>
<style>{_CSS}</style>
</head>
<body>
<div class="container">
<h1>Sent-Eye Intelligence Report</h1>
<div class="summary-bar">
  <p style="margin:0 0 6px 0;">Target: <code>{_esc(target)}</code></p>
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

    def _render_module(self, name: str, data: Dict[str, Any], target=None) -> str:
        parts = [f"<h2>{_esc(name)}</h2>"]
        parts.append(f"<p style='color:#94a3b8;'>{_esc(data.get('description', ''))}</p>")

        errors = data.get("errors", [])
        if errors:
            parts.append('<div class="card"><h3>Errors</h3>')
            for err in errors:
                parts.append(f'<p class="error">* {_esc(err)}</p>')
            parts.append("</div>")

        findings = data.get("findings", [])
        if name == "metadata_extraction":
            parts.append(self._render_metadata(findings))
        elif name == "geolocation":
            parts.append(self._render_geolocation(findings))
        elif name == "reverse_image_search":
            parts.append(self._render_reverse_search(findings))
        elif name == "face_analysis":
            parts.append(self._render_face_analysis(findings, target=target))
        else:
            parts.append(self._render_generic(findings))

        return "\n".join(parts)

    def _render_metadata(self, findings: List[Dict]) -> str:
        if not findings:
            return "<p>No metadata findings.</p>"
        rows = []
        for finding in findings:
            meta = finding.get("metadata", {})
            for key, value in meta.items():
                if isinstance(value, str) and "Binary data" in value:
                    continue
                if key == "SourceFile":
                    continue
                rows.append(f"<tr><td>{_esc(key)}</td><td>{_esc(value)}</td></tr>")
        if not rows:
            return "<p>No displayable metadata fields.</p>"
        return f'<table class="meta-table">{"".join(rows)}</table>'

    def _render_geolocation(self, findings: List[Dict]) -> str:
        if not findings:
            return "<p>No GPS coordinates found.</p>"
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

    def _render_face_analysis(self, findings, target=None):
        if not findings:
            return "<p>No faces detected in the image.</p>"

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

    def _render_generic(self, findings: List[Dict]) -> str:
        if not findings:
            return "<p>No findings.</p>"
        return f"<pre>{_esc(json.dumps(findings, indent=2, default=str))}</pre>"
