"""Batch HTML reporter with categorised per-image sections."""
from datetime import datetime
from pathlib import Path

from .html_report import HTMLReporter, _CSS, _esc


_BATCH_EXTRA_CSS = """
.toc{background:#1e293b;padding:16px 20px;border-radius:8px;margin:16px 0;}
.toc-grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(320px,1fr));gap:8px;}
.toc-item{background:#0f172a;padding:10px 14px;border-radius:6px;display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;}
.toc-item a{flex:1;min-width:120px;}
.image-section{border-top:2px solid #38bdf8;margin-top:56px;padding-top:24px;}
.image-header{background:linear-gradient(135deg,#1e3a5f,#1e293b);padding:20px;border-radius:8px;margin-bottom:24px;}
.image-header h2{margin:0 0 8px 0;border:none;color:#38bdf8;}
.badge-row{display:flex;flex-wrap:wrap;gap:6px;margin-top:12px;}
.badge{display:inline-flex;align-items:center;padding:4px 10px;border-radius:12px;font-size:0.75em;font-weight:600;}
.badge.success{background:#166534;color:#86efac;}
.badge.partial{background:#854d0e;color:#fde047;}
.badge.failed{background:#991b1b;color:#fca5a5;}
.badge.skipped{background:#334155;color:#94a3b8;}
.badge.unknown{background:#334155;color:#94a3b8;}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:16px 0;}
.stat{background:#1e293b;padding:16px;border-radius:8px;text-align:center;}
.stat-value{font-size:2em;font-weight:700;color:#38bdf8;}
.stat-label{color:#94a3b8;font-size:0.78em;text-transform:uppercase;letter-spacing:0.05em;margin-top:4px;}
.to-top{display:inline-block;margin-top:24px;padding:6px 14px;background:#1e293b;border-radius:6px;color:#7dd3fc;font-size:0.85em;}
.batch-err{background:#7f1d1d;padding:12px;border-radius:8px;margin:8px 0;}
"""


class BatchHTMLReporter(HTMLReporter):
    """Renders SentEyeBatchRunner JSON as one combined HTML dossier."""

    def _badge(self, name, status):
        return f'<span class="badge {status}">{_esc(name)}</span>'

    def _render_toc(self, reports):
        items = []
        for i, r in enumerate(reports, 1):
            name = Path(r.get("target", "")).name
            badges = "".join(
                self._badge(mn, md.get("status", "unknown"))
                for mn, md in r.get("results", {}).items()
            )
            items.append(
                f'<div class="toc-item"><a href="#img-{i}">{i}. {_esc(name)}</a>'
                f'<div style="display:flex;gap:4px;flex-wrap:wrap;">{badges}</div></div>'
            )
        return '<div class="toc-grid">' + ("".join(items) or "(no images)") + "</div>"

    def _render_stats(self, reports):
        total = len(reports)
        per_module = {}
        for r in reports:
            for name, data in r.get("results", {}).items():
                s = data.get("status", "unknown")
                per_module.setdefault(name, {})
                per_module[name][s] = per_module[name].get(s, 0) + 1
        blocks = [f'<div class="stat"><div class="stat-value">{total}</div>'
                  f'<div class="stat-label">Images</div></div>']
        for mod_name, statuses in per_module.items():
            ok = statuses.get("success", 0)
            blocks.append(
                f'<div class="stat"><div class="stat-value">{ok}/{total}</div>'
                f'<div class="stat-label">{_esc(mod_name)}</div></div>'
            )
        return '<div class="stats">' + "".join(blocks) + "</div>"

    def render(self):
        reports = self.report.get("reports", [])
        batch_errors = self.report.get("batch_errors", [])
        directory = self.report.get("directory", "")
        total = self.report.get("images_found", 0)
        analyzed = self.report.get("images_analyzed", 0)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        stats_html = self._render_stats(reports)
        toc_html = self._render_toc(reports)

        sections = []
        for i, r in enumerate(reports, 1):
            target = r.get("target", "")
            name = Path(target).name
            results = r.get("results", {})
            badges = "".join(
                self._badge(mn, md.get("status", "unknown"))
                for mn, md in results.items()
            )
            sections.append(
                f'<div class="image-section" id="img-{i}">'
                f'<div class="image-header">'
                f'<h2>Image {i}: {_esc(name)}</h2>'
                f'<p style="color:#94a3b8;margin:0;">Path: <code>{_esc(target)}</code></p>'
                f'<div class="badge-row">{badges}</div>'
                f'</div>'
            )
            for mod_name, mod_data in results.items():
                sections.append(
                    self._render_module(mod_name, mod_data, target=target, header="h3")
                )
            sections.append('<a href="#top" class="to-top">Back to top</a></div>')

        errors_html = ""
        if batch_errors:
            errors_html = "<h2>Batch Errors</h2>"
            for err in batch_errors:
                errors_html += (
                    f'<div class="batch-err"><code>{_esc(err.get("image", ""))}</code><br>'
                    f'{_esc(err.get("error", ""))}</div>'
                )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sent Eye Batch Report - {_esc(Path(directory).name)}</title>
<style>{_CSS}{_BATCH_EXTRA_CSS}</style>
</head>
<body>
<div class="container" id="top">
<h1>Sent Eye Batch Report</h1>
<div class="summary-bar">
  <p style="margin:0 0 6px 0;">Directory: <code>{_esc(directory)}</code></p>
  <p style="margin:0 0 6px 0;">Generated: {_esc(timestamp)}</p>
  <p style="margin:0;">Images found: {total} | Analyzed: {analyzed} | Errors: {len(batch_errors)}</p>
</div>
{stats_html}
<h2>Contents</h2>
{toc_html}
{errors_html}
{"".join(sections)}
</div>
</body>
</html>"""
