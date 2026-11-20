"""Batch HTML reporter — reuses single-image renderers from html_report.py."""
from datetime import datetime
from pathlib import Path

from .html_report import HTMLReporter, _CSS, _esc


_BATCH_EXTRA_CSS = """
.toc{background:#1e293b;padding:12px 20px;border-radius:8px;margin:12px 0;}
.toc a{margin-right:16px;display:inline-block;}
.image-section{border-top:2px solid #38bdf8;margin-top:48px;padding-top:24px;}
.batch-error{background:#7f1d1d;padding:12px;border-radius:8px;margin:8px 0;}
"""


class BatchHTMLReporter(HTMLReporter):
    """Renders the JSON output of SentEyeBatchRunner as one combined HTML dossier."""

    def render(self) -> str:
        reports = self.report.get("reports", [])
        batch_errors = self.report.get("batch_errors", [])
        directory = self.report.get("directory", "")
        total = self.report.get("images_found", 0)
        analyzed = self.report.get("images_analyzed", 0)
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        toc_links = "".join(
            f'<a href="#img-{i}">{i}. {_esc(Path(r.get("target", "")).name)}</a>'
            for i, r in enumerate(reports, 1)
        ) or "(no images)"

        summary_rows = []
        for i, r in enumerate(reports, 1):
            statuses = [
                f"{name}={data.get('status', '?')}"
                for name, data in r.get("results", {}).items()
            ]
            summary_rows.append(
                f'<tr><td>{i}</td>'
                f'<td><a href="#img-{i}">{_esc(Path(r.get("target", "")).name)}</a></td>'
                f'<td><code>{_esc(", ".join(statuses))}</code></td></tr>'
            )

        sections = []
        for i, r in enumerate(reports, 1):
            target = r.get("target", "")
            sections.append(
                f'<div class="image-section">'
                f'<h2 id="img-{i}">Image {i}: {_esc(Path(target).name)}</h2>'
                f'<p style="color:#94a3b8;">Path: <code>{_esc(target)}</code></p>'
            )
            for name, data in r.get("results", {}).items():
                sections.append(self._render_module(name, data, target=target))
            sections.append("</div>")

        errors_html = ""
        if batch_errors:
            errors_html = "<h2>Batch Errors</h2>"
            for err in batch_errors:
                errors_html += (
                    f'<div class="batch-error">'
                    f'<code>{_esc(err.get("image", ""))}</code>: '
                    f'{_esc(err.get("error", ""))}'
                    f'</div>'
                )

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Sent-Eye Batch Report - {_esc(Path(directory).name)}</title>
<style>{_CSS}{_BATCH_EXTRA_CSS}</style>
</head>
<body>
<div class="container">
<h1>Sent-Eye Batch Report</h1>
<div class="summary-bar">
  <p style="margin:0 0 6px 0;">Directory: <code>{_esc(directory)}</code></p>
  <p style="margin:0 0 6px 0;">Generated: {_esc(timestamp)}</p>
  <p style="margin:0;">Images found: {total} | Analyzed: {analyzed} | Errors: {len(batch_errors)}</p>
</div>
<h2>Contents</h2>
<div class="toc">{toc_links}</div>
<h2>Summary</h2>
<table>
<tr><th>#</th><th>Image</th><th>Module statuses</th></tr>
{"".join(summary_rows) or "<tr><td colspan='3'>(no images)</td></tr>"}
</table>
{errors_html}
{"".join(sections)}
</div>
</body>
</html>"""
