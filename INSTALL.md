# Sent Eye dashboard files

This package adds the missing dashboard template and its local static assets. It uses the existing FastAPI routes only:

- `GET /health`
- `GET /api/modules`
- `POST /api/investigate`
- `GET /api/jobs`
- `GET /api/jobs/{job_id}`
- `GET /api/jobs/{job_id}/report.json`
- `GET /api/jobs/{job_id}/report.html`

## Install in the Codespace

From the repository root (`/workspaces/Sent-Eye`), extract this ZIP while preserving its directory structure. The files should land at:

- `backend/templates/dashboard.html`
- `backend/static/css/dashboard.css`
- `backend/static/js/dashboard.js`

Then restart the FastAPI process:

```bash
# Stop the existing run_web.sh process with Ctrl+C, then:
bash run_web.sh
```

Verify the page and API:

```bash
curl -sS -o /dev/null -w 'Dashboard: HTTP %{http_code}\n' http://127.0.0.1:8000/
curl -sS http://127.0.0.1:8000/health
curl -sS http://127.0.0.1:8000/api/modules
```

Expected dashboard result: `HTTP 200`.

The dashboard does not add authentication. Keep the hostname protected by Cloudflare Access and add application-level authentication before using it as an unrestricted public service.
