from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from backend.api.routes import router
from backend.api.auth_routes import router as auth_router
from backend.services.job_manager import job_manager
from backend.services.auth_store import auth_store

BASE_DIR = Path(__file__).parent
TEMPLATES_DIR = BASE_DIR / "templates"
STATIC_DIR = BASE_DIR / "static"

MAX_REQUEST_BYTES = 20 * 1024 * 1024


@asynccontextmanager
async def lifespan(app: FastAPI):
    auth_store.init_db()
    job_manager.start_cleanup()
    yield


app = FastAPI(
    title="Sent Eye",
    version="0.2.0",
    lifespan=lifespan,
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)

app.include_router(router)
app.include_router(auth_router)

if STATIC_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(STATIC_DIR)), name="static")

templates = Jinja2Templates(directory=str(TEMPLATES_DIR)) if TEMPLATES_DIR.exists() else None


@app.middleware("http")
async def _middleware(request: Request, call_next):
    # Request size cap (defence-in-depth; actual byte check in save_upload)
    if request.method == "POST":
        cl = request.headers.get("content-length")
        if cl:
            try:
                if int(cl) > MAX_REQUEST_BYTES:
                    return JSONResponse(
                        {"detail": "Request body too large."},
                        status_code=413,
                    )
            except ValueError:
                pass

    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data: https:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self'; "
        "frame-src https://www.openstreetmap.org; "
        "connect-src 'self'"
    )
    return response


@app.get("/", response_class=HTMLResponse)
async def root(request: Request) -> HTMLResponse:
    if templates is None:
        return HTMLResponse(
            "<h1>Sent Eye API</h1>"
            "<p>Templates not installed yet. API is running:</p>"
            "<ul>"
            "<li><a href='/health'>/health</a></li>"
            "<li><a href='/api/modules'>/api/modules</a></li>"
            "</ul>"
        )
    return templates.TemplateResponse(request, "dashboard.html", {})
