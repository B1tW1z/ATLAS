"""
ATLAS FastAPI Application

Main entry point for the ATLAS Web API.
"""

import logging
import secrets
import sys
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi import _rate_limit_exceeded_handler

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from api.routes import scans, checks, reports, presets, auth, dashboard, activity, scheduler, terminal
from atlas.utils.config import get_config


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan handler"""
    # Startup
    print("ATLAS API Starting...")
    
    # Initialize database
    from atlas.persistence.database import Database
    db = Database()
    print("Database initialized")
    
    # Initialize check registry
    from atlas.checks.registry import CheckRegistry
    registry = CheckRegistry()
    print(f"Loaded {len(registry.get_all_checks())} vulnerability checks")
    
    # Start scheduler worker
    from atlas.core.scheduler_worker import get_scheduler_worker
    worker = get_scheduler_worker()
    await worker.start()
    print("Scheduler worker started")
    
    yield
    
    # Shutdown
    await worker.stop()
    print("ATLAS API Shutting down...")


# Create FastAPI app
app = FastAPI(
    title="ATLAS API",
    description="Advanced Testing Lab for Application Security - REST API",
    version="1.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
    lifespan=lifespan
)
config = get_config()
app.state.limiter = auth.limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include API routers
app.include_router(scans.router, prefix="/api")
app.include_router(checks.router, prefix="/api")
app.include_router(reports.router, prefix="/api")
app.include_router(presets.router, prefix="/api")
app.include_router(auth.router, prefix="/api")
app.include_router(dashboard.router, prefix="/api")
app.include_router(activity.router, prefix="/api")
app.include_router(scheduler.router, prefix="/api")
app.include_router(terminal.router, prefix="/api")

# Mount static files for Web UI
web_dir = Path(__file__).parent.parent / "web"
if web_dir.exists():
    app.mount("/static", StaticFiles(directory=str(web_dir)), name="static")


# Request logging middleware
import time
import logging

req_logger = logging.getLogger("atlas.requests")
error_logger = logging.getLogger("atlas.errors")

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all API requests with timing"""
    start = time.time()
    response = await call_next(request)
    duration_ms = (time.time() - start) * 1000
    
    if request.url.path.startswith("/api"):
        req_logger.info(
            f"{request.method} {request.url.path} → {response.status_code} "
            f"({duration_ms:.0f}ms) ip={request.client.host if request.client else 'unknown'} "
            f'ua="{request.headers.get("user-agent", "-")[:120]}"'
        )
    
    return response


@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com; "
        "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://cdnjs.cloudflare.com https://cdn.jsdelivr.net; "
        "font-src 'self' https://fonts.gstatic.com https://cdnjs.cloudflare.com; "
        "img-src 'self' data: https:; "
        "connect-src 'self' ws: wss: https:; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'"
    )
    if request.url.scheme == "https":
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    return response


@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    unsafe_methods = {"POST", "PUT", "PATCH", "DELETE"}
    exempt_paths = {
        "/api/auth/login",
        "/api/auth/signup",
        "/api/auth/oauth/google/start",
        "/api/auth/oauth/microsoft/start",
        "/api/auth/oauth/github/start",
        "/api/auth/oauth/google/callback",
        "/api/auth/oauth/microsoft/callback",
        "/api/auth/oauth/github/callback",
        "/api/auth/csrf",
        "/api/health",
    }
    if request.method in unsafe_methods and request.url.path.startswith("/api"):
        if request.url.path not in exempt_paths:
            csrf_cookie = request.cookies.get(config.csrf_cookie_name)
            csrf_header = request.headers.get("x-csrf-token")
            if not csrf_cookie or not csrf_header or not secrets.compare_digest(csrf_cookie, csrf_header):
                return JSONResponse(status_code=403, content={"error": "Forbidden", "detail": "Invalid CSRF token"})
    return await call_next(request)


@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=429,
        content={
            "error": "Too Many Requests",
            "detail": "Rate limit exceeded. Try again in a few minutes."
        }
    )


@app.get("/login", response_class=HTMLResponse)
async def login_page():
    """Serve login page"""
    login_path = web_dir / "login.html"
    if login_path.exists():
        return HTMLResponse(content=login_path.read_text(encoding='utf-8'))
    return HTMLResponse(content="<h1>Login page not found</h1>", status_code=404)


@app.get("/signup", response_class=HTMLResponse)
async def signup_page():
    """Serve signup page"""
    signup_path = web_dir / "signup.html"
    if signup_path.exists():
        return HTMLResponse(content=signup_path.read_text(encoding='utf-8'))
    return HTMLResponse(content="<h1>Signup page not found</h1>", status_code=404)


@app.get("/about", response_class=HTMLResponse)
async def about_page():
    """Serve About Team page"""
    about_path = web_dir / "about_team.html"
    if about_path.exists():
        return HTMLResponse(content=about_path.read_text(encoding='utf-8'))
    return HTMLResponse(content="<h1>About page not found</h1>", status_code=404)


@app.get("/loading", response_class=HTMLResponse)
async def loading_page():
    """Serve loading screen"""
    loading_path = web_dir / "loading.html"
    if loading_path.exists():
        return HTMLResponse(content=loading_path.read_text(encoding='utf-8'))
    return HTMLResponse(content="<h1>Loading...</h1>")


# Test routes to preview error pages
@app.get("/test/404", response_class=HTMLResponse)
async def test_404_page():
    """Preview 404 error page"""
    error_path = web_dir / "error" / "404.html"
    if error_path.exists():
        return HTMLResponse(content=error_path.read_text(encoding='utf-8'))
    return HTMLResponse(content="<h1>404 page not found</h1>")


@app.get("/test/500", response_class=HTMLResponse)
async def test_500_page():
    """Preview 500 error page"""
    error_path = web_dir / "error" / "500.html"
    if error_path.exists():
        return HTMLResponse(content=error_path.read_text(encoding='utf-8'))
    return HTMLResponse(content="<h1>500 page not found</h1>")


@app.get("/test/403", response_class=HTMLResponse)
async def test_403_page():
    """Preview 403 error page"""
    error_path = web_dir / "error" / "403.html"
    if error_path.exists():
        return HTMLResponse(content=error_path.read_text(encoding='utf-8'))
    return HTMLResponse(content="<h1>403 page not found</h1>")


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve landing page"""
    landing_path = web_dir / "landing.html"
    if landing_path.exists():
        return HTMLResponse(content=landing_path.read_text(encoding='utf-8'))
    return HTMLResponse(content="<h1>Landing page not found</h1>", status_code=404)


@app.get("/landing", response_class=HTMLResponse)
async def landing_alias():
    """Alias for landing page"""
    landing_path = web_dir / "landing.html"
    if landing_path.exists():
        return HTMLResponse(content=landing_path.read_text(encoding='utf-8'))
    return HTMLResponse(content="<h1>Landing page not found</h1>", status_code=404)


@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard_page():
    """Serve main dashboard Web UI"""
    index_path = web_dir / "index.html"
    if index_path.exists():
        return HTMLResponse(content=index_path.read_text(encoding='utf-8'))
    return HTMLResponse(content="<h1>Dashboard not found</h1>", status_code=404)


@app.get("/api/health")
async def health_check():
    """API health check endpoint"""
    return {
        "status": "healthy",
        "service": "atlas-api",
        "version": "1.0.0"
    }


# Custom error handlers
from starlette.exceptions import HTTPException as StarletteHTTPException

@app.exception_handler(404)
async def not_found_handler(request: Request, exc: StarletteHTTPException):
    """Custom 404 error handler"""
    if request.url.path.startswith("/api"):
        return JSONResponse(status_code=404, content={"error": "Not Found", "detail": str(exc.detail)})
        
    error_path = web_dir / "error" / "404.html"
    if error_path.exists():
        return HTMLResponse(content=error_path.read_text(encoding='utf-8'), status_code=404)
    return HTMLResponse(content="<h1>404 Not Found</h1>", status_code=404)


@app.exception_handler(403)
async def forbidden_handler(request: Request, exc: StarletteHTTPException):
    """Custom 403 error handler"""
    if request.url.path.startswith("/api"):
        return JSONResponse(status_code=403, content={"error": "Forbidden", "detail": str(exc.detail)})
        
    error_path = web_dir / "error" / "403.html"
    if error_path.exists():
        return HTMLResponse(content=error_path.read_text(encoding='utf-8'), status_code=403)
    return HTMLResponse(content="<h1>403 Forbidden</h1>", status_code=403)


@app.exception_handler(500)
async def server_error_handler(request: Request, exc: Exception):
    """Custom 500 error handler"""
    error_logger.exception("Unhandled server error at path=%s", request.url.path)
    if request.url.path.startswith("/api"):
        return JSONResponse(
            status_code=500,
            content={"error": "Internal Server Error", "detail": "An unexpected error occurred"}
        )
        
    error_path = web_dir / "error" / "500.html"
    if error_path.exists():
        return HTMLResponse(content=error_path.read_text(encoding='utf-8'), status_code=500)
    return HTMLResponse(content="<h1>500 Internal Server Error</h1>", status_code=500)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    error_logger.exception("Unhandled exception at path=%s", request.url.path)
    if request.url.path.startswith("/api"):
        return JSONResponse(
            status_code=500,
            content={"error": "Internal Server Error", "detail": "An unexpected error occurred"}
        )
        
    error_path = web_dir / "error" / "500.html"
    if error_path.exists():
        return HTMLResponse(content=error_path.read_text(encoding='utf-8'), status_code=500)
    return HTMLResponse(content="<h1>500 Internal Server Error</h1>", status_code=500)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )

