"""
ATLAS FastAPI Application

Main entry point for the ATLAS Web API.
"""

import sys
from pathlib import Path
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from api.routes import scans, checks, reports, presets, auth, dashboard, activity, scheduler, terminal


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

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Configure appropriately for production
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

@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Log all API requests with timing"""
    start = time.time()
    response = await call_next(request)
    duration_ms = (time.time() - start) * 1000
    
    if request.url.path.startswith("/api"):
        req_logger.info(
            f"{request.method} {request.url.path} → {response.status_code} "
            f"({duration_ms:.0f}ms)"
        )
    
    return response


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
    if request.url.path.startswith("/api"):
        return JSONResponse(status_code=500, content={"error": "Internal Server Error", "detail": str(exc)})
        
    error_path = web_dir / "error" / "500.html"
    if error_path.exists():
        return HTMLResponse(content=error_path.read_text(encoding='utf-8'), status_code=500)
    return HTMLResponse(content=f"<h1>500 Internal Server Error</h1><p>{str(exc)}</p>", status_code=500)


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    if request.url.path.startswith("/api"):
        return JSONResponse(status_code=500, content={"error": "Internal Server Error", "detail": str(exc)})
        
    error_path = web_dir / "error" / "500.html"
    if error_path.exists():
        return HTMLResponse(content=error_path.read_text(encoding='utf-8'), status_code=500)
    return HTMLResponse(content=f"<h1>500 Internal Server Error</h1><p>{str(exc)}</p>", status_code=500)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )

