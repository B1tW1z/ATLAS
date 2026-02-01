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

from api.routes import scans, checks, reports, presets, auth


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
    
    yield
    
    # Shutdown
    print("ATLAS API Shutting down...")


# Create FastAPI app
app = FastAPI(
    title="ATLAS API",
    description="Automated Threat and Lifecycle Assessment System - REST API",
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

# Mount static files for Web UI
web_dir = Path(__file__).parent.parent / "web"
if web_dir.exists():
    app.mount("/static", StaticFiles(directory=str(web_dir)), name="static")


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


@app.get("/", response_class=HTMLResponse)
async def root():
    """Serve main Web UI"""
    index_path = web_dir / "index.html"
    if index_path.exists():
        return HTMLResponse(content=index_path.read_text(encoding='utf-8'))
    
    return HTMLResponse(content="""
    <!DOCTYPE html>
    <html>
    <head>
        <title>ATLAS</title>
        <style>
            body { font-family: system-ui; background: #1a1a2e; color: #eee; 
                   display: flex; justify-content: center; align-items: center; 
                   min-height: 100vh; margin: 0; }
            .container { text-align: center; }
            h1 { color: #4fc3f7; font-size: 3rem; }
            a { color: #4fc3f7; }
        </style>
    </head>
    <body>
        <div class="container">
            <h1> ATLAS</h1>
            <p> Advanced Testing Lab for Application Security </p>
            <p><a href="/api/docs">API Documentation</a></p>
        </div>
    </body>
    </html>
    """)


@app.get("/api/health")
async def health_check():
    """API health check endpoint"""
    return {
        "status": "healthy",
        "service": "atlas-api",
        "version": "1.0.0"
    }


@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    """Global exception handler"""
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal Server Error",
            "detail": str(exc)
        }
    )


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "api.main:app",
        host="127.0.0.1",
        port=8000,
        reload=True
    )
