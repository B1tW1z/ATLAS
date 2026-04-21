"""
ATLAS Configuration Module

Centralized configuration management for the ATLAS framework.
"""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List


@dataclass
class Config:
    """ATLAS Configuration"""
    
    # Paths
    base_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent)
    data_dir: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent / "data")
    db_path: Path = field(default_factory=lambda: Path(__file__).parent.parent.parent / "data" / "atlas.db")
    
    # Scan Settings
    default_timeout: int = 30  # seconds
    max_concurrent_checks: int = 5
    
    # Nmap Settings
    nmap_path: Optional[str] = None  # Auto-detect if None
    nmap_default_args: str = "-sV -T4 --top-ports 100"
    nmap_timeout: int = 300  # 5 minutes
    
    # Web UI Settings
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    
    # Logging
    log_level: str = "INFO"
    log_file: Optional[Path] = None

    # Security
    app_base_url: str = "http://127.0.0.1:8000"
    cors_origins: List[str] = field(default_factory=lambda: ["http://127.0.0.1:8000", "http://localhost:8000"])
    csrf_cookie_name: str = "atlas_csrf"

    # OAuth
    google_client_id: Optional[str] = None
    google_client_secret: Optional[str] = None
    google_redirect_uri: Optional[str] = None

    microsoft_client_id: Optional[str] = None
    microsoft_client_secret: Optional[str] = None
    microsoft_redirect_uri: Optional[str] = None
    microsoft_tenant: str = "common"

    github_client_id: Optional[str] = None
    github_client_secret: Optional[str] = None
    github_redirect_uri: Optional[str] = None
    
    def __post_init__(self):
        """Ensure data directory exists"""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        # Override from environment variables
        if env_db := os.getenv("ATLAS_DB_PATH"):
            self.db_path = Path(env_db)
        if env_nmap := os.getenv("ATLAS_NMAP_PATH"):
            self.nmap_path = env_nmap
        if env_log := os.getenv("ATLAS_LOG_LEVEL"):
            self.log_level = env_log
        if env_base_url := os.getenv("ATLAS_APP_BASE_URL"):
            self.app_base_url = env_base_url
        if env_origins := os.getenv("ATLAS_CORS_ORIGINS"):
            self.cors_origins = [origin.strip() for origin in env_origins.split(",") if origin.strip()]

        self.google_client_id = os.getenv("ATLAS_GOOGLE_CLIENT_ID")
        self.google_client_secret = os.getenv("ATLAS_GOOGLE_CLIENT_SECRET")
        self.google_redirect_uri = os.getenv("ATLAS_GOOGLE_REDIRECT_URI")

        self.microsoft_client_id = os.getenv("ATLAS_MICROSOFT_CLIENT_ID")
        self.microsoft_client_secret = os.getenv("ATLAS_MICROSOFT_CLIENT_SECRET")
        self.microsoft_redirect_uri = os.getenv("ATLAS_MICROSOFT_REDIRECT_URI")
        self.microsoft_tenant = os.getenv("ATLAS_MICROSOFT_TENANT", self.microsoft_tenant)

        self.github_client_id = os.getenv("ATLAS_GITHUB_CLIENT_ID")
        self.github_client_secret = os.getenv("ATLAS_GITHUB_CLIENT_SECRET")
        self.github_redirect_uri = os.getenv("ATLAS_GITHUB_REDIRECT_URI")


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get or create global config instance"""
    global _config
    if _config is None:
        _config = Config()
    return _config
