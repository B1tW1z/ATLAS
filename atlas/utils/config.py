"""
ATLAS Configuration Module

Centralized configuration management for the ATLAS framework.
"""

import os
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional


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
    nmap_default_args: str = "-sV -sC"
    nmap_timeout: int = 300  # 5 minutes
    
    # Web UI Settings
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    
    # Logging
    log_level: str = "INFO"
    log_file: Optional[Path] = None
    
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


# Global config instance
_config: Optional[Config] = None


def get_config() -> Config:
    """Get or create global config instance"""
    global _config
    if _config is None:
        _config = Config()
    return _config
