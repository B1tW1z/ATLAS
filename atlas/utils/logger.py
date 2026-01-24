"""
ATLAS Logging Module

Provides consistent logging across the framework with rich formatting.
"""

import logging
import sys
from typing import Optional
from pathlib import Path

from rich.logging import RichHandler
from rich.console import Console

# Console for rich output
console = Console()

# Cache for loggers
_loggers: dict[str, logging.Logger] = {}


def get_logger(name: str, level: Optional[str] = None) -> logging.Logger:
    """
    Get or create a logger with consistent formatting.
    
    Args:
        name: Logger name (usually __name__)
        level: Optional log level override
        
    Returns:
        Configured logger instance
    """
    if name in _loggers:
        return _loggers[name]
    
    logger = logging.getLogger(f"atlas.{name}")
    
    # Set level
    log_level = level or "INFO"
    logger.setLevel(getattr(logging, log_level.upper()))
    
    # Avoid duplicate handlers
    if not logger.handlers:
        # Rich console handler
        rich_handler = RichHandler(
            console=console,
            show_time=True,
            show_path=False,
            rich_tracebacks=True
        )
        rich_handler.setFormatter(logging.Formatter("%(message)s"))
        logger.addHandler(rich_handler)
    
    _loggers[name] = logger
    return logger


def setup_file_logging(log_path: Path, level: str = "DEBUG"):
    """
    Add file logging to all ATLAS loggers.
    
    Args:
        log_path: Path to log file
        level: Log level for file handler
    """
    log_path.parent.mkdir(parents=True, exist_ok=True)
    
    file_handler = logging.FileHandler(log_path)
    file_handler.setLevel(getattr(logging, level.upper()))
    file_handler.setFormatter(
        logging.Formatter("%(asctime)s | %(name)s | %(levelname)s | %(message)s")
    )
    
    # Add to root ATLAS logger
    root_logger = logging.getLogger("atlas")
    root_logger.addHandler(file_handler)
