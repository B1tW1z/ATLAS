"""
ATLAS Dashboard API Routes

Aggregated statistics and trend analytics for the dashboard.
"""

from fastapi import APIRouter
from typing import Optional

from atlas.persistence.database import Database

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

_db = None


def get_db():
    global _db
    if _db is None:
        _db = Database()
    return _db


@router.get("/stats")
async def get_dashboard_stats():
    """
    Get aggregated dashboard statistics.
    
    Returns total scans, findings breakdown by severity,
    scans by status, top targets, and recent activity.
    """
    db = get_db()
    return db.get_dashboard_stats()


@router.get("/trends")
async def get_scan_trends(days: int = 30):
    """
    Get scan and finding trends over time.
    
    Returns scans per day, findings per day, and severity
    distribution for the specified number of days.
    """
    db = get_db()
    return db.get_scan_trends(days=days)
