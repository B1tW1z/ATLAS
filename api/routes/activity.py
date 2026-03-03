"""
ATLAS Activity Log API Routes

Endpoints for scan event tracking and activity feed.
"""

from fastapi import APIRouter, HTTPException
from typing import Optional

from atlas.persistence.database import Database

router = APIRouter(prefix="/activity", tags=["Activity"])

_db = None


def get_db():
    global _db
    if _db is None:
        _db = Database()
    return _db


@router.get("")
async def get_activity_feed(limit: int = 50):
    """
    Get recent activity feed across all scans.
    
    Returns a chronological list of scan events including
    scan starts, recon completions, findings, etc.
    """
    db = get_db()
    events = db.get_recent_events(limit=limit)
    return {"events": events, "total": len(events)}


@router.get("/{scan_id}")
async def get_scan_activity(scan_id: str):
    """
    Get activity events for a specific scan.
    """
    db = get_db()
    
    # Verify scan exists
    session = db.get_scan_session(scan_id)
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    events = db.get_scan_events(scan_id)
    return {
        "scan_id": scan_id,
        "target": session.target,
        "events": events,
        "total": len(events)
    }
