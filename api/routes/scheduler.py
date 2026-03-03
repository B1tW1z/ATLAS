"""
ATLAS Scan Scheduler API Routes

CRUD endpoints for managing scheduled/recurring scans.
"""

from fastapi import APIRouter, HTTPException
from typing import Optional

from api.schemas import ScheduledScanCreate, ScheduledScanUpdate, SuccessResponse
from atlas.persistence.database import Database

router = APIRouter(prefix="/scheduler", tags=["Scheduler"])

_db = None


def get_db():
    global _db
    if _db is None:
        _db = Database()
    return _db


@router.post("")
async def create_scheduled_scan(data: ScheduledScanCreate):
    """
    Create a new scheduled scan.
    
    Accepts a target URL, cron expression, and optional scan options.
    The scheduler worker will automatically launch scans when due.
    """
    db = get_db()
    result = db.create_scheduled_scan(data.model_dump())
    return {"message": "Scheduled scan created", "schedule": result}


@router.get("")
async def list_scheduled_scans():
    """
    List all scheduled scans.
    """
    db = get_db()
    schedules = db.list_scheduled_scans()
    return {"schedules": schedules, "total": len(schedules)}


@router.put("/{schedule_id}")
async def update_scheduled_scan(schedule_id: str, data: ScheduledScanUpdate):
    """
    Update a scheduled scan configuration.
    """
    db = get_db()
    updates = {k: v for k, v in data.model_dump().items() if v is not None}
    
    if not updates:
        raise HTTPException(status_code=400, detail="No fields to update")
    
    updated = db.update_scheduled_scan(schedule_id, **updates)
    if not updated:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    
    return {"message": "Scheduled scan updated"}


@router.delete("/{schedule_id}")
async def delete_scheduled_scan(schedule_id: str):
    """
    Delete a scheduled scan.
    """
    db = get_db()
    deleted = db.delete_scheduled_scan(schedule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scheduled scan not found")
    
    return {"message": "Scheduled scan deleted"}
