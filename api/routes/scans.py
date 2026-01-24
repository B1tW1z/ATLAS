"""
ATLAS Scans API Routes

Endpoints for scan management.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import List

from api.schemas import (
    ScanCreate, ScanResponse, ScanListResponse, ScanProgress,
    CheckSelection, SuccessResponse, ErrorResponse, ScanStatus, ScanPhase
)
from atlas.core.engine import ATLASEngine
from atlas.persistence.database import Database

router = APIRouter(prefix="/scans", tags=["Scans"])

# Global engine instance (would use dependency injection in production)
_db = None
_engine = None
_active_scans = {}


def get_db():
    global _db
    if _db is None:
        _db = Database()
    return _db


def get_engine(scan_id: str = None):
    global _engine, _active_scans
    
    if scan_id and scan_id in _active_scans:
        return _active_scans[scan_id]
    
    db = get_db()
    engine = ATLASEngine(database=db)
    
    if scan_id:
        _active_scans[scan_id] = engine
    
    return engine


@router.post("", response_model=ScanResponse)
async def create_scan(scan: ScanCreate):
    """
    Create a new vulnerability assessment scan.
    
    This initializes a scan session and prepares for reconnaissance.
    """
    try:
        engine = get_engine()
        state = await engine.start_scan(scan.target, scan.options)
        
        # Store engine reference
        _active_scans[state.scan_id] = engine
        
        return ScanResponse(
            id=state.scan_id,
            target=state.target,
            status=ScanStatus.ACTIVE,
            phase=ScanPhase(state.phase.name),
            created_at=state.created_at,
            updated_at=state.updated_at
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("", response_model=ScanListResponse)
async def list_scans(limit: int = 20):
    """
    List recent scan sessions.
    """
    db = get_db()
    sessions = db.list_scan_sessions(limit=limit)
    
    scans = [
        ScanResponse(
            id=s.id,
            target=s.target,
            status=ScanStatus(s.status),
            phase=ScanPhase(s.phase),
            created_at=s.created_at,
            updated_at=s.updated_at
        )
        for s in sessions
    ]
    
    return ScanListResponse(scans=scans, total=len(scans))


@router.get("/{scan_id}", response_model=ScanProgress)
async def get_scan(scan_id: str):
    """
    Get scan status and progress.
    """
    engine = get_engine(scan_id)
    
    # Try to load if not active
    if engine.state is None or engine.state.scan_id != scan_id:
        state = await engine.resume_scan(scan_id)
        if not state:
            raise HTTPException(status_code=404, detail="Scan not found")
    
    progress = engine.get_progress()
    
    return ScanProgress(
        scan_id=progress["scan_id"],
        phase=ScanPhase(progress["phase"]),
        target=progress["target"],
        recon_completed=progress["recon_completed"],
        total_checks=progress["total_checks"],
        completed_checks=progress["completed_checks"],
        current_check=progress.get("current_check"),
        findings_count=progress["findings_count"],
        progress_percent=progress["progress_percent"]
    )


@router.post("/{scan_id}/recon")
async def run_reconnaissance(scan_id: str):
    """
    Run reconnaissance on the scan target.
    
    Returns discovered ports, services, and any fingerprint information.
    """
    engine = get_engine(scan_id)
    
    if engine.state is None:
        await engine.resume_scan(scan_id)
        if engine.state is None:
            raise HTTPException(status_code=404, detail="Scan not found")
    
    try:
        results = await engine.run_reconnaissance()
        return {
            "host": results.get("host"),
            "ports": results.get("ports", []),
            "services": results.get("services", {}),
            "fingerprint": results.get("fingerprint")
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{scan_id}/select", response_model=SuccessResponse)
async def select_checks(scan_id: str, selection: CheckSelection):
    """
    Select vulnerability checks to execute.
    """
    engine = get_engine(scan_id)
    
    if engine.state is None:
        await engine.resume_scan(scan_id)
        if engine.state is None:
            raise HTTPException(status_code=404, detail="Scan not found")
    
    engine.select_checks(selection.check_ids)
    
    return SuccessResponse(
        message=f"Selected {len(selection.check_ids)} checks for execution"
    )


@router.post("/{scan_id}/execute")
async def execute_checks(scan_id: str, background_tasks: BackgroundTasks):
    """
    Execute selected vulnerability checks.
    
    Returns list of findings.
    """
    engine = get_engine(scan_id)
    
    if engine.state is None:
        await engine.resume_scan(scan_id)
        if engine.state is None:
            raise HTTPException(status_code=404, detail="Scan not found")
    
    try:
        findings = await engine.execute_checks()
        return {
            "findings": findings,
            "total": len(findings)
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.post("/{scan_id}/pause", response_model=SuccessResponse)
async def pause_scan(scan_id: str):
    """
    Pause an active scan.
    """
    engine = get_engine(scan_id)
    
    if engine.state is None:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    engine.pause_scan()
    
    return SuccessResponse(message="Scan paused")


@router.post("/{scan_id}/resume", response_model=ScanProgress)
async def resume_scan(scan_id: str):
    """
    Resume a paused scan.
    """
    engine = get_engine(scan_id)
    state = await engine.resume_scan(scan_id)
    
    if not state:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    _active_scans[scan_id] = engine
    
    progress = engine.get_progress()
    return ScanProgress(**progress)
