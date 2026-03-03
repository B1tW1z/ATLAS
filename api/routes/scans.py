"""
ATLAS Scans API Routes

Endpoints for scan management.
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks
from typing import List

from api.schemas import (
    ScanCreate, ScanResponse, ScanListResponse, ScanProgress,
    CheckSelection, SuccessResponse, ErrorResponse, ScanStatus, ScanPhase,
    ScanNotesUpdate
)
from atlas.core.engine import ATLASEngine
from atlas.persistence.database import Database

router = APIRouter(prefix="/scans", tags=["Scans"])

# Global engine instance (would use dependency injection in production)
_db = None
_engine = None
_active_scans = {}
_running_tasks = {}  # Track running background tasks per scan


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
        
        # Merge wordlist into options
        options = scan.options or {}
        if scan.wordlist:
            options["wordlist"] = scan.wordlist
            
        state = await engine.start_scan(scan.target, options)
        
        # Store engine reference
        _active_scans[state.scan_id] = engine
        
        # Log activity event
        try:
            db = get_db()
            db.add_scan_event(state.scan_id, "scan_created", f"Scan created for target: {scan.target}")
        except Exception:
            pass  # Don't fail scan creation if event logging fails
        
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
    
    Launches recon as a background task and returns immediately.
    Frontend should poll GET /scans/{scan_id} for phase transition.
    """
    import asyncio
    
    engine = get_engine(scan_id)
    
    if engine.state is None:
        await engine.resume_scan(scan_id)
        if engine.state is None:
            raise HTTPException(status_code=404, detail="Scan not found")
    
    # Don't launch if already running
    task_key = f"{scan_id}_recon"
    if task_key in _running_tasks and not _running_tasks[task_key].done():
        return {"status": "running", "message": "Reconnaissance already in progress"}
    
    async def _run_recon():
        try:
            await engine.run_reconnaissance()
            try:
                db = get_db()
                db.add_scan_event(scan_id, "recon_completed", "Reconnaissance completed successfully")
            except Exception:
                pass
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Background recon failed: {e}")
            try:
                db = get_db()
                db.add_scan_event(scan_id, "recon_failed", f"Reconnaissance failed: {e}")
            except Exception:
                pass
        finally:
            _running_tasks.pop(task_key, None)
    
    _running_tasks[task_key] = asyncio.create_task(_run_recon())
    
    return {"status": "running", "message": "Reconnaissance started"}


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
    
    # Log activity event
    try:
        db = get_db()
        db.add_scan_event(scan_id, "checks_selected", f"{len(selection.check_ids)} checks selected for execution")
    except Exception:
        pass
    
    return SuccessResponse(
        message=f"Selected {len(selection.check_ids)} checks for execution"
    )


@router.post("/{scan_id}/execute")
async def execute_checks(scan_id: str, background_tasks: BackgroundTasks):
    """
    Execute selected vulnerability checks.
    
    Launches execution as a background task and returns immediately.
    Frontend should poll GET /scans/{scan_id} for progress and phase transition.
    """
    import asyncio
    
    engine = get_engine(scan_id)
    
    if engine.state is None:
        await engine.resume_scan(scan_id)
        if engine.state is None:
            raise HTTPException(status_code=404, detail="Scan not found")
    
    # Don't launch if already running
    task_key = f"{scan_id}_execute"
    if task_key in _running_tasks and not _running_tasks[task_key].done():
        return {"status": "running", "message": "Execution already in progress"}
    
    async def _run_execute():
        try:
            findings = await engine.execute_checks()
            # Store findings in state for later retrieval
            if hasattr(engine, '_last_findings'):
                engine._last_findings = findings
            try:
                db = get_db()
                count = len(findings) if findings else 0
                db.add_scan_event(scan_id, "execution_completed", f"Execution completed with {count} findings")
            except Exception:
                pass
        except Exception as e:
            import logging
            logging.getLogger(__name__).error(f"Background execution failed: {e}")
            try:
                db = get_db()
                db.add_scan_event(scan_id, "execution_failed", f"Execution failed: {e}")
            except Exception:
                pass
        finally:
            _running_tasks.pop(task_key, None)
    
    _running_tasks[task_key] = asyncio.create_task(_run_execute())
    
    return {"status": "running", "message": "Execution started"}


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


@router.delete("/{scan_id}")
async def delete_scan(scan_id: str):
    """
    Delete a scan and all associated data.
    
    Removes scan session, recon results, findings, executed checks,
    and activity events. Also cleans up any in-memory references.
    """
    db = get_db()
    
    # Cancel any running tasks for this scan
    for key in list(_running_tasks.keys()):
        if key.startswith(scan_id):
            task = _running_tasks.pop(key, None)
            if task and not task.done():
                task.cancel()
    
    # Remove from active scans
    _active_scans.pop(scan_id, None)
    
    # Delete from database
    deleted = db.delete_scan_session(scan_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    # Also remove report files if they exist
    from atlas.utils.config import get_config
    config = get_config()
    for ext in ["html", "json"]:
        f = config.data_dir / "reports" / f"{scan_id}.{ext}"
        if f.exists():
            f.unlink()
    
    return {"message": f"Scan {scan_id} and all associated data deleted"}


@router.put("/{scan_id}/notes", response_model=SuccessResponse)
async def update_scan_notes(scan_id: str, data: ScanNotesUpdate):
    """
    Update notes and/or tags for a scan.
    """
    db = get_db()
    updated = db.update_scan_notes(scan_id, notes=data.notes, tags=data.tags)
    if not updated:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return SuccessResponse(message="Scan notes updated")


@router.get("/{scan_id}/export")
async def export_scan(scan_id: str):
    """
    Export complete scan data as JSON.
    
    Returns session info, findings, recon results, and executed checks.
    """
    db = get_db()
    export_data = db.get_scan_export(scan_id)
    if not export_data:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return export_data


@router.post("/{scan_id}/cancel")
async def cancel_scan(scan_id: str):
    """
    Cancel a running scan.
    
    Aborts any background recon or check execution tasks
    and marks the scan as failed.
    """
    cancelled = False
    
    # Cancel running background tasks
    for key in list(_running_tasks.keys()):
        if key.startswith(scan_id):
            task = _running_tasks.pop(key, None)
            if task and not task.done():
                task.cancel()
                cancelled = True
    
    # Update scan status in database
    db = get_db()
    db.update_scan_session(scan_id, status="failed", phase="ERROR")
    
    # Log the cancellation
    try:
        db.add_scan_event(scan_id, "scan_cancelled", "Scan was cancelled by user")
    except Exception:
        pass
    
    return {
        "message": "Scan cancelled" if cancelled else "Scan marked as failed",
        "scan_id": scan_id
    }


@router.get("/compare/{scan_id_a}/{scan_id_b}")
async def compare_scans(scan_id_a: str, scan_id_b: str):
    """
    Compare findings between two scans.
    
    Returns findings unique to each scan and findings common to both.
    """
    db = get_db()
    
    session_a = db.get_scan_session(scan_id_a)
    session_b = db.get_scan_session(scan_id_b)
    
    if not session_a:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id_a} not found")
    if not session_b:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id_b} not found")
    
    findings_a = db.get_findings(scan_id_a)
    findings_b = db.get_findings(scan_id_b)
    
    # Compare by check_id + title
    set_a = {(f.check_id, f.title) for f in findings_a}
    set_b = {(f.check_id, f.title) for f in findings_b}
    
    common_keys = set_a & set_b
    only_a_keys = set_a - set_b
    only_b_keys = set_b - set_a
    
    def to_dicts(findings, keys):
        return [f.to_dict() for f in findings if (f.check_id, f.title) in keys]
    
    return {
        "scan_a": {"id": scan_id_a, "target": session_a.target},
        "scan_b": {"id": scan_id_b, "target": session_b.target},
        "common_findings": to_dicts(findings_a, common_keys),
        "only_in_a": to_dicts(findings_a, only_a_keys),
        "only_in_b": to_dicts(findings_b, only_b_keys),
        "summary": {
            "total_a": len(findings_a),
            "total_b": len(findings_b),
            "common": len(common_keys),
            "unique_to_a": len(only_a_keys),
            "unique_to_b": len(only_b_keys)
        }
    }
