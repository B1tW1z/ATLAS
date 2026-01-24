"""
ATLAS Checks API Routes

Endpoints for vulnerability check management.
"""

from fastapi import APIRouter, HTTPException
from typing import Optional

from api.schemas import CheckListResponse, CheckInfo, SeverityLevel

router = APIRouter(prefix="/checks", tags=["Checks"])


@router.get("", response_model=CheckListResponse)
async def list_checks(category: Optional[str] = None):
    """
    List all available vulnerability checks.
    
    Optionally filter by category.
    """
    from atlas.checks.registry import CheckRegistry
    
    registry = CheckRegistry()
    
    if category:
        checks = registry.get_checks_by_category(category)
        metadata = [c.metadata.to_dict() for c in checks]
    else:
        metadata = registry.get_all_metadata()
    
    check_infos = [
        CheckInfo(
            id=m["id"],
            name=m["name"],
            category=m["category"],
            severity=SeverityLevel(m["severity"]),
            description=m["description"],
            owasp_category=m.get("owasp_category"),
            cwe_id=m.get("cwe_id"),
            tags=m.get("tags", [])
        )
        for m in metadata
    ]
    
    categories = registry.get_categories()
    
    return CheckListResponse(
        checks=check_infos,
        total=len(check_infos),
        categories=categories
    )


@router.get("/categories")
async def list_categories():
    """
    List all check categories.
    """
    from atlas.checks.registry import CheckRegistry
    
    registry = CheckRegistry()
    summary = registry.get_checks_summary()
    
    return {
        "categories": summary["categories"],
        "by_category": summary["by_category"],
        "by_severity": summary["by_severity"],
        "total": summary["total"]
    }


@router.get("/{check_id}")
async def get_check(check_id: str):
    """
    Get details for a specific check.
    """
    from atlas.checks.registry import CheckRegistry
    
    registry = CheckRegistry()
    metadata = registry.get_check_metadata(check_id)
    
    if not metadata:
        raise HTTPException(status_code=404, detail="Check not found")
    
    return metadata.to_dict()


@router.get("/{scan_id}/applicable")
async def get_applicable_checks(scan_id: str):
    """
    Get checks applicable to a specific scan based on recon results.
    """
    from atlas.persistence.database import Database
    from atlas.checks.registry import CheckRegistry
    
    db = Database()
    recon_results = db.get_recon_results(scan_id)
    
    if not recon_results:
        raise HTTPException(status_code=404, detail="No recon results found for scan")
    
    # Build services dict
    services = {
        r.port: {
            "service": r.service,
            "version": r.version,
            "protocol": r.protocol
        }
        for r in recon_results
    }
    
    registry = CheckRegistry()
    applicable = registry.get_applicable_checks(services)
    
    return {
        "checks": applicable,
        "total": len(applicable)
    }
