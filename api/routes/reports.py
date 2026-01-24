"""
ATLAS Reports API Routes

Endpoints for findings and report generation.
"""

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse

from api.schemas import FindingListResponse, FindingResponse, ReportRequest, ReportResponse, SeverityLevel

router = APIRouter(prefix="/reports", tags=["Reports"])


@router.get("/{scan_id}/findings", response_model=FindingListResponse)
async def get_findings(scan_id: str):
    """
    Get vulnerability findings for a scan.
    """
    from atlas.persistence.database import Database
    
    db = Database()
    findings = db.get_findings(scan_id)
    
    if not findings:
        # Check if scan exists
        session = db.get_scan_session(scan_id)
        if not session:
            raise HTTPException(status_code=404, detail="Scan not found")
    
    finding_responses = [
        FindingResponse(
            id=f.id,
            check_id=f.check_id,
            title=f.title,
            severity=SeverityLevel(f.severity.value),
            description=f.description,
            evidence=f.evidence,
            remediation=f.remediation,
            url=f.url,
            parameter=f.parameter,
            payload=f.payload,
            owasp_category=f.owasp_category,
            cwe_id=f.cwe_id,
            cvss_score=f.cvss_score
        )
        for f in findings
    ]
    
    # Group by severity
    by_severity = db.get_findings_summary(scan_id)
    
    return FindingListResponse(
        findings=finding_responses,
        total=len(finding_responses),
        by_severity=by_severity
    )


@router.post("/{scan_id}/generate", response_model=ReportResponse)
async def generate_report(scan_id: str, request: ReportRequest):
    """
    Generate a vulnerability report.
    """
    from atlas.persistence.database import Database
    from atlas.reporting.generator import ReportGenerator
    
    db = Database()
    session = db.get_scan_session(scan_id)
    
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    findings = db.get_findings(scan_id)
    recon_results = db.get_recon_results(scan_id)
    
    generator = ReportGenerator()
    
    try:
        report_path = await generator.generate_from_data(
            scan_id=scan_id,
            target=session.target,
            findings=findings,
            recon_results=recon_results,
            format=request.format
        )
        
        return ReportResponse(
            report_path=str(report_path),
            format=request.format,
            findings_count=len(findings)
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/{scan_id}/download")
async def download_report(scan_id: str, format: str = "html"):
    """
    Download generated report file.
    """
    from pathlib import Path
    from atlas.utils.config import get_config
    
    config = get_config()
    report_path = config.data_dir / "reports" / f"{scan_id}.{format}"
    
    if not report_path.exists():
        raise HTTPException(status_code=404, detail="Report not found. Generate first.")
    
    media_type = "text/html" if format == "html" else "application/json"
    
    return FileResponse(
        path=str(report_path),
        media_type=media_type,
        filename=f"atlas_report_{scan_id}.{format}"
    )


@router.get("/{scan_id}/summary")
async def get_scan_summary(scan_id: str):
    """
    Get a summary of scan results.
    """
    from atlas.persistence.database import Database
    
    db = Database()
    session = db.get_scan_session(scan_id)
    
    if not session:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    findings = db.get_findings(scan_id)
    recon_results = db.get_recon_results(scan_id)
    executed_checks = db.get_executed_checks(scan_id)
    
    severity_counts = db.get_findings_summary(scan_id)
    
    return {
        "scan_id": scan_id,
        "target": session.target,
        "status": session.status,
        "phase": session.phase,
        "created_at": session.created_at.isoformat(),
        "summary": {
            "total_findings": len(findings),
            "by_severity": severity_counts,
            "ports_discovered": len(recon_results),
            "checks_executed": len(executed_checks)
        }
    }
