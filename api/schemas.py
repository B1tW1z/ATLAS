"""
ATLAS API Schemas

Pydantic models for request/response validation.
"""

from pydantic import BaseModel, Field, HttpUrl
from typing import Optional, List, Dict, Any
from datetime import datetime
from enum import Enum


# ========== Enums ==========

class ScanStatus(str, Enum):
    ACTIVE = "active"
    PAUSED = "paused"
    COMPLETED = "completed"
    FAILED = "failed"


class SeverityLevel(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ScanPhase(str, Enum):
    IDLE = "IDLE"
    INITIALIZING = "INITIALIZING"
    RECON = "RECON"
    SELECTION = "SELECTION"
    TESTING = "TESTING"
    REPORTING = "REPORTING"
    COMPLETED = "COMPLETED"
    PAUSED = "PAUSED"
    ERROR = "ERROR"


# ========== Request Models ==========

class ScanCreate(BaseModel):
    """Request to create a new scan"""
    target: str = Field(..., description="Target URL or IP address", examples=["http://localhost:3000"])
    options: Optional[Dict[str, Any]] = Field(default=None, description="Optional scan configuration")


class CheckSelection(BaseModel):
    """Request to select checks for execution"""
    check_ids: List[str] = Field(..., description="List of check IDs to execute")


class ReportRequest(BaseModel):
    """Request to generate a report"""
    format: str = Field(default="html", description="Report format (html/json)")


# ========== Response Models ==========

class ServiceInfo(BaseModel):
    """Information about a discovered service"""
    port: int
    protocol: str
    service: str
    version: Optional[str] = None
    product: Optional[str] = None
    state: str = "open"


class ReconResponse(BaseModel):
    """Reconnaissance results"""
    host: str
    ports: List[int]
    services: Dict[str, ServiceInfo]
    fingerprint: Optional[str] = None


class CheckInfo(BaseModel):
    """Vulnerability check information"""
    id: str
    name: str
    category: str
    severity: SeverityLevel
    description: str
    owasp_category: Optional[str] = None
    cwe_id: Optional[str] = None
    applicable: bool = True
    tags: List[str] = []


class FindingResponse(BaseModel):
    """Vulnerability finding"""
    id: str
    check_id: str
    title: str
    severity: SeverityLevel
    description: str
    evidence: str
    remediation: str
    url: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    owasp_category: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None


class ScanProgress(BaseModel):
    """Scan progress information"""
    scan_id: str
    phase: ScanPhase
    target: str
    recon_completed: bool
    total_checks: int
    completed_checks: int
    current_check: Optional[str] = None
    findings_count: int
    progress_percent: float


class ScanResponse(BaseModel):
    """Scan session response"""
    id: str
    target: str
    status: ScanStatus
    phase: ScanPhase
    created_at: datetime
    updated_at: datetime
    findings_count: Optional[int] = None


class ScanListResponse(BaseModel):
    """List of scans"""
    scans: List[ScanResponse]
    total: int


class CheckListResponse(BaseModel):
    """List of available checks"""
    checks: List[CheckInfo]
    total: int
    categories: List[str]


class FindingListResponse(BaseModel):
    """List of findings"""
    findings: List[FindingResponse]
    total: int
    by_severity: Dict[str, int]


class ReportResponse(BaseModel):
    """Report generation response"""
    report_path: str
    format: str
    findings_count: int


class ErrorResponse(BaseModel):
    """API error response"""
    error: str
    detail: Optional[str] = None


class SuccessResponse(BaseModel):
    """Generic success response"""
    success: bool = True
    message: str
