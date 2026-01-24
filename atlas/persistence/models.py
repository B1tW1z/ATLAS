"""
ATLAS Data Models

Dataclasses for type-safe data handling across the framework.
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum


class Severity(Enum):
    """Vulnerability severity levels"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CheckStatus(Enum):
    """Check execution status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"


@dataclass
class ScanSession:
    """Represents a scan session"""
    
    id: str
    target: str
    status: str
    phase: str
    created_at: datetime
    updated_at: datetime
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "target": self.target,
            "status": self.status,
            "phase": self.phase,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "metadata": self.metadata
        }
    
    @classmethod
    def from_row(cls, row: tuple) -> "ScanSession":
        import json
        return cls(
            id=row[0],
            target=row[1],
            status=row[2],
            phase=row[3],
            created_at=datetime.fromisoformat(row[4]),
            updated_at=datetime.fromisoformat(row[5]),
            metadata=json.loads(row[6]) if row[6] else {}
        )


@dataclass
class ReconResult:
    """Reconnaissance result for a port/service"""
    
    scan_id: str
    port: int
    protocol: str
    service: str
    version: Optional[str] = None
    product: Optional[str] = None
    extra_info: Optional[str] = None
    state: str = "open"
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "port": self.port,
            "protocol": self.protocol,
            "service": self.service,
            "version": self.version,
            "product": self.product,
            "extra_info": self.extra_info,
            "state": self.state
        }
    
    @classmethod
    def from_row(cls, row: tuple) -> "ReconResult":
        return cls(
            scan_id=row[0],
            port=row[1],
            protocol=row[2],
            service=row[3],
            version=row[4],
            product=row[5],
            extra_info=row[6],
            state=row[7]
        )


@dataclass
class ExecutedCheck:
    """Record of an executed vulnerability check"""
    
    id: str
    scan_id: str
    check_id: str
    check_name: str
    status: CheckStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    error_message: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "check_id": self.check_id,
            "check_name": self.check_name,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "error_message": self.error_message
        }
    
    @classmethod
    def from_row(cls, row: tuple) -> "ExecutedCheck":
        return cls(
            id=row[0],
            scan_id=row[1],
            check_id=row[2],
            check_name=row[3],
            status=CheckStatus(row[4]),
            started_at=datetime.fromisoformat(row[5]),
            completed_at=datetime.fromisoformat(row[6]) if row[6] else None,
            error_message=row[7]
        )


@dataclass
class Finding:
    """Vulnerability finding"""
    
    id: str
    scan_id: str
    check_id: str
    title: str
    severity: Severity
    description: str
    evidence: str
    remediation: str
    owasp_category: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    url: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "check_id": self.check_id,
            "title": self.title,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "owasp_category": self.owasp_category,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "created_at": self.created_at.isoformat()
        }
    
    @classmethod
    def from_row(cls, row: tuple) -> "Finding":
        return cls(
            id=row[0],
            scan_id=row[1],
            check_id=row[2],
            title=row[3],
            severity=Severity(row[4]),
            description=row[5],
            evidence=row[6],
            remediation=row[7],
            owasp_category=row[8],
            cwe_id=row[9],
            cvss_score=row[10],
            url=row[11],
            parameter=row[12],
            payload=row[13],
            created_at=datetime.fromisoformat(row[14])
        )


@dataclass
class TargetInfo:
    """Information about a scan target"""
    
    url: str
    host: str
    port: int
    scheme: str = "http"
    path: str = "/"
    
    @classmethod
    def from_url(cls, url: str) -> "TargetInfo":
        from urllib.parse import urlparse
        parsed = urlparse(url)
        
        # Default port based on scheme
        port = parsed.port
        if port is None:
            port = 443 if parsed.scheme == "https" else 80
        
        return cls(
            url=url,
            host=parsed.hostname or parsed.netloc,
            port=port,
            scheme=parsed.scheme or "http",
            path=parsed.path or "/"
        )
