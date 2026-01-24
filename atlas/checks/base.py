"""
ATLAS Vulnerability Check Base Class

Abstract base for all vulnerability checks with metadata and execution.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, List, Dict, Any
import uuid


class Severity(Enum):
    """Vulnerability severity levels following CVSS"""
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"
    
    @property
    def color(self) -> str:
        """Get display color for severity"""
        colors = {
            "info": "#3498db",
            "low": "#2ecc71",
            "medium": "#f39c12",
            "high": "#e74c3c",
            "critical": "#9b59b6"
        }
        return colors.get(self.value, "#95a5a6")
    
    @property
    def score_range(self) -> tuple:
        """CVSS score range"""
        ranges = {
            "info": (0.0, 0.0),
            "low": (0.1, 3.9),
            "medium": (4.0, 6.9),
            "high": (7.0, 8.9),
            "critical": (9.0, 10.0)
        }
        return ranges.get(self.value, (0.0, 0.0))


class CheckStatus(Enum):
    """Check result status"""
    VULNERABLE = "vulnerable"      # Vulnerability confirmed
    NOT_VULNERABLE = "not_vulnerable"  # No vulnerability found
    INCONCLUSIVE = "inconclusive"  # Could not determine
    ERROR = "error"                # Check failed
    SKIPPED = "skipped"            # Check was skipped


@dataclass
class CheckResult:
    """Result of a vulnerability check execution"""
    
    check_id: str
    check_name: str
    status: CheckStatus
    severity: Severity = Severity.INFO
    title: str = ""
    description: str = ""
    evidence: str = ""
    remediation: str = ""
    url: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    owasp_category: Optional[str] = None
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    execution_time: float = 0.0
    error_message: Optional[str] = None
    raw_response: Optional[str] = None
    
    @property
    def is_vulnerable(self) -> bool:
        """Check if vulnerability was found"""
        return self.status == CheckStatus.VULNERABLE
    
    def to_finding(self) -> Dict[str, Any]:
        """Convert to finding dict for persistence"""
        return {
            "id": str(uuid.uuid4())[:8],
            "check_id": self.check_id,
            "title": self.title or self.check_name,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
            "remediation": self.remediation,
            "url": self.url,
            "parameter": self.parameter,
            "payload": self.payload,
            "owasp_category": self.owasp_category,
            "cwe_id": self.cwe_id,
            "cvss_score": self.cvss_score
        }


@dataclass  
class CheckMetadata:
    """Metadata for a vulnerability check"""
    
    id: str
    name: str
    category: str
    severity: Severity
    description: str
    owasp_category: Optional[str] = None
    cwe_id: Optional[str] = None
    prerequisites: List[str] = field(default_factory=list)
    applicable_services: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity.value,
            "description": self.description,
            "owasp_category": self.owasp_category,
            "cwe_id": self.cwe_id,
            "prerequisites": self.prerequisites,
            "applicable_services": self.applicable_services,
            "tags": self.tags
        }


class VulnerabilityCheck(ABC):
    """
    Abstract base class for all vulnerability checks.
    
    Subclasses must implement:
    - metadata property
    - execute() method
    
    Optional overrides:
    - is_applicable() - custom applicability logic
    - setup() - pre-execution setup
    - teardown() - post-execution cleanup
    """
    
    @property
    @abstractmethod
    def metadata(self) -> CheckMetadata:
        """Check metadata including ID, name, severity, etc."""
        pass
    
    @abstractmethod
    async def execute(self, target: str, context: Dict[str, Any]) -> CheckResult:
        """
        Execute the vulnerability check.
        
        Args:
            target: Target URL or IP
            context: Scan context including services, ports, etc.
            
        Returns:
            CheckResult with findings
        """
        pass
    
    def is_applicable(self, services: Dict[int, Dict], fingerprint: Optional[str] = None) -> bool:
        """
        Check if this check is applicable to the target.
        
        Args:
            services: Discovered services
            fingerprint: Target fingerprint if identified
            
        Returns:
            True if check should be offered to user
        """
        # If no specific services required, always applicable
        if not self.metadata.applicable_services:
            return True
        
        # Check if any required service is present
        service_names = [s.get("service", "") for s in services.values()]
        return any(
            req in service_names 
            for req in self.metadata.applicable_services
        )
    
    async def setup(self, target: str, context: Dict[str, Any]):
        """Optional pre-execution setup"""
        pass
    
    async def teardown(self, target: str, context: Dict[str, Any]):
        """Optional post-execution cleanup"""
        pass
    
    def _create_result(
        self,
        status: CheckStatus,
        **kwargs
    ) -> CheckResult:
        """Helper to create result with common fields populated"""
        return CheckResult(
            check_id=self.metadata.id,
            check_name=self.metadata.name,
            status=status,
            severity=kwargs.get("severity", self.metadata.severity),
            owasp_category=kwargs.get("owasp_category", self.metadata.owasp_category),
            cwe_id=kwargs.get("cwe_id", self.metadata.cwe_id),
            **{k: v for k, v in kwargs.items() if k not in ["severity", "owasp_category", "cwe_id"]}
        )
    
    def _vulnerable(self, **kwargs) -> CheckResult:
        """Shorthand for vulnerable result"""
        return self._create_result(CheckStatus.VULNERABLE, **kwargs)
    
    def _not_vulnerable(self, **kwargs) -> CheckResult:
        """Shorthand for not vulnerable result"""
        return self._create_result(CheckStatus.NOT_VULNERABLE, **kwargs)
    
    def _inconclusive(self, **kwargs) -> CheckResult:
        """Shorthand for inconclusive result"""
        return self._create_result(CheckStatus.INCONCLUSIVE, **kwargs)
    
    def _error(self, message: str, **kwargs) -> CheckResult:
        """Shorthand for error result"""
        return self._create_result(CheckStatus.ERROR, error_message=message, **kwargs)
