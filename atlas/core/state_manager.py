"""
ATLAS State Manager

Manages scan session state with persistence support.
"""

import uuid
from datetime import datetime
from typing import Optional, Dict, Any, List
from dataclasses import dataclass, field

from atlas.core.phase_controller import PhaseController, ScanPhase
from atlas.utils.logger import get_logger
from atlas.persistence.models import ReconResult, Finding, ExecutedCheck, CheckStatus, Severity

logger = get_logger(__name__)


@dataclass
class ScanState:
    """Represents the current state of a scan session"""
    
    scan_id: str
    target: str
    created_at: datetime
    updated_at: datetime
    phase: ScanPhase
    
    # Reconnaissance data
    recon_completed: bool = False
    open_ports: List[int] = field(default_factory=list)
    services: Dict[int, Dict[str, Any]] = field(default_factory=dict)
    target_fingerprint: Optional[str] = None
    
    # Check selection
    selected_checks: List[str] = field(default_factory=list)
    
    # Execution tracking
    executed_checks: List[str] = field(default_factory=list)
    current_check: Optional[str] = None
    
    # Findings
    findings: List[Dict[str, Any]] = field(default_factory=list)
    
    # Metadata
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert state to dictionary for serialization"""
        return {
            "scan_id": self.scan_id,
            "target": self.target,
            "created_at": self.created_at.isoformat(),
            "updated_at": self.updated_at.isoformat(),
            "phase": self.phase.name,
            "recon_completed": self.recon_completed,
            "open_ports": self.open_ports,
            "services": self.services,
            "target_fingerprint": self.target_fingerprint,
            "selected_checks": self.selected_checks,
            "executed_checks": self.executed_checks,
            "current_check": self.current_check,
            "findings": self.findings,
            "metadata": self.metadata,
        }
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ScanState":
        """Create state from dictionary"""
        return cls(
            scan_id=data["scan_id"],
            target=data["target"],
            created_at=datetime.fromisoformat(data["created_at"]),
            updated_at=datetime.fromisoformat(data["updated_at"]),
            phase=ScanPhase[data["phase"]],
            recon_completed=data.get("recon_completed", False),
            open_ports=data.get("open_ports", []),
            services=data.get("services", {}),
            target_fingerprint=data.get("target_fingerprint"),
            selected_checks=data.get("selected_checks", []),
            executed_checks=data.get("executed_checks", []),
            current_check=data.get("current_check"),
            findings=data.get("findings", []),
            metadata=data.get("metadata", {}),
        )


class StateManager:
    """
    Manages scan session state.
    
    Provides a unified interface for state access and modification,
    with automatic persistence through the database layer.
    """
    
    def __init__(self, database=None):
        """
        Initialize state manager.
        
        Args:
            database: Optional database instance for persistence
        """
        self._database = database
        self._current_state: Optional[ScanState] = None
        self._phase_controller = PhaseController()
        
        # Sync phase controller with state
        self._phase_controller.add_listener(self._on_phase_change)
    
    def create_session(self, target: str, metadata: Optional[Dict[str, Any]] = None) -> ScanState:
        """
        Create a new scan session.
        
        Args:
            target: Target URL or IP
            metadata: Optional session metadata
            
        Returns:
            New ScanState instance
        """
        now = datetime.utcnow()
        scan_id = str(uuid.uuid4())[:8]  # Short ID for convenience
        
        self._current_state = ScanState(
            scan_id=scan_id,
            target=target,
            created_at=now,
            updated_at=now,
            phase=ScanPhase.IDLE,
            metadata=metadata or {}
        )
        
        logger.info(f"Created scan session: {scan_id} for target: {target}")
        
        # Transition to initializing
        self._phase_controller.transition_to(ScanPhase.INITIALIZING)
        
        return self._current_state
    
    def load_session(self, scan_id: str) -> Optional[ScanState]:
        """
        Load an existing scan session.
        
        Rebuilds full ScanState from DB by loading the session record
        plus recon results, executed checks, and findings from their
        respective tables.
        
        Args:
            scan_id: Session identifier
            
        Returns:
            ScanState if found, None otherwise
        """
        if self._database:
            session = self._database.get_scan_session(scan_id)
            if session:
                # Load recon results from DB
                recon_results = self._database.get_recon_results(scan_id)
                open_ports = [r.port for r in recon_results]
                services = {}
                for r in recon_results:
                    services[r.port] = {
                        "protocol": r.protocol,
                        "service": r.service,
                        "version": r.version or "",
                        "product": r.product or "",
                        "extra_info": r.extra_info or "",
                        "state": r.state or "open"
                    }
                
                # Load executed checks from DB
                executed_checks_list = self._database.get_executed_checks(scan_id)
                executed_check_ids = [ec.check_id for ec in executed_checks_list]
                
                # Load findings from DB
                findings_list = self._database.get_findings(scan_id)
                findings = [f.to_dict() for f in findings_list]
                
                # Determine if recon was completed
                recon_completed = session.phase in ("SELECTION", "TESTING", "REPORTING", "COMPLETE")
                
                # Build the state dict for ScanState.from_dict
                # Recover selected_checks from metadata if persisted
                saved_selected = (session.metadata or {}).get("selected_checks", [])
                state_data = {
                    "scan_id": session.id,
                    "target": session.target,
                    "created_at": session.created_at.isoformat(),
                    "updated_at": session.updated_at.isoformat(),
                    "phase": session.phase,
                    "recon_completed": recon_completed,
                    "open_ports": open_ports,
                    "services": services,
                    "target_fingerprint": None,
                    "selected_checks": saved_selected,
                    "executed_checks": executed_check_ids,
                    "findings": findings,
                    "metadata": session.metadata or {},
                }
                
                self._current_state = ScanState.from_dict(state_data)
                self._phase_controller.current_phase = self._current_state.phase
                logger.info(f"Loaded scan session: {scan_id} (phase={session.phase}, ports={len(open_ports)}, checks={len(executed_check_ids)})")
                return self._current_state
        
        logger.warning(f"Scan session not found: {scan_id}")
        return None
    
    def save_session(self):
        """Persist current session to database"""
        if self._current_state and self._database:
            self._current_state.updated_at = datetime.utcnow()
            self._database.save_scan_session(self._current_state.to_dict())
            logger.debug(f"Saved scan session: {self._current_state.scan_id}")
    
    @property
    def state(self) -> Optional[ScanState]:
        """Get current scan state"""
        return self._current_state
    
    @property
    def phase_controller(self) -> PhaseController:
        """Get phase controller"""
        return self._phase_controller
    
    def _on_phase_change(self, old_phase: ScanPhase, new_phase: ScanPhase):
        """Handle phase transitions"""
        if self._current_state:
            self._current_state.phase = new_phase
            self._current_state.updated_at = datetime.utcnow()
            self.save_session()
    
    def update_recon(
        self,
        open_ports: List[int],
        services: Dict[int, Dict[str, Any]],
        fingerprint: Optional[str] = None
    ):
        """Update reconnaissance results"""
        if self._current_state:
            self._current_state.open_ports = open_ports
            self._current_state.services = services
            self._current_state.target_fingerprint = fingerprint
            self._current_state.recon_completed = True
            self.save_session()
            
            # Persist to database
            if self._database:
                try:
                    results = []
                    # Process services
                    for port, svc in services.items():
                        results.append(ReconResult(
                            scan_id=self._current_state.scan_id,
                            port=int(port),
                            protocol=svc.get("protocol", "tcp"),
                            service=svc.get("service", "unknown"),
                            version=svc.get("version"),
                            product=svc.get("product"),
                            extra_info=svc.get("extra_info") or str(svc),
                            state=svc.get("state", "open")
                        ))
                    
                    # Add any ports without service details
                    existing_ports = set(r.port for r in results)
                    for port in open_ports:
                        if int(port) not in existing_ports:
                            results.append(ReconResult(
                                scan_id=self._current_state.scan_id,
                                port=int(port),
                                protocol="tcp",
                                service="unknown"
                            ))
                            
                    if results:
                        self._database.add_recon_results(results)
                        logger.debug(f"Persisted {len(results)} recon results")
                except Exception as e:
                    logger.error(f"Failed to persist recon results: {e}")

    def set_selected_checks(self, check_ids: List[str]):
        """Set user-selected checks and persist to metadata"""
        if self._current_state:
            self._current_state.selected_checks = check_ids
            # Store in metadata so they survive server restarts
            self._current_state.metadata["selected_checks"] = check_ids
            self.save_session()


    def mark_check_started(self, check_id: str):
        """Mark a check as started"""
        if self._current_state:
            self._current_state.current_check = check_id
            self.save_session()
            
            if self._database:
                try:
                    check = ExecutedCheck(
                        id=f"{self._current_state.scan_id}_{check_id}",
                        scan_id=self._current_state.scan_id,
                        check_id=check_id,
                        check_name=check_id,  # Name not available here, using ID
                        status=CheckStatus.RUNNING,
                        started_at=datetime.utcnow()
                    )
                    self._database.add_executed_check(check)
                except Exception as e:
                    logger.error(f"Failed to persist check start: {e}")
    
    def mark_check_completed(self, check_id: str):
        """Mark a check as completed"""
        if self._current_state:
            if check_id not in self._current_state.executed_checks:
                self._current_state.executed_checks.append(check_id)
            self._current_state.current_check = None
            self.save_session()
            
            if self._database:
                try:
                    self._database.update_executed_check(
                        check_id=f"{self._current_state.scan_id}_{check_id}",
                        status=CheckStatus.COMPLETED,
                        completed_at=datetime.utcnow()
                    )
                except Exception as e:
                    # If update failed, try adding (maybe start wasn't recorded)
                    logger.debug(f"Update executed check failed, trying insert: {e}")
    
    def add_finding(self, finding: Dict[str, Any]):
        """Add a vulnerability finding"""
        if self._current_state:
            self._current_state.findings.append(finding)
            self.save_session()
            
            if self._database:
                try:
                    f_obj = Finding(
                        id=finding["id"],
                        scan_id=self._current_state.scan_id,
                        check_id=finding["check_id"],
                        title=finding["title"],
                        severity=Severity(finding["severity"]),
                        description=finding["description"],
                        evidence=finding["evidence"],
                        remediation=finding["remediation"],
                        owasp_category=finding.get("owasp_category"),
                        cwe_id=finding.get("cwe_id"),
                        cvss_score=finding.get("cvss_score"),
                        url=finding.get("url"),
                        parameter=finding.get("parameter"),
                        payload=finding.get("payload")
                    )
                    self._database.add_finding(f_obj)
                    logger.debug(f"Persisted finding: {finding['title']}")
                except Exception as e:
                    logger.error(f"Failed to persist finding: {e}")
    
    def get_progress(self) -> Dict[str, Any]:
        """Get scan progress information"""
        if not self._current_state:
            return {"status": "no_session"}
        
        total_checks = len(self._current_state.selected_checks)
        completed_checks = len(self._current_state.executed_checks)
        
        return {
            "scan_id": self._current_state.scan_id,
            "phase": self._current_state.phase.name,
            "target": self._current_state.target,
            "recon_completed": self._current_state.recon_completed,
            "total_checks": total_checks,
            "completed_checks": completed_checks,
            "current_check": self._current_state.current_check,
            "findings_count": len(self._current_state.findings),
            "progress_percent": (completed_checks / total_checks * 100) if total_checks > 0 else 0
        }
