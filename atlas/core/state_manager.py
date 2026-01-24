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
        
        Args:
            scan_id: Session identifier
            
        Returns:
            ScanState if found, None otherwise
        """
        if self._database:
            data = self._database.get_scan_session(scan_id)
            if data:
                self._current_state = ScanState.from_dict(data)
                self._phase_controller.current_phase = self._current_state.phase
                logger.info(f"Loaded scan session: {scan_id}")
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
    
    def set_selected_checks(self, check_ids: List[str]):
        """Set user-selected checks"""
        if self._current_state:
            self._current_state.selected_checks = check_ids
            self.save_session()
    
    def mark_check_started(self, check_id: str):
        """Mark a check as started"""
        if self._current_state:
            self._current_state.current_check = check_id
            self.save_session()
    
    def mark_check_completed(self, check_id: str):
        """Mark a check as completed"""
        if self._current_state:
            if check_id not in self._current_state.executed_checks:
                self._current_state.executed_checks.append(check_id)
            self._current_state.current_check = None
            self.save_session()
    
    def add_finding(self, finding: Dict[str, Any]):
        """Add a vulnerability finding"""
        if self._current_state:
            self._current_state.findings.append(finding)
            self.save_session()
    
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
