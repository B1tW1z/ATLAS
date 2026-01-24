"""
ATLAS Phase Controller

Manages the scan workflow phases with state transitions.
"""

from enum import Enum, auto
from typing import Optional, Callable, List
from dataclasses import dataclass, field

from atlas.utils.logger import get_logger

logger = get_logger(__name__)


class ScanPhase(Enum):
    """Scan workflow phases"""
    IDLE = auto()           # No active scan
    INITIALIZING = auto()   # Setting up scan session
    RECON = auto()          # Reconnaissance in progress
    SELECTION = auto()      # User selecting checks
    TESTING = auto()        # Executing vulnerability checks
    REPORTING = auto()      # Generating reports
    COMPLETED = auto()      # Scan finished
    PAUSED = auto()         # Scan paused (can resume)
    ERROR = auto()          # Error state


# Valid phase transitions
PHASE_TRANSITIONS = {
    ScanPhase.IDLE: [ScanPhase.INITIALIZING],
    ScanPhase.INITIALIZING: [ScanPhase.RECON, ScanPhase.ERROR],
    ScanPhase.RECON: [ScanPhase.SELECTION, ScanPhase.ERROR, ScanPhase.PAUSED],
    ScanPhase.SELECTION: [ScanPhase.TESTING, ScanPhase.PAUSED],
    ScanPhase.TESTING: [ScanPhase.REPORTING, ScanPhase.ERROR, ScanPhase.PAUSED],
    ScanPhase.REPORTING: [ScanPhase.COMPLETED, ScanPhase.ERROR],
    ScanPhase.COMPLETED: [ScanPhase.IDLE],
    ScanPhase.PAUSED: [ScanPhase.RECON, ScanPhase.SELECTION, ScanPhase.TESTING, ScanPhase.IDLE],
    ScanPhase.ERROR: [ScanPhase.IDLE, ScanPhase.PAUSED],
}


@dataclass
class PhaseController:
    """
    Controls scan workflow phases and transitions.
    
    Ensures valid state transitions and notifies listeners of changes.
    """
    
    current_phase: ScanPhase = ScanPhase.IDLE
    _listeners: List[Callable[[ScanPhase, ScanPhase], None]] = field(default_factory=list)
    _phase_history: List[ScanPhase] = field(default_factory=list)
    
    def transition_to(self, new_phase: ScanPhase) -> bool:
        """
        Transition to a new phase.
        
        Args:
            new_phase: Target phase
            
        Returns:
            True if transition successful, False otherwise
        """
        if new_phase not in PHASE_TRANSITIONS.get(self.current_phase, []):
            logger.warning(
                f"Invalid phase transition: {self.current_phase.name} -> {new_phase.name}"
            )
            return False
        
        old_phase = self.current_phase
        self._phase_history.append(old_phase)
        self.current_phase = new_phase
        
        logger.info(f"Phase transition: {old_phase.name} -> {new_phase.name}")
        
        # Notify listeners
        for listener in self._listeners:
            try:
                listener(old_phase, new_phase)
            except Exception as e:
                logger.error(f"Phase listener error: {e}")
        
        return True
    
    def can_transition_to(self, phase: ScanPhase) -> bool:
        """Check if transition to phase is valid"""
        return phase in PHASE_TRANSITIONS.get(self.current_phase, [])
    
    def add_listener(self, callback: Callable[[ScanPhase, ScanPhase], None]):
        """Add a phase change listener"""
        self._listeners.append(callback)
    
    def remove_listener(self, callback: Callable[[ScanPhase, ScanPhase], None]):
        """Remove a phase change listener"""
        if callback in self._listeners:
            self._listeners.remove(callback)
    
    def get_available_transitions(self) -> List[ScanPhase]:
        """Get list of valid transitions from current phase"""
        return PHASE_TRANSITIONS.get(self.current_phase, [])
    
    def reset(self):
        """Reset to idle state"""
        self._phase_history.append(self.current_phase)
        self.current_phase = ScanPhase.IDLE
        logger.info("Phase controller reset to IDLE")
    
    @property
    def is_active(self) -> bool:
        """Check if a scan is actively running"""
        return self.current_phase in [
            ScanPhase.INITIALIZING,
            ScanPhase.RECON,
            ScanPhase.TESTING,
            ScanPhase.REPORTING
        ]
    
    @property
    def can_resume(self) -> bool:
        """Check if scan can be resumed"""
        return self.current_phase == ScanPhase.PAUSED
