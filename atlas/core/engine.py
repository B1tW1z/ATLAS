"""
ATLAS Core Engine

Main orchestration layer coordinating all assessment components.
"""

import asyncio
from typing import Optional, Dict, Any, List, Callable
from datetime import datetime

from atlas.core.phase_controller import PhaseController, ScanPhase
from atlas.core.state_manager import StateManager, ScanState
from atlas.utils.logger import get_logger
from atlas.utils.config import get_config

logger = get_logger(__name__)


class ATLASEngine:
    """
    Main ATLAS orchestration engine.
    
    Coordinates reconnaissance, vulnerability checks, and reporting
    with user-controlled workflows.
    """
    
    def __init__(self, database=None):
        """
        Initialize ATLAS engine.
        
        Args:
            database: Optional database instance for persistence
        """
        self._config = get_config()
        self._state_manager = StateManager(database)
        self._database = database
        
        # Component references (lazy-loaded)
        self._recon_scanner = None
        self._check_registry = None
        self._report_generator = None
        
        # Event callbacks
        self._event_callbacks: Dict[str, List[Callable]] = {
            "scan_started": [],
            "recon_completed": [],
            "check_started": [],
            "check_completed": [],
            "finding_discovered": [],
            "scan_completed": [],
            "error": [],
        }
        
        logger.info("ATLAS Engine initialized")
    
    # ========== Properties ==========
    
    @property
    def state(self) -> Optional[ScanState]:
        """Get current scan state"""
        return self._state_manager.state
    
    @property
    def phase(self) -> ScanPhase:
        """Get current scan phase"""
        return self._state_manager.phase_controller.current_phase
    
    @property
    def is_active(self) -> bool:
        """Check if scan is active"""
        return self._state_manager.phase_controller.is_active
    
    # ========== Scan Lifecycle ==========
    
    async def start_scan(self, target: str, options: Optional[Dict[str, Any]] = None) -> ScanState:
        """
        Start a new vulnerability assessment scan.
        
        Args:
            target: Target URL or IP address
            options: Optional scan configuration
            
        Returns:
            ScanState for the new session
        """
        logger.info(f"Starting scan for target: {target}")
        
        # Create new session
        state = self._state_manager.create_session(target, metadata=options or {})
        
        # Emit event
        self._emit_event("scan_started", {"scan_id": state.scan_id, "target": target})
        
        return state
    
    async def run_reconnaissance(self) -> Dict[str, Any]:
        """
        Execute reconnaissance phase.
        
        Returns:
            Recon results including ports and services
        """
        if not self.state:
            raise RuntimeError("No active scan session")
        
        # Transition to recon phase
        self._state_manager.phase_controller.transition_to(ScanPhase.RECON)
        
        logger.info(f"Running reconnaissance on {self.state.target}")
        
        try:
            # Lazy-load scanner
            if self._recon_scanner is None:
                from atlas.recon import ReconScanner
                self._recon_scanner = ReconScanner()
            
            # Execute scan
            results = await self._recon_scanner.scan(self.state.target)
            
            # Update state
            self._state_manager.update_recon(
                open_ports=results.get("ports", []),
                services=results.get("services", {}),
                fingerprint=results.get("fingerprint")
            )
            
            # Transition to selection
            self._state_manager.phase_controller.transition_to(ScanPhase.SELECTION)
            
            # Emit event
            self._emit_event("recon_completed", results)
            
            return results
            
        except Exception as e:
            logger.error(f"Reconnaissance failed: {e}")
            self._state_manager.phase_controller.transition_to(ScanPhase.ERROR)
            self._emit_event("error", {"phase": "recon", "error": str(e)})
            raise
    
    def get_available_checks(self) -> List[Dict[str, Any]]:
        """
        Get list of available vulnerability checks.
        
        Returns list of checks applicable to current target.
        """
        if not self.state:
            return []
        
        # Lazy-load registry
        if self._check_registry is None:
            from atlas.checks import CheckRegistry
            self._check_registry = CheckRegistry()
        
        # Get checks applicable to discovered services
        return self._check_registry.get_applicable_checks(
            services=self.state.services,
            fingerprint=self.state.target_fingerprint
        )
    
    def select_checks(self, check_ids: List[str]):
        """
        Select checks for execution.
        
        Args:
            check_ids: List of check identifiers to execute
        """
        if not self.state:
            raise RuntimeError("No active scan session")
        
        self._state_manager.set_selected_checks(check_ids)
        logger.info(f"Selected {len(check_ids)} checks for execution")
    
    async def execute_checks(self) -> List[Dict[str, Any]]:
        """
        Execute selected vulnerability checks.
        
        Returns:
            List of findings from all checks
        """
        if not self.state:
            raise RuntimeError("No active scan session")
        
        if not self.state.selected_checks:
            raise ValueError("No checks selected")
        
        # Transition to testing
        self._state_manager.phase_controller.transition_to(ScanPhase.TESTING)
        
        findings = []
        
        # Lazy-load registry
        if self._check_registry is None:
            from atlas.checks import CheckRegistry
            self._check_registry = CheckRegistry()
        
        for check_id in self.state.selected_checks:
            # Skip if already executed
            if check_id in self.state.executed_checks:
                continue
            
            try:
                self._state_manager.mark_check_started(check_id)
                self._emit_event("check_started", {"check_id": check_id})
                
                # Get and execute check
                check = self._check_registry.get_check(check_id)
                if check:
                    result = await check.execute(
                        target=self.state.target,
                        context={
                            "services": self.state.services,
                            "ports": self.state.open_ports,
                            "metadata": self.state.metadata  # Pass scan metadata (options)
                        }
                    )
                    
                    # Process result
                    if result.is_vulnerable:
                        finding = result.to_finding()
                        findings.append(finding)
                        self._state_manager.add_finding(finding)
                        self._emit_event("finding_discovered", finding)
                
                self._state_manager.mark_check_completed(check_id)
                self._emit_event("check_completed", {"check_id": check_id, "success": True})
                
            except Exception as e:
                logger.error(f"Check {check_id} failed: {e}")
                self._state_manager.mark_check_completed(check_id)
                self._emit_event("check_completed", {
                    "check_id": check_id, 
                    "success": False, 
                    "error": str(e)
                })
        
        # Transition to reporting
        self._state_manager.phase_controller.transition_to(ScanPhase.REPORTING)
        
        return findings
    
    async def generate_report(self, format: str = "html") -> str:
        """
        Generate vulnerability report.
        
        Args:
            format: Report format ('html' or 'json')
            
        Returns:
            Path to generated report
        """
        if not self.state:
            raise RuntimeError("No active scan session")
        
        # Lazy-load generator
        if self._report_generator is None:
            from atlas.reporting import ReportGenerator
            self._report_generator = ReportGenerator()
        
        report_path = await self._report_generator.generate(
            scan_state=self.state,
            format=format
        )
        
        # Transition to completed
        self._state_manager.phase_controller.transition_to(ScanPhase.COMPLETED)
        self._emit_event("scan_completed", {
            "scan_id": self.state.scan_id,
            "findings_count": len(self.state.findings),
            "report_path": report_path
        })
        
        return report_path
    
    # ========== Session Management ==========
    
    async def resume_scan(self, scan_id: str) -> Optional[ScanState]:
        """
        Resume a paused or interrupted scan.
        
        Args:
            scan_id: Session identifier
            
        Returns:
            Loaded ScanState or None
        """
        state = self._state_manager.load_session(scan_id)
        
        if state and state.phase == ScanPhase.PAUSED:
            logger.info(f"Resuming scan {scan_id}")
            # Determine resume point based on state
            if not state.recon_completed:
                self._state_manager.phase_controller.transition_to(ScanPhase.RECON)
            elif state.selected_checks and state.executed_checks != state.selected_checks:
                self._state_manager.phase_controller.transition_to(ScanPhase.TESTING)
            else:
                self._state_manager.phase_controller.transition_to(ScanPhase.SELECTION)
        
        return state
    
    def pause_scan(self):
        """Pause the current scan"""
        if self.is_active:
            self._state_manager.phase_controller.transition_to(ScanPhase.PAUSED)
            logger.info(f"Scan paused: {self.state.scan_id}")
    
    def get_progress(self) -> Dict[str, Any]:
        """Get current scan progress"""
        return self._state_manager.get_progress()
    
    # ========== Event System ==========
    
    def on(self, event: str, callback: Callable):
        """Register event callback"""
        if event in self._event_callbacks:
            self._event_callbacks[event].append(callback)
    
    def off(self, event: str, callback: Callable):
        """Unregister event callback"""
        if event in self._event_callbacks and callback in self._event_callbacks[event]:
            self._event_callbacks[event].remove(callback)
    
    def _emit_event(self, event: str, data: Any):
        """Emit event to all listeners and persist to database"""
        for callback in self._event_callbacks.get(event, []):
            try:
                callback(data)
            except Exception as e:
                logger.error(f"Event callback error: {e}")
        
        # Persist to database activity log
        try:
            if self._database and self.state:
                messages = {
                    "scan_started": f"Scan started for {data.get('target', 'unknown')}",
                    "recon_completed": f"Reconnaissance completed — {len(data.get('ports', []))} ports found",
                    "check_started": f"Check started: {data.get('check_id', '')}",
                    "check_completed": f"Check completed: {data.get('check_id', '')}",
                    "finding_discovered": f"Finding: {data.get('title', 'Unknown')} ({data.get('severity', '')})",
                    "scan_completed": f"Scan completed — {data.get('findings_count', 0)} findings",
                    "error": f"Error in {data.get('phase', 'unknown')}: {data.get('error', '')}",
                }
                msg = messages.get(event, str(data))
                self._database.add_scan_event(self.state.scan_id, event, msg)
        except Exception as e:
            logger.debug(f"Failed to persist event: {e}")
