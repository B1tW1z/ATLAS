"""
ATLAS Database Layer

SQLite-based persistence for scan sessions, recon results, and findings.
"""

import sqlite3
import json
import uuid
from pathlib import Path
from datetime import datetime
from typing import Optional, List, Dict, Any
from contextlib import contextmanager

from atlas.utils.logger import get_logger
from atlas.utils.config import get_config
from atlas.persistence.models import (
    ScanSession, ReconResult, ExecutedCheck, Finding,
    Severity, CheckStatus
)

logger = get_logger(__name__)


class Database:
    """
    SQLite database manager for ATLAS persistence.
    
    Handles all database operations with connection pooling
    and proper transaction management.
    """
    
    def __init__(self, db_path: Optional[Path] = None):
        """
        Initialize database connection.
        
        Args:
            db_path: Optional custom database path
        """
        config = get_config()
        self.db_path = db_path or config.db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        
        self._init_schema()
        logger.info(f"Database initialized at {self.db_path}")
    
    @contextmanager
    def _get_connection(self):
        """Get database connection with context management"""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise
        finally:
            conn.close()
    
    def _init_schema(self):
        """Initialize database schema"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Scan sessions table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_sessions (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    status TEXT NOT NULL,
                    phase TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    metadata TEXT
                )
            """)
            
            # Recon results table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS recon_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    service TEXT,
                    version TEXT,
                    product TEXT,
                    extra_info TEXT,
                    state TEXT DEFAULT 'open',
                    FOREIGN KEY (scan_id) REFERENCES scan_sessions(id)
                )
            """)
            
            # Executed checks table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS executed_checks (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    check_id TEXT NOT NULL,
                    check_name TEXT NOT NULL,
                    status TEXT NOT NULL,
                    started_at TEXT NOT NULL,
                    completed_at TEXT,
                    error_message TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scan_sessions(id)
                )
            """)
            
            # Findings table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS findings (
                    id TEXT PRIMARY KEY,
                    scan_id TEXT NOT NULL,
                    check_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    evidence TEXT,
                    remediation TEXT,
                    owasp_category TEXT,
                    cwe_id TEXT,
                    cvss_score REAL,
                    url TEXT,
                    parameter TEXT,
                    payload TEXT,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scan_sessions(id)
                )
            """)
            
            # Indexes
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_recon_scan ON recon_results(scan_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_checks_scan ON executed_checks(scan_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity)")
    
    # ========== Scan Sessions ==========
    
    def create_scan_session(self, target: str, metadata: Optional[Dict] = None) -> ScanSession:
        """Create a new scan session"""
        now = datetime.utcnow()
        session = ScanSession(
            id=str(uuid.uuid4())[:8],
            target=target,
            status="active",
            phase="IDLE",
            created_at=now,
            updated_at=now,
            metadata=metadata or {}
        )
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_sessions (id, target, status, phase, created_at, updated_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                session.id,
                session.target,
                session.status,
                session.phase,
                session.created_at.isoformat(),
                session.updated_at.isoformat(),
                json.dumps(session.metadata)
            ))
        
        logger.info(f"Created scan session: {session.id}")
        return session
    
    def get_scan_session(self, scan_id: str) -> Optional[ScanSession]:
        """Get scan session by ID"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scan_sessions WHERE id = ?", (scan_id,))
            row = cursor.fetchone()
            
            if row:
                return ScanSession.from_row(tuple(row))
        return None
    
    def update_scan_session(self, scan_id: str, **updates) -> bool:
        """Update scan session fields"""
        updates["updated_at"] = datetime.utcnow().isoformat()
        
        if "metadata" in updates:
            updates["metadata"] = json.dumps(updates["metadata"])
        
        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [scan_id]
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                f"UPDATE scan_sessions SET {set_clause} WHERE id = ?",
                values
            )
            return cursor.rowcount > 0
    
    def list_scan_sessions(self, limit: int = 50) -> List[ScanSession]:
        """List recent scan sessions"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM scan_sessions ORDER BY created_at DESC LIMIT ?",
                (limit,)
            )
            return [ScanSession.from_row(tuple(row)) for row in cursor.fetchall()]
    
    def save_scan_session(self, data: Dict[str, Any]):
        """Save scan session from dict (for state manager)"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO scan_sessions 
                (id, target, status, phase, created_at, updated_at, metadata)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                data["scan_id"],
                data["target"],
                "active",
                data["phase"],
                data["created_at"],
                data["updated_at"],
                json.dumps(data.get("metadata", {}))
            ))
    
    # ========== Recon Results ==========
    
    def add_recon_result(self, result: ReconResult):
        """Add a reconnaissance result"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO recon_results 
                (scan_id, port, protocol, service, version, product, extra_info, state)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                result.scan_id,
                result.port,
                result.protocol,
                result.service,
                result.version,
                result.product,
                result.extra_info,
                result.state
            ))
    
    def add_recon_results(self, results: List[ReconResult]):
        """Add multiple recon results"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.executemany("""
                INSERT INTO recon_results 
                (scan_id, port, protocol, service, version, product, extra_info, state)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, [
                (r.scan_id, r.port, r.protocol, r.service, r.version, r.product, r.extra_info, r.state)
                for r in results
            ])
    
    def get_recon_results(self, scan_id: str) -> List[ReconResult]:
        """Get recon results for a scan"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT scan_id, port, protocol, service, version, product, extra_info, state "
                "FROM recon_results WHERE scan_id = ? ORDER BY port",
                (scan_id,)
            )
            return [ReconResult.from_row(tuple(row)) for row in cursor.fetchall()]
    
    # ========== Executed Checks ==========
    
    def add_executed_check(self, check: ExecutedCheck):
        """Record an executed check"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO executed_checks 
                (id, scan_id, check_id, check_name, status, started_at, completed_at, error_message)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                check.id,
                check.scan_id,
                check.check_id,
                check.check_name,
                check.status.value,
                check.started_at.isoformat(),
                check.completed_at.isoformat() if check.completed_at else None,
                check.error_message
            ))
    
    def update_executed_check(self, check_id: str, status: CheckStatus, 
                               completed_at: datetime = None, error: str = None):
        """Update check execution status"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                UPDATE executed_checks 
                SET status = ?, completed_at = ?, error_message = ?
                WHERE id = ?
            """, (
                status.value,
                completed_at.isoformat() if completed_at else None,
                error,
                check_id
            ))
    
    def get_executed_checks(self, scan_id: str) -> List[ExecutedCheck]:
        """Get executed checks for a scan"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM executed_checks WHERE scan_id = ? ORDER BY started_at",
                (scan_id,)
            )
            return [ExecutedCheck.from_row(tuple(row)) for row in cursor.fetchall()]
    
    # ========== Findings ==========
    
    def add_finding(self, finding: Finding):
        """Add a vulnerability finding"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO findings 
                (id, scan_id, check_id, title, severity, description, evidence, 
                 remediation, owasp_category, cwe_id, cvss_score, url, parameter, payload, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                finding.id,
                finding.scan_id,
                finding.check_id,
                finding.title,
                finding.severity.value,
                finding.description,
                finding.evidence,
                finding.remediation,
                finding.owasp_category,
                finding.cwe_id,
                finding.cvss_score,
                finding.url,
                finding.parameter,
                finding.payload,
                finding.created_at.isoformat()
            ))
        logger.info(f"Added finding: {finding.title} ({finding.severity.value})")
    
    def get_findings(self, scan_id: str) -> List[Finding]:
        """Get findings for a scan"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT * FROM findings WHERE scan_id = ? ORDER BY "
                "CASE severity "
                "  WHEN 'critical' THEN 1 "
                "  WHEN 'high' THEN 2 "
                "  WHEN 'medium' THEN 3 "
                "  WHEN 'low' THEN 4 "
                "  ELSE 5 END",
                (scan_id,)
            )
            return [Finding.from_row(tuple(row)) for row in cursor.fetchall()]
    
    def get_findings_summary(self, scan_id: str) -> Dict[str, int]:
        """Get findings count by severity"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT severity, COUNT(*) FROM findings WHERE scan_id = ? GROUP BY severity",
                (scan_id,)
            )
            return {row[0]: row[1] for row in cursor.fetchall()}
