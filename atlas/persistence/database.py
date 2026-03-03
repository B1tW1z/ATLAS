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
    Severity, CheckStatus, User
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
            
            # Users table for authentication
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    id TEXT PRIMARY KEY,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT DEFAULT 'user',
                    created_at TEXT NOT NULL
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
            
            # Scan events / activity log table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id TEXT,
                    event_type TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scan_sessions(id)
                )
            """)
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_scan ON scan_events(scan_id)")
            cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_time ON scan_events(timestamp)")
            
            # Scheduled scans table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scheduled_scans (
                    id TEXT PRIMARY KEY,
                    target TEXT NOT NULL,
                    cron_expr TEXT NOT NULL,
                    enabled INTEGER DEFAULT 1,
                    last_run TEXT,
                    next_run TEXT,
                    options TEXT,
                    created_by TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                )
            """)
            
            # Add notes/tags columns to scan_sessions if not present
            try:
                cursor.execute("ALTER TABLE scan_sessions ADD COLUMN notes TEXT DEFAULT ''")
            except sqlite3.OperationalError:
                pass  # Column already exists
            try:
                cursor.execute("ALTER TABLE scan_sessions ADD COLUMN tags TEXT DEFAULT '[]'")
            except sqlite3.OperationalError:
                pass  # Column already exists
    
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
    
    def delete_scan_session(self, scan_id: str) -> bool:
        """Delete a scan and all associated data (cascade)"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM findings WHERE scan_id = ?", (scan_id,))
            cursor.execute("DELETE FROM executed_checks WHERE scan_id = ?", (scan_id,))
            cursor.execute("DELETE FROM recon_results WHERE scan_id = ?", (scan_id,))
            cursor.execute("DELETE FROM scan_events WHERE scan_id = ?", (scan_id,))
            cursor.execute("DELETE FROM scan_sessions WHERE id = ?", (scan_id,))
            deleted = cursor.rowcount > 0
        if deleted:
            logger.info(f"Deleted scan session and all data: {scan_id}")
        return deleted
    
    def update_scan_notes(self, scan_id: str, notes: str = None, tags: list = None) -> bool:
        """Update scan notes and/or tags"""
        updates = {"updated_at": datetime.utcnow().isoformat()}
        if notes is not None:
            updates["notes"] = notes
        if tags is not None:
            updates["tags"] = json.dumps(tags)
        
        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [scan_id]
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"UPDATE scan_sessions SET {set_clause} WHERE id = ?", values)
            return cursor.rowcount > 0
    
    def get_scan_export(self, scan_id: str) -> Optional[Dict[str, Any]]:
        """Export full scan data as a dictionary"""
        session = self.get_scan_session(scan_id)
        if not session:
            return None
        findings = self.get_findings(scan_id)
        recon = self.get_recon_results(scan_id)
        checks = self.get_executed_checks(scan_id)
        return {
            "session": session.to_dict(),
            "findings": [f.to_dict() for f in findings],
            "recon_results": [r.to_dict() for r in recon],
            "executed_checks": [c.to_dict() for c in checks],
            "exported_at": datetime.utcnow().isoformat()
        }
    
    # ========== Scan Events / Activity Log ==========
    
    def add_scan_event(self, scan_id: str, event_type: str, message: str):
        """Add a scan lifecycle event"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_events (scan_id, event_type, message, timestamp)
                VALUES (?, ?, ?, ?)
            """, (scan_id, event_type, message, datetime.utcnow().isoformat()))
    
    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent activity events across all scans"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT e.id, e.scan_id, e.event_type, e.message, e.timestamp,
                       s.target
                FROM scan_events e
                LEFT JOIN scan_sessions s ON e.scan_id = s.id
                ORDER BY e.timestamp DESC LIMIT ?
            """, (limit,))
            return [
                {"id": row[0], "scan_id": row[1], "event_type": row[2],
                 "message": row[3], "timestamp": row[4], "target": row[5]}
                for row in cursor.fetchall()
            ]
    
    def get_scan_events(self, scan_id: str) -> List[Dict[str, Any]]:
        """Get events for a specific scan"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, scan_id, event_type, message, timestamp
                FROM scan_events WHERE scan_id = ? ORDER BY timestamp DESC
            """, (scan_id,))
            return [
                {"id": row[0], "scan_id": row[1], "event_type": row[2],
                 "message": row[3], "timestamp": row[4]}
                for row in cursor.fetchall()
            ]
    
    # ========== Dashboard & Analytics ==========
    
    def get_dashboard_stats(self) -> Dict[str, Any]:
        """Get aggregated dashboard statistics"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Total scans
            cursor.execute("SELECT COUNT(*) FROM scan_sessions")
            total_scans = cursor.fetchone()[0]
            
            # Scans by status
            cursor.execute("SELECT status, COUNT(*) FROM scan_sessions GROUP BY status")
            scans_by_status = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Total findings
            cursor.execute("SELECT COUNT(*) FROM findings")
            total_findings = cursor.fetchone()[0]
            
            # Findings by severity
            cursor.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
            findings_by_severity = {row[0]: row[1] for row in cursor.fetchall()}
            
            # Most tested targets (top 5)
            cursor.execute("""
                SELECT target, COUNT(*) as cnt FROM scan_sessions 
                GROUP BY target ORDER BY cnt DESC LIMIT 5
            """)
            top_targets = [{"target": row[0], "count": row[1]} for row in cursor.fetchall()]
            
            # Recent scans (last 5)
            cursor.execute("""
                SELECT id, target, status, phase, created_at FROM scan_sessions 
                ORDER BY created_at DESC LIMIT 5
            """)
            recent_scans = [
                {"id": row[0], "target": row[1], "status": row[2],
                 "phase": row[3], "created_at": row[4]}
                for row in cursor.fetchall()
            ]
            
            # Total checks executed
            cursor.execute("SELECT COUNT(*) FROM executed_checks")
            total_checks = cursor.fetchone()[0]
            
            return {
                "total_scans": total_scans,
                "scans_by_status": scans_by_status,
                "total_findings": total_findings,
                "findings_by_severity": findings_by_severity,
                "top_targets": top_targets,
                "recent_scans": recent_scans,
                "total_checks_executed": total_checks
            }
    
    def get_scan_trends(self, days: int = 30) -> Dict[str, Any]:
        """Get scan and finding trends over time"""
        from datetime import timedelta
        cutoff = (datetime.utcnow() - timedelta(days=days)).isoformat()
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            
            # Scans per day
            cursor.execute("""
                SELECT DATE(created_at) as day, COUNT(*) 
                FROM scan_sessions WHERE created_at >= ?
                GROUP BY day ORDER BY day
            """, (cutoff,))
            scans_per_day = [{"date": row[0], "count": row[1]} for row in cursor.fetchall()]
            
            # Findings per day
            cursor.execute("""
                SELECT DATE(created_at) as day, COUNT(*) 
                FROM findings WHERE created_at >= ?
                GROUP BY day ORDER BY day
            """, (cutoff,))
            findings_per_day = [{"date": row[0], "count": row[1]} for row in cursor.fetchall()]
            
            # Severity distribution over time
            cursor.execute("""
                SELECT DATE(created_at) as day, severity, COUNT(*)
                FROM findings WHERE created_at >= ?
                GROUP BY day, severity ORDER BY day
            """, (cutoff,))
            severity_trends = {}
            for row in cursor.fetchall():
                day = row[0]
                if day not in severity_trends:
                    severity_trends[day] = {}
                severity_trends[day][row[1]] = row[2]
            
            return {
                "scans_per_day": scans_per_day,
                "findings_per_day": findings_per_day,
                "severity_trends": severity_trends
            }
    
    # ========== Scheduled Scans ==========
    
    def create_scheduled_scan(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new scheduled scan"""
        now = datetime.utcnow().isoformat()
        schedule_id = str(uuid.uuid4())[:8]
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scheduled_scans 
                (id, target, cron_expr, enabled, options, created_by, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                schedule_id,
                data["target"],
                data["cron_expr"],
                1 if data.get("enabled", True) else 0,
                json.dumps(data.get("options", {})),
                data.get("created_by"),
                now, now
            ))
        logger.info(f"Created scheduled scan: {schedule_id}")
        return {"id": schedule_id, **data, "created_at": now, "updated_at": now}
    
    def list_scheduled_scans(self) -> List[Dict[str, Any]]:
        """List all scheduled scans"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM scheduled_scans ORDER BY created_at DESC")
            return [
                {"id": row[0], "target": row[1], "cron_expr": row[2],
                 "enabled": bool(row[3]), "last_run": row[4], "next_run": row[5],
                 "options": json.loads(row[6]) if row[6] else {},
                 "created_by": row[7], "created_at": row[8], "updated_at": row[9]}
                for row in cursor.fetchall()
            ]
    
    def update_scheduled_scan(self, schedule_id: str, **updates) -> bool:
        """Update a scheduled scan"""
        updates["updated_at"] = datetime.utcnow().isoformat()
        if "options" in updates:
            updates["options"] = json.dumps(updates["options"])
        if "enabled" in updates:
            updates["enabled"] = 1 if updates["enabled"] else 0
        
        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [schedule_id]
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"UPDATE scheduled_scans SET {set_clause} WHERE id = ?", values)
            return cursor.rowcount > 0
    
    def delete_scheduled_scan(self, schedule_id: str) -> bool:
        """Delete a scheduled scan"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM scheduled_scans WHERE id = ?", (schedule_id,))
            return cursor.rowcount > 0
    
    def get_due_scans(self) -> List[Dict[str, Any]]:
        """Get scheduled scans that are due to run"""
        now = datetime.utcnow().isoformat()
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM scheduled_scans 
                WHERE enabled = 1 AND (next_run IS NULL OR next_run <= ?)
            """, (now,))
            return [
                {"id": row[0], "target": row[1], "cron_expr": row[2],
                 "enabled": bool(row[3]), "last_run": row[4], "next_run": row[5],
                 "options": json.loads(row[6]) if row[6] else {},
                 "created_by": row[7], "created_at": row[8], "updated_at": row[9]}
                for row in cursor.fetchall()
            ]
    
    # ========== Users ==========
    
    def create_user(self, user: User) -> User:
        """Create a new user"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO users (id, username, email, name, password_hash, role, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                user.id,
                user.username,
                user.email,
                user.name,
                user.password_hash,
                user.role,
                user.created_at.isoformat()
            ))
        logger.info(f"Created user: {user.username}")
        return user
    
    def get_user_by_username(self, username: str) -> Optional[User]:
        """Get user by username"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, email, name, password_hash, role, created_at FROM users WHERE username = ?",
                (username,)
            )
            row = cursor.fetchone()
            if row:
                return User.from_row(tuple(row))
        return None
    
    def get_user_by_email(self, email: str) -> Optional[User]:
        """Get user by email"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, email, name, password_hash, role, created_at FROM users WHERE email = ?",
                (email,)
            )
            row = cursor.fetchone()
            if row:
                return User.from_row(tuple(row))
        return None
    
    def get_user_by_id(self, user_id: str) -> Optional[User]:
        """Get user by ID"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "SELECT id, username, email, name, password_hash, role, created_at FROM users WHERE id = ?",
                (user_id,)
            )
            row = cursor.fetchone()
            if row:
                return User.from_row(tuple(row))
        return None
    
    def username_exists(self, username: str) -> bool:
        """Check if username exists"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM users WHERE username = ?", (username,))
            return cursor.fetchone() is not None
    
    def email_exists(self, email: str) -> bool:
        """Check if email exists"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT 1 FROM users WHERE email = ?", (email,))
            return cursor.fetchone() is not None
    
    def update_user(self, user_id: str, **fields) -> bool:
        """Update user profile fields (name, email)"""
        allowed = {"name", "email"}
        updates = {k: v for k, v in fields.items() if k in allowed}
        if not updates:
            return False
        
        set_clause = ", ".join(f"{k} = ?" for k in updates.keys())
        values = list(updates.values()) + [user_id]
        
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(f"UPDATE users SET {set_clause} WHERE id = ?", values)
            return cursor.rowcount > 0
    
    def update_user_password(self, user_id: str, new_hash: str) -> bool:
        """Update user password hash"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE users SET password_hash = ? WHERE id = ?",
                (new_hash, user_id)
            )
            return cursor.rowcount > 0

