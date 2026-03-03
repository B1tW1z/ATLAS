"""
ATLAS Scheduler Worker

Background worker that periodically checks for due scheduled scans
and automatically launches them.
"""

import asyncio
import logging
from datetime import datetime, timedelta

from atlas.persistence.database import Database

logger = logging.getLogger(__name__)


class SchedulerWorker:
    """
    Background worker for scheduled scan execution.
    
    Runs in a loop checking for due scans every 60 seconds.
    When a scheduled scan is due, it creates a new scan session
    and triggers reconnaissance.
    """
    
    def __init__(self, check_interval: int = 60):
        self.check_interval = check_interval
        self._running = False
        self._task = None
        self._db = None
    
    def _get_db(self):
        if self._db is None:
            self._db = Database()
        return self._db
    
    async def start(self):
        """Start the scheduler worker"""
        if self._running:
            return
        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("Scheduler worker started")
    
    async def stop(self):
        """Stop the scheduler worker"""
        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Scheduler worker stopped")
    
    async def _run_loop(self):
        """Main scheduler loop"""
        while self._running:
            try:
                await self._check_and_run_due_scans()
            except Exception as e:
                logger.error(f"Scheduler error: {e}")
            
            await asyncio.sleep(self.check_interval)
    
    async def _check_and_run_due_scans(self):
        """Check for and execute any due scans"""
        db = self._get_db()
        due_scans = db.get_due_scans()
        
        for schedule in due_scans:
            try:
                logger.info(f"Launching scheduled scan for {schedule['target']}")
                
                # Create a new scan session
                session = db.create_scan_session(
                    target=schedule["target"],
                    metadata={"scheduled": True, "schedule_id": schedule["id"]}
                )
                
                # Log event
                db.add_scan_event(
                    session.id,
                    "scheduled_scan_launched",
                    f"Automatically launched from schedule {schedule['id']}"
                )
                
                # Update last_run and calculate next_run
                now = datetime.utcnow()
                next_run = self._calculate_next_run(schedule["cron_expr"])
                
                db.update_scheduled_scan(
                    schedule["id"],
                    last_run=now.isoformat(),
                    next_run=next_run.isoformat() if next_run else None
                )
                
            except Exception as e:
                logger.error(f"Failed to launch scheduled scan {schedule['id']}: {e}")
    
    def _calculate_next_run(self, cron_expr: str) -> datetime:
        """
        Calculate next run time from a simple cron expression.
        
        Supports basic intervals:
        - '*/N * * * *' = every N minutes
        - '0 */N * * *' = every N hours
        - '0 0 */N * *' = every N days
        
        Falls back to 6 hours if expression can't be parsed.
        """
        try:
            parts = cron_expr.strip().split()
            if len(parts) >= 5:
                # Check for minute interval
                if parts[0].startswith("*/"):
                    minutes = int(parts[0][2:])
                    return datetime.utcnow() + timedelta(minutes=minutes)
                # Check for hour interval
                elif parts[1].startswith("*/"):
                    hours = int(parts[1][2:])
                    return datetime.utcnow() + timedelta(hours=hours)
                # Check for day interval
                elif parts[2].startswith("*/"):
                    days = int(parts[2][2:])
                    return datetime.utcnow() + timedelta(days=days)
        except (ValueError, IndexError):
            pass
        
        # Default: next run in 6 hours
        return datetime.utcnow() + timedelta(hours=6)


# Singleton worker instance
_worker = None


def get_scheduler_worker() -> SchedulerWorker:
    """Get the singleton scheduler worker instance"""
    global _worker
    if _worker is None:
        _worker = SchedulerWorker()
    return _worker
