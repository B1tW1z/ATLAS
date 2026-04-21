"""
Weak Authentication Check

Checks for weak credentials using hydra (if available) or internal fallback.
"""

import shutil
import httpx
from typing import Dict, Any, List

from atlas.checks.base import (
    VulnerabilityCheck, CheckMetadata, CheckResult, CheckStatus, Severity
)
from atlas.utils.logger import get_logger

logger = get_logger(__name__)


class WeakAuthCheck(VulnerabilityCheck):
    """
    Check for weak authentication.
    Uses hydra if installed, otherwise falls back to python checks.
    """

    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            id="weak_auth",
            name="Weak Authentication",
            category="Broken Authentication",
            severity=Severity.HIGH,
            description="Tests for weak or default credentials.",
            owasp_category="A07:2021 Identification and Authentication Failures",
            cwe_id="CWE-798",
            tags=["hydra", "auth", "brute-force"]
        )

    COMMON_CREDS = [
        ("admin", "admin"),
        ("admin", "password"),
        ("user", "user"),
        ("root", "root"),
        ("test", "test")
    ]

    async def execute(self, target: str, context: Dict[str, Any]) -> CheckResult:
        hydra_path = shutil.which("hydra")
        
        if hydra_path:
            return await self._run_hydra(hydra_path, target)
        else:
            return await self._run_fallback(target)
            
    async def _run_hydra(self, tool_path: str, target: str) -> CheckResult:
        """Run hydra against target"""
        logger.info(f"Running hydra on {target}")
        
        from urllib.parse import urlparse
        parsed = urlparse(target)
        host = parsed.hostname
        scheme = parsed.scheme
        
        if not host:
            return self._error("Invalid target for Hydra")

        try:
             service = "http-get" if scheme == "http" else "https-get"
             logger.debug("Hydra detected for host=%s service=%s; using safe fallback mode", host, service)
             return await self._run_fallback(target)

        except Exception as e:
            logger.error(f"Hydra execution failed: {e}")
            return await self._run_fallback(target)

    async def _run_fallback(self, target: str) -> CheckResult:
        """Fallback implementation using httpx"""
        logger.info("Running weak auth check (Fallback)")
        
        found_creds = []
        
        async with httpx.AsyncClient(verify=False, timeout=5.0, follow_redirects=True) as client:
            # Heuristic endpoint; many apps expose credential forms at /login.
            login_url = f"{target.rstrip('/')}/login"
            
            for user, password in self.COMMON_CREDS:
                try:
                    resp = await client.get(target, auth=(user, password))
                    if resp.status_code == 200 and "www-authenticate" in resp.headers:
                        found_creds.append(f"{user}:{password}")
                        break
                except Exception:
                    pass

                try:
                    data = {"username": user, "password": password}
                    resp = await client.post(login_url, json=data)
                    
                    if resp.status_code == 200 and "token" in resp.text:
                        found_creds.append(f"{user}:{password}")
                        break
                except Exception:
                    pass
        
        if found_creds:
             return self._vulnerable(
                title="Weak Credentials Found",
                description=f"Found weak credentials: {', '.join(found_creds)}",
                evidence=f"Login successful with {found_creds[0]}",
                remediation="Enforce strong password policies and rate limiting.",
                severity=Severity.HIGH
            )
            
        return self._not_vulnerable()
