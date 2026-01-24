"""
ATLAS Target Fingerprinting

Identifies known vulnerable applications and frameworks.
"""

from typing import Dict, Any, Optional, List
from dataclasses import dataclass
import re

from atlas.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class TargetProfile:
    """Profile of identified target application"""
    name: str
    category: str  # "vulnerable_app", "framework", "cms", "iot"
    confidence: float  # 0.0 - 1.0
    version: Optional[str] = None
    known_vulns: List[str] = None
    recommended_checks: List[str] = None
    
    def __post_init__(self):
        if self.known_vulns is None:
            self.known_vulns = []
        if self.recommended_checks is None:
            self.recommended_checks = []


# Known target signatures
TARGET_SIGNATURES = {
    "juice-shop": {
        "category": "vulnerable_app",
        "patterns": {
            "body": ["juice shop", "owasp juice", "juice-shop"],
            "headers": ["juice"],
            "paths": ["/api/Products", "/rest/user/login"],
        },
        "known_vulns": ["sqli", "xss", "xxe", "broken-auth", "sensitive-data"],
        "recommended_checks": [
            "sqli_basic", "xss_reflected", "broken_auth", 
            "sensitive_data_exposure", "api_security"
        ]
    },
    "dvwa": {
        "category": "vulnerable_app",
        "patterns": {
            "body": ["damn vulnerable web application", "dvwa"],
            "headers": [],
            "paths": ["/DVWA/", "/dvwa/"],
        },
        "known_vulns": ["sqli", "xss", "csrf", "file-upload", "command-injection"],
        "recommended_checks": [
            "sqli_basic", "xss_reflected", "command_injection", 
            "file_upload", "csrf"
        ]
    },
    "webgoat": {
        "category": "vulnerable_app",
        "patterns": {
            "body": ["webgoat"],
            "headers": [],
            "paths": ["/WebGoat/"],
        },
        "known_vulns": ["sqli", "xss", "xxe", "insecure-deserialization"],
        "recommended_checks": [
            "sqli_basic", "xss_reflected", "xxe", "insecure_deserialization"
        ]
    },
    "bwapp": {
        "category": "vulnerable_app",
        "patterns": {
            "body": ["bwapp", "buggy web application"],
            "headers": [],
            "paths": ["/bWAPP/"],
        },
        "known_vulns": ["sqli", "xss", "ldap-injection", "ssrf"],
        "recommended_checks": [
            "sqli_basic", "xss_reflected", "ssrf", "ldap_injection"
        ]
    },
    "mutillidae": {
        "category": "vulnerable_app",
        "patterns": {
            "body": ["mutillidae", "nowasp"],
            "headers": [],
            "paths": ["/mutillidae/"],
        },
        "known_vulns": ["sqli", "xss", "clickjacking"],
        "recommended_checks": [
            "sqli_basic", "xss_reflected", "clickjacking"
        ]
    },
    "wordpress": {
        "category": "cms",
        "patterns": {
            "body": ["wp-content", "wp-includes"],
            "headers": ["wordpress"],
            "paths": ["/wp-admin/", "/wp-login.php"],
        },
        "known_vulns": ["sqli", "xss", "file-upload", "plugin-vulns"],
        "recommended_checks": [
            "sqli_basic", "xss_reflected", "wordpress_enum", "directory_traversal"
        ]
    },
    "express": {
        "category": "framework",
        "patterns": {
            "body": [],
            "headers": ["express"],
            "paths": [],
        },
        "known_vulns": ["xss", "nosqli", "prototype-pollution"],
        "recommended_checks": [
            "xss_reflected", "nosql_injection", "prototype_pollution"
        ]
    },
    "flask": {
        "category": "framework",
        "patterns": {
            "body": [],
            "headers": ["werkzeug"],
            "paths": [],
        },
        "known_vulns": ["ssti", "xss", "debug-mode"],
        "recommended_checks": [
            "ssti", "xss_reflected", "debug_endpoints"
        ]
    },
    "django": {
        "category": "framework",
        "patterns": {
            "body": ["csrfmiddlewaretoken"],
            "headers": [],
            "paths": ["/admin/"],
        },
        "known_vulns": ["sqli", "xss", "csrf"],
        "recommended_checks": [
            "sqli_basic", "xss_reflected", "csrf"
        ]
    },
}


class TargetFingerprint:
    """
    Identifies target applications based on signatures.
    
    Features:
    - HTTP response analysis
    - Header inspection  
    - Path probing
    - Confidence scoring
    """
    
    def __init__(self):
        self._signatures = TARGET_SIGNATURES
    
    async def identify(
        self,
        target: str,
        http_response: Optional[Dict[str, Any]] = None,
        services: Optional[Dict[int, Dict]] = None
    ) -> Optional[TargetProfile]:
        """
        Identify target application.
        
        Args:
            target: Target URL
            http_response: Optional pre-fetched HTTP response
            services: Optional discovered services
            
        Returns:
            TargetProfile if identified, None otherwise
        """
        # Fetch response if not provided
        if http_response is None:
            http_response = await self._fetch_response(target)
        
        if not http_response:
            return None
        
        body = http_response.get("body", "").lower()
        headers = {k.lower(): v.lower() for k, v in http_response.get("headers", {}).items()}
        
        best_match = None
        best_confidence = 0.0
        
        for name, sig in self._signatures.items():
            confidence = self._calculate_confidence(body, headers, sig)
            
            if confidence > best_confidence and confidence >= 0.5:
                best_confidence = confidence
                best_match = TargetProfile(
                    name=name,
                    category=sig["category"],
                    confidence=confidence,
                    known_vulns=sig.get("known_vulns", []),
                    recommended_checks=sig.get("recommended_checks", [])
                )
        
        if best_match:
            logger.info(f"Target identified: {best_match.name} (confidence: {best_match.confidence:.1%})")
        else:
            logger.info("Target not identified - will use generic checks")
        
        return best_match
    
    def _calculate_confidence(
        self,
        body: str,
        headers: Dict[str, str],
        signature: Dict
    ) -> float:
        """Calculate match confidence score"""
        patterns = signature.get("patterns", {})
        matches = 0
        total_patterns = 0
        
        # Check body patterns
        for pattern in patterns.get("body", []):
            total_patterns += 1
            if pattern.lower() in body:
                matches += 1
        
        # Check header patterns
        header_str = " ".join(headers.values())
        for pattern in patterns.get("headers", []):
            total_patterns += 1
            if pattern.lower() in header_str:
                matches += 1
        
        if total_patterns == 0:
            return 0.0
        
        return matches / total_patterns
    
    async def _fetch_response(self, target: str) -> Optional[Dict[str, Any]]:
        """Fetch HTTP response for fingerprinting"""
        try:
            import httpx
            
            async with httpx.AsyncClient(timeout=10, verify=False, follow_redirects=True) as client:
                response = await client.get(target)
                
                return {
                    "body": response.text,
                    "headers": dict(response.headers),
                    "status": response.status_code
                }
        except Exception as e:
            logger.debug(f"Failed to fetch response: {e}")
            return None
    
    async def probe_paths(self, target: str, paths: List[str]) -> List[str]:
        """Probe target for specific paths"""
        found_paths = []
        
        try:
            import httpx
            
            async with httpx.AsyncClient(timeout=5, verify=False) as client:
                for path in paths:
                    try:
                        url = target.rstrip("/") + path
                        response = await client.get(url)
                        
                        if response.status_code < 400:
                            found_paths.append(path)
                    except Exception:
                        pass
        except Exception as e:
            logger.debug(f"Path probing failed: {e}")
        
        return found_paths
    
    def get_recommended_checks(self, profile: Optional[TargetProfile]) -> List[str]:
        """Get recommended checks for target profile"""
        if profile:
            return profile.recommended_checks
        
        # Return generic checks for unknown targets
        return [
            "sqli_basic",
            "xss_reflected",
            "directory_traversal",
            "sensitive_data_exposure",
            "security_headers"
        ]
