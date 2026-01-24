"""
Cross-Site Scripting (XSS) Check

Tests for reflected and basic DOM-based XSS vulnerabilities.
"""

import re
import time
import html
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from atlas.checks.base import (
    VulnerabilityCheck, CheckMetadata, CheckResult, CheckStatus, Severity
)
from atlas.utils.logger import get_logger

logger = get_logger(__name__)


class XSSCheck(VulnerabilityCheck):
    """
    Cross-Site Scripting (XSS) vulnerability check.
    
    Tests for reflected XSS using various payloads.
    """
    
    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            id="xss_reflected",
            name="Cross-Site Scripting (Reflected)",
            category="Injection",
            severity=Severity.MEDIUM,
            description="Tests for reflected XSS vulnerabilities by injecting script payloads",
            owasp_category="A03:2021 Injection",
            cwe_id="CWE-79",
            prerequisites=[],
            applicable_services=["http", "https", "http-alt"],
            tags=["xss", "injection", "javascript"]
        )
    
    # XSS test payloads - minimal set  
    PAYLOADS = [
        # Basic script injection
        '<script>alert("XSS")</script>',
        '<script>alert(1)</script>',
        
        # Event handlers
        '<img src=x onerror=alert(1)>',
        '<svg onload=alert(1)>',
        '<body onload=alert(1)>',
        
        # Attribute injection
        '" onmouseover="alert(1)"',
        "' onmouseover='alert(1)'",
        
        # JavaScript protocol
        'javascript:alert(1)',
        
        # Encoded variants
        '<script>alert(String.fromCharCode(88,83,83))</script>',
        '<img src=x onerror=alert`1`>',
    ]
    
    # Unique marker for detection
    MARKER = "ATLAS_XSS_TEST_"
    
    async def execute(self, target: str, context: Dict[str, Any]) -> CheckResult:
        """Execute XSS check"""
        import httpx
        
        start_time = time.time()
        
        try:
            async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
                vulnerable_points = []
                
                # Test URL parameters
                param_results = await self._test_url_params(client, target)
                vulnerable_points.extend(param_results)
                
                # Test forms
                form_results = await self._test_forms(client, target)
                vulnerable_points.extend(form_results)
                
                execution_time = time.time() - start_time
                
                if vulnerable_points:
                    return self._vulnerable(
                        title="Reflected XSS Vulnerability Detected",
                        description=f"Found {len(vulnerable_points)} potential XSS injection point(s)",
                        evidence=self._format_evidence(vulnerable_points),
                        remediation=self._get_remediation(),
                        url=target,
                        parameter=vulnerable_points[0].get("parameter"),
                        payload=vulnerable_points[0].get("payload"),
                        cvss_score=6.1,
                        execution_time=execution_time
                    )
                else:
                    return self._not_vulnerable(
                        description="No reflected XSS vulnerabilities detected",
                        execution_time=execution_time
                    )
                    
        except Exception as e:
            logger.error(f"XSS check error: {e}")
            return self._error(str(e))
    
    async def _test_url_params(self, client, target: str) -> List[Dict]:
        """Test URL parameters for XSS"""
        vulnerable = []
        parsed = urlparse(target)
        params = parse_qs(parsed.query)
        
        if not params:
            # Add common test parameters
            params = {"q": ["test"], "search": ["test"], "input": ["test"]}
        
        for param_name in list(params.keys()):
            # First test with marker to detect reflection
            marker = f"{self.MARKER}{param_name}"
            test_params = params.copy()
            test_params[param_name] = [marker]
            
            new_query = urlencode(test_params, doseq=True)
            test_url = urlunparse(parsed._replace(query=new_query))
            
            try:
                response = await client.get(test_url)
                
                # Check if marker is reflected
                if marker in response.text:
                    # Parameter is reflected, test payloads
                    for payload in self.PAYLOADS[:6]:  # Limit tests
                        test_params[param_name] = [payload]
                        new_query = urlencode(test_params, doseq=True)
                        payload_url = urlunparse(parsed._replace(query=new_query))
                        
                        resp = await client.get(payload_url)
                        
                        # Check if payload is reflected unencoded
                        if self._check_xss_reflection(payload, resp.text):
                            vulnerable.append({
                                "type": "url_parameter",
                                "parameter": param_name,
                                "payload": payload,
                                "evidence": self._extract_context(payload, resp.text),
                                "url": payload_url
                            })
                            break
                            
            except Exception:
                continue
        
        return vulnerable
    
    async def _test_forms(self, client, target: str) -> List[Dict]:
        """Test form inputs for XSS"""
        vulnerable = []
        
        try:
            response = await client.get(target)
            
            # Find forms
            form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
            input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*type=["\']?(text|search|hidden)?["\']?[^>]*>'
            
            forms = re.findall(form_pattern, response.text, re.IGNORECASE | re.DOTALL)
            
            for action, form_content in forms[:2]:  # Limit forms
                inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
                input_names = [inp[0] for inp in inputs]
                
                if not input_names:
                    continue
                
                for input_name in input_names[:3]:  # Limit inputs
                    # Test marker first
                    marker = f"{self.MARKER}{input_name}"
                    form_data = {inp: "test" for inp in input_names}
                    form_data[input_name] = marker
                    
                    try:
                        from urllib.parse import urljoin
                        form_url = urljoin(target, action) if action else target
                        
                        resp = await client.post(form_url, data=form_data)
                        
                        if marker in resp.text:
                            # Test payloads
                            for payload in self.PAYLOADS[:4]:
                                form_data[input_name] = payload
                                resp = await client.post(form_url, data=form_data)
                                
                                if self._check_xss_reflection(payload, resp.text):
                                    vulnerable.append({
                                        "type": "form_input",
                                        "parameter": input_name,
                                        "payload": payload,
                                        "evidence": self._extract_context(payload, resp.text),
                                        "url": form_url
                                    })
                                    break
                                    
                    except Exception:
                        continue
                        
        except Exception as e:
            logger.debug(f"Form XSS testing error: {e}")
        
        return vulnerable
    
    def _check_xss_reflection(self, payload: str, response_text: str) -> bool:
        """Check if XSS payload is reflected without encoding"""
        # Check for exact payload
        if payload in response_text:
            return True
        
        # Check for common XSS patterns in response
        xss_patterns = [
            r'<script[^>]*>.*?alert\s*\(',
            r'on\w+\s*=\s*["\']?alert',
            r'javascript:\s*alert',
            r'<img[^>]*onerror\s*=',
            r'<svg[^>]*onload\s*=',
        ]
        
        for pattern in xss_patterns:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        return False
    
    def _extract_context(self, payload: str, text: str) -> str:
        """Extract context around reflected payload"""
        idx = text.find(payload)
        if idx >= 0:
            start = max(0, idx - 50)
            end = min(len(text), idx + len(payload) + 50)
            return f"...{text[start:end]}..."
        
        # Try to find script/event pattern
        for pattern in [r'<script.*?</script>', r'on\w+=["\'][^"\']*["\']']:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                return match.group(0)[:100]
        
        return "XSS payload reflected in response"
    
    def _format_evidence(self, points: List[Dict]) -> str:
        """Format vulnerability evidence"""
        lines = []
        for i, point in enumerate(points, 1):
            lines.append(f"{i}. {point['type']}: {point['parameter']}")
            lines.append(f"   Payload: {point['payload'][:50]}")
            lines.append(f"   Context: {point['evidence'][:100]}")
        return "\n".join(lines)
    
    def _get_remediation(self) -> str:
        """Get remediation guidance"""
        return """
1. Encode all user input before output (HTML entity encoding)
2. Use Content Security Policy (CSP) headers
3. Implement HttpOnly and Secure flags on cookies
4. Use framework-provided auto-escaping features
5. Validate and sanitize input using allowlists
6. Use DOM manipulation methods instead of innerHTML
7. Apply context-aware encoding (HTML, JavaScript, URL, CSS)
        """.strip()
