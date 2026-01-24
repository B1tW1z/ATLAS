"""
ATLAS Reconnaissance Scanner

Nmap-based port and service enumeration with fallback support.
"""

import asyncio
import re
import shutil
from typing import Dict, Any, List, Optional
from urllib.parse import urlparse

from atlas.utils.logger import get_logger
from atlas.utils.config import get_config

logger = get_logger(__name__)


class ReconScanner:
    """
    Reconnaissance scanner using Nmap for port/service enumeration.
    
    Features:
    - Async execution
    - Service version detection
    - Fallback for missing Nmap
    """
    
    def __init__(self):
        self._config = get_config()
        self._nmap_available = self._check_nmap()
    
    def _check_nmap(self) -> bool:
        """Check if Nmap is available"""
        nmap_path = self._config.nmap_path or shutil.which("nmap")
        if nmap_path:
            logger.info(f"Nmap found at: {nmap_path}")
            return True
        logger.warning("Nmap not found - using fallback scanner")
        return False
    
    async def scan(self, target: str) -> Dict[str, Any]:
        """
        Perform reconnaissance scan on target.
        
        Args:
            target: URL or IP address
            
        Returns:
            Dict with ports, services, and fingerprint info
        """
        # Parse target
        parsed = urlparse(target)
        host = parsed.hostname or target
        
        # Remove protocol and path for IP/hostname
        if not parsed.scheme:
            host = target.split("/")[0].split(":")[0]
        
        logger.info(f"Starting reconnaissance on: {host}")
        
        if self._nmap_available:
            return await self._nmap_scan(host)
        else:
            return await self._fallback_scan(host, parsed)
    
    async def _nmap_scan(self, host: str) -> Dict[str, Any]:
        """Execute Nmap scan"""
        try:
            import nmap
            
            nm = nmap.PortScanner()
            
            # Run scan in thread pool to avoid blocking
            loop = asyncio.get_event_loop()
            
            def run_scan():
                return nm.scan(
                    hosts=host,
                    arguments=self._config.nmap_default_args
                )
            
            await loop.run_in_executor(None, run_scan)
            
            # Parse results
            results = {
                "host": host,
                "ports": [],
                "services": {},
                "os_matches": [],
                "fingerprint": None
            }
            
            if host in nm.all_hosts():
                host_info = nm[host]
                
                # Extract port/service info
                for proto in host_info.all_protocols():
                    for port in host_info[proto].keys():
                        port_info = host_info[proto][port]
                        
                        if port_info["state"] == "open":
                            results["ports"].append(port)
                            results["services"][port] = {
                                "protocol": proto,
                                "service": port_info.get("name", "unknown"),
                                "version": port_info.get("version", ""),
                                "product": port_info.get("product", ""),
                                "extra_info": port_info.get("extrainfo", ""),
                                "state": port_info["state"]
                            }
                
                # Try to determine fingerprint
                results["fingerprint"] = self._analyze_fingerprint(results["services"])
            
            logger.info(f"Nmap scan complete: {len(results['ports'])} open ports")
            return results
            
        except ImportError:
            logger.error("python-nmap not installed")
            return await self._fallback_scan(host, urlparse(f"http://{host}"))
        except Exception as e:
            logger.error(f"Nmap scan failed: {e}")
            return await self._fallback_scan(host, urlparse(f"http://{host}"))
    
    async def _fallback_scan(self, host: str, parsed) -> Dict[str, Any]:
        """
        Fallback scanner using socket connections.
        
        Used when Nmap is not available.
        """
        import socket
        
        logger.info("Using fallback port scanner")
        
        results = {
            "host": host,
            "ports": [],
            "services": {},
            "fingerprint": None
        }
        
        # Common web ports to check
        common_ports = [
            (80, "http"),
            (443, "https"),
            (8080, "http-alt"),
            (8443, "https-alt"),
            (3000, "http"),  # Node.js
            (5000, "http"),  # Flask
            (8000, "http"),  # Various
            (22, "ssh"),
            (21, "ftp"),
            (3306, "mysql"),
            (5432, "postgresql"),
            (27017, "mongodb"),
            (6379, "redis"),
            (1883, "mqtt"),  # IoT
            (8883, "mqtt-tls"),
        ]
        
        async def check_port(port: int, service: str):
            try:
                loop = asyncio.get_event_loop()
                
                def try_connect():
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    result = sock.connect_ex((host, port))
                    sock.close()
                    return result == 0
                
                is_open = await loop.run_in_executor(None, try_connect)
                
                if is_open:
                    return (port, service)
            except Exception:
                pass
            return None
        
        # Check ports concurrently
        tasks = [check_port(port, service) for port, service in common_ports]
        port_results = await asyncio.gather(*tasks)
        
        for result in port_results:
            if result:
                port, service = result
                results["ports"].append(port)
                results["services"][port] = {
                    "protocol": "tcp",
                    "service": service,
                    "version": "",
                    "product": "",
                    "extra_info": "",
                    "state": "open"
                }
        
        # Try HTTP fingerprinting if web ports found
        if any(p in results["ports"] for p in [80, 443, 8080, 3000, 5000, 8000]):
            results["fingerprint"] = await self._http_fingerprint(host, parsed)
        
        logger.info(f"Fallback scan complete: {len(results['ports'])} open ports")
        return results
    
    async def _http_fingerprint(self, host: str, parsed) -> Optional[str]:
        """Attempt HTTP fingerprinting"""
        try:
            import httpx
            
            port = parsed.port or 80
            scheme = parsed.scheme or "http"
            url = f"{scheme}://{host}:{port}/"
            
            async with httpx.AsyncClient(timeout=10, verify=False) as client:
                response = await client.get(url)
                
                headers = response.headers
                body = response.text.lower()
                
                # Check for known frameworks/apps
                fingerprints = {
                    "juice-shop": ["juice shop", "owasp juice"],
                    "dvwa": ["damn vulnerable", "dvwa"],
                    "webgoat": ["webgoat"],
                    "mutillidae": ["mutillidae"],
                    "bwapp": ["bwapp", "buggy web"],
                    "wordpress": ["wp-content", "wp-includes"],
                    "drupal": ["drupal"],
                    "joomla": ["joomla"],
                    "express": ["express"],
                    "flask": ["werkzeug"],
                    "django": ["csrfmiddlewaretoken"],
                    "spring": ["spring"],
                    "asp.net": ["asp.net", "__viewstate"],
                }
                
                server = headers.get("server", "").lower()
                powered_by = headers.get("x-powered-by", "").lower()
                
                for name, patterns in fingerprints.items():
                    if any(p in body or p in server or p in powered_by for p in patterns):
                        logger.info(f"Fingerprint detected: {name}")
                        return name
                
        except Exception as e:
            logger.debug(f"HTTP fingerprinting failed: {e}")
        
        return None
    
    def _analyze_fingerprint(self, services: Dict[int, Dict]) -> Optional[str]:
        """Analyze services to determine target type"""
        service_names = [s.get("service", "") for s in services.values()]
        products = [s.get("product", "").lower() for s in services.values()]
        
        # Check for known vulnerable apps
        for product in products:
            if "juice" in product:
                return "juice-shop"
            if "dvwa" in product:
                return "dvwa"
            if "webgoat" in product:
                return "webgoat"
        
        # Check for IoT indicators
        iot_services = ["mqtt", "coap", "modbus", "bacnet"]
        if any(s in service_names for s in iot_services):
            return "iot-device"
        
        return None
