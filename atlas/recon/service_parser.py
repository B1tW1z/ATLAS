"""
ATLAS Service Parser

Parses and normalizes reconnaissance results.
"""

from typing import Dict, Any, List
from dataclasses import dataclass, field

from atlas.persistence.models import ReconResult
from atlas.utils.logger import get_logger

logger = get_logger(__name__)


@dataclass
class ParsedService:
    """Normalized service information"""
    port: int
    protocol: str
    service_type: str  # e.g., "web", "database", "ssh", "iot"
    name: str
    version: str = ""
    product: str = ""
    is_encrypted: bool = False
    
    @property
    def is_web(self) -> bool:
        return self.service_type == "web"
    
    @property
    def is_database(self) -> bool:
        return self.service_type == "database"


class ServiceParser:
    """
    Parses raw scan results into normalized service information.
    
    Provides categorization and filtering of discovered services.
    """
    
    # Service type mappings
    SERVICE_TYPES = {
        # Web services
        "http": "web",
        "https": "web",
        "http-alt": "web",
        "http-proxy": "web",
        
        # Databases
        "mysql": "database",
        "postgresql": "database",
        "mongodb": "database",
        "redis": "database",
        "mssql": "database",
        "oracle": "database",
        
        # Remote access
        "ssh": "remote",
        "telnet": "remote",
        "ftp": "file",
        "sftp": "file",
        
        # IoT
        "mqtt": "iot",
        "coap": "iot",
        "modbus": "iot",
        "bacnet": "iot",
        "upnp": "iot",
        
        # Other
        "smtp": "mail",
        "pop3": "mail",
        "imap": "mail",
        "dns": "infrastructure",
        "ldap": "directory",
    }
    
    # Encrypted service indicators
    ENCRYPTED_SERVICES = {"https", "ssl", "tls", "sftp", "imaps", "pop3s", "smtps"}
    
    def parse(self, scan_results: Dict[str, Any]) -> List[ParsedService]:
        """
        Parse scan results into normalized services.
        
        Args:
            scan_results: Raw scan results from ReconScanner
            
        Returns:
            List of ParsedService objects
        """
        services = []
        
        for port, info in scan_results.get("services", {}).items():
            port = int(port)
            service_name = info.get("service", "unknown")
            
            # Determine service type
            service_type = self._get_service_type(service_name, port)
            
            # Check encryption
            is_encrypted = self._is_encrypted(service_name, port)
            
            parsed = ParsedService(
                port=port,
                protocol=info.get("protocol", "tcp"),
                service_type=service_type,
                name=service_name,
                version=info.get("version", ""),
                product=info.get("product", ""),
                is_encrypted=is_encrypted
            )
            
            services.append(parsed)
            logger.debug(f"Parsed service: {parsed.name} on port {parsed.port}")
        
        return services
    
    def _get_service_type(self, service_name: str, port: int) -> str:
        """Determine service type from name and port"""
        service_name = service_name.lower()
        
        # Check direct mapping
        if service_name in self.SERVICE_TYPES:
            return self.SERVICE_TYPES[service_name]
        
        # Check partial matches
        for key, stype in self.SERVICE_TYPES.items():
            if key in service_name:
                return stype
        
        # Port-based guessing
        web_ports = {80, 443, 8080, 8443, 3000, 5000, 8000}
        if port in web_ports:
            return "web"
        
        db_ports = {3306, 5432, 27017, 6379, 1433}
        if port in db_ports:
            return "database"
        
        return "other"
    
    def _is_encrypted(self, service_name: str, port: int) -> bool:
        """Check if service is encrypted"""
        service_name = service_name.lower()
        
        if any(enc in service_name for enc in self.ENCRYPTED_SERVICES):
            return True
        
        # Common encrypted ports
        encrypted_ports = {443, 8443, 990, 993, 995, 465}
        return port in encrypted_ports
    
    def to_recon_results(self, scan_id: str, services: List[ParsedService]) -> List[ReconResult]:
        """Convert parsed services to ReconResult models for persistence"""
        return [
            ReconResult(
                scan_id=scan_id,
                port=s.port,
                protocol=s.protocol,
                service=s.name,
                version=s.version,
                product=s.product,
                extra_info=f"type:{s.service_type},encrypted:{s.is_encrypted}",
                state="open"
            )
            for s in services
        ]
    
    def filter_by_type(self, services: List[ParsedService], service_type: str) -> List[ParsedService]:
        """Filter services by type"""
        return [s for s in services if s.service_type == service_type]
    
    def get_web_services(self, services: List[ParsedService]) -> List[ParsedService]:
        """Get only web services"""
        return self.filter_by_type(services, "web")
    
    def get_database_services(self, services: List[ParsedService]) -> List[ParsedService]:
        """Get only database services"""
        return self.filter_by_type(services, "database")
