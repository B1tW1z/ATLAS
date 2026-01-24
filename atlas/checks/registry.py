"""
ATLAS Check Registry

Auto-discovers and manages vulnerability check modules.
"""

import importlib
import pkgutil
from typing import Dict, List, Optional, Any, Type
from pathlib import Path

from atlas.checks.base import VulnerabilityCheck, CheckMetadata
from atlas.utils.logger import get_logger

logger = get_logger(__name__)


class CheckRegistry:
    """
    Registry for vulnerability check discovery and management.
    
    Features:
    - Auto-discovery of check modules
    - Filtering by category, applicability
    - Check instantiation
    """
    
    def __init__(self, auto_discover: bool = True):
        """
        Initialize check registry.
        
        Args:
            auto_discover: If True, automatically discover checks
        """
        self._checks: Dict[str, Type[VulnerabilityCheck]] = {}
        self._instances: Dict[str, VulnerabilityCheck] = {}
        
        if auto_discover:
            self._discover_checks()
    
    def _discover_checks(self):
        """Auto-discover check modules"""
        # Discover generic checks
        try:
            from atlas.checks import generic
            self._discover_from_package(generic)
            logger.info(f"Discovered {len(self._checks)} vulnerability checks")
        except ImportError as e:
            logger.warning(f"Failed to import generic checks: {e}")
    
    def _discover_from_package(self, package):
        """Discover checks from a package"""
        package_path = Path(package.__file__).parent
        
        for _, module_name, _ in pkgutil.iter_modules([str(package_path)]):
            try:
                module = importlib.import_module(f"{package.__name__}.{module_name}")
                
                # Find VulnerabilityCheck subclasses
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    
                    if (isinstance(attr, type) and 
                        issubclass(attr, VulnerabilityCheck) and 
                        attr is not VulnerabilityCheck):
                        
                        # Instantiate to get metadata
                        try:
                            instance = attr()
                            check_id = instance.metadata.id
                            self._checks[check_id] = attr
                            self._instances[check_id] = instance
                            logger.debug(f"Registered check: {check_id}")
                        except Exception as e:
                            logger.warning(f"Failed to register {attr_name}: {e}")
                            
            except Exception as e:
                logger.warning(f"Failed to load module {module_name}: {e}")
    
    def register(self, check_class: Type[VulnerabilityCheck]):
        """Manually register a check class"""
        try:
            instance = check_class()
            check_id = instance.metadata.id
            self._checks[check_id] = check_class
            self._instances[check_id] = instance
            logger.debug(f"Manually registered check: {check_id}")
        except Exception as e:
            logger.error(f"Failed to register check: {e}")
    
    def get_check(self, check_id: str) -> Optional[VulnerabilityCheck]:
        """Get check instance by ID"""
        return self._instances.get(check_id)
    
    def get_all_checks(self) -> List[VulnerabilityCheck]:
        """Get all registered checks"""
        return list(self._instances.values())
    
    def get_check_metadata(self, check_id: str) -> Optional[CheckMetadata]:
        """Get check metadata by ID"""
        check = self._instances.get(check_id)
        return check.metadata if check else None
    
    def get_all_metadata(self) -> List[Dict[str, Any]]:
        """Get metadata for all checks"""
        return [check.metadata.to_dict() for check in self._instances.values()]
    
    def get_checks_by_category(self, category: str) -> List[VulnerabilityCheck]:
        """Get checks filtered by category"""
        return [
            check for check in self._instances.values()
            if check.metadata.category.lower() == category.lower()
        ]
    
    def get_applicable_checks(
        self,
        services: Dict[int, Dict[str, Any]],
        fingerprint: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """
        Get checks applicable to discovered services.
        
        Args:
            services: Discovered services
            fingerprint: Target fingerprint if identified
            
        Returns:
            List of applicable check metadata
        """
        applicable = []
        
        for check in self._instances.values():
            if check.is_applicable(services, fingerprint):
                meta = check.metadata.to_dict()
                meta["applicable"] = True
                applicable.append(meta)
        
        # Sort by category then severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        applicable.sort(key=lambda x: (x["category"], severity_order.get(x["severity"], 5)))
        
        return applicable
    
    def get_categories(self) -> List[str]:
        """Get list of all check categories"""
        categories = set()
        for check in self._instances.values():
            categories.add(check.metadata.category)
        return sorted(list(categories))
    
    def get_checks_summary(self) -> Dict[str, Any]:
        """Get summary of registered checks"""
        by_category = {}
        by_severity = {}
        
        for check in self._instances.values():
            cat = check.metadata.category
            sev = check.metadata.severity.value
            
            by_category[cat] = by_category.get(cat, 0) + 1
            by_severity[sev] = by_severity.get(sev, 0) + 1
        
        return {
            "total": len(self._instances),
            "by_category": by_category,
            "by_severity": by_severity,
            "categories": list(by_category.keys())
        }
