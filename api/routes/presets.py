"""
ATLAS Presets API Routes

Endpoints for demo preset targets.
"""

from fastapi import APIRouter, HTTPException
from typing import List, Dict, Any

router = APIRouter(prefix="/presets", tags=["Presets"])


@router.get("")
async def list_presets():
    """
    List all available demo preset targets.
    """
    from atlas.presets import list_presets
    
    presets_list = list_presets()
    
    return {
        "presets": [
            {
                "id": p.id,
                "name": p.name,
                "description": p.description,
                "category": p.category.value,
                "github_url": p.github_url,
                "default_url": p.default_url,
                "setup_instructions": p.setup_instructions,
                "vulnerability_count": len(p.vulnerabilities),
                "tags": p.tags
            }
            for p in presets_list
        ]
    }


@router.get("/{preset_id}")
async def get_preset(preset_id: str):
    """
    Get detailed information about a preset target.
    """
    from atlas.presets import get_preset
    
    preset = get_preset(preset_id)
    
    if not preset:
        raise HTTPException(status_code=404, detail=f"Preset '{preset_id}' not found")
    
    # Group vulnerabilities by category
    by_category = preset.get_vulnerabilities_by_category()
    
    return {
        "id": preset.id,
        "name": preset.name,
        "description": preset.description,
        "category": preset.category.value,
        "github_url": preset.github_url,
        "default_url": preset.default_url,
        "setup_instructions": preset.setup_instructions,
        "tags": preset.tags,
        "vulnerabilities_by_category": {
            cat: [
                {
                    "id": v.id,
                    "name": v.name,
                    "category": v.category,
                    "severity": v.severity,
                    "description": v.description,
                    "test_command": v.test_command,
                    "check_id": v.check_id,
                    "owasp_category": v.owasp_category,
                    "cwe_id": v.cwe_id
                }
                for v in vulns
            ]
            for cat, vulns in by_category.items()
        }
    }


@router.get("/{preset_id}/vulnerabilities")
async def get_preset_vulnerabilities(preset_id: str):
    """
    Get all vulnerabilities for a preset target.
    """
    from atlas.presets import get_preset
    
    preset = get_preset(preset_id)
    
    if not preset:
        raise HTTPException(status_code=404, detail=f"Preset '{preset_id}' not found")
    
    return {
        "preset_id": preset_id,
        "vulnerabilities": [
            {
                "id": v.id,
                "name": v.name,
                "category": v.category,
                "severity": v.severity,
                "description": v.description,
                "test_command": v.test_command,
                "check_id": v.check_id,
                "owasp_category": v.owasp_category,
                "cwe_id": v.cwe_id
            }
            for v in preset.vulnerabilities
        ]
    }
