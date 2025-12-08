"""CycloneDX SBOM builder."""

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from models import ComponentRecord


def build_sbom(components: List[ComponentRecord], component_type: str = "library") -> dict:
    """
    Build a CycloneDX 1.6 JSON SBOM from component records.
    
    Args:
        components: List of component records
        component_type: Type of components (default: "library")
    
    Returns:
        Dictionary representing the SBOM
    """
    sbom_components = []
    
    for comp in components:
        component_obj = {
            "type": component_type,
            "name": comp.component_name,
            "version": comp.component_version,
            "supplier": {
                "name": comp.supplier_name
            },
            "swid": {
                "tagId": comp.swid_tag_id
            }
        }
        sbom_components.append(component_obj)
    
    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "tools": [
                {
                    "vendor": "Finite State",
                    "name": "SBOM Component Injection Script",
                    "version": "0.1.0"
                }
            ]
        },
        "components": sbom_components
    }
    
    return sbom


def write_sbom(sbom: dict, output_path: str) -> None:
    """
    Write SBOM to JSON file.
    
    Args:
        sbom: SBOM dictionary
        output_path: Path to output file
    """
    output_file = Path(output_path)
    output_file.parent.mkdir(parents=True, exist_ok=True)
    
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(sbom, f, indent=2, ensure_ascii=False)

