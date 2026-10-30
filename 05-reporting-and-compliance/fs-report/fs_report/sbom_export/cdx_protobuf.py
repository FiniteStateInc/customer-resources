"""CycloneDX protobuf encoding: converts the validated CycloneDX JSON dict.

The converter is explicit: it knows exactly the JSON keys the writer emits
(see ``cyclonedx_writer``). Any other key (or unknown enum value) raises
``NotImplementedError`` so a new writer field can't be silently dropped.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from types import ModuleType
from typing import Any, Literal

from fs_report.sbom_export.cdx_proto import bom_1_6_pb2, bom_1_7_pb2

_MODULES: dict[str, ModuleType] = {"1.6": bom_1_6_pb2, "1.7": bom_1_7_pb2}

# kind: s scalar | t timestamp | e enum | m message | M repeated message
#       | E repeated enum | S repeated scalar | D dependsOn refs | x ignored envelope key
# tuple = (proto field, kind, arg); arg = message class or enum-name prefix
_Spec = dict[str, tuple[str, str, str]]
_SPECS: dict[str, _Spec] = {
    "Bom": {
        "$schema": ("", "x", ""),
        "bomFormat": ("", "x", ""),  # implied by the proto message type
        "specVersion": ("spec_version", "s", ""),
        "version": ("version", "s", ""),
        "serialNumber": ("serial_number", "s", ""),
        "metadata": ("metadata", "m", "Metadata"),
        "components": ("components", "M", "Component"),
        "dependencies": ("dependencies", "M", "Dependency"),
        "vulnerabilities": ("vulnerabilities", "M", "Vulnerability"),
        "compositions": ("compositions", "M", "Composition"),
    },
    "Composition": {
        "aggregate": ("aggregate", "e", "AGGREGATE_"),
        "dependencies": ("dependencies", "S", ""),
    },
    "Metadata": {
        "timestamp": ("timestamp", "t", ""),
        "tools": ("tools", "m", "Tool"),
        "authors": ("authors", "M", "OrganizationalContact"),
        "manufacturer": ("manufacturer", "m", "OrganizationalEntity"),
        "supplier": ("supplier", "m", "OrganizationalEntity"),
        "licenses": ("licenses", "M", "LicenseChoice"),
        "lifecycles": ("lifecycles", "M", "Lifecycles"),
        "component": ("component", "m", "Component"),
    },
    "Tool": {"components": ("components", "M", "Component")},
    "Lifecycles": {"phase": ("phase", "e", "LIFECYCLE_PHASE_")},
    "OrganizationalEntity": {
        "name": ("name", "s", ""),
        "url": ("url", "S", ""),
        "contact": ("contact", "M", "OrganizationalContact"),
    },
    "OrganizationalContact": {
        "name": ("name", "s", ""),
        "email": ("email", "s", ""),
    },
    "Component": {
        "bom-ref": ("bom_ref", "s", ""),
        "type": ("type", "e", "CLASSIFICATION_"),
        "group": ("group", "s", ""),
        "name": ("name", "s", ""),
        "version": ("version", "s", ""),
        "description": ("description", "s", ""),
        "purl": ("purl", "s", ""),
        "cpe": ("cpe", "s", ""),
        "supplier": ("supplier", "m", "OrganizationalEntity"),
        "authors": ("authors", "M", "OrganizationalContact"),
        "licenses": ("licenses", "M", "LicenseChoice"),
        "hashes": ("hashes", "M", "Hash"),
        "copyright": ("copyright", "s", ""),
        "externalReferences": (
            "external_references",
            "M",
            "ExternalReference",
        ),
        "properties": ("properties", "M", "Property"),
        "evidence": ("evidence", "m", "Evidence"),
        "pedigree": ("pedigree", "m", "Pedigree"),
        "components": ("components", "M", "Component"),
    },
    "Pedigree": {"ancestors": ("ancestors", "M", "Component")},
    "LicenseChoice": {
        "license": ("license", "m", "License"),
        "expression": ("expression", "s", ""),
        "acknowledgement": (
            "acknowledgement",
            "e",
            "LICENSE_ACKNOWLEDGEMENT_ENUMERATION_",
        ),
    },
    "License": {
        "id": ("id", "s", ""),
        "name": ("name", "s", ""),
        "acknowledgement": (
            "acknowledgement",
            "e",
            "LICENSE_ACKNOWLEDGEMENT_ENUMERATION_",
        ),
    },
    "Hash": {
        "alg": ("alg", "e", "HASH_ALG_"),
        "content": ("value", "s", ""),
    },
    "ExternalReference": {
        "type": ("type", "e", "EXTERNAL_REFERENCE_TYPE_"),
        "url": ("url", "s", ""),
    },
    "Property": {"name": ("name", "s", ""), "value": ("value", "s", "")},
    "Evidence": {"identity": ("identity", "M", "EvidenceIdentity")},
    "EvidenceIdentity": {
        "field": ("field", "e", "EVIDENCE_FIELD_"),
        "concludedValue": ("concludedValue", "s", ""),
    },
    "Dependency": {
        "ref": ("ref", "s", ""),
        "dependsOn": ("dependencies", "D", ""),  # list of refs
    },
    "Vulnerability": {
        "bom-ref": ("bom_ref", "s", ""),
        "id": ("id", "s", ""),
        "source": ("source", "m", "Source"),
        "ratings": ("ratings", "M", "VulnerabilityRating"),
        "cwes": ("cwes", "S", ""),
        "description": ("description", "s", ""),
        "affects": ("affects", "M", "VulnerabilityAffects"),
        "analysis": ("analysis", "m", "VulnerabilityAnalysis"),
        "advisories": ("advisories", "M", "Advisory"),
        "properties": ("properties", "M", "Property"),
    },
    "Advisory": {"title": ("title", "s", ""), "url": ("url", "s", "")},
    "Source": {"name": ("name", "s", ""), "url": ("url", "s", "")},
    "VulnerabilityRating": {
        "source": ("source", "m", "Source"),
        "score": ("score", "s", ""),
        "severity": ("severity", "e", "SEVERITY_"),
        "method": ("method", "e", "SCORE_METHOD_"),  # CVSSv31 -> CVSSV31
        "vector": ("vector", "s", ""),
    },
    "VulnerabilityAffects": {"ref": ("ref", "s", "")},
    "VulnerabilityAnalysis": {
        "state": ("state", "e", "IMPACT_ANALYSIS_STATE_"),
        "justification": ("justification", "e", "IMPACT_ANALYSIS_JUSTIFICATION_"),
        "response": ("response", "E", "VULNERABILITY_RESPONSE_"),
        "detail": ("detail", "s", ""),
    },
}


def _enum(mod: ModuleType, prefix: str, value: str) -> int:
    name = value.upper().replace("-", "_")
    if prefix == "HASH_ALG_":  # SHA3-256 -> SHA_3_256, BLAKE2b-256 -> BLAKE_2_B_256
        name = re.sub(r"(?<=[A-Z])(?=\d)|(?<=\d)(?=[A-Z])", "_", name)
    try:
        return int(getattr(mod, prefix + name))
    except AttributeError:
        raise NotImplementedError(value) from None


def _timestamp(msg: Any, value: str) -> None:
    dt = datetime.fromisoformat(value)
    msg.FromDatetime(dt if dt.tzinfo else dt.replace(tzinfo=UTC))


def _fill(mod: ModuleType, cls: str, data: dict[str, Any]) -> Any:
    msg = getattr(mod, cls)()
    spec = _SPECS[cls]
    for key, value in data.items():
        if key not in spec:
            raise NotImplementedError(key)
        field, kind, arg = spec[key]
        if kind == "x":
            continue
        target = getattr(msg, field)
        if kind == "s":
            setattr(msg, field, value)
        elif kind == "t":
            _timestamp(target, value)
        elif kind == "e":
            setattr(msg, field, _enum(mod, arg, value))
        elif kind == "m":
            target.CopyFrom(_fill(mod, arg, value))
        elif kind == "M":
            # evidence.identity is an object in some schemas, a list in others
            for item in [value] if isinstance(value, dict) else value:
                target.add().CopyFrom(_fill(mod, arg, item))
        elif kind == "E":
            target.extend(_enum(mod, arg, v) for v in value)
        elif kind == "D":
            for ref in value:
                target.add(ref=ref)
        elif kind == "S":
            target.extend(value)
    return msg


def cdx_json_to_proto(cdx: dict[str, Any], spec: Literal["1.6", "1.7"]) -> bytes:
    """Encode a CycloneDX JSON dict as protobuf (``Bom.SerializeToString()``).

    ``cdx_dict`` output is NOT schema-validated, so feed this the dict of a
    BOM already validated by ``encode_cdx(bom, spec, "json")``.
    """
    return bytes(_fill(_MODULES[spec], "Bom", cdx).SerializeToString())
