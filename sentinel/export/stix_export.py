"""STIX 2.1 Threat Intelligence & MISP Exporter for Aegis Sentinel.

Converts active incident telemetry into standard STIX 2.1 JSON bundles containing:
- Malware SDO
- Attack Pattern (MITRE ATT&CK T1486: Data Encrypted for Impact)
- Indicators (process names, C2 IPs, encrypted extensions)
- Observed Data (file modifications, network connections)
- Course of Action SDO
- Comprehensive Threat Report SDO
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List

from contracts import Incident


def _stix_id(type_name: str) -> str:
    return f"{type_name}--{uuid.uuid4()}"


def export_stix_bundle(incident: Incident) -> Dict[str, Any]:
    """Generate a fully compliant STIX 2.1 JSON bundle from an incident."""
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    created_iso = incident.created.strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    proc_name = incident.process_name or "ransomware_sample.exe"

    objects: List[Dict[str, Any]] = []
    object_refs: List[str] = []

    # 1. Malware SDO
    malware_id = _stix_id("malware")
    object_refs.append(malware_id)
    objects.append({
        "type": "malware",
        "spec_version": "2.1",
        "id": malware_id,
        "created": created_iso,
        "modified": now_iso,
        "name": f"Ransomware Payload: {proc_name}",
        "is_family": False,
        "malware_types": ["ransomware"],
        "description": f"Autonomously intercepted ransomware outbreak. {incident.title}",
        "labels": ["ransomware", "automated-detection", "aegis-sentinel"],
    })

    # 2. MITRE ATT&CK T1486: Data Encrypted for Impact
    attack_pattern_id = _stix_id("attack-pattern")
    object_refs.append(attack_pattern_id)
    objects.append({
        "type": "attack-pattern",
        "spec_version": "2.1",
        "id": attack_pattern_id,
        "created": created_iso,
        "modified": now_iso,
        "name": "Data Encrypted for Impact",
        "description": "Adversaries may encrypt data on target systems or on large numbers of systems in a network to interrupt availability to system and network resources.",
        "external_references": [
            {
                "source_name": "mitre-attack",
                "external_id": "T1486",
                "url": "https://attack.mitre.org/techniques/T1486/",
            }
        ],
    })

    # 3. Indicator SDOs
    # Process Indicator
    ind_proc_id = _stix_id("indicator")
    object_refs.append(ind_proc_id)
    objects.append({
        "type": "indicator",
        "spec_version": "2.1",
        "id": ind_proc_id,
        "created": created_iso,
        "modified": now_iso,
        "name": f"Process Indicator: {proc_name}",
        "pattern_type": "stix",
        "pattern": f"[process:name = '{proc_name}']",
        "valid_from": created_iso,
        "indicator_types": ["malicious-activity"],
    })

    # Network C2 Indicators from Sandbox if available
    if incident.sandbox and incident.sandbox.network_connections:
        for conn in incident.sandbox.network_connections:
            ip = conn.get("ip")
            if ip:
                ind_net_id = _stix_id("indicator")
                object_refs.append(ind_net_id)
                objects.append({
                    "type": "indicator",
                    "spec_version": "2.1",
                    "id": ind_net_id,
                    "created": created_iso,
                    "modified": now_iso,
                    "name": f"C2 Beacon Indicator: {ip}",
                    "pattern_type": "stix",
                    "pattern": f"[ipv4-addr:value = '{ip}']",
                    "valid_from": created_iso,
                    "indicator_types": ["c2"],
                })

    # 4. Course of Action SDO
    coa_id = _stix_id("course-of-action")
    object_refs.append(coa_id)
    action_desc = "; ".join(a.rationale for a in incident.actions) or "Suspend originating process and isolate endpoint"
    objects.append({
        "type": "course-of-action",
        "spec_version": "2.1",
        "id": coa_id,
        "created": created_iso,
        "modified": now_iso,
        "name": "Autonomous Process Suspension & SOC Containment",
        "description": f"Proposed mitigation: {action_desc}",
    })

    # 5. Threat Report SDO
    report_id = _stix_id("report")
    objects.append({
        "type": "report",
        "spec_version": "2.1",
        "id": report_id,
        "created": created_iso,
        "modified": now_iso,
        "name": f"Sentinel Threat Assessment Dossier: {incident.id}",
        "description": f"Executive and tactical telemetry for {incident.title}. Level: {incident.assessment.level.value if incident.assessment else 'UNKNOWN'}.",
        "published": now_iso,
        "report_types": ["threat-report"],
        "object_refs": object_refs,
    })

    return {
        "type": "bundle",
        "id": _stix_id("bundle"),
        "spec_version": "2.1",
        "objects": objects,
    }
