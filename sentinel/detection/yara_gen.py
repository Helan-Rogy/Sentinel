"""Autonomous YARA Rule Generator for Detected Ransomware Incidents.

Synthesizes dynamic incident artifacts, encrypted file extensions, ransom note markers,
and observed memory/payload signatures into valid, production-ready YARA rules.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import List, Optional

from contracts import Incident


def _sanitize_identifier(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_]", "_", name)
    return cleaned.strip("_") or "Ransomware_Artifact"


def generate_yara_rule(incident: Incident) -> str:
    """Generate a production-ready YARA rule from incident evidence."""
    rule_id = _sanitize_identifier(incident.id)
    target_proc = incident.process_name or "unknown_malware.exe"
    created_iso = incident.created.strftime("%Y-%m-%d %H:%M:%SZ")

    # Gather extension markers
    exts = set()
    for e in incident.entropy:
        if e.path.endswith(".locked"):
            exts.add(".locked")
        elif "." in e.path:
            ext = "." + e.path.split(".")[-1].lower()
            if ext not in (".txt", ".pdf", ".docx", ".xlsx", ".csv", ".jpg", ".png"):
                exts.add(ext)

    if incident.sandbox and incident.sandbox.extensions_changed:
        exts.update(incident.sandbox.extensions_changed)

    # Gather strings
    string_entries: List[tuple[str, str]] = []

    # 1. Process name
    string_entries.append(("$proc_name", f'"{target_proc}" ascii wide nocase'))

    # 2. Extensions
    for i, ext in enumerate(sorted(exts)):
        string_entries.append((f"$ext_{i+1}", f'"{ext}" ascii wide nocase'))

    # 3. Ransom note indicators
    string_entries.append(("$ransom_note_1", '"YOUR FILES HAVE BEEN ENCRYPTED" ascii wide nocase'))
    string_entries.append(("$ransom_note_2", '"README_RESTORE_FILES" ascii wide nocase'))
    string_entries.append(("$ransom_note_3", '"All your documents, spreadsheets" ascii wide nocase'))

    # 4. Canary token indicators if hit
    for i, h in enumerate(incident.honey_hits[:3]):
        base_h = h.path.split("\\")[-1].split("/")[-1]
        string_entries.append((f"$canary_{i+1}", f'"{base_h}" ascii wide nocase'))

    # Format YARA strings block
    strings_block = "\n        ".join(f"{name} = {val}" for name, val in string_entries)

    # Condition: PE file with target strings OR ransom note markers present
    condition = (
        "uint16(0) == 0x5a4d and ($proc_name or any of ($ext_*)) or\n"
        "        any of ($ransom_note_*) or\n"
        "        (2 of ($canary_*) and any of ($ext_*))"
    )

    yara_rule = f"""/*
  Rule: Ransomware_{rule_id}
  Generated autonomously by Aegis Sentinel Defense Platform
  Incident Reference : {incident.id}
  Target Executable  : {target_proc} (PID: {incident.pid or 'N/A'})
  Timestamp          : {created_iso}
*/

rule Ransomware_{rule_id} : ransomware dynamic_defense
{{
    meta:
        description = "Autonomously generated rule for {target_proc} outbreak"
        author = "Aegis Sentinel Autonomous Threat Defense"
        incident_id = "{incident.id}"
        severity = "{incident.assessment.level.value if incident.assessment else 'high'}"
        date = "{created_iso}"
        reference = "urn:sentinel:incident:{incident.id}"
        tlp = "AMBER"

    strings:
        {strings_block}

    condition:
        {condition}
}}
"""
    return yara_rule
