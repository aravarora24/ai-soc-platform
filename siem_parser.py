"""
Tool 1: SIEM Log & Alert Triage Analyzer Tool
Parses structured/unstructured log streams, extracts IOCs (IPs, hashes, domains, processes, users), and computes baseline threat score.
"""

import re
from typing import Dict, List, Any

# Regular Expressions for Indicator Extraction
IP_REGEX = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
HASH_REGEX = r'\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b'
DOMAIN_REGEX = r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b'
PROCESS_REGEX = r'\b[\w-]+\.(?:exe|dll|ps1|bat|sh|py|elf)\b'

def parse_siem_alert(raw_alert: Dict[str, Any]) -> Dict[str, Any]:
    """
    Parses a raw SIEM alert and extracts key threat indicators.
    """
    text_content = str(raw_alert)
    
    # Extract IPs, filtering out loopback and private internal defaults if desired
    raw_ips = list(set(re.findall(IP_REGEX, text_content)))
    ips = [ip for ip in raw_ips if not (ip.startswith("127.") or ip == "0.0.0.0")]
    
    # Extract file hashes (MD5, SHA1, SHA256)
    hashes = list(set(re.findall(HASH_REGEX, text_content)))
    
    # Extract suspicious domains
    domains = [d for d in set(re.findall(DOMAIN_REGEX, text_content)) if not d.endswith(('.local', '.lan', '.internal'))]
    
    # Extract executable process names
    processes = list(set(re.findall(PROCESS_REGEX, text_content, re.IGNORECASE)))
    
    # Determine alert categorization & initial score calculation
    alert_name = raw_alert.get("alert_name", raw_alert.get("title", "Unknown Security Alert"))
    severity = raw_alert.get("severity", "MEDIUM").upper()
    source_system = raw_alert.get("source", raw_alert.get("host", "SIEM-Collector-01"))
    timestamp = raw_alert.get("timestamp", "2026-08-10T11:20:00Z")
    
    # Severity weighting score
    score_map = {"CRITICAL": 85, "HIGH": 70, "MEDIUM": 45, "LOW": 20, "INFO": 5}
    base_score = score_map.get(severity, 40)
    
    # Modifier for extracted IOC count
    ioc_count = len(ips) + len(hashes) + len(domains)
    computed_score = min(99, base_score + (ioc_count * 3))
    
    return {
        "alert_name": alert_name,
        "severity": severity,
        "source_system": source_system,
        "timestamp": timestamp,
        "computed_threat_score": computed_score,
        "iocs": {
            "ip_addresses": ips,
            "file_hashes": hashes,
            "domains": domains,
            "processes": processes
        },
        "raw_event_summary": text_content[:500]
    }
