"""
Tool 5: Vector Knowledge Base & Security Playbook RAG Store
Indexed database of MITRE ATT&CK techniques, NIST SP 800-61 playbooks, enterprise policies, and YARA rules.
"""

import math
from typing import Dict, List, Any

# Vector Corpus Knowledge Base
SECURITY_KNOWLEDGE_CORPUS = [
    {
        "id": "PLAYBOOK-RANSOMWARE-01",
        "title": "NIST SP 800-61 Ransomware Containment & Recovery Playbook",
        "category": "Playbook",
        "mitre_id": "T1486 - Data Encrypted for Impact",
        "tags": ["ransomware", "encryption", "vssadmin", "lockbit", "shadowcopy"],
        "content": """Immediate Containment Protocol for Ransomware:
1. Immediately isolate affected endpoint from network (disable Wi-Fi, sever LAN cable, EDR isolation).
2. Terminate malicious process tree (vssadmin delete shadows, powershell encoded commands).
3. Block external C2 IP addresses at firewall perimeter.
4. Export forensic memory dump prior to host shutdown.
5. Verify offline cloud backups integrity before initiating restore."""
    },
    {
        "id": "PLAYBOOK-EXFILTRATION-02",
        "title": "Data Exfiltration & Cloud Storage Leak Response",
        "category": "Playbook",
        "mitre_id": "T1041 - Exfiltration Over C2 Channel",
        "tags": ["exfiltration", "rclone", "aws", "s3", "megaupload", "beacon"],
        "content": """Data Exfiltration Mitigation Steps:
1. Identify high-volume egress sessions using network flow telemetry.
2. Revoke compromised IAM credentials and AWS access tokens immediately.
3. Apply egress filtering rule blocking destination IP/domain at network edge.
4. Initiate DLP (Data Loss Prevention) audit to enumerate affected data categories (PII, IP, PCI-DSS)."""
    },
    {
        "id": "PLAYBOOK-COBALT-STRIKE-03",
        "title": "Cobalt Strike Beacon Detection & Mitigation Guide",
        "category": "YARA & Threat Guide",
        "mitre_id": "T1055 - Process Injection",
        "tags": ["cobaltstrike", "beacon", "reflective_loader", "rundll32", "named_pipes"],
        "content": """Cobalt Strike Detection & Containment:
1. Inspect rundll32.exe and powershell.exe parent-child process relationships.
2. Scan process memory using YARA rule 'win_cobaltstrike_auto'.
3. Terminate injected worker threads and kill host process.
4. Block named pipe communication patterns (e.g. \\\\.\\pipe\\msse-*)."""
    },
    {
        "id": "PLAYBOOK-CREDENTIAL-DUMPING-04",
        "title": "LSASS Credential Dumping & Kerberoasting Playbook",
        "category": "Identity Security",
        "mitre_id": "T1003 - OS Credential Dumping",
        "tags": ["lsass", "mimikatz", "kerberoasting", "active_directory", "ntlm"],
        "content": """Credential Harvesting Response:
1. Force Active Directory password reset for affected domain account.
2. Reset krbtgt account password twice if domain admin hash compromise is suspected.
3. Enable LSA Protection (RunAsPPL) on domain workstations.
4. Audit Active Directory event log ID 4624 (Successful Logon) for lateral movement."""
    }
]

def _tokenize(text: str) -> set:
    """Helper to convert text into token set."""
    return set(text.lower().replace("-", " ").replace("_", " ").split())

def query_knowledge_base(query: str, top_k: int = 2) -> List[Dict[str, Any]]:
    """
    Vector similarity search over the Security Knowledge Corpus using term overlap scoring (TF-IDF approximation).
    """
    query_tokens = _tokenize(query)
    scored_results = []
    
    for item in SECURITY_KNOWLEDGE_CORPUS:
        corpus_tokens = _tokenize(f"{item['title']} {' '.join(item['tags'])} {item['content']}")
        intersection = query_tokens.intersection(corpus_tokens)
        if intersection:
            score = len(intersection) / math.sqrt(len(query_tokens) * len(corpus_tokens))
        else:
            score = 0.0
            
        scored_results.append({
            "id": item["id"],
            "title": item["title"],
            "category": item["category"],
            "mitre_id": item["mitre_id"],
            "relevance_score": round(score, 4),
            "excerpt": item["content"].strip()
        })
        
    scored_results.sort(key=lambda x: x["relevance_score"], reverse=True)
    return scored_results[:top_k]
