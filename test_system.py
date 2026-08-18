"""
Automated Verification & System Test for AI SOC Backend
"""

import asyncio
import json
from orchestrator.workflow import SOCWorkflowOrchestrator
from database import list_incidents, get_pending_approvals

async def main():
    print("--- Starting AI SOC System Test ---")
    orchestrator = SOCWorkflowOrchestrator()
    
    sample_alert = {
        "alert_name": "LockBit 3.0 Ransomware Encryptor & Shadow Copy Deletion",
        "severity": "CRITICAL",
        "source": "CrowdStrike EDR",
        "timestamp": "2026-08-10T11:15:00Z",
        "host": "WORKSTATION-SEC-09",
        "ip_address": "185.220.101.5",
        "user": "admin_corp",
        "process": "vssadmin.exe delete shadows",
        "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "description": "Suspicious volume shadow copy deletion request."
    }
    
    print("\n[1] Launching Multi-Agent Pipeline...")
    res = await orchestrator.run_investigation(sample_alert)
    
    print(f"\n[2] Pipeline Execution Succeeded! Incident ID: {res['incident_id']}")
    print(f"  - Threat Detection Score: {res['detection']['computed_score']}")
    print(f"  - Threat Intel Score: {res['threat_intel']['threat_score']}")
    print(f"  - Threat Actor: {res['threat_intel']['threat_actor_attribution']}")
    print(f"  - MITRE ATT&CK Techniques Mapped: {len(res['investigation']['mitre_attack_matrix'])}")
    print(f"  - RAG Playbooks Retrieved: {len(res['knowledge_base']['retrieved_playbooks'])}")
    print(f"  - Pending Human Approvals: {res['response']['pending_human_approvals_count']}")
    print(f"  - Self-Review False Positive Risk: {res['critic_reflection']['false_positive_risk']}")
    
    print("\n[3] Verifying SQLite Persistence...")
    incidents = list_incidents()
    print(f"  - Total Persisted Incidents in DB: {len(incidents)}")
    
    pending = get_pending_approvals()
    print(f"  - Total Pending HITL Approvals in DB: {len(pending)}")
    for p in pending:
        print(f"    * Request ID: {p['id']} | Action: {p['action_name']} | Status: {p['status']}")
        
    print("\n--- System Test Completed Successfully! ---")

if __name__ == "__main__":
    asyncio.run(main())
