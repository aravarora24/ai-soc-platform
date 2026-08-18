"""
Multi-Agent Workflow Orchestrator
Coordinates agent execution pipelines, state handoffs, error handling, reflection, and SQLite database persistence.
"""

import uuid
import json
import asyncio
from typing import Dict, Any, Callable, Optional

from agents.threat_detection import ThreatDetectionAgent
from agents.threat_intel import ThreatIntelAgent
from agents.investigation import InvestigationAgent
from agents.knowledge_base import KnowledgeBaseAgent
from agents.incident_response import IncidentResponseAgent
from agents.security_reporting import SecurityReportingAgent
from orchestrator.reflection import ReflectionCriticAgent
from database import save_incident, add_audit_log, get_incident

class SOCWorkflowOrchestrator:
    def __init__(self):
        self.detection_agent = ThreatDetectionAgent()
        self.intel_agent = ThreatIntelAgent()
        self.investigation_agent = InvestigationAgent()
        self.kb_agent = KnowledgeBaseAgent()
        self.response_agent = IncidentResponseAgent()
        self.reporting_agent = SecurityReportingAgent()
        self.critic_agent = ReflectionCriticAgent()

    async def run_investigation(
        self,
        alert_payload: Dict[str, Any],
        progress_callback: Optional[Callable[[str, str, Dict[str, Any]], None]] = None
    ) -> Dict[str, Any]:
        """
        Executes the full multi-agent SOC investigation pipeline with live handoffs and persistent state.
        """
        incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
        alert_title = alert_payload.get("title", alert_payload.get("alert_name", "Security Alert Triage"))
        severity = alert_payload.get("severity", "MEDIUM").upper()
        
        # Save initial state in DB
        save_incident(
            incident_id=incident_id,
            title=alert_title,
            severity=severity,
            status="INVESTIGATING",
            alert_data=alert_payload
        )
        
        async def notify(agent_name: str, event_type: str, message: str, payload: Any = None):
            add_audit_log(incident_id, agent_name, event_type, message, payload)
            if progress_callback:
                try:
                    await progress_callback(agent_name, message, payload)
                except Exception:
                    pass

        try:
            # Step 1: Threat Detection Agent
            await notify("Threat Detection Agent", "HANDOFF_START", "Ingesting SIEM telemetry and parsing IOCs...")
            detection_res = await self.detection_agent.execute(alert_payload)
            await notify("Threat Detection Agent", "HANDOFF_COMPLETE", "IOC triage completed.", detection_res)
            
            # Step 2: Threat Intelligence Agent (Parallel OSINT feeds + Network flow)
            await notify("Threat Intelligence Agent", "HANDOFF_START", "Querying OSINT feeds & analyzing network flow...")
            intel_res = await self.intel_agent.execute(detection_res)
            await notify("Threat Intelligence Agent", "HANDOFF_COMPLETE", "Threat actor attribution & reputation enriched.", intel_res)
            
            # Step 3: Investigation Agent (Root cause & MITRE ATT&CK correlation)
            await notify("Investigation Agent", "HANDOFF_START", "Reconstructing attack tree & mapping MITRE ATT&CK matrix...")
            investigation_res = await self.investigation_agent.execute(detection_res, intel_res)
            await notify("Investigation Agent", "HANDOFF_COMPLETE", "Forensic attack tree reconstructed.", investigation_res)
            
            # Step 4: Knowledge Base RAG Agent (Vector similarity search over security playbooks)
            await notify("Knowledge Base RAG Agent", "HANDOFF_START", "Searching vector store for NIST playbooks & YARA rules...")
            kb_res = await self.kb_agent.execute(investigation_res)
            await notify("Knowledge Base RAG Agent", "HANDOFF_COMPLETE", "RAG security playbooks retrieved.", kb_res)
            
            # Step 5: Incident Response Agent (Containment strategy & HITL approval staging)
            await notify("Incident Response Agent", "HANDOFF_START", "Building containment plan & staging Human Approvals...")
            response_res = await self.response_agent.execute(incident_id, investigation_res, kb_res)
            await notify("Incident Response Agent", "HANDOFF_COMPLETE", "Containment actions staged for Human Analyst Approval.", response_res)
            
            # Step 6: Reflection & Critic Agent (Self-Review / Quality control check)
            await notify("Reflection & Critic Agent", "HANDOFF_START", "Performing self-review reflection & evidence quality audit...")
            critic_res = await self.critic_agent.review_investigation(detection_res, intel_res, response_res)
            await notify("Reflection & Critic Agent", "HANDOFF_COMPLETE", "Self-review verification complete.", critic_res)
            
            # Step 7: Security Reporting Agent (Post-mortem synthesis)
            await notify("Security Reporting Agent", "HANDOFF_START", "Synthesizing executive briefing & technical report...")
            reporting_res = await self.reporting_agent.execute(incident_id, detection_res, intel_res, investigation_res, kb_res, response_res)
            await notify("Security Reporting Agent", "HANDOFF_COMPLETE", "Final Post-Mortem Report generated.", reporting_res)
            
            # Persist full multi-agent state to SQLite database
            save_incident(
                incident_id=incident_id,
                title=alert_title,
                severity=severity,
                status="ACTION_REQUIRED" if response_res.get("pending_human_approvals_count", 0) > 0 else "RESOLVED",
                alert_data=alert_payload,
                detection_result=json.dumps(detection_res),
                threat_intel_result=json.dumps(intel_res),
                investigation_result=json.dumps(investigation_res),
                kb_result=json.dumps(kb_res),
                response_result=json.dumps(response_res),
                reporting_result=json.dumps(reporting_res),
                risk_score=intel_res.get("threat_score", 75),
                mitre_tactics=json.dumps([m.get("tactic") for m in investigation_res.get("mitre_attack_matrix", [])]),
                hitl_status="PENDING_APPROVAL" if response_res.get("pending_human_approvals_count", 0) > 0 else "APPROVED"
            )
            
            return {
                "incident_id": incident_id,
                "status": "ACTION_REQUIRED" if response_res.get("pending_human_approvals_count", 0) > 0 else "RESOLVED",
                "detection": detection_res,
                "threat_intel": intel_res,
                "investigation": investigation_res,
                "knowledge_base": kb_res,
                "response": response_res,
                "critic_reflection": critic_res,
                "reporting": reporting_res
            }

        except Exception as e:
            error_msg = f"Orchestration failure during agent execution: {str(e)}"
            await notify("Orchestrator", "ERROR", error_msg)
            save_incident(
                incident_id=incident_id,
                title=alert_title,
                severity=severity,
                status="FAILED",
                alert_data=alert_payload
            )
            raise e
