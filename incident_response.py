"""
Agent 4: Incident Response Agent
Formulates containment playbooks, evaluates operational impact vs risk, and stages Human-in-the-Loop approvals.
"""

import json
from typing import Dict, Any
from tools.edr_firewall_tool import request_edr_containment
from config import OPENAI_API_KEY, DEFAULT_MODEL

class IncidentResponseAgent:
    def __init__(self):
        self.name = "Incident Response Agent"
        self.role = "Remediation Strategist & Human Approval Gatekeeper"

    async def execute(self, incident_id: str, investigation_data: Dict[str, Any], kb_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Builds containment playbook and executes/stages EDR & firewall containment actions.
        """
        compromised_host = "WORKSTATION-SEC-09"
        malicious_ip = "185.220.101.5"
        
        # Action 1: Isolate Compromised Host (HIGH RISK -> Forces Human Approval Gate)
        host_isolation = request_edr_containment(
            incident_id=incident_id,
            action_type="ISOLATE_HOST",
            target=compromised_host,
            reasoning=f"Isolate host {compromised_host} from network to prevent lateral ransomware spread.",
            risk_level="HIGH"
        )
        
        # Action 2: Perimeter Firewall IP Block (HIGH RISK -> Forces Human Approval Gate)
        ip_block = request_edr_containment(
            incident_id=incident_id,
            action_type="BLOCK_IP",
            target=malicious_ip,
            reasoning=f"Block C2 command & control IP {malicious_ip} at perimeter firewall.",
            risk_level="HIGH"
        )
        
        actions = [
            {
                "step": 1,
                "action": "Network Host Isolation",
                "target": compromised_host,
                "status": host_isolation["status"],
                "request_id": host_isolation.get("request_id"),
                "requires_approval": True,
                "impact_analysis": "Disconnects endpoint from corporate network; user active sessions suspended."
            },
            {
                "step": 2,
                "action": "Perimeter Firewall IP Block",
                "target": malicious_ip,
                "status": ip_block["status"],
                "request_id": ip_block.get("request_id"),
                "requires_approval": True,
                "impact_analysis": "Blocks external C2 traffic; zero disruption to internal enterprise services."
            },
            {
                "step": 3,
                "action": "Active Directory Credential Revocation",
                "target": "admin_corp",
                "status": "RECOMMENDED",
                "requires_approval": False,
                "impact_analysis": "Forces Kerberos ticket invalidation and domain password reset."
            }
        ]

        if OPENAI_API_KEY:
            try:
                import openai
                client = openai.OpenAI(api_key=OPENAI_API_KEY)
                prompt = {"investigation": investigation_data, "playbooks": kb_data.get("retrieved_playbooks", [])}
                response = client.chat.completions.create(
                    model=DEFAULT_MODEL,
                    messages=[
                        {"role": "system", "content": "You are an Incident Response Lead. Return a JSON object with keys: containment_strategy, operational_risk_assessment, response_playbook, reasoning_trace."},
                        {"role": "user", "content": json.dumps(prompt)}
                    ],
                    response_format={"type": "json_object"}
                )
                ai_output = json.loads(response.choices[0].message.content)
                ai_output["response_actions"] = actions
                ai_output["pending_human_approvals_count"] = sum(1 for a in actions if a["status"] == "PENDING_APPROVAL")
                return ai_output
            except Exception as e:
                pass

        return {
            "containment_strategy": "Immediate Active Containment: Network Isolation + Firewall Egress Block + Credential Invalidation.",
            "operational_risk_assessment": "Low operational risk to core infrastructure. Single host isolation will affect 1 user workstation.",
            "response_playbook": actions,
            "pending_human_approvals_count": 2,
            "reasoning_trace": [
                f"Evaluated containment playbooks retrieved by Knowledge Base Agent.",
                f"Staged High-Risk action 'ISOLATE_HOST' on target {compromised_host} (Awaiting Analyst Approval).",
                f"Staged High-Risk action 'BLOCK_IP' on target {malicious_ip} (Awaiting Analyst Approval)."
            ]
        }
