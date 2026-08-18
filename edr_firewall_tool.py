"""
Tool 4: EDR Endpoint Isolation & Firewall Response Tool (Human-in-the-Loop Guarded)
Executes containment actions on EDR agents and network firewalls.
"""

import uuid
from typing import Dict, Any
from database import save_approval_request

def request_edr_containment(incident_id: str, action_type: str, target: str, reasoning: str, risk_level: str = "HIGH") -> Dict[str, Any]:
    """
    Submits a containment action to EDR / Firewall.
    If risk_level is HIGH or CRITICAL, forces Human Analyst Approval before execution.
    """
    valid_actions = ["ISOLATE_HOST", "BLOCK_IP", "KILL_PROCESS", "REVOKE_USER_SESSION", "UPDATE_FIREWALL_RULE"]
    if action_type not in valid_actions:
        return {"status": "ERROR", "message": f"Invalid containment action type: {action_type}"}

    request_id = f"REQ-{uuid.uuid4().hex[:8].upper()}"
    
    # High-Risk Actions require Human Approval
    requires_approval = risk_level in ["HIGH", "CRITICAL"] or action_type in ["ISOLATE_HOST", "REVOKE_USER_SESSION"]
    
    if requires_approval:
        action_title = f"{action_type.replace('_', ' ')} on {target}"
        save_approval_request(
            request_id=request_id,
            incident_id=incident_id,
            action_name=action_title,
            target_entity=target,
            action_type=action_type,
            risk_level=risk_level,
            reasoning=reasoning
        )
        return {
            "status": "PENDING_APPROVAL",
            "request_id": request_id,
            "action_type": action_type,
            "target": target,
            "requires_human_gate": True,
            "message": f"Action '{action_type}' on '{target}' staged for Human Analyst Approval.",
            "execution_result": "Awaiting SOC Analyst Sign-off"
        }
    else:
        # Automated non-destructive execution (e.g. LOW risk firewall log capture)
        return {
            "status": "EXECUTED",
            "request_id": request_id,
            "action_type": action_type,
            "target": target,
            "requires_human_gate": False,
            "message": f"Automated response executed successfully on target {target}.",
            "execution_result": "Success - Applied low-risk policy update"
        }
