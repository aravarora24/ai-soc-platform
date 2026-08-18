"""
AI Security Operations Centre (AI SOC) - Main FastAPI Server Application
OpenAI Capstone Project Implementation
"""

import os
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Dict, Any, Optional, List

from database import init_db, list_incidents, get_incident, get_pending_approvals, update_approval_status, get_audit_logs
from orchestrator.workflow import SOCWorkflowOrchestrator
from tools.webhook_tool import send_webhook_notification
import config

# Initialize FastAPI App
app = FastAPI(
    title="AI Security Operations Centre (AI SOC)",
    description="Autonomous Multi-Agent AI SOC for Cyber Incident Investigation, Threat Intelligence Correlation, and Response.",
    version="1.0.0"
)

# Initialize DB Schema
init_db()

# Instantiate Multi-Agent Orchestrator
orchestrator = SOCWorkflowOrchestrator()

# Mount Static Assets Directory
static_dir = os.path.join(os.path.dirname(__file__), "static")
app.mount("/static", StaticFiles(directory=static_dir), name="static")

# Data Models
class AlertRequest(BaseModel):
    alert_name: Optional[str] = "Security Alert"
    severity: Optional[str] = "HIGH"
    source: Optional[str] = "SIEM Log"
    timestamp: Optional[str] = None
    host: Optional[str] = "WORKSTATION-SEC-09"
    ip_address: Optional[str] = "185.220.101.5"
    user: Optional[str] = "admin_corp"
    process: Optional[str] = "vssadmin.exe"
    hash: Optional[str] = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    description: Optional[str] = "Suspicious volume shadow copy deletion request."

class ApprovalResponse(BaseModel):
    request_id: str
    status: str  # APPROVED or REJECTED
    analyst_notes: Optional[str] = ""

class LoginRequest(BaseModel):
    username: str
    password: str

class WebhookRequest(BaseModel):
    webhook_url: Optional[str] = ""
    incident_id: Optional[str] = "INC-ALERT-01"
    action_name: Optional[str] = "ISOLATE_HOST"
    target: Optional[str] = "WORKSTATION-SEC-09"
    reasoning: Optional[str] = "Suspicious volume shadow copy deletion request."
    severity: Optional[str] = "CRITICAL"

# Routes
@app.get("/")
async def root():
    return FileResponse(os.path.join(static_dir, "index.html"))

@app.get("/api/health")
async def health_check():
    return {"status": "HEALTHY", "system": "AI Security Operations Centre", "agents_active": 6, "database": "SQLite Persistent"}

@app.post("/api/login")
async def login(credentials: LoginRequest):
    """
    Authenticates SOC Analyst credentials (ID: user, Password: 123).
    """
    if credentials.username.strip() == "user" and credentials.password.strip() == "123":
        return {
            "status": "SUCCESS",
            "message": "Authentication successful. Access granted to SOC Command Dashboard.",
            "user": "user",
            "token": "soc-auth-token-user-123"
        }
    raise HTTPException(status_code=401, detail="Invalid User ID or Password. Access Denied.")

@app.post("/api/investigate")
async def investigate_alert(payload: Dict[str, Any]):
    """
    Triggers the multi-agent AI SOC investigation pipeline.
    """
    try:
        result = await orchestrator.run_investigation(payload)
        return result
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"AI SOC Investigation failed: {str(e)}")

@app.get("/api/incidents")
async def get_all_incidents():
    """
    Returns list of all historical incidents stored in database.
    """
    return list_incidents()

@app.get("/api/incidents/{incident_id}")
async def get_incident_details(incident_id: str):
    """
    Returns full multi-agent state for a specific incident.
    """
    incident = get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found.")
    logs = get_audit_logs(incident_id)
    return {"incident": incident, "audit_logs": logs}

@app.get("/api/approvals/pending")
async def list_pending_approvals():
    """
    Returns pending Human-in-the-Loop approval requests.
    """
    return get_pending_approvals()

@app.post("/api/approvals/respond")
async def respond_approval(response: ApprovalResponse):
    """
    Records Human Analyst Approval or Rejection decision for staged containment actions.
    """
    if response.status not in ["APPROVED", "REJECTED"]:
        raise HTTPException(status_code=400, detail="Status must be APPROVED or REJECTED.")
    
    update_approval_status(response.request_id, response.status, response.analyst_notes)
    return {
        "status": "SUCCESS",
        "request_id": response.request_id,
        "new_status": response.status,
        "message": f"Human Analyst recorded decision '{response.status}' for action request {response.request_id}."
    }

@app.post("/api/webhook/send")
async def trigger_webhook(req: WebhookRequest):
    """
    Sends rich alert card to Slack or Discord webhook.
    """
    res = send_webhook_notification(
        webhook_url=req.webhook_url or "",
        incident_id=req.incident_id or "INC-DEMO-01",
        action_name=req.action_name or "ISOLATE_HOST",
        target=req.target or "WORKSTATION-SEC-09",
        reasoning=req.reasoning or "Suspicious activity detected.",
        severity=req.severity or "CRITICAL"
    )
    return res

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app:app", host="127.0.0.1", port=8000, reload=True)
