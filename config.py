"""
AI Security Operations Centre (AI SOC) - Configuration Module
"""

import os

# OpenAI API Key & Model Configuration
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY", "")
DEFAULT_MODEL = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

def set_openai_api_key(key: str):
    global OPENAI_API_KEY
    OPENAI_API_KEY = key
    os.environ["OPENAI_API_KEY"] = key

# Database & Storage Settings
DB_PATH = os.path.join(os.path.dirname(__file__), "soc_incidents.db")

# Threat Intel Thresholds
HIGH_RISK_THRESHOLD = 75
CRITICAL_RISK_THRESHOLD = 90

# Agent System Prompts & Identity Definitions
AGENT_CONFIGS = {
    "threat_detection": {
        "name": "Threat Detection Agent",
        "role": "SIEM Log Triage & Indicator Extraction Specialist",
        "description": "Parses raw security alerts and SIEM event streams, identifies Indicator of Compromise (IOC) types, and computes baseline risk scores."
    },
    "threat_intel": {
        "name": "Threat Intelligence Agent",
        "role": "OSINT & Threat Actor Reputation Analyst",
        "description": "Queries threat feeds, VirusTotal, AbuseIPDB, and CISA KEV databases concurrently to evaluate IOC reputation and actor attribution."
    },
    "investigation": {
        "name": "Investigation Agent",
        "role": "Cyber Forensics & MITRE ATT&CK Correlation Specialist",
        "description": "Reconstructs attack execution trees, correlates network packet flows, and maps attacker behaviors to the MITRE ATT&CK Framework."
    },
    "knowledge_base": {
        "name": "Knowledge Base RAG Agent",
        "role": "Security Policy & Historical Case Retrieval Specialist",
        "description": "Performs vector search across NIST incident playbooks, enterprise security policies, YARA rules, and historical post-mortems."
    },
    "incident_response": {
        "name": "Incident Response Agent",
        "role": "Remediation Strategist & Human Approval Gatekeeper",
        "description": "Builds tactical containment playbooks, evaluates operational impact, and submits critical containment actions for human analyst approval."
    },
    "security_reporting": {
        "name": "Security Reporting Agent",
        "role": "Executive & Technical Security Auditor",
        "description": "Synthesizes multi-agent findings into comprehensive incident post-mortems, executive briefings, and compliance audit logs."
    },
    "reflection_critic": {
        "name": "Reflection & Critic Agent",
        "role": "Quality Control & False-Positive Reviewer",
        "description": "Performs double-check self-review on proposed response actions to ensure zero false positives and operational continuity."
    }
}
