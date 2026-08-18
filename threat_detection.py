"""
Agent 1: Threat Detection Agent
Parses SIEM alerts, extracts Indicators of Compromise (IOCs), and classifies threat severity.
"""

import json
from typing import Dict, Any
from tools.siem_parser import parse_siem_alert
import config

class ThreatDetectionAgent:
    def __init__(self):
        self.name = "Threat Detection Agent"
        self.role = "SIEM Log Triage & IOC Extractor"

    async def execute(self, alert_payload: Dict[str, Any]) -> Dict[str, Any]:
        """
        Ingests raw security alert, runs SIEM parser tool, and produces structured triage output.
        """
        # Step 1: Run Tool 1 SIEM Parser
        parsed_siem = parse_siem_alert(alert_payload)
        
        # Step 2: Formulate Reasoning & Structured Output
        api_key = config.OPENAI_API_KEY or config.os.environ.get("OPENAI_API_KEY", "")
        if api_key:
            try:
                import openai
                client = openai.OpenAI(api_key=api_key)
                response = client.chat.completions.create(
                    model=config.DEFAULT_MODEL,
                    messages=[
                        {"role": "system", "content": "You are a Tier-1 SOC Threat Detection Agent. Analyze the parsed alert data and return a JSON object with keys: summary, threat_category, initial_severity, extracted_iocs, reasoning_trace."},
                        {"role": "user", "content": json.dumps(parsed_siem)}
                    ],
                    response_format={"type": "json_object"}
                )
                ai_output = json.loads(response.choices[0].message.content)
                ai_output["computed_score"] = parsed_siem["computed_threat_score"]
                return ai_output
            except Exception as e:
                pass # Fallback to deterministic cyber reasoning engine
                
        # Deterministic Cyber Reasoning Fallback
        score = parsed_siem["computed_threat_score"]
        severity = "CRITICAL" if score >= 85 else ("HIGH" if score >= 70 else "MEDIUM")
        
        return {
            "summary": f"Alert '{parsed_siem['alert_name']}' triaged from {parsed_siem['source_system']}.",
            "threat_category": "Endpoint Malicious Activity" if parsed_siem["iocs"]["processes"] else "Network Traffic Anomaly",
            "initial_severity": severity,
            "computed_score": score,
            "extracted_iocs": parsed_siem["iocs"],
            "reasoning_trace": [
                f"Parsed SIEM telemetry from source system {parsed_siem['source_system']}.",
                f"Extracted {len(parsed_siem['iocs']['ip_addresses'])} IP addresses, {len(parsed_siem['iocs']['file_hashes'])} file hashes, and {len(parsed_siem['iocs']['domains'])} suspicious domains.",
                f"Computed baseline threat score of {score}/100."
            ]
        }
