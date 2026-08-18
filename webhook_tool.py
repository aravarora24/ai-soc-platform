"""
Webhook Notification Tool (Slack / Discord Alert Dispatcher)
Dispatches rich alert cards to Slack or Discord webhooks when Human-in-the-Loop containment authorization is required.
"""

import json
import urllib.request
from typing import Dict, Any, Optional

def format_slack_payload(incident_id: str, action_name: str, target: str, reasoning: str, severity: str) -> Dict[str, Any]:
    """Formats a rich Slack Block Kit alert payload."""
    return {
        "text": f"🚨 *AI SOC ALERT: Action Pending Approval [{incident_id}]*",
        "blocks": [
            {
                "type": "header",
                "text": {
                    "type": "plain_text",
                    "text": f"🚨 AI SOC Containment Gate: {severity} Risk Alert",
                    "emoji": True
                }
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Incident ID:*\n`{incident_id}`"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n`{severity}`"},
                    {"type": "mrkdwn", "text": f"*Action Staged:*\n*{action_name}*"},
                    {"type": "mrkdwn", "text": f"*Target Host:*\n`{target}`"}
                ]
            },
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*Reasoning:* {reasoning}"
                }
            },
            {
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "✅ Open SOC Dashboard"},
                        "url": "http://127.0.0.1:8000",
                        "style": "primary"
                    }
                ]
            }
        ]
    }

def format_discord_payload(incident_id: str, action_name: str, target: str, reasoning: str, severity: str) -> Dict[str, Any]:
    """Formats a rich Discord Embed alert payload."""
    return {
        "content": "🚨 **AI SOC ACTION PENDING APPROVAL**",
        "embeds": [
            {
                "title": f"Shield AI SOC Gate: {severity} Severity Alert",
                "description": f"The Incident Response Agent has staged a high-impact containment action requiring mandatory analyst sign-off.",
                "color": 16711765 if severity == "CRITICAL" else 16753920,
                "fields": [
                    {"name": "Incident ID", "value": f"`{incident_id}`", "inline": True},
                    {"name": "Staged Action", "value": f"**{action_name}**", "inline": True},
                    {"name": "Target Host/IP", "value": f"`{target}`", "inline": True},
                    {"name": "Reasoning", "value": reasoning, "inline": False}
                ],
                "footer": {"text": "AI Security Operations Centre • Human-in-the-Loop Gateway"}
            }
        ]
    }

def send_webhook_notification(webhook_url: str, incident_id: str, action_name: str, target: str, reasoning: str, severity: str = "HIGH") -> Dict[str, Any]:
    """
    Dispatches alert payload to a Slack or Discord webhook endpoint.
    """
    if not webhook_url or not webhook_url.startswith("http"):
        # Simulated Webhook Log Execution
        return {
            "status": "SIMULATED",
            "message": f"Simulated Webhook Alert dispatched for action '{action_name}' on '{target}'.",
            "slack_payload": format_slack_payload(incident_id, action_name, target, reasoning, severity)
        }

    try:
        is_discord = "discord.com" in webhook_url
        payload = format_discord_payload(incident_id, action_name, target, reasoning, severity) if is_discord else format_slack_payload(incident_id, action_name, target, reasoning, severity)
        
        req = urllib.request.Request(
            webhook_url,
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json", "User-Agent": "AI-SOC-Agent/1.0"}
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            return {"status": "SUCCESS", "http_code": resp.status, "message": "Webhook alert successfully delivered!"}
    except Exception as e:
        return {"status": "ERROR", "message": f"Failed delivering webhook notification: {str(e)}"}
