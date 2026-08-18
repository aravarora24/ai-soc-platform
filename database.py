"""
AI Security Operations Centre - SQLite Database & Session Persistence Layer
"""

import sqlite3
import json
from datetime import datetime, timezone
from config import DB_PATH

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    
    # Table 1: Incidents table for multi-agent investigation sessions
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS incidents (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        alert_data TEXT NOT NULL,
        detection_result TEXT,
        threat_intel_result TEXT,
        investigation_result TEXT,
        kb_result TEXT,
        response_result TEXT,
        reporting_result TEXT,
        risk_score INTEGER DEFAULT 0,
        mitre_tactics TEXT,
        hitl_status TEXT DEFAULT 'PENDING'
    )
    """)
    
    # Table 2: Human Approval Requests (Human-in-the-Loop)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS approval_requests (
        id TEXT PRIMARY KEY,
        incident_id TEXT NOT NULL,
        action_name TEXT NOT NULL,
        target_entity TEXT NOT NULL,
        action_type TEXT NOT NULL,
        risk_level TEXT NOT NULL,
        reasoning TEXT NOT NULL,
        status TEXT NOT NULL, -- PENDING, APPROVED, REJECTED
        requested_at TEXT NOT NULL,
        responded_at TEXT,
        analyst_notes TEXT,
        FOREIGN KEY (incident_id) REFERENCES incidents (id)
    )
    """)
    
    # Table 3: Audit Logs & Agent Handoff Execution Traces
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        incident_id TEXT NOT NULL,
        agent_name TEXT NOT NULL,
        event_type TEXT NOT NULL,
        message TEXT NOT NULL,
        timestamp TEXT NOT NULL,
        payload TEXT
    )
    """)
    
    conn.commit()
    conn.close()

def save_incident(incident_id, title, severity, status, alert_data, **kwargs):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    
    cursor.execute("SELECT id FROM incidents WHERE id = ?", (incident_id,))
    exists = cursor.fetchone()
    
    alert_str = json.dumps(alert_data) if isinstance(alert_data, dict) else str(alert_data)
    
    if exists:
        cursor.execute("""
        UPDATE incidents SET
            title = ?, severity = ?, status = ?, updated_at = ?, alert_data = ?,
            detection_result = COALESCE(?, detection_result),
            threat_intel_result = COALESCE(?, threat_intel_result),
            investigation_result = COALESCE(?, investigation_result),
            kb_result = COALESCE(?, kb_result),
            response_result = COALESCE(?, response_result),
            reporting_result = COALESCE(?, reporting_result),
            risk_score = COALESCE(?, risk_score),
            mitre_tactics = COALESCE(?, mitre_tactics),
            hitl_status = COALESCE(?, hitl_status)
        WHERE id = ?
        """, (
            title, severity, status, now, alert_str,
            kwargs.get("detection_result"),
            kwargs.get("threat_intel_result"),
            kwargs.get("investigation_result"),
            kwargs.get("kb_result"),
            kwargs.get("response_result"),
            kwargs.get("reporting_result"),
            kwargs.get("risk_score"),
            kwargs.get("mitre_tactics"),
            kwargs.get("hitl_status"),
            incident_id
        ))
    else:
        cursor.execute("""
        INSERT INTO incidents (
            id, title, severity, status, created_at, updated_at, alert_data,
            detection_result, threat_intel_result, investigation_result, kb_result,
            response_result, reporting_result, risk_score, mitre_tactics, hitl_status
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            incident_id, title, severity, status, now, now, alert_str,
            kwargs.get("detection_result"),
            kwargs.get("threat_intel_result"),
            kwargs.get("investigation_result"),
            kwargs.get("kb_result"),
            kwargs.get("response_result"),
            kwargs.get("reporting_result"),
            kwargs.get("risk_score", 0),
            kwargs.get("mitre_tactics", "[]"),
            kwargs.get("hitl_status", "PENDING")
        ))
    
    conn.commit()
    conn.close()

def get_incident(incident_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM incidents WHERE id = ?", (incident_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return dict(row)
    return None

def list_incidents():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id, title, severity, status, risk_score, created_at, hitl_status FROM incidents ORDER BY created_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def save_approval_request(request_id, incident_id, action_name, target_entity, action_type, risk_level, reasoning):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    
    cursor.execute("""
    INSERT INTO approval_requests (
        id, incident_id, action_name, target_entity, action_type, risk_level, reasoning, status, requested_at
    ) VALUES (?, ?, ?, ?, ?, ?, ?, 'PENDING', ?)
    """, (request_id, incident_id, action_name, target_entity, action_type, risk_level, reasoning, now))
    
    conn.commit()
    conn.close()

def update_approval_status(request_id, new_status, analyst_notes=""):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    
    cursor.execute("""
    UPDATE approval_requests SET status = ?, responded_at = ?, analyst_notes = ? WHERE id = ?
    """, (new_status, now, analyst_notes, request_id))
    
    # Get associated incident_id
    cursor.execute("SELECT incident_id FROM approval_requests WHERE id = ?", (request_id,))
    row = cursor.fetchone()
    if row:
        inc_id = row["incident_id"]
        cursor.execute("UPDATE incidents SET hitl_status = ? WHERE id = ?", (new_status, inc_id))
        
    conn.commit()
    conn.close()

def get_pending_approvals():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM approval_requests WHERE status = 'PENDING' ORDER BY requested_at DESC")
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

def add_audit_log(incident_id, agent_name, event_type, message, payload=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    now = datetime.now(timezone.utc).isoformat()
    payload_str = json.dumps(payload) if payload else None
    
    cursor.execute("""
    INSERT INTO audit_logs (incident_id, agent_name, event_type, message, timestamp, payload)
    VALUES (?, ?, ?, ?, ?, ?)
    """, (incident_id, agent_name, event_type, message, now, payload_str))
    
    conn.commit()
    conn.close()

def get_audit_logs(incident_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM audit_logs WHERE incident_id = ? ORDER BY id ASC", (incident_id,))
    rows = cursor.fetchall()
    conn.close()
    return [dict(r) for r in rows]

# Initialize database schema on module import
init_db()
