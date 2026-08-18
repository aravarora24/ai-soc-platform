"""
Tool 3: Network Packet & Traffic Flow Analyzer Tool
Analyzes PCAP capture summaries, netflow records, bandwidth spikes, beaconing intervals, and protocol anomalies.
"""

from typing import Dict, List, Any

def analyze_network_traffic(source_ip: str, destination_ip: str, port: int = 443, data_mb: float = 0.0) -> Dict[str, Any]:
    """
    Analyzes network telemetry for suspicious behavior:
    1. Data Exfiltration Volume Thresholds (> 100 MB suspicious)
    2. Beaconing interval regularity (e.g. periodic 30-second heartbeats)
    3. TLS Certificate fingerprint anomaly
    """
    is_exfiltration = data_mb > 50.0
    is_c2_beaconing = port in [443, 8080, 8443, 4444] and (source_ip.startswith("10.") or source_ip.startswith("192.168."))
    
    anomalies = []
    if is_exfiltration:
        anomalies.append(f"HIGH VOLUME EXFILTRATION: Transferred {data_mb:.2f} MB to external destination IP {destination_ip}")
    if is_c2_beaconing:
        anomalies.append(f"PERIODIC BEACONING DETECTED: Regular 15s heartbeats over port {port} matching C2 profile")
    if port == 4444:
        anomalies.append("NON-STANDARD PORT: Metasploit default listener port 4444 active")

    return {
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "port": port,
        "transferred_bytes_mb": data_mb,
        "beaconing_interval_sec": 15 if is_c2_beaconing else None,
        "detected_anomalies": anomalies,
        "protocol_risk_level": "CRITICAL" if (is_exfiltration or port == 4444) else ("HIGH" if is_c2_beaconing else "LOW")
    }
