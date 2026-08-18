"""
Agent 6: Knowledge Base RAG Agent
Queries security playbook vector store, NIST guidelines, enterprise policies, and YARA rules.
"""

from typing import Dict, Any
from tools.rag_store import query_knowledge_base

class KnowledgeBaseAgent:
    def __init__(self):
        self.name = "Knowledge Base RAG Agent"
        self.role = "Security Policy & RAG Search Specialist"

    async def execute(self, investigation_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Uses RAG similarity search to retrieve relevant enterprise playbooks and policy documents.
        """
        root_cause = investigation_data.get("root_cause_analysis", "")
        mitre_list = [m.get("technique_name", "") for m in investigation_data.get("mitre_attack_matrix", [])]
        search_query = f"{root_cause} {' '.join(mitre_list)} ransomware exfiltration cobaltstrike"
        
        # Execute RAG query against Vector Store (Tool 5)
        rag_hits = query_knowledge_base(search_query, top_k=3)
        
        return {
            "query_used": search_query[:120] + "...",
            "retrieved_playbooks": rag_hits,
            "policy_compliance_status": "NON_COMPLIANT - Unauthorized Execution Policy Violation",
            "recommended_guidelines": [
                "NIST SP 800-61 Rev 2 Incident Handling Guidelines",
                "ISO 27001 Control A.12.6 Management of Technical Vulnerabilities"
            ],
            "reasoning_trace": [
                f"Generated RAG embedding query based on investigation root cause.",
                f"Retrieved {len(rag_hits)} matching enterprise playbooks with highest similarity score {rag_hits[0]['relevance_score'] if rag_hits else 0.0}.",
                "Attached NIST SP 800-61 containment guidelines to incident context."
            ]
        }
