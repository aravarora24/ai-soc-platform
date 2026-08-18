# Autonomous AI Security Operations Centre (SOC) Platform 🛡️🤖

An enterprise-grade, multi-agent cybersecurity platform built on the **OpenAI Agents SDK**. The platform automates security incident triage, threat intelligence correlation, forensic investigation, and post-mortem reporting while enforcing mandatory **Human-in-the-Loop (HITL)** safety gates for high-risk containment actions.

---

## 🌟 Key Features

* **6 Specialised AI Agents:** Sequential orchestration across Threat Detection, Threat Intelligence, Investigation, Incident Response, Self-Review Critic, and Security Report agents.
* **Gadget Belt Tools:** Modular utilities for Syslog parsing, VirusTotal reputation checks, MITRE ATT&CK RAG search, CVE lookups, and host network isolation.
* **Human Approval Gate (HITL):** Automatic execution pauses on high-risk actions (`Host Isolator`), requiring explicit analyst sign-off before proceeding.
* **Session Persistence & Auditing:** Relational SQLite backend (`soc_incidents.db`) tracking multi-turn interaction state and historical incident audits.
* **Real-time Observability:** Interactive dashboard with real-time execution logs and CISO-level security metrics.

---

## 🛠️ Tech Stack

* **Framework:** OpenAI Agents SDK, Python 3.10+
* **Backend:** FastAPI / FastHTML
* **Database:** SQLite
* **Frontend:** Tailwind CSS, JavaScript (SSE/WebSockets)

---

## 📁 Repository Structure

```text
├── agents/             # Specialised OpenAI SDK Agent definitions
├── tools/              # Cybersecurity execution tools & API integrations
├── app.py              # Main application backend and Web UI server
├── config.py           # Configuration settings and API keys
├── database.py         # SQLite database models and persistence handlers
├── soc_incidents.db    # Persistent incident database
├── test_system.py      # Test suite for agent handoffs and tool calls
├── requirements.txt    # Python dependencies
└── README.md           # Documentation
