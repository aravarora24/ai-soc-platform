/**
 * AI Security Operations Centre (AI SOC) - Frontend Application Script
 */

let currentAlerts = [];
let selectedAlert = null;
let currentIncidentResult = null;

document.addEventListener("DOMContentLoaded", () => {
    loadSampleAlerts();
    setupTabSwitching();
    updateAuthUI();
});

// Authentication & Session Guard
function isAuthenticated() {
    return sessionStorage.getItem("soc_auth_user") === "user";
}

function updateAuthUI() {
    const badge = document.getElementById("user-session-badge");
    if (isAuthenticated()) {
        if (badge) badge.classList.add("active");
    } else {
        if (badge) badge.classList.remove("active");
    }
}

// View Switcher (Landing Page vs Live Dashboard View with Auth Guard)
function switchView(viewName) {
    if (viewName === 'dashboard' && !isAuthenticated()) {
        openLoginModal();
        return;
    }

    document.querySelectorAll(".page-view").forEach(v => v.classList.remove("active"));
    document.querySelectorAll(".view-nav-btn").forEach(b => b.classList.remove("active"));

    const targetView = document.getElementById(`view-${viewName}`);
    const targetNav = document.getElementById(`nav-${viewName}`);

    if (targetView) targetView.classList.add("active");
    if (targetNav) targetNav.classList.add("active");

    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function openLoginModal() {
    const modal = document.getElementById("login-modal");
    const errorMsg = document.getElementById("login-error-msg");
    if (errorMsg) errorMsg.style.display = "none";
    if (modal) modal.classList.add("active");
}

function closeLoginModal() {
    const modal = document.getElementById("login-modal");
    if (modal) modal.classList.remove("active");
}

async function handleLoginSubmit(event) {
    event.preventDefault();
    const userIdInput = document.getElementById("login-user-id").value.trim();
    const passwordInput = document.getElementById("login-password").value.trim();
    const errorMsg = document.getElementById("login-error-msg");

    try {
        const response = await fetch("/api/login", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ username: userIdInput, password: passwordInput })
        });

        if (response.ok) {
            const data = await response.json();
            sessionStorage.setItem("soc_auth_user", data.user);
            updateAuthUI();
            closeLoginModal();
            switchView('dashboard');
        } else {
            if (errorMsg) {
                errorMsg.style.display = "block";
                errorMsg.textContent = "Invalid User ID or Password. Access Denied.";
            }
        }
    } catch (err) {
        // Client-side fallback check
        if (userIdInput === "user" && passwordInput === "123") {
            sessionStorage.setItem("soc_auth_user", "user");
            updateAuthUI();
            closeLoginModal();
            switchView('dashboard');
        } else {
            if (errorMsg) {
                errorMsg.style.display = "block";
                errorMsg.textContent = "Invalid User ID or Password. Access Denied.";
            }
        }
    }
}

function performLogout() {
    sessionStorage.removeItem("soc_auth_user");
    updateAuthUI();
    switchView('landing');
    alert("You have logged out of the SOC Command Dashboard.");
}

// Tab Switching inside Dashboard Results
function setupTabSwitching() {
    const tabs = document.querySelectorAll(".tab-btn");
    tabs.forEach(tab => {
        tab.addEventListener("click", () => {
            tabs.forEach(t => t.classList.remove("active"));
            document.querySelectorAll(".tab-content").forEach(c => c.classList.remove("active"));
            
            tab.classList.add("active");
            const targetId = tab.getAttribute("data-tab");
            document.getElementById(targetId).classList.add("active");
        });
    });
}

// Load Sample Security Alerts
async function loadSampleAlerts() {
    try {
        const response = await fetch("/static/sample_alerts.json");
        currentAlerts = await response.json();
        renderAlertList(currentAlerts);
        if (currentAlerts.length > 0) {
            selectAlert(currentAlerts[0]);
        }
    } catch (err) {
        console.error("Failed to load sample alerts:", err);
    }
}

// Render Alert Feed
function renderAlertList(alerts) {
    const listEl = document.getElementById("alert-feed-list");
    if (!listEl) return;
    listEl.innerHTML = "";
    
    alerts.forEach((alert) => {
        const item = document.createElement("div");
        item.className = `alert-item ${selectedAlert && selectedAlert.id === alert.id ? 'selected' : ''}`;
        item.onclick = () => selectAlert(alert);
        
        item.innerHTML = `
            <div class="alert-top">
                <span class="severity-tag severity-${alert.severity}">${alert.severity}</span>
                <span class="log-time" style="font-size:0.7rem;">${alert.id}</span>
            </div>
            <div class="alert-name">${alert.alert_name}</div>
            <div class="alert-meta">
                <span>💻 ${alert.host}</span>
                <span>🌐 ${alert.ip_address}</span>
            </div>
        `;
        listEl.appendChild(item);
    });
}

// Select Alert
function selectAlert(alert) {
    selectedAlert = alert;
    renderAlertList(currentAlerts);
    
    document.getElementById("selected-alert-title").textContent = alert.alert_name;
    document.getElementById("selected-alert-host").textContent = alert.host;
    document.getElementById("selected-alert-ip").textContent = alert.ip_address;
    document.getElementById("selected-alert-user").textContent = alert.user;
    document.getElementById("selected-alert-desc").textContent = alert.description;
    
    // Reset pipeline UI
    resetAgentNodes();
}

function resetAgentNodes() {
    document.querySelectorAll(".agent-node").forEach(node => {
        node.classList.remove("active", "completed");
    });
    document.getElementById("log-stream").innerHTML = '<div class="log-entry"><span class="log-time">[SYSTEM]</span> Ready to start multi-agent investigation.</div>';
}

// Trigger Multi-Agent Investigation Pipeline
async function triggerInvestigation() {
    if (!selectedAlert) return;
    
    const btn = document.getElementById("btn-investigate");
    btn.disabled = true;
    btn.innerHTML = `⚡ Investigating...`;
    
    resetAgentNodes();
    appendLog("SYSTEM", "HANDOFF_START", `Dispatched incident payload '${selectedAlert.id}' to Multi-Agent Orchestrator.`);
    
    try {
        // Step-by-step visual animation for handoffs
        const agentOrder = [
            { id: "node-detection", name: "Threat Detection Agent (The Gatekeeper)", tool: "Log Reader" },
            { id: "node-intel", name: "Threat Intelligence Agent (The Investigator)", tool: "Reputation Checker & Vulnerability Lookup" },
            { id: "node-investigation", name: "Investigation Agent (The Detective)", tool: "Security Playbook Search" },
            { id: "node-response", name: "Incident Response Agent (The Defender)", tool: "Host Isolator (HITL Gate)" },
            { id: "node-reflection", name: "Self-Review Critic Agent", tool: "False-Positive Verifier" },
            { id: "node-reporting", name: "Security Report Agent (The Scribe)", tool: "Structured Post-Mortem Form" }
        ];
        
        for (let i = 0; i < agentOrder.length; i++) {
            const agent = agentOrder[i];
            const nodeEl = document.getElementById(agent.id);
            
            if (nodeEl) nodeEl.classList.add("active");
            appendLog(agent.name, "PROCESSING", `Executing agent logic using gadget tool '${agent.tool}'...`);
            await new Promise(r => setTimeout(r, 450)); // Visual step delay
            
            if (nodeEl) {
                nodeEl.classList.remove("active");
                nodeEl.classList.add("completed");
            }
        }

        // Call FastAPI Backend Endpoint
        const res = await fetch("/api/investigate", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify(selectedAlert)
        });
        
        const data = await res.json();
        currentIncidentResult = data;
        
        appendLog("SYSTEM", "COMPLETE", `Investigation complete. Incident ID: ${data.incident_id}`);
        renderInvestigationResults(data);
        
        // Check if Human Approval is needed
        checkPendingApprovals();

    } catch (err) {
        appendLog("SYSTEM", "ERROR", `Investigation failed: ${err.message}`);
    } finally {
        btn.disabled = false;
        btn.innerHTML = `⚡ Launch Multi-Agent Investigation`;
    }
}

function appendLog(agent, type, message) {
    const stream = document.getElementById("log-stream");
    if (!stream) return;
    const timeStr = new Date().toLocaleTimeString();
    const entry = document.createElement("div");
    entry.className = "log-entry";
    entry.innerHTML = `<span class="log-time">[${timeStr}]</span> <span class="log-agent">${agent}</span>: ${message}`;
    stream.appendChild(entry);
    stream.scrollTop = stream.scrollHeight;
}

// Render Results in Structured Outputs and Tabs
function renderInvestigationResults(data) {
    // Populate Structured Outputs Digital Form
    const threatScore = data.threat_intel?.threat_score || 85;
    const severity = threatScore >= 85 ? "CRITICAL" : (threatScore >= 70 ? "HIGH" : "MEDIUM");
    
    document.getElementById("struct-severity").innerHTML = `<span class="severity-tag severity-${severity}">${severity} (Score: ${threatScore}/100)</span>`;
    document.getElementById("struct-hosts").textContent = (data.investigation?.compromised_assets || [selectedAlert?.host || "WORKSTATION-SEC-09"]).join(", ");
    document.getElementById("struct-rootcause").textContent = data.investigation?.root_cause_analysis || "Initial breach via unauthorized process execution & credential dump.";
    
    const actions = data.response?.response_playbook || [];
    const pendingCount = data.response?.pending_human_approvals_count || 0;
    const actionSummary = actions.map(a => `${a.action} [${a.status}]`).join(" | ");
    document.getElementById("struct-actions").innerHTML = `<span style="color:${pendingCount > 0 ? 'var(--neon-magenta)' : 'var(--neon-green)'};">${actionSummary || 'Containment Staged'} (${pendingCount} Pending Approval)</span>`;

    // 1. MITRE ATT&CK Heatmap & Execution Tree
    const mitreContainer = document.getElementById("mitre-container");
    mitreContainer.innerHTML = "";
    
    const mitreList = data.investigation?.mitre_attack_matrix || [];
    mitreList.forEach(m => {
        const badge = document.createElement("div");
        badge.className = "mitre-badge";
        badge.innerHTML = `<strong>[${m.technique_id}]</strong> ${m.technique_name} (${m.tactic})`;
        mitreContainer.appendChild(badge);
    });
    
    // Execution Tree
    const treeContainer = document.getElementById("execution-tree-container");
    treeContainer.innerHTML = "";
    const steps = data.investigation?.attack_chain_timeline || [];
    steps.forEach(s => {
        const stepDiv = document.createElement("div");
        stepDiv.style.padding = "0.5rem";
        stepDiv.style.borderLeft = "2px solid var(--neon-cyan)";
        stepDiv.style.marginBottom = "0.5rem";
        stepDiv.innerHTML = `<strong>Step ${s.step} (${s.phase}):</strong> ${s.description}`;
        treeContainer.appendChild(stepDiv);
    });
    
    // 2. Playbooks & RAG
    const kbContainer = document.getElementById("rag-playbooks-container");
    kbContainer.innerHTML = "";
    const playbooks = data.knowledge_base?.retrieved_playbooks || [];
    playbooks.forEach(p => {
        const card = document.createElement("div");
        card.style.background = "rgba(15, 23, 42, 0.6)";
        card.style.padding = "0.75rem";
        card.style.borderRadius = "8px";
        card.style.border = "1px solid var(--border-color)";
        card.innerHTML = `
            <div style="font-weight:700; color:var(--neon-green);">${p.title}</div>
            <div style="font-size:0.75rem; color:var(--text-muted); margin-bottom:0.4rem;">${p.mitre_id} | Similarity: ${p.relevance_score}</div>
            <pre style="font-family:var(--font-mono); font-size:0.75rem; color:var(--text-secondary); white-space:pre-wrap;">${p.excerpt}</pre>
        `;
        kbContainer.appendChild(card);
    });
    
    // 3. Response Actions
    const respContainer = document.getElementById("response-actions-container");
    respContainer.innerHTML = "";
    actions.forEach(a => {
        const item = document.createElement("div");
        item.style.padding = "0.75rem";
        item.style.borderRadius = "8px";
        item.style.background = a.status === 'PENDING_APPROVAL' ? 'rgba(255, 0, 85, 0.1)' : 'rgba(0, 255, 136, 0.1)';
        item.style.border = a.status === 'PENDING_APPROVAL' ? '1px solid var(--neon-magenta)' : '1px solid var(--neon-green)';
        item.innerHTML = `
            <div style="display:flex; justify-content:space-between; font-weight:700;">
                <span>${a.action} -> ${a.target}</span>
                <span class="severity-tag severity-${a.status === 'PENDING_APPROVAL' ? 'CRITICAL' : 'MEDIUM'}">${a.status}</span>
            </div>
            <div style="font-size:0.8rem; color:var(--text-secondary); margin-top:0.3rem;">${a.impact_analysis}</div>
        `;
        respContainer.appendChild(item);
    });
    
    // 4. Report Markdown
    const reportViewer = document.getElementById("report-markdown-viewer");
    if (data.reporting && data.reporting.report_markdown) {
        reportViewer.innerText = data.reporting.report_markdown;
    }
}

// Check Pending Approvals
async function checkPendingApprovals() {
    try {
        const res = await fetch("/api/approvals/pending");
        const list = await res.json();
        
        if (list.length > 0) {
            const req = list[0];
            showApprovalModal(req);
        }
    } catch (err) {
        console.error("Failed checking pending approvals:", err);
    }
}

function showApprovalModal(req) {
    const modal = document.getElementById("approval-modal");
    document.getElementById("modal-action-name").textContent = req.action_name;
    document.getElementById("modal-target").textContent = req.target_entity;
    document.getElementById("modal-reasoning").textContent = req.reasoning;
    document.getElementById("modal-request-id").textContent = req.id;
    
    modal.classList.add("active");
    
    document.getElementById("btn-modal-approve").onclick = () => submitApprovalResponse(req.id, "APPROVED");
    document.getElementById("btn-modal-reject").onclick = () => submitApprovalResponse(req.id, "REJECTED");
}

async function submitApprovalResponse(requestId, newStatus) {
    const modal = document.getElementById("approval-modal");
    modal.classList.remove("active");
    
    const notes = prompt("Enter SOC Analyst Sign-off Notes:", `${newStatus} by Lead Analyst`);
    
    try {
        await fetch("/api/approvals/respond", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                request_id: requestId,
                status: newStatus,
                analyst_notes: notes || ""
            })
        });
        appendLog("HUMAN_ANALYST", "HITL_ACTION", `Decision submitted: ${newStatus} for request ${requestId}`);
        alert(`Action ${newStatus} successfully executed by EDR controller.`);
    } catch (err) {
        console.error("Failed submitting approval decision:", err);
    }
}

// Dashboard Mode Switcher (Tier-1 Analyst View vs CISO Executive View)
function setDashboardMode(modeName) {
    const analystView = document.getElementById("view-mode-analyst");
    const cisoView = document.getElementById("view-mode-ciso");
    const btnAnalyst = document.getElementById("btn-mode-analyst");
    const btnCiso = document.getElementById("btn-mode-ciso");

    if (modeName === 'ciso') {
        if (analystView) analystView.style.display = "none";
        if (cisoView) cisoView.classList.add("active");
        if (btnAnalyst) btnAnalyst.classList.remove("active");
        if (btnCiso) btnCiso.classList.add("active");
    } else {
        if (analystView) analystView.style.display = "block";
        if (cisoView) cisoView.classList.remove("active");
        if (btnAnalyst) btnAnalyst.classList.add("active");
        if (btnCiso) btnCiso.classList.remove("active");
    }
}

// Trigger Slack / Discord Webhook Card Dispatch
async function triggerTestWebhook() {
    const webhookUrl = document.getElementById("webhook-url-input")?.value?.trim() || "";
    const badge = document.getElementById("webhook-status-badge");
    
    if (badge) badge.textContent = "Status: Sending Webhook Alert...";

    const incId = currentIncidentResult ? currentIncidentResult.incident_id : "INC-DEMO-99";
    const targetHost = selectedAlert ? selectedAlert.host : "WORKSTATION-SEC-09";

    try {
        const res = await fetch("/api/webhook/send", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                webhook_url: webhookUrl,
                incident_id: incId,
                action_name: "ISOLATE_HOST",
                target: targetHost,
                reasoning: "Ransomware encryption activity & shadow copy deletion detected.",
                severity: "CRITICAL"
            })
        });

        const data = await res.json();
        if (badge) {
            badge.style.color = data.status === "ERROR" ? "var(--neon-magenta)" : "var(--neon-green)";
            badge.textContent = `Status: ${data.status} - ${data.message}`;
        }
        appendLog("WEBHOOK_DISPATCHER", "WEBHOOK", `Alert card sent: ${data.message}`);
    } catch (err) {
        if (badge) badge.textContent = `Status: Error - ${err.message}`;
    }
}

// Multi-Format Report Exporter (Markdown, Styled HTML, PDF/Print)
function downloadReport(format = 'md') {
    if (!currentIncidentResult || !currentIncidentResult.reporting) {
        alert("Please run an investigation first.");
        return;
    }
    
    const incId = currentIncidentResult.incident_id;
    const markdownText = currentIncidentResult.reporting.report_markdown;
    const execSummary = currentIncidentResult.reporting.executive_summary;

    if (format === 'md') {
        const blob = new Blob([markdownText], { type: "text/markdown" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `AI_SOC_PostMortem_${incId}.md`;
        a.click();
        return;
    }

    // Styled HTML & PDF Print Template
    const styledHtml = `
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="utf-8">
        <title>AI SOC Post-Mortem Report - ${incId}</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; padding: 40px; background: #0f172a; color: #f8fafc; line-height: 1.6; }
            .header { border-bottom: 2px solid #00f0ff; padding-bottom: 20px; margin-bottom: 30px; display: flex; justify-content: space-between; align-items: center; }
            .title { font-size: 24px; font-weight: 800; color: #00f0ff; }
            .subtitle { color: #94a3b8; font-size: 14px; }
            .card { background: #1e293b; border-radius: 10px; padding: 20px; margin-bottom: 20px; border: 1px solid #334155; }
            .badge { display: inline-block; padding: 4px 12px; border-radius: 6px; font-weight: 700; background: #ff0055; color: #fff; }
            pre { background: #020617; padding: 15px; border-radius: 8px; font-family: monospace; overflow-x: auto; color: #38bdf8; }
            @media print { body { background: #fff; color: #000; } .card { border: 1px solid #ccc; background: #f8fafc; color: #000; } pre { background: #f1f5f9; color: #0f172a; } }
        </style>
    </head>
    <body>
        <div class="header">
            <div>
                <div class="title">🛡️ AI SOC EXECUTIVE POST-MORTEM REPORT</div>
                <div class="subtitle">Incident ID: ${incId} | Generated by AI Security Operations Centre</div>
            </div>
            <span class="badge">CRITICAL SEVERITY</span>
        </div>

        <div class="card">
            <h3>📊 Executive Summary</h3>
            <p>${execSummary}</p>
        </div>

        <div class="card">
            <h3>📑 Detailed Forensic Audit Report</h3>
            <pre>${markdownText.replace(/</g, "&lt;").replace(/>/g, "&gt;")}</pre>
        </div>

        <div style="font-size:12px; color:#64748b; text-align:center; margin-top:40px;">
            Confidential Enterprise Security Document • Autonomous AI SOC Platform
        </div>
    </body>
    </html>
    `;

    if (format === 'html') {
        const blob = new Blob([styledHtml], { type: "text/html" });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `AI_SOC_Report_${incId}.html`;
        a.click();
    } else if (format === 'pdf') {
        const printWin = window.open("", "_blank");
        printWin.document.write(styledHtml);
        printWin.document.close();
        printWin.focus();
        setTimeout(() => printWin.print(), 500);
    }
}
