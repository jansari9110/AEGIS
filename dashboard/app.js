/**
 * AEGIS Dashboard — app.js
 * ========================
 * Handles all dashboard interactions:
 *   - Live alert polling from FastAPI
 *   - IOC checker form
 *   - Email analyser form
 *   - ATT&CK heatmap
 *   - Metrics page
 *   - Alert detail panel
 *   - Analyst actions (notes, feedback, escalate)
 *   - Gemini AI report generation
 *
 * New JavaScript concepts explained inline:
 *   fetch()           — makes HTTP requests to FastAPI
 *   async/await       — cleaner way to handle promises
 *   setInterval()     — runs a function repeatedly
 *   JSON.stringify()  — converts JS object to JSON string
 *   template literals — `${variable}` inside backtick strings
 *   DOM manipulation  — getElementById, innerHTML, classList
 */

// ── CONFIGURATION ────────────────────────────────────────────────
const API_BASE    = "http://localhost:8000";
const POLL_INTERVAL = 10000; // refresh alerts every 10 seconds

// Currently selected alert ID — used by action buttons
let currentAlertId = null;
let currentAlertData = null;

// MITRE techniques for heatmap display
const MITRE_DISPLAY = {
    "T1595":    { name: "Active Scanning",       tactic: "Recon" },
    "T1592":    { name: "Host Info Gathering",   tactic: "Recon" },
    "T1566":    { name: "Phishing",              tactic: "Initial Access" },
    "T1566.001":{ name: "Spearphishing",         tactic: "Initial Access" },
    "T1190":    { name: "Exploit Web App",       tactic: "Initial Access" },
    "T1059":    { name: "Command Execution",     tactic: "Execution" },
    "T1059.004":{ name: "Unix Shell",            tactic: "Execution" },
    "T1110":    { name: "Brute Force",           tactic: "Cred Access" },
    "T1110.001":{ name: "Password Guessing",     tactic: "Cred Access" },
    "T1110.003":{ name: "Password Spraying",     tactic: "Cred Access" },
    "T1003":    { name: "Cred Dumping",          tactic: "Cred Access" },
    "T1557":    { name: "MITM",                  tactic: "Cred Access" },
    "T1046":    { name: "Network Discovery",     tactic: "Discovery" },
    "T1083":    { name: "File Discovery",        tactic: "Discovery" },
    "T1021.004":{ name: "SSH Lateral Move",      tactic: "Lateral Move" },
    "T1040":    { name: "Network Sniffing",      tactic: "Collection" },
    "T1041":    { name: "Exfiltration",          tactic: "Exfiltration" },
    "T1499":    { name: "DoS",                   tactic: "Impact" },
    "T1053":    { name: "Scheduled Task",        tactic: "Persistence" },
};


// ══════════════════════════════════════════════════════════════════
// CLOCK — updates every second
// ══════════════════════════════════════════════════════════════════

/**
 * NEW CONCEPT — setInterval(function, ms):
 *   Calls a function repeatedly every N milliseconds.
 *   1000ms = 1 second.
 *   Returns an ID you can use to stop it with clearInterval().
 */
function updateClock() {
    const el = document.getElementById("clock");
    if (el) {
        el.textContent = new Date().toTimeString().slice(0, 8);
    }
}
setInterval(updateClock, 1000);
updateClock();


// ══════════════════════════════════════════════════════════════════
// PAGE NAVIGATION
// ══════════════════════════════════════════════════════════════════

/**
 * Switches between dashboard pages.
 * Hides all pages, shows the selected one.
 * Updates nav button active state.
 */
function showPage(pageId, btnEl) {
    // Hide all pages
    document.querySelectorAll(".page").forEach(p => {
        p.classList.remove("active");
    });

    // Remove active from all nav buttons
    document.querySelectorAll(".nav-btn").forEach(b => {
        b.classList.remove("active");
    });

    // Show selected page
    const page = document.getElementById("page-" + pageId);
    if (page) page.classList.add("active");

    // Mark button as active
    if (btnEl) btnEl.classList.add("active");

    // Load data for the page being shown
    if (pageId === "heatmap") loadHeatmap();
    if (pageId === "metrics") loadMetrics();
}


// ══════════════════════════════════════════════════════════════════
// API HELPER — all requests go through this function
// ══════════════════════════════════════════════════════════════════

/**
 * NEW CONCEPT — async function + await:
 *   async functions always return a Promise.
 *   await pauses execution until the Promise resolves.
 *   This makes async code look like synchronous code.
 *   Without async/await you would need .then().catch() chains.
 *
 * NEW CONCEPT — fetch(url, options):
 *   Built-in browser function to make HTTP requests.
 *   Returns a Promise that resolves to a Response object.
 *   response.json() parses the JSON body — also async.
 */
async function apiCall(endpoint, method = "GET", body = null) {
    try {
        const options = {
            method: method,
            headers: { "Content-Type": "application/json" },
        };

        // Only add body for POST/PUT requests
        if (body && method !== "GET") {
            options.body = JSON.stringify(body);
            // NEW CONCEPT — JSON.stringify():
            // Converts JS object { key: value } to JSON string
            // '{"key":"value"}' — what the server receives
        }

        const response = await fetch(API_BASE + endpoint, options);

        // Check if request succeeded
        if (!response.ok) {
            const error = await response.json().catch(() => ({}));
            throw new Error(error.detail || `HTTP ${response.status}`);
        }

        return await response.json();
        // response.json() reads the body and parses JSON
        // Returns a JS object we can use directly

    } catch (err) {
        console.error(`API call failed: ${endpoint}`, err);
        throw err;
    }
}


// ══════════════════════════════════════════════════════════════════
// ALERT QUEUE — main dashboard page
// ══════════════════════════════════════════════════════════════════

async function loadAlerts() {
    try {
        const data = await apiCall("/alerts?limit=100");
        renderAlerts(data.alerts);
        updateMetricBar(data);

        // Update footer count
        const footer = document.getElementById("footer-count");
        if (footer) footer.textContent = data.total || 0;

    } catch (err) {
        const tbody = document.getElementById("alert-tbody");
        if (tbody) {
            tbody.innerHTML = `
            <tr>
            <td colspan="8" class="loading-row" style="color:#f85149;">
            <i class="ti ti-alert-circle"></i>
            Cannot connect to AEGIS backend.
            Make sure server is running on port 8000.
            </td>
            </tr>`;
        }
    }
}

function renderAlerts(alerts) {
    const tbody = document.getElementById("alert-tbody");
    if (!tbody) return;

    if (!alerts || alerts.length === 0) {
        tbody.innerHTML = `
        <tr>
        <td colspan="8" class="loading-row">
        No alerts yet. Submit an IOC to create the first alert.
        </td>
        </tr>`;
        return;
    }

    /**
     * NEW CONCEPT — Array.map() + join():
     *   .map() transforms each item in an array.
     *   .join("") combines all strings with no separator.
     *   Together they build an HTML string from an array of objects.
     *   More efficient than looping and appending strings.
     */
    tbody.innerHTML = alerts.map(alert => {
        const pill     = getRiskPill(alert.risk_score);
        const scoreCol = getScoreClass(alert.risk_score);
        const time     = formatTime(alert.created_at);
        const mitre    = alert.mitre_technique_id || "—";
        const kc       = alert.kill_chain_stage || "—";

        return `
        <tr class="clickable"
        onclick="showDetail(${alert.id})">
        <td>${pill}</td>
        <td>
        <span class="${scoreCol}">
        ${alert.risk_score}
        </span>
        </td>
        <td style="color:var(--text-primary);">
        ${alert.alert_type || "—"}
        </td>
        <td class="mono">
        ${truncate(alert.indicator, 30)}
        </td>
        <td class="mono" style="color:var(--text-tertiary);">
        ${mitre}
        </td>
        <td style="font-size:12px;">
        ${kc}
        </td>
        <td>${getStatusBadge(alert.status)}</td>
        <td style="font-size:11px;color:var(--text-tertiary);">
        ${time}
        </td>
        </tr>`;
    }).join("");
}

async function updateMetricBar(data) {
    try {
        const stats = await apiCall("/stats");

        setEl("m-total", stats.total_alerts || 0);
        setEl("m-high",  stats.high_risk || 0);
        setEl("m-open",  stats.open_alerts || 0);
        setEl("m-fp",    (stats.fp_rate || 0) + "%");
        setEl("m-total-sub",
              `${stats.total_alerts || 0} total processed`);

    } catch (err) {
        // Stats failed — not critical, alerts still show
    }
}


// ══════════════════════════════════════════════════════════════════
// ALERT DETAIL PANEL
// ══════════════════════════════════════════════════════════════════

async function showDetail(alertId) {
    currentAlertId = alertId;

    try {
        const alert = await apiCall(`/alert/${alertId}`);
        currentAlertData = alert;

        // Fill in header
        setEl("d-title",
              `${alert.alert_type || "Alert"} — ID #${alert.id}`);
        setEl("d-sub",
              `Source: ${alert.source || "manual"} · ` +
              `Created: ${formatTime(alert.created_at)}`);

        // Fill in fields
        setEl("d-indicator", alert.indicator || "—");
        setEl("d-score",
              `${alert.risk_score}/100 — ${alert.verdict}`);
        setEl("d-vt",
              `${alert.vt_malicious || 0}/${alert.vt_total || 0} ` +
              `engines flagged`);
        setEl("d-abuse",
              `${alert.abuse_score || 0}/100`);
        setEl("d-mitre",
              `${alert.mitre_technique_id || "—"} ` +
              `${alert.mitre_technique_name
                  ? "(" + alert.mitre_technique_name + ")"
                  : ""}`);
        setEl("d-killchain", alert.kill_chain_stage || "—");
        setEl("d-cve",
              alert.cve_id
              ? `${alert.cve_id} CVSS ${alert.cvss_score}`
              : "No CVE linked");
        setEl("d-source", alert.source || "manual");

        // Score bar
        const score    = alert.risk_score || 0;
        const bar      = document.getElementById("d-score-bar");
        const scoreLabel = document.getElementById("d-score-pct");
        if (bar) {
            bar.style.width = score + "%";
            bar.style.background =
            score >= 70 ? "var(--danger)" :
            score >= 40 ? "var(--warning)" :
            "var(--success)";
        }
        if (scoreLabel) scoreLabel.textContent = `${score}/100`;

        // AI report — show existing or prompt to generate
        const aiBox = document.getElementById("d-ai-report");
        if (alert.ai_report) {
            if (aiBox) aiBox.textContent = alert.ai_report;
            const btn = document.getElementById("ai-btn");
            if (btn) btn.textContent = "Regenerate report";
        } else {
            if (aiBox) {
                aiBox.textContent =
                "Click Generate AI Report to analyse this alert";
            }
        }

        // Analyst notes
        const notesEl = document.getElementById("analyst-notes");
        if (notesEl) notesEl.value = alert.analyst_notes || "";

        // Show the panel
        const panel = document.getElementById("detail-panel");
        if (panel) {
            panel.classList.add("visible");
            panel.scrollIntoView({ behavior: "smooth", block: "nearest"});
        }

    } catch (err) {
        showToast("Could not load alert details: " + err.message,
                  "danger");
    }
}

function closeDetail() {
    const panel = document.getElementById("detail-panel");
    if (panel) panel.classList.remove("visible");
    currentAlertId   = null;
    currentAlertData = null;
}


// ══════════════════════════════════════════════════════════════════
// GEMINI AI REPORT
// ══════════════════════════════════════════════════════════════════

async function generateAIReport() {
    if (!currentAlertId) return;

    const btn   = document.getElementById("ai-btn");
    const aiBox = document.getElementById("d-ai-report");

    if (btn) {
        btn.disabled     = true;
        btn.innerHTML    =
        '<i class="ti ti-loader spin"></i> Generating...';
    }
    if (aiBox) aiBox.textContent = "AI is analysing this alert...";

    try {
        // Call Gemini via our backend
        const result = await apiCall(
            `/alert/${currentAlertId}/ai-report`,
            "POST"
        );

        if (aiBox && result.report) {
            aiBox.textContent = result.report;
        }

        if (btn) {
            btn.disabled  = false;
            btn.innerHTML =
            '<i class="ti ti-sparkles"></i> Regenerate report';
        }

    } catch (err) {
        // If AI endpoint not built yet — generate locally
        if (aiBox && currentAlertData) {
            aiBox.textContent = generateLocalReport(currentAlertData);
        }
        if (btn) {
            btn.disabled  = false;
            btn.innerHTML =
            '<i class="ti ti-sparkles"></i> Generate AI Report';
        }
    }
}

/**
 * Generates a basic report locally if Gemini API
 * endpoint is not yet built. Acts as a placeholder.
 */
function generateLocalReport(alert) {
    const score   = alert.risk_score || 0;
    const type    = alert.alert_type || "unknown";
    const ind     = alert.indicator || "unknown";
    const mitre   = alert.mitre_technique_id || "unknown";
    const abuse   = alert.abuse_score || 0;
    const vt      = alert.vt_malicious || 0;

    const level =
    score >= 70 ? "CRITICAL" :
    score >= 40 ? "HIGH" : "LOW";

    return `${level}: ${type} detected from ${ind} ` +
    `with risk score ${score}/100. ` +
    `VirusTotal flagged by ${vt} engines and ` +
    `AbuseIPDB score is ${abuse}/100, ` +
    `mapped to MITRE technique ${mitre}. ` +
    `Recommend immediate investigation and ` +
    `verification of source legitimacy.`;
}


// ══════════════════════════════════════════════════════════════════
// ANALYST ACTIONS
// ══════════════════════════════════════════════════════════════════

async function updateStatus(newStatus) {
    if (!currentAlertId) return;

    try {
        await apiCall(
            `/alert/${currentAlertId}/status`,
            "PUT",
            { status: newStatus }
        );
        showToast(`Alert ${newStatus}`, "success");
        loadAlerts();
        closeDetail();
    } catch (err) {
        showToast("Failed to update status: " + err.message, "danger");
    }
}

async function saveNote() {
    if (!currentAlertId) return;

    const notes = document.getElementById("analyst-notes");
    if (!notes || !notes.value.trim()) {
        showToast("Please write a note first", "warning");
        return;
    }

    try {
        await apiCall(
            `/alert/${currentAlertId}/notes`,
            "POST",
            { note: notes.value.trim() }
        );
        showToast("Note saved", "success");
    } catch (err) {
        showToast("Failed to save note: " + err.message, "danger");
    }
}

async function submitFeedback(isTruePositive) {
    if (!currentAlertId) return;

    const notes = document.getElementById("analyst-notes");
    const label = isTruePositive ? "True Positive" : "False Positive";

    try {
        await apiCall(
            `/alert/${currentAlertId}/feedback`,
            "POST",
            {
                is_true_positive: isTruePositive,
                notes: notes ? notes.value.trim() : "",
            }
        );
        showToast(`Marked as ${label}`, "success");
        loadAlerts();
        closeDetail();
    } catch (err) {
        showToast("Failed to save feedback: " + err.message, "danger");
    }
}


// ══════════════════════════════════════════════════════════════════
// IOC CHECKER PAGE
// ══════════════════════════════════════════════════════════════════

async function submitIOC() {
    const input = document.getElementById("ioc-input");
    const result = document.getElementById("ioc-result");

    if (!input || !input.value.trim()) {
        showToast("Please enter an indicator", "warning");
        return;
    }

    const indicator = input.value.trim();

    // Show loading state
    result.classList.remove("hidden");
    result.innerHTML = `
    <div class="loading-row">
    <i class="ti ti-loader spin"></i>
    Checking ${indicator} against threat intelligence...
    </div>`;

    try {
        const data = await apiCall(
            "/alert/manual",
            "POST",
            {
                alert_type: detectType(indicator),
                                   indicator:  indicator,
                                   source:     "manual_ioc_check",
            }
        );

        renderIOCResult(data, indicator);

    } catch (err) {
        result.innerHTML = `
        <div style="color:var(--danger);padding:12px;">
        <i class="ti ti-alert-circle"></i>
        Error: ${err.message}
        </div>`;
    }
}

function renderIOCResult(data, indicator) {
    const result   = document.getElementById("ioc-result");
    const details  = data.details || {};
    const ioc      = details.ioc || {};
    const vt       = ioc.vt_result || {};
    const abuse    = ioc.abuse_result || {};
    const mitre    = details.mitre || {};
    const score    = data.score || 0;
    const verdict  = data.verdict || "UNKNOWN";

    const verdictClass =
    score >= 70 ? "danger" :
    score >= 40 ? "warning" : "success";

    result.classList.remove("hidden");
    result.innerHTML = `
    <div class="result-section">
    <div class="result-section-title">
    <i class="ti ti-shield"></i> VirusTotal
    </div>
    <div class="result-row">
    <span class="result-label">Engines flagged</span>
    <span class="result-val
    ${(vt.malicious||0)>0 ? "danger" : "success"}">
    ${vt.malicious||0}/${vt.total||0}
    </span>
    </div>
    <div class="result-row">
    <span class="result-label">Suspicious</span>
    <span class="result-val">
    ${vt.suspicious||0}/${vt.total||0}
    </span>
    </div>
    </div>

    ${abuse.abuse_score !== undefined ? `
        <div class="result-section">
        <div class="result-section-title">
        <i class="ti ti-database"></i> AbuseIPDB
        </div>
        <div class="result-row">
        <span class="result-label">Abuse score</span>
        <span class="result-val
        ${(abuse.abuse_score||0)>70 ? "danger" :
            (abuse.abuse_score||0)>30 ? "warning" : "success"}">
            ${abuse.abuse_score||0}/100
            </span>
            </div>
            <div class="result-row">
            <span class="result-label">Country</span>
            <span class="result-val">${abuse.country||"—"}</span>
            </div>
            <div class="result-row">
            <span class="result-label">ISP</span>
            <span class="result-val">${abuse.isp||"—"}</span>
            </div>
            <div class="result-row">
            <span class="result-label">Total reports</span>
            <span class="result-val">${abuse.total_reports||0}</span>
            </div>
            </div>` : ""}

            <div class="result-section">
            <div class="result-section-title">
            <i class="ti ti-map"></i> MITRE ATT&CK
            </div>
            <div class="result-row">
            <span class="result-label">Technique</span>
            <span class="result-val mono">
            ${mitre.technique_id||"—"}
            </span>
            </div>
            <div class="result-row">
            <span class="result-label">Name</span>
            <span class="result-val">
            ${mitre.technique_name||"—"}
            </span>
            </div>
            <div class="result-row">
            <span class="result-label">Kill chain</span>
            <span class="result-val">
            ${mitre.kill_chain||"—"}
            </span>
            </div>
            </div>

            <div class="verdict-box ${verdictClass}">
            <div>
            <div class="verdict-label
            ${verdictClass === "danger" ? "danger" :
                verdictClass === "warning" ? "warning" : "success"}">
                ${verdict}
                </div>
                <div style="font-size:12px;
                color:var(--text-secondary);
                margin-top:3px;">
                Alert saved — ID #${data.alert_id||"pending"}
                </div>
                </div>
                <div class="verdict-score
                ${verdictClass === "danger" ? "danger" :
                    verdictClass === "warning" ? "warning" : "success"}">
                    ${score}/100
                    </div>
                    </div>`;

                    // Reload alert queue
                    loadAlerts();
}


// ══════════════════════════════════════════════════════════════════
// EMAIL ANALYSER PAGE
// ══════════════════════════════════════════════════════════════════

function loadTestEmail() {
    const input = document.getElementById("email-input");
    if (input) {
        input.value = `From: security@paypa1-verify.com
        To: victim@example.com
        Subject: Urgent: Your account has been suspended
        Date: Mon, 01 Jan 2024 10:00:00 +0000
        Reply-To: attacker@evil-domain.ru
        Return-Path: bounce@paypa1-verify.com
        Received: from mail.paypa1-verify.com (185.220.101.47)
        by mx.example.com; Mon, 01 Jan 2024 10:00:00 +0000
        MIME-Version: 1.0
        Content-Type: text/html

        <html><body>
        <p>Your account is suspended. Verify here:</p>
        <a href="http://paypa1-verify.com/login">Verify Account</a>
        </body></html>`;
    }
}

async function submitEmail() {
    const input  = document.getElementById("email-input");
    const result = document.getElementById("email-result");

    if (!input || !input.value.trim()) {
        showToast("Please paste email headers first", "warning");
        return;
    }

    result.classList.remove("hidden");
    result.innerHTML = `
    <div class="loading-row">
    <i class="ti ti-loader spin"></i>
    Analysing email for phishing indicators...
    </div>`;

    // For now submit as a phishing alert with the headers as indicator
    // Full email_analyser.py integration comes in v0.3
    const fromMatch = input.value.match(/From:\s*(.+)/i);
    const fromAddr  = fromMatch ? fromMatch[1].trim() : "unknown";

    try {
        const data = await apiCall("/alert/manual", "POST", {
            alert_type:  "phishing",
            indicator:   fromAddr,
            source:      "email_analyser",
            description: input.value.slice(0, 200),
        });

        result.innerHTML = `
        <div class="result-section">
        <div class="result-section-title">
        <i class="ti ti-mail-search"></i> Email Analysis
        </div>
        <div class="result-row">
        <span class="result-label">From address</span>
        <span class="result-val mono">${fromAddr}</span>
        </div>
        <div class="result-row">
        <span class="result-label">Reply-To mismatch</span>
        <span class="result-val">
        ${checkReplyMismatch(input.value)}
        </span>
        </div>
        <div class="result-row">
        <span class="result-label">Suspicious keywords</span>
        <span class="result-val">
        ${checkSuspiciousKeywords(input.value)}
        </span>
        </div>
        </div>
        <div class="verdict-box
        ${data.score >= 70 ? "danger" :
            data.score >= 40 ? "warning" : "success"}">
            <div class="verdict-label
            ${data.score >= 70 ? "danger" :
                data.score >= 40 ? "warning" : "success"}">
                ${data.score >= 70 ? "PHISHING DETECTED" :
                    data.score >= 40 ? "SUSPICIOUS" : "LIKELY CLEAN"}
                    </div>
                    <div class="verdict-score
                    ${data.score >= 70 ? "danger" :
                        data.score >= 40 ? "warning" : "success"}">
                        ${data.score}/100
                        </div>
                        </div>
                        <div style="font-size:12px;
                        color:var(--text-tertiary);
                        margin-top:8px;">
                        Alert saved — ID #${data.alert_id||"pending"}.
                        Full email parsing available via CLI:
                        python3 backend/email_analyser.py
                        </div>`;

                        loadAlerts();

    } catch (err) {
        result.innerHTML = `
        <div style="color:var(--danger);padding:12px;">
        Error: ${err.message}
        </div>`;
    }
}

function checkReplyMismatch(headers) {
    const fromMatch    = headers.match(/From:.*@([\w.-]+)/i);
    const replyMatch   = headers.match(/Reply-To:.*@([\w.-]+)/i);
    if (!fromMatch || !replyMatch) return "Cannot determine";
    const fromDomain   = fromMatch[1].toLowerCase();
    const replyDomain  = replyMatch[1].toLowerCase();
    if (fromDomain !== replyDomain) {
        return `<span style="color:var(--danger);">
        MISMATCH — ${fromDomain} vs ${replyDomain}
        </span>`;
    }
    return `<span style="color:var(--success);">No mismatch</span>`;
}

function checkSuspiciousKeywords(text) {
    const keywords = [
        "urgent", "suspended", "verify", "account",
        "click here", "confirm", "password", "login",
        "update", "expire", "warning"
    ];
    const found = keywords.filter(kw =>
    text.toLowerCase().includes(kw)
    );
    if (found.length > 3) {
        return `<span style="color:var(--danger);">
        ${found.length} found: ${found.slice(0,4).join(", ")}
        </span>`;
    } else if (found.length > 0) {
        return `<span style="color:var(--warning);">
        ${found.length} found: ${found.join(", ")}
        </span>`;
    }
    return `<span style="color:var(--success);">None</span>`;
}


// ══════════════════════════════════════════════════════════════════
// ATT&CK HEATMAP PAGE
// ══════════════════════════════════════════════════════════════════

async function loadHeatmap() {
    const grid = document.getElementById("heatmap-grid");
    if (!grid) return;

    try {
        const data = await apiCall("/mitre/heatmap");
        const heatmap = data.heatmap || {};

        // Build cells for all known techniques
        const cells = Object.entries(MITRE_DISPLAY).map(
            ([id, info]) => {
                const count = heatmap[id]
                ? heatmap[id].count : 0;
                const bg = count > 5
                ? "rgba(248,81,73,0.25)"
                : count > 2
                ? "rgba(227,179,65,0.2)"
                : count > 0
                ? "rgba(63,185,80,0.15)"
                : "var(--bg-secondary)";
                const textCol = count > 5
                ? "var(--danger)"
                : count > 2
                ? "var(--warning)"
                : count > 0
                ? "var(--success)"
                : "var(--text-tertiary)";
                const border = count > 0
                ? "1px solid " + (
                    count > 5 ? "rgba(248,81,73,0.4)" :
                    count > 2 ? "rgba(227,179,65,0.4)" :
                    "rgba(63,185,80,0.3)")
                : "1px solid var(--border)";

                return `
                <div class="hm-cell"
                style="background:${bg};border:${border};">
                <div class="hm-id"
                style="color:${textCol}">${id}</div>
                <div class="hm-name"
                style="color:${textCol}">${info.name}</div>
                <div class="hm-count"
                style="color:${textCol}">${count}</div>
                </div>`;
            }
        ).join("");

        grid.innerHTML = cells || `
        <div class="loading-row">
        No MITRE data yet. Submit alerts to populate heatmap.
        </div>`;

    } catch (err) {
        grid.innerHTML = `
        <div class="loading-row" style="color:var(--danger);">
        <i class="ti ti-alert-circle"></i>
        Could not load heatmap. Is the server running?
        </div>`;
    }
}


// ══════════════════════════════════════════════════════════════════
// METRICS PAGE
// ══════════════════════════════════════════════════════════════════

async function loadMetrics() {
    const detail = document.getElementById("stats-detail");
    const fpEl   = document.getElementById("fp-compare");

    try {
        const stats = await apiCall("/stats");

        if (fpEl) {
            fpEl.textContent = (stats.fp_rate || 0) + "% auto-identified";
        }

        if (detail) {
            detail.innerHTML = `
            <div class="stats-row">
            <span class="stats-key">Total alerts processed</span>
            <span class="stats-val">${stats.total_alerts||0}</span>
            </div>
            <div class="stats-row">
            <span class="stats-key">High risk alerts</span>
            <span class="stats-val"
            style="color:var(--danger);">
            ${stats.high_risk||0}
            </span>
            </div>
            <div class="stats-row">
            <span class="stats-key">Open (pending review)</span>
            <span class="stats-val">${stats.open_alerts||0}</span>
            </div>
            <div class="stats-row">
            <span class="stats-key">Escalated to L2</span>
            <span class="stats-val">${stats.escalated||0}</span>
            </div>
            <div class="stats-row">
            <span class="stats-key">Confirmed true positives</span>
            <span class="stats-val"
            style="color:var(--success);">
            ${stats.true_positives||0}
            </span>
            </div>
            <div class="stats-row">
            <span class="stats-key">False positives identified</span>
            <span class="stats-val">${stats.false_positives||0}</span>
            </div>
            <div class="stats-row">
            <span class="stats-key">False positive rate</span>
            <span class="stats-val">${stats.fp_rate||0}%</span>
            </div>
            <div class="stats-row">
            <span class="stats-key">
            MITRE techniques detected today
            </span>
            <span class="stats-val">
            ${Object.keys(stats.mitre_heatmap||{}).length}
            </span>
            </div>`;
        }

    } catch (err) {
        if (detail) {
            detail.innerHTML = `
            <div class="loading-row" style="color:var(--danger);">
            Could not load metrics.
            </div>`;
        }
    }
}


// ══════════════════════════════════════════════════════════════════
// UTILITY FUNCTIONS
// ══════════════════════════════════════════════════════════════════

/** Sets textContent of an element by ID */
function setEl(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

/** Truncates a string to max length with ellipsis */
function truncate(str, max) {
    if (!str) return "—";
    return str.length > max ? str.slice(0, max) + "..." : str;
}

/** Returns appropriate risk pill HTML */
function getRiskPill(score) {
    if (score >= 70) {
        return '<span class="pill pill-high">High</span>';
    } else if (score >= 40) {
        return '<span class="pill pill-medium">Medium</span>';
    } else if (score > 0) {
        return '<span class="pill pill-low">Low</span>';
    }
    return '<span class="pill pill-unknown">Unknown</span>';
}

/** Returns CSS class for score number colour */
function getScoreClass(score) {
    if (score >= 70) return "score-high";
    if (score >= 40) return "score-medium";
    return "score-low";
}

/** Returns status badge HTML */
function getStatusBadge(status) {
    const map = {
        "open":         `<span style="font-size:11px;
        color:var(--info);">Open</span>`,
        "investigating":`<span style="font-size:11px;
        color:var(--warning);">
        Investigating</span>`,
        "escalated":    `<span style="font-size:11px;
        color:var(--danger);">
        Escalated</span>`,
        "closed_tp":    `<span style="font-size:11px;
        color:var(--success);">
        Closed TP</span>`,
        "closed_fp":    `<span style="font-size:11px;
        color:var(--text-tertiary);">
        Closed FP</span>`,
    };
    return map[status] || status || "—";
}

/** Formats ISO timestamp to readable time */
function formatTime(isoStr) {
    if (!isoStr) return "—";
    try {
        const d = new Date(isoStr);
        return d.toLocaleTimeString("en-GB", {
            hour:   "2-digit",
            minute: "2-digit"
        });
    } catch {
        return isoStr.slice(11, 16);
    }
}

/** Auto-detects indicator type from string */
function detectType(indicator) {
    if (indicator.startsWith("http://") ||
        indicator.startsWith("https://")) return "url_check";
    if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(indicator)) {
        return "ip_reputation";
    }
    if (/^[a-f0-9]{32,64}$/i.test(indicator)) return "hash_check";
    return "domain_check";
}

/** Shows a toast notification */
function showToast(message, type = "success") {
    // Simple alert for now — can be replaced with
    // a proper toast notification library later
    const colours = {
        success: "var(--success)",
        danger:  "var(--danger)",
        warning: "var(--warning)",
    };

    // Create toast element
    const toast   = document.createElement("div");
    toast.textContent = message;
    toast.style.cssText = `
    position: fixed;
    bottom: 20px;
    right: 20px;
    background: var(--bg-tertiary);
    color: ${colours[type] || colours.success};
    border: 1px solid ${colours[type] || colours.success};
    padding: 10px 16px;
    border-radius: 8px;
    font-size: 13px;
    z-index: 1000;
    animation: fadeIn 0.2s ease;
    `;

    document.body.appendChild(toast);

    // Remove after 3 seconds
    setTimeout(() => {
        toast.remove();
    }, 3000);
}


// ══════════════════════════════════════════════════════════════════
// INITIALISE — runs when page loads
// ══════════════════════════════════════════════════════════════════

/**
 * NEW CONCEPT — DOMContentLoaded event:
 *   Fires when the HTML is fully parsed and ready.
 *   We put all initialisation here so we know all
 *   elements exist before we try to use them.
 */
document.addEventListener("DOMContentLoaded", () => {

    // Load initial data
    loadAlerts();

    // Poll for new alerts every 10 seconds
    setInterval(loadAlerts, POLL_INTERVAL);

    console.log("AEGIS v1.0 — Dashboard initialised");
    console.log("Built by Jigar | AI-Powered SOC Toolkit");
});
