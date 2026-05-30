"""
AEGIS — FastAPI Backend (main.py)
==================================
What this file does:
  The central nervous system of AEGIS.
  Every other module plugs into this file.

  It creates a web server with these endpoints:

  POST /alert              — receive a new alert (from Shuffle/Wazuh)
  POST /alert/manual       — analyst submits IOC manually
  GET  /alerts             — get all alerts (dashboard)
  GET  /alert/{id}         — get one alert with full details
  PUT  /alert/{id}/status  — update alert status
  POST /alert/{id}/notes   — add analyst note
  POST /alert/{id}/feedback — thumbs up/down
  GET  /stats              — dashboard metrics
  GET  /health             — is AEGIS running?
  POST /wazuh-alert        — webhook for Wazuh via Shuffle
  GET  /mitre/heatmap      — ATT&CK heatmap data

New Python concepts in this file:
  @app.get / @app.post     — route decorators
  async def                — async function (non-blocking)
  Depends()                — dependency injection
  HTTPException            — raise HTTP errors cleanly
  BaseModel (Pydantic)     — data validation models
  Optional[]               — type hint for optional fields
  BackgroundTasks          — run tasks after response sent
  JSONResponse             — return custom JSON response
  status codes             — HTTP 200, 201, 404, 422, 500
"""

import sys
import os
import json
from datetime import datetime
from typing import Optional, List
import traceback

# FastAPI imports
from fastapi import (
    FastAPI, Depends, HTTPException,
    BackgroundTasks, status
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

# Pydantic for data validation
from pydantic import BaseModel

# SQLAlchemy session
from sqlalchemy.orm import Session

# Add backend directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# AEGIS modules
from database import (
    init_db, get_db, save_alert,
    get_all_alerts, get_alert_by_id, get_stats,
    Alert, AnalystNote, SessionLocal
)
from ioc_checker import check_ioc
from risk_scorer import calculate_score, score_from_ioc_result
from mitre_tagger import tag_alert, MitreTag
from cve_lookup import enrich_alert_with_cves
from branding import TOOL_NAME, VERSION, AUTHOR, FOOTER

# ── COLOURS FOR TERMINAL ──────────────────────────────────────────────────────
GREEN  = "\033[92m"
BLUE   = "\033[94m"
YELLOW = "\033[93m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


# ══════════════════════════════════════════════════════════════════════════════
# FASTAPI APP SETUP
# ══════════════════════════════════════════════════════════════════════════════

"""
NEW CONCEPT — FastAPI():
  Creates the web application instance.
  title, description, version appear in the auto-generated
  API documentation at localhost:8000/docs
"""
app = FastAPI(
    title       = f"AEGIS — {TOOL_NAME}",
    description = f"AI-Powered SOC Analyst Toolkit by {AUTHOR}",
    version     = VERSION,
    docs_url    = "/docs",
    # Auto-generated interactive API docs — very useful for testing
)

"""
NEW CONCEPT — CORS Middleware:
  CORS (Cross-Origin Resource Sharing) controls which
  websites can call your API.
  Without this, your HTML dashboard (localhost:5500)
  cannot call your FastAPI (localhost:8000) — browser blocks it.
  allow_origins=["*"] means any origin can call the API.
  Fine for local development — restrict in production.
"""
app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["*"],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)


# ══════════════════════════════════════════════════════════════════════════════
# PYDANTIC MODELS — data validation for incoming requests
# ══════════════════════════════════════════════════════════════════════════════

"""
NEW CONCEPT — Pydantic BaseModel:
  Defines the exact shape of data that must arrive
  in a POST request body.

  FastAPI uses this to:
  1. Automatically validate incoming JSON
  2. Return a clear error if data is wrong format
  3. Give you typed Python objects instead of raw dicts

  Optional[str] = None means the field is not required.
  If not provided, it defaults to None.
"""

class AlertCreate(BaseModel):
    """Schema for creating a new alert manually."""
    alert_type:     str
    indicator:      str
    indicator_type: Optional[str] = None
    # If None, ioc_checker will auto-detect the type
    source:         Optional[str] = "manual"
    description:    Optional[str] = None
    mitre_id:       Optional[str] = None
    # If provided, skips auto-tagging


class WazuhAlert(BaseModel):
    """
    Schema for alerts arriving from Wazuh via Shuffle webhook.
    Wazuh sends alerts in this format.
    All fields are Optional because Wazuh alert format varies.
    """
    rule_id:          Optional[str]  = None
    rule_description: Optional[str]  = None
    rule_level:       Optional[int]  = None
    # Wazuh severity level 1-15
    agent_name:       Optional[str]  = None
    # Which machine generated the alert
    agent_ip:         Optional[str]  = None
    src_ip:           Optional[str]  = None
    dst_ip:           Optional[str]  = None
    timestamp:        Optional[str]  = None
    full_log:         Optional[str]  = None
    mitre_id:         Optional[str]  = None
    mitre_tactic:     Optional[str]  = None
    location:         Optional[str]  = None
    data:             Optional[dict] = None
    # Raw Wazuh data field — contains additional context


class AlertStatusUpdate(BaseModel):
    """Schema for updating alert status."""
    status: str
    # Must be one of: open, investigating, escalated,
    #                 closed_tp, closed_fp


class NoteCreate(BaseModel):
    """Schema for adding analyst investigation notes."""
    note:   str
    action: Optional[str] = None


class FeedbackCreate(BaseModel):
    """Schema for analyst true positive / false positive feedback."""
    is_true_positive: bool
    # True = real threat, False = false positive
    notes: Optional[str] = None


# ══════════════════════════════════════════════════════════════════════════════
# STARTUP AND SHUTDOWN EVENTS
# ══════════════════════════════════════════════════════════════════════════════

"""
NEW CONCEPT — @app.on_event():
  Runs a function when the server starts or stops.
  We use startup to:
    - initialise the database
    - print the AEGIS banner
"""

from contextlib import asynccontextmanager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    print(f"\n{BOLD}{BLUE}")
    print("  ╔══════════════════════════════════════════╗")
    print(f"  ║   AEGIS {VERSION} — SOC Analyst Toolkit      ║")
    print(f"  ║   Built by {AUTHOR:<33}║")
    print("  ╚══════════════════════════════════════════╝")
    print(f"{RESET}")
    print(f"  {GREEN}[✓] Starting AEGIS backend...{RESET}")
    init_db()
    print(f"  {GREEN}[✓] Database ready{RESET}")
    print(f"  {GREEN}[✓] API docs: http://localhost:8000/docs{RESET}")
    print(f"  {GREEN}[✓] Dashboard: http://localhost:8000/dashboard{RESET}\n")
    yield
    # Shutdown (nothing needed)


# ══════════════════════════════════════════════════════════════════════════════
# CORE PROCESSING FUNCTION
# ══════════════════════════════════════════════════════════════════════════════

def process_alert_pipeline(
    indicator:      str,
    alert_type:     str,
    indicator_type: Optional[str] = None,
    source:         str = "manual",
    description:    str = "",
    mitre_id:       Optional[str] = None,
    db:             Session = None
) -> dict:
    """
    The main AEGIS processing pipeline.
    Every alert — whether from Wazuh, manual entry,
    or attack engine — goes through this function.

    Pipeline steps:
      1. IOC check    — VirusTotal + AbuseIPDB + WHOIS
      2. Risk score   — 0-100 from all sources
      3. MITRE tag    — technique ID + kill chain
      4. CVE lookup   — related vulnerabilities
      5. Save to DB   — persist everything
      6. Return dict  — sent back to caller

    This is called a 'pipeline' because data flows
    through each step in order, each step enriching it.
    """

    print(f"\n{BLUE}[*] Processing alert: "
          f"{indicator} ({alert_type}){RESET}")

    result = {
        "indicator":    indicator,
        "alert_type":   alert_type,
        "source":       source,
        "processed_at": datetime.utcnow().isoformat(),
    }

    # ── Step 1: IOC Check ─────────────────────────────────────────────────────
    try:
        ioc_result     = check_ioc(indicator)
        result["ioc"]  = ioc_result
        print(f"  {GREEN}[✓] IOC check complete — "
              f"VT: {ioc_result.get('vt_result',{}).get('malicious',0)}"
              f"/{ioc_result.get('vt_result',{}).get('total',0)} "
              f"detections{RESET}")
    except Exception as e:
        print(f"  {YELLOW}[!] IOC check failed: {e}{RESET}")
        ioc_result = {}
        result["ioc"] = {}

    # ── Step 2: Risk Score ────────────────────────────────────────
    try:
        from risk_scorer import score_from_ioc_result
        score_result = score_from_ioc_result(ioc_result)
        result["score"] = score_result.to_dict()
        print(f"  {GREEN}[✓] Risk score: "
              f"{score_result.score}/100 "
              f"— {score_result.verdict}{RESET}")
    except Exception as e:
        print(f"  {YELLOW}[!] Risk scoring failed: {e}{RESET}")
        score_result = type('obj', (object,), {
            'score': 0, 'verdict': 'UNKNOWN',
            'risk_level': 'LOW', 'colour': 'green',
            'flags': [], 'to_dict': lambda self: {}
        })()

    # ── Step 3: MITRE ATT&CK Tag ──────────────────────────────────────────────
    try:
        mitre_tag = tag_alert(
            alert_type  = alert_type,
            mitre_id    = mitre_id,
            description = description
        )
        result["mitre"] = mitre_tag.to_dict()
        print(f"  {GREEN}[✓] MITRE tag: "
              f"{mitre_tag.technique_id} "
              f"({mitre_tag.technique_name}){RESET}")
    except Exception as e:
        print(f"  {YELLOW}[!] MITRE tagging failed: {e}{RESET}")
        mitre_tag = MitreTag()

    # ── Step 4: CVE Lookup ────────────────────────────────────────────────────
    try:
        # Only do CVE lookup for exploitation alerts
        # to avoid too many NVD API calls
        exploitation_types = [
            "sql_injection", "web_exploit", "ssh_brute_force",
            "brute_force", "port_scan", "ftp_brute_force"
        ]
        cve_result = {}
        if any(t in alert_type.lower()
               for t in exploitation_types):
            cve_result = enrich_alert_with_cves(alert_type)
            if cve_result.get("cves_found", 0) > 0:
                print(f"  {GREEN}[✓] CVE lookup: "
                      f"{cve_result['cves_found']} CVEs found, "
                      f"top: {cve_result.get('top_cve_id','?')} "
                      f"CVSS {cve_result.get('top_cvss','?')}"
                      f"{RESET}")
        result["cve"] = cve_result
    except Exception as e:
        print(f"  {YELLOW}[!] CVE lookup failed: {e}{RESET}")
        cve_result = {}

    # ── Step 5: Save to Database ──────────────────────────────────────────────

    own_session = False
    if db is None:
        db = SessionLocal()
        own_session = True

    try:
        alert_data = {
            "alert_type":           alert_type,
            "source":               source,
            "indicator":            indicator,
            "indicator_type":       (ioc_result.get("type")
                                     or indicator_type
                                     or "unknown"),
            "risk_score":           score_result.score,
            "verdict":              score_result.verdict,
            "mitre_technique_id":   mitre_tag.technique_id,
            "mitre_technique_name": mitre_tag.technique_name,
            "mitre_tactic":         mitre_tag.tactic,
            "kill_chain_stage":     mitre_tag.kill_chain,
            "vt_malicious":  ioc_result.get(
                "vt_result", {}).get("malicious", 0),
            "vt_total":      ioc_result.get(
                "vt_result", {}).get("total", 0),
            "abuse_score":   (ioc_result.get(
                "abuse_result") or {}).get("abuse_score", 0),
            "domain_age_days": (ioc_result.get(
                "whois_result") or {}).get("age_days"),
            "cve_id":    cve_result.get("top_cve_id"),
            "cvss_score": cve_result.get("top_cvss"),
            "status":    "open",
            "raw_data":  json.dumps({
                "ioc":   ioc_result,
                "score": ioc_result.get("score", 0),
                "verdict": ioc_result.get("verdict", "UNKNOWN"),
                "cve":   cve_result,
            }),
        }

        saved_alert        = save_alert(db, alert_data)
        result["alert_id"] = saved_alert.id
        print(f"  {GREEN}[✓] Alert saved — "
              f"ID: {saved_alert.id}{RESET}")

    except Exception as e:
        import traceback
        print(f"  {YELLOW}[!] Database save failed: {e}{RESET}")
        print(traceback.format_exc())
        result["alert_id"] = None
    finally:
        if own_session:
            db.close()

    return result


# ══════════════════════════════════════════════════════════════════════════════
# API ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════════

# ── Health check ──────────────────────────────────────────────────────────────
@app.get("/health")
async def health_check():
    """
    NEW CONCEPT — @app.get("/health"):
      The decorator registers this function as a GET endpoint.
      When browser or curl sends GET to /health,
      FastAPI calls this function and returns its result as JSON.

    Returns simple status — used to verify AEGIS is running.
    """
    return {
        "status":    "running",
        "tool":      TOOL_NAME,
        "version":   VERSION,
        "author":    AUTHOR,
        "timestamp": datetime.utcnow().isoformat(),
    }


# ── Manual IOC check endpoint ─────────────────────────────────────────────────
@app.post("/alert/manual",
          status_code=status.HTTP_201_CREATED)
async def create_manual_alert(
    alert_in: AlertCreate,
    db:       Session = Depends(get_db)
):
    """
    Analyst manually submits an IOC to investigate.

    NEW CONCEPT — status_code=201:
      HTTP 201 = Created. Correct code when a new
      resource is created. 200 = OK for reads.
      FastAPI returns 200 by default — we override here.

    NEW CONCEPT — Depends(get_db):
      Dependency injection. FastAPI automatically calls
      get_db() and passes the result as 'db'.
      When the function returns, FastAPI calls get_db()'s
      finally block to close the session.
      You never manage the session manually.

    NEW CONCEPT — async def:
      Async functions can be paused while waiting
      (e.g. waiting for API response) and other
      requests can be handled in the meantime.
      Makes the server more efficient under load.
    """
    try:
        result = process_alert_pipeline(
            indicator      = alert_in.indicator,
            alert_type     = alert_in.alert_type,
            indicator_type = alert_in.indicator_type,
            source         = alert_in.source or "manual",
            description    = alert_in.description or "",
            mitre_id       = alert_in.mitre_id,
            db             = db
        )
        return {
            "message":  "Alert processed successfully",
            "alert_id": result.get("alert_id"),
            "score":    result.get("score", {}).get("score", 0),
            "verdict":  result.get("score", {}).get(
                "verdict", "UNKNOWN"),
            "mitre_id": result.get("mitre", {}).get(
                "technique_id", "Unknown"),
            "details":  result,
        }

    except Exception as e:
        """
        NEW CONCEPT — HTTPException:
          Raises an HTTP error with a status code and message.
          FastAPI converts this to a proper JSON error response.
          status_code=500 = Internal Server Error
          detail = the error message the client receives
        """
        raise HTTPException(
            status_code = status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail      = f"Alert processing failed: {str(e)}"
        )


# ── Wazuh webhook — receives alerts from Shuffle ──────────────────────────────
@app.post("/wazuh-alert",
          status_code=status.HTTP_200_OK)
async def receive_wazuh_alert(
    wazuh_alert:      WazuhAlert,
    background_tasks: BackgroundTasks,
    db:               Session = Depends(get_db)
):
    """
    Webhook endpoint that receives Wazuh alerts via Shuffle.

    How this works in the pipeline:
      Wazuh detects something on Windows 10 agent
      → Wazuh sends alert to Shuffle
      → Shuffle workflow sends POST to this endpoint
      → AEGIS processes the alert
      → AEGIS saves to database
      → Dashboard shows it in 5 seconds

    NEW CONCEPT — BackgroundTasks:
      Some operations are slow (CVE lookup, Gemini AI).
      We don't want Shuffle to wait 30 seconds for a response.
      BackgroundTasks lets us:
        1. Return HTTP 200 immediately to Shuffle
        2. Continue heavy processing in the background
      Shuffle is happy, processing happens, everyone wins.
    """

    # Extract the most useful indicator from Wazuh alert
    # Priority: src_ip → agent_ip → rule description
    indicator = (wazuh_alert.src_ip
                 or wazuh_alert.agent_ip
                 or "unknown")

    # Determine alert type from Wazuh rule description
    alert_type = "wazuh_alert"
    if wazuh_alert.rule_description:
        desc_lower = wazuh_alert.rule_description.lower()
        if "brute" in desc_lower or "authentication failure" in desc_lower:
            alert_type = "brute_force"
        elif "scan" in desc_lower or "nmap" in desc_lower:
            alert_type = "port_scan"
        elif "sql" in desc_lower or "injection" in desc_lower:
            alert_type = "sql_injection"
        elif "phish" in desc_lower or "malicious email" in desc_lower:
            alert_type = "phishing"
        elif "exfil" in desc_lower or "large transfer" in desc_lower:
            alert_type = "data_exfil"
        elif "lateral" in desc_lower or "rdp" in desc_lower:
            alert_type = "lateral_movement"

    # Return immediately to Shuffle, process in background
    background_tasks.add_task(
        process_alert_pipeline,
        indicator   = indicator,
        alert_type  = alert_type,
        source      = "wazuh",
        description = wazuh_alert.rule_description or "",
        mitre_id    = wazuh_alert.mitre_id,
        db          = db
    )

    return {
        "status":     "received",
        "message":    "Wazuh alert queued for processing",
        "indicator":  indicator,
        "rule_id":    wazuh_alert.rule_id,
        "alert_type": alert_type,
    }


# ── Get all alerts ────────────────────────────────────────────────────────────
@app.get("/alerts")
async def get_alerts(
    limit:  int     = 100,
    offset: int     = 0,
    db:     Session = Depends(get_db)
):
    """
    Returns all alerts sorted by risk score (highest first).
    Used by the dashboard alert queue.

    Query parameters:
      limit=100  — return up to 100 alerts
      offset=0   — start from alert 0 (pagination)

    Example: GET /alerts?limit=50&offset=50
      Returns alerts 51-100
    """
    alerts = get_all_alerts(db, limit=limit, offset=offset)
    return {
        "alerts": [a.to_dict() for a in alerts],
        "count":  len(alerts),
        "total":  db.query(Alert).count(),
    }


# ── Get single alert with full details ───────────────────────────────────────
@app.get("/alert/{alert_id}")
async def get_alert(
    alert_id: int,
    db:       Session = Depends(get_db)
):
    """
    Returns one alert with all enrichment data.
    Called when analyst clicks an alert in the dashboard.

    NEW CONCEPT — path parameter {alert_id}:
      The {alert_id} in the URL path becomes a function parameter.
      GET /alert/42 → alert_id = 42
      FastAPI automatically converts it to int.
    """
    alert = get_alert_by_id(db, alert_id)

    if not alert:
        raise HTTPException(
            status_code = status.HTTP_404_NOT_FOUND,
            detail      = f"Alert {alert_id} not found"
        )

    alert_dict = alert.to_dict()

    # Parse raw_data JSON if it exists
    if alert.raw_data:
        try:
            alert_dict["enrichment"] = json.loads(alert.raw_data)
        except json.JSONDecodeError:
            alert_dict["enrichment"] = {}

    # Get analyst notes for this alert
    notes = (db.query(AnalystNote)
               .filter(AnalystNote.alert_id == alert_id)
               .all())
    alert_dict["notes"] = [
        {
            "id":         n.id,
            "note":       n.note,
            "action":     n.action,
            "created_at": n.created_at.isoformat()
                          if n.created_at else None,
        }
        for n in notes
    ]

    return alert_dict


# ── Update alert status ───────────────────────────────────────────────────────
@app.put("/alert/{alert_id}/status")
async def update_status(
    alert_id:  int,
    status_in: AlertStatusUpdate,
    db:        Session = Depends(get_db)
):
    """
    Updates the status of an alert.
    Called when analyst escalates, closes, or begins
    investigating an alert.

    Valid statuses:
      open          — default, not looked at yet
      investigating — analyst is working on it
      escalated     — sent to L2
      closed_tp     — closed as true positive
      closed_fp     — closed as false positive
    """
    alert = get_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404,
                           detail=f"Alert {alert_id} not found")

    valid_statuses = [
        "open", "investigating", "escalated",
        "closed_tp", "closed_fp"
    ]
    if status_in.status not in valid_statuses:
        raise HTTPException(
            status_code = 422,
            detail      = f"Invalid status. Must be one of: "
                          f"{valid_statuses}"
        )

    alert.status = status_in.status
    if status_in.status == "escalated":
        alert.escalated = True

    db.commit()
    db.refresh(alert)

    return {
        "message":  "Status updated",
        "alert_id": alert_id,
        "status":   alert.status,
    }


# ── Add analyst note ──────────────────────────────────────────────────────────
@app.post("/alert/{alert_id}/notes",
          status_code=201)
async def add_note(
    alert_id: int,
    note_in:  NoteCreate,
    db:       Session = Depends(get_db)
):
    """
    Adds an investigation note to an alert.
    Called when analyst types findings in the
    notes field of the dashboard.
    """
    alert = get_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404,
                           detail=f"Alert {alert_id} not found")

    note = AnalystNote(
        alert_id = alert_id,
        note     = note_in.note,
        action   = note_in.action,
    )
    db.add(note)

    # Also update the alert's notes field for quick access
    existing = alert.analyst_notes or ""
    timestamp = datetime.utcnow().strftime("%H:%M")
    alert.analyst_notes = (f"{existing}\n[{timestamp}] "
                           f"{note_in.note}").strip()

    db.commit()

    return {
        "message":  "Note added",
        "alert_id": alert_id,
        "note":     note_in.note,
    }


# ── Analyst feedback (thumbs up/down) ────────────────────────────────────────
@app.post("/alert/{alert_id}/feedback")
async def add_feedback(
    alert_id:    int,
    feedback_in: FeedbackCreate,
    db:          Session = Depends(get_db)
):
    """
    Records analyst judgment: true positive or false positive.
    This feedback is used by F20 (FP pattern learner)
    to suggest suppression rules over time.
    """
    alert = get_alert_by_id(db, alert_id)
    if not alert:
        raise HTTPException(status_code=404,
                           detail=f"Alert {alert_id} not found")

    alert.is_true_positive = feedback_in.is_true_positive

    if feedback_in.is_true_positive:
        alert.status = "closed_tp"
    else:
        alert.status = "closed_fp"

    if feedback_in.notes:
        existing = alert.analyst_notes or ""
        timestamp = datetime.utcnow().strftime("%H:%M")
        feedback_label = ("TRUE POSITIVE"
                          if feedback_in.is_true_positive
                          else "FALSE POSITIVE")
        alert.analyst_notes = (
            f"{existing}\n[{timestamp}] "
            f"[{feedback_label}] {feedback_in.notes}"
        ).strip()

    db.commit()

    return {
        "message":          "Feedback recorded",
        "alert_id":         alert_id,
        "is_true_positive": feedback_in.is_true_positive,
        "new_status":       alert.status,
    }


# ── Dashboard statistics ──────────────────────────────────────────────────────
@app.get("/stats")
async def get_dashboard_stats(db: Session = Depends(get_db)):
    """
    Returns metrics for the dashboard top bar.
    Called every 10 seconds by the dashboard.
    """
    stats = get_stats(db)

    # Add MITRE heatmap data
    mitre_counts = {}
    alerts = db.query(Alert).filter(
        Alert.mitre_technique_id.isnot(None)
    ).all()

    for alert in alerts:
        tid = alert.mitre_technique_id
        if tid and tid != "Unknown":
            mitre_counts[tid] = mitre_counts.get(tid, 0) + 1

    stats["mitre_heatmap"] = mitre_counts

    return stats


# ── MITRE heatmap data ────────────────────────────────────────────────────────
@app.get("/mitre/heatmap")
async def get_mitre_heatmap(db: Session = Depends(get_db)):
    """
    Returns ATT&CK technique counts for dashboard heatmap.
    """
    alerts = db.query(Alert).filter(
        Alert.mitre_technique_id.isnot(None)
    ).all()

    heatmap = {}
    for alert in alerts:
        tid = alert.mitre_technique_id
        if tid and tid not in ["Unknown", "T0000"]:
            if tid not in heatmap:
                heatmap[tid] = {
                    "count":   0,
                    "name":    alert.mitre_technique_name,
                    "tactic":  alert.mitre_tactic,
                }
            heatmap[tid]["count"] += 1

    return {
        "heatmap":    heatmap,
        "techniques": len(heatmap),
        "total":      sum(v["count"] for v in heatmap.values()),
    }


# ── Serve dashboard static files ──────────────────────────────────────────────
"""
NEW CONCEPT — StaticFiles:
  Serves HTML, CSS, JS files directly from FastAPI.
  Your dashboard/index.html is served at /dashboard
  No separate web server needed.
"""
dashboard_dir = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "dashboard"
)

if os.path.exists(dashboard_dir):
    app.mount(
        "/dashboard",
        StaticFiles(directory=dashboard_dir, html=True),
        name="dashboard"
    )


# ══════════════════════════════════════════════════════════════════════════════
# RUN SERVER
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import uvicorn

    print(f"\n{BOLD}Starting AEGIS server...{RESET}")
    print(f"  Dashboard : http://localhost:8000/dashboard")
    print(f"  API docs  : http://localhost:8000/docs")
    print(f"  Health    : http://localhost:8000/health\n")

    """
    NEW CONCEPT — uvicorn.run():
      Uvicorn is the ASGI server that runs FastAPI.
      host="0.0.0.0" means accept connections from
      any network interface (not just localhost).
      port=8000 is the port number.
      reload=True restarts server when code changes —
      very useful during development.
    """
    uvicorn.run(
        "main:app",
        host    = "0.0.0.0",
        port    = 8000,
        reload  = True
    )
