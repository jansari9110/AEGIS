"""
AEGIS — Reconstructed FastAPI Backend
======================================
Complete rewrite following Sentinel pattern.

Endpoints:
  AUTH
    POST /auth/login          — get JWT token
    GET  /auth/me             — get current analyst

  INCIDENTS (Wazuh/attack engine only)
    GET  /incidents           — get incidents by status
    GET  /incident/{id}       — get one incident + timeline
    POST /incident/{id}/assign       — analyst takes ownership
    POST /incident/{id}/investigate  — mark as investigating
    POST /incident/{id}/note         — add investigation note
    POST /incident/{id}/close        — close as TP or FP
    POST /incident/{id}/escalate     — escalate to L2
    POST /incident/{id}/ai-report    — generate Gemini 6W report

  WEBHOOKS (automated sources)
    POST /webhook/wazuh       — receive Wazuh alerts via Shuffle

  ANALYST TOOLKIT (separate from incidents)
    POST /toolkit/ioc         — check IP/domain/URL/hash
    POST /toolkit/email       — analyse phishing email headers

  STATS + INTELLIGENCE
    GET  /stats               — dashboard metrics
    GET  /mitre/heatmap       — ATT&CK technique counts
    GET  /analysts/active     — who is online

  HEALTH
    GET  /health              — server status
"""

import sys, os, json
from datetime import datetime, timedelta
from typing import Optional
from contextlib import asynccontextmanager

from fastapi import (
    FastAPI, Depends, HTTPException,
    BackgroundTasks, status
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

# JWT
import jwt as pyjwt

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

from database import (
    init_db, get_db, SessionLocal,
    Analyst, Incident, InvestigationNote, IOCScan,
    save_incident, get_incidents, get_incident_by_id,
    add_investigation_note, get_incident_timeline,
    get_analyst_by_username, get_analyst_by_id,
    create_analyst, verify_password, get_stats
)
from ioc_checker import check_ioc
from risk_scorer import score_from_ioc_result
from mitre_tagger import tag_alert
from cve_lookup import enrich_alert_with_cves
from branding import TOOL_NAME, VERSION, AUTHOR

# ── COLOURS ───────────────────────────────────────────────────────
GREEN  = "\033[92m"
BLUE   = "\033[94m"
YELLOW = "\033[93m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ── JWT CONFIG ────────────────────────────────────────────────────
JWT_SECRET    = "aegis-secret-key-change-in-production"
JWT_ALGORITHM = "HS256"
JWT_EXPIRE_HOURS = 8

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")


# ══════════════════════════════════════════════════════════════════
# APP SETUP
# ══════════════════════════════════════════════════════════════════

@asynccontextmanager
async def lifespan(app: FastAPI):
    print(f"\n{BOLD}{BLUE}")
    print("  ╔══════════════════════════════════════════╗")
    print(f"  ║   AEGIS {VERSION} — SOC Analyst Toolkit      ║")
    print(f"  ║   Built by {AUTHOR:<33}║")
    print("  ╚══════════════════════════════════════════╝")
    print(f"{RESET}")
    init_db()
    print(f"  {GREEN}[✓] AEGIS backend ready{RESET}")
    print(f"  {GREEN}[✓] Dashboard: http://localhost:8000/dashboard{RESET}")
    print(f"  {GREEN}[✓] API docs:   http://localhost:8000/docs{RESET}\n")
    yield

app = FastAPI(
    title       = f"AEGIS — {TOOL_NAME}",
    description = f"AI-Powered SOC Toolkit by {AUTHOR}",
    version     = VERSION,
    lifespan    = lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins     = ["*"],
    allow_credentials = True,
    allow_methods     = ["*"],
    allow_headers     = ["*"],
)


# ══════════════════════════════════════════════════════════════════
# PYDANTIC MODELS
# ══════════════════════════════════════════════════════════════════

class NoteIn(BaseModel):
    note: str
    action: Optional[str] = "note_added"

class CloseIn(BaseModel):
    is_true_positive: bool
    closing_note: str

class EscalateIn(BaseModel):
    escalate_to: str
    note: str

class IOCRequest(BaseModel):
    indicator: str
    indicator_type: Optional[str] = None
    incident_id: Optional[int] = None
    # If linked to an incident — shows in timeline

class EmailRequest(BaseModel):
    raw_headers: str
    incident_id: Optional[int] = None

class WazuhAlert(BaseModel):
    rule_id:          Optional[str]  = None
    rule_description: Optional[str]  = None
    rule_level:       Optional[int]  = None
    agent_name:       Optional[str]  = None
    agent_ip:         Optional[str]  = None
    src_ip:           Optional[str]  = None
    dst_ip:           Optional[str]  = None
    timestamp:        Optional[str]  = None
    mitre_id:         Optional[str]  = None
    full_log:         Optional[str]  = None
    data:             Optional[dict] = None

class SignupIn(BaseModel):
    username:     str
    display_name: str
    password:     str
    email:        Optional[str] = None
    role:         Optional[str] = "analyst"


# ══════════════════════════════════════════════════════════════════
# JWT HELPERS
# ══════════════════════════════════════════════════════════════════

def create_token(analyst_id: int, username: str) -> str:
    """Creates a JWT token for an analyst."""
    payload = {
        "sub":      str(analyst_id),
        "username": username,
        "exp":      datetime.utcnow() +
                    timedelta(hours=JWT_EXPIRE_HOURS),
    }
    return pyjwt.encode(payload, JWT_SECRET,
                        algorithm=JWT_ALGORITHM)


def get_current_analyst(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db)
) -> Analyst:
    """
    Dependency — validates JWT token and returns analyst.
    Used by every protected endpoint.
    """
    try:
        payload  = pyjwt.decode(token, JWT_SECRET,
                                algorithms=[JWT_ALGORITHM])
        analyst_id = int(payload.get("sub"))
        analyst  = get_analyst_by_id(db, analyst_id)
        if not analyst or not analyst.is_active:
            raise HTTPException(status_code=401,
                               detail="Invalid credentials")
        return analyst
    except pyjwt.ExpiredSignatureError:
        raise HTTPException(status_code=401,
                           detail="Token expired — please login again")
    except Exception:
        raise HTTPException(status_code=401,
                           detail="Could not validate token")


# ══════════════════════════════════════════════════════════════════
# AUTH ENDPOINTS
# ══════════════════════════════════════════════════════════════════

@app.post("/auth/login")
async def login(
    form: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    Analyst login. Returns JWT token.
    Use username: admin  password: aegis2025 for first login.
    """
    analyst = get_analyst_by_username(db, form.username)

    if not analyst or not verify_password(
            form.password, analyst.password_hash):
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password"
        )

    # Update last login time
    analyst.last_login = datetime.utcnow()
    db.commit()

    token = create_token(analyst.id, analyst.username)

    return {
        "access_token": token,
        "token_type":   "bearer",
        "analyst": {
            "id":           analyst.id,
            "username":     analyst.username,
            "display_name": analyst.display_name,
            "role":         analyst.role,
        }
    }


@app.get("/auth/me")
async def get_me(
    analyst: Analyst = Depends(get_current_analyst)
):
    """Returns current analyst details."""
    return analyst.to_dict()


@app.post("/auth/signup", status_code=201)
async def signup(
    data: SignupIn,
    db: Session = Depends(get_db)
):
    """Creates a new analyst account."""
    existing = get_analyst_by_username(db, data.username)
    if existing:
        raise HTTPException(
            status_code=400,
            detail=f"Username '{data.username}' already exists"
        )
    analyst = create_analyst(
        db,
        username     = data.username,
        display_name = data.display_name,
        password     = data.password,
        email        = data.email,
        role         = data.role or "analyst",
    )
    return {
        "message":  "Analyst account created",
        "analyst":  analyst.to_dict()
    }


# ══════════════════════════════════════════════════════════════════
# INCIDENT ENDPOINTS
# ══════════════════════════════════════════════════════════════════

@app.get("/incidents")
async def get_all_incidents(
    status_filter: Optional[str] = None,
    limit:  int = 100,
    offset: int = 0,
    analyst: Analyst = Depends(get_current_analyst),
    db: Session = Depends(get_db)
):
    """
    Returns incidents filtered by status.
    status_filter options:
      new, assigned, investigating, escalated,
      closed_tp, closed_fp, open (= new+assigned+investigating)
    """
    if status_filter == "open":
        status_list = ["new", "assigned", "investigating"]
    elif status_filter:
        status_list = [status_filter]
    else:
        status_list = None

    incidents = get_incidents(db, status_list, limit, offset)
    return {
        "incidents": [i.to_dict() for i in incidents],
        "count":     len(incidents),
        "total":     db.query(Incident).count(),
    }


@app.get("/incident/{incident_id}")
async def get_incident(
    incident_id: int,
    analyst: Analyst = Depends(get_current_analyst),
    db: Session = Depends(get_db)
):
    """Returns one incident with full timeline."""
    inc = get_incident_by_id(db, incident_id)
    if not inc:
        raise HTTPException(status_code=404,
                           detail=f"Incident {incident_id} not found")

    result = inc.to_dict()

    # Add raw enrichment data
    if inc.raw_data:
        try:
            result["enrichment"] = json.loads(inc.raw_data)
        except Exception:
            result["enrichment"] = {}

    # Add full timeline
    timeline = get_incident_timeline(db, incident_id)
    result["timeline"] = [t.to_dict() for t in timeline]

    return result


@app.post("/incident/{incident_id}/assign")
async def assign_incident(
    incident_id: int,
    analyst: Analyst = Depends(get_current_analyst),
    db: Session = Depends(get_db)
):
    """Analyst takes ownership of an incident."""
    inc = get_incident_by_id(db, incident_id)
    if not inc:
        raise HTTPException(status_code=404,
                           detail="Incident not found")

    if inc.assigned_to and inc.assigned_to != analyst.id:
        assigned = get_analyst_by_id(db, inc.assigned_to)
        name = assigned.display_name if assigned else "another analyst"
        raise HTTPException(
            status_code=409,
            detail=f"Already assigned to {name}"
        )

    inc.assigned_to = analyst.id
    inc.assigned_at = datetime.utcnow()
    inc.status      = "assigned"

    # Update analyst stats
    analyst.alerts_investigated += 1

    # Add timeline entry
    add_investigation_note(
        db, incident_id, analyst.id, analyst.display_name,
        "assigned",
        f"Incident assigned to {analyst.display_name}"
    )

    db.commit()
    return {
        "message":   "Incident assigned",
        "analyst":   analyst.display_name,
        "status":    inc.status,
    }


@app.post("/incident/{incident_id}/investigate")
async def start_investigation(
    incident_id: int,
    analyst: Analyst = Depends(get_current_analyst),
    db: Session = Depends(get_db)
):
    """Marks incident as actively being investigated."""
    inc = get_incident_by_id(db, incident_id)
    if not inc:
        raise HTTPException(status_code=404,
                           detail="Incident not found")

    inc.status = "investigating"
    add_investigation_note(
        db, incident_id, analyst.id, analyst.display_name,
        "status_changed",
        f"Investigation started by {analyst.display_name}"
    )
    db.commit()
    return {"message": "Investigation started", "status": inc.status}


@app.post("/incident/{incident_id}/note")
async def add_note(
    incident_id: int,
    note_in: NoteIn,
    analyst: Analyst = Depends(get_current_analyst),
    db: Session = Depends(get_db)
):
    """Adds investigation note to incident timeline."""
    inc = get_incident_by_id(db, incident_id)
    if not inc:
        raise HTTPException(status_code=404,
                           detail="Incident not found")

    add_investigation_note(
        db, incident_id, analyst.id, analyst.display_name,
        note_in.action or "note_added",
        note_in.note
    )
    db.commit()
    return {"message": "Note added", "incident_id": incident_id}


@app.post("/incident/{incident_id}/close")
async def close_incident(
    incident_id: int,
    close_in: CloseIn,
    analyst: Analyst = Depends(get_current_analyst),
    db: Session = Depends(get_db)
):
    """
    Closes an incident as True Positive or False Positive.
    Records analyst name, time, verdict, and closing note.
    """
    inc = get_incident_by_id(db, incident_id)
    if not inc:
        raise HTTPException(status_code=404,
                           detail="Incident not found")

    inc.status           = ("closed_tp"
                            if close_in.is_true_positive
                            else "closed_fp")
    inc.is_true_positive = close_in.is_true_positive
    inc.closing_note     = close_in.closing_note
    inc.closed_at        = datetime.utcnow()
    inc.closed_by        = analyst.id

    # Calculate investigation time in minutes
    if inc.assigned_at:
        delta = datetime.utcnow() - inc.assigned_at
        inc.investigation_time_mins = int(delta.total_seconds() / 60)

    # Update analyst stats
    if close_in.is_true_positive:
        analyst.true_positives  += 1
    else:
        analyst.false_positives += 1

    verdict = "TRUE POSITIVE" if close_in.is_true_positive else "FALSE POSITIVE"

    add_investigation_note(
        db, incident_id, analyst.id, analyst.display_name,
        inc.status,
        f"Closed as {verdict} by {analyst.display_name}. "
        f"Note: {close_in.closing_note}"
    )
    db.commit()

    return {
        "message":          "Incident closed",
        "incident_id":      incident_id,
        "verdict":          verdict,
        "closed_by":        analyst.display_name,
        "closed_at":        inc.closed_at.isoformat(),
        "investigation_time": inc.investigation_time_mins,
    }


@app.post("/incident/{incident_id}/escalate")
async def escalate_incident(
    incident_id: int,
    esc_in: EscalateIn,
    analyst: Analyst = Depends(get_current_analyst),
    db: Session = Depends(get_db)
):
    """Escalates incident to L2 with note."""
    inc = get_incident_by_id(db, incident_id)
    if not inc:
        raise HTTPException(status_code=404,
                           detail="Incident not found")

    inc.status       = "escalated"
    inc.escalated_to = esc_in.escalate_to

    add_investigation_note(
        db, incident_id, analyst.id, analyst.display_name,
        "escalated",
        f"Escalated to {esc_in.escalate_to} by "
        f"{analyst.display_name}. Note: {esc_in.note}"
    )
    db.commit()

    return {
        "message":      "Incident escalated",
        "escalated_to": esc_in.escalate_to,
        "by":           analyst.display_name,
    }


@app.post("/incident/{incident_id}/ai-report")
async def generate_ai_report(
    incident_id: int,
    analyst: Analyst = Depends(get_current_analyst),
    db: Session = Depends(get_db)
):
    """Generates Gemini 6W investigation report."""
    from llm_reporter import generate_investigation_report

    inc = get_incident_by_id(db, incident_id)
    if not inc:
        raise HTTPException(status_code=404,
                           detail="Incident not found")

    result = generate_investigation_report(inc.to_dict())

    if result.get("report"):
        inc.ai_report = result["report"]
        add_investigation_note(
            db, incident_id, analyst.id, analyst.display_name,
            "ai_report_generated",
            "AI investigation report generated by Gemini"
        )
        db.commit()

    return {
        "incident_id": incident_id,
        "report":      result.get("report", ""),
        "who":         result.get("who", ""),
        "what":        result.get("what", ""),
        "where":       result.get("where", ""),
        "when":        result.get("when", ""),
        "why":         result.get("why", ""),
        "how":         result.get("how", ""),
        "model":       result.get("model", ""),
        "error":       result.get("error"),
    }


# ══════════════════════════════════════════════════════════════════
# WEBHOOK — WAZUH ALERTS VIA SHUFFLE
# ══════════════════════════════════════════════════════════════════

@app.post("/webhook/wazuh", status_code=200)
async def wazuh_webhook(
    alert: WazuhAlert,
    background_tasks: BackgroundTasks,
    db: Session = Depends(get_db)
):
    """
    Receives Wazuh alerts from Shuffle.
    Creates an incident automatically.
    No auth required — webhook endpoint.
    """
    indicator = (alert.src_ip or
                 alert.agent_ip or
                 "unknown")

    # Determine alert type from rule description
    alert_type = _classify_wazuh_alert(
        alert.rule_description or "")

    # Build incident title
    title = (alert.rule_description or
             f"{alert_type} detected")
    if indicator != "unknown":
        title = f"{title[:60]} — {indicator}"

    # Map Wazuh severity (1-15) to our levels
    level     = alert.rule_level or 5
    severity  = ("critical" if level >= 12 else
                 "high"     if level >= 9  else
                 "medium"   if level >= 6  else
                 "low")

    # Process in background so Shuffle gets instant response
    background_tasks.add_task(
        _process_wazuh_incident,
        indicator  = indicator,
        alert_type = alert_type,
        title      = title,
        severity   = severity,
        mitre_id   = alert.mitre_id,
        description= alert.rule_description or "",
        rule_id    = alert.rule_id,
    )

    return {
        "status":     "received",
        "indicator":  indicator,
        "alert_type": alert_type,
        "severity":   severity,
    }


def _classify_wazuh_alert(description: str) -> str:
    """Maps Wazuh rule description to AEGIS alert type."""
    d = description.lower()
    if any(k in d for k in ["brute", "authentication failure",
                             "failed login", "invalid user"]):
        return "brute_force"
    if any(k in d for k in ["scan", "nmap", "port scan"]):
        return "port_scan"
    if any(k in d for k in ["sql", "injection"]):
        return "sql_injection"
    if any(k in d for k in ["phish", "malicious email"]):
        return "phishing"
    if any(k in d for k in ["exfil", "large transfer",
                             "data transfer"]):
        return "data_exfil"
    if any(k in d for k in ["lateral", "rdp", "internal ssh"]):
        return "lateral_movement"
    if any(k in d for k in ["malware", "trojan", "virus"]):
        return "malware"
    return "wazuh_alert"


def _process_wazuh_incident(indicator, alert_type, title,
                             severity, mitre_id,
                             description, rule_id):
    """Background task — enriches and saves Wazuh incident."""
    db = SessionLocal()
    try:
        # IOC enrichment
        ioc_result   = check_ioc(indicator)
        score_result = score_from_ioc_result(ioc_result)
        score_result.score = ioc_result.get("score", score_result.score)
        score_result.verdict = ioc_result.get("verdict", score_result.verdict)
        mitre_tag    = tag_alert(alert_type, mitre_id,
                                 description)
        cve_result   = {}

        inc_data = {
            "title":                title,
            "alert_type":           alert_type,
            "source":               "wazuh",
            "severity":             severity,
            "indicator":            indicator,
            "indicator_type":       ioc_result.get("type", "ip"),
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
            "wazuh_rule_id": rule_id,
            "status":        "new",
            "raw_data":      json.dumps({
                "ioc":   ioc_result,
                "score": score_result.to_dict(),
            }),
        }

        inc = save_incident(db, inc_data)

        # Auto-add creation note
        add_investigation_note(
            db, inc.id, None, "AEGIS",
            "note_added",
            f"Incident auto-created from Wazuh rule "
            f"{rule_id or 'unknown'}. "
            f"Risk score: {score_result.score}/100. "
            f"MITRE: {mitre_tag.technique_id}"
        )

        print(f"  {GREEN}[✓] Wazuh incident created — "
              f"ID: {inc.id} Score: {score_result.score}{RESET}")

    except Exception as e:
        print(f"  {YELLOW}[!] Wazuh incident failed: {e}{RESET}")
    finally:
        db.close()


# ══════════════════════════════════════════════════════════════════
# ANALYST TOOLKIT ENDPOINTS
# ══════════════════════════════════════════════════════════════════

@app.post("/toolkit/ioc")
async def toolkit_ioc(
    req: IOCRequest,
    analyst: Analyst = Depends(get_current_analyst),
    db: Session = Depends(get_db)
):
    """
    Manual IOC investigation tool.
    Results saved to ioc_scans table — NOT incidents.
    Can be linked to an incident if analyst chooses.
    """
    print(f"\n{BLUE}[*] IOC check by {analyst.display_name}: "
          f"{req.indicator}{RESET}")

    ioc_result   = check_ioc(req.indicator)
    score_result = score_from_ioc_result(ioc_result)
    score_result.score = ioc_result.get("score", score_result.score)
    score_result.verdict = ioc_result.get("verdict", score_result.verdict)
    mitre_tag    = tag_alert(
        _type_to_alert(ioc_result.get("type", "ip")),
        None, ""
    )

    # Save to ioc_scans table
    vt    = ioc_result.get("vt_result", {})
    abuse = ioc_result.get("abuse_result") or {}
    whois = ioc_result.get("whois_result") or {}

    scan = IOCScan(
        analyst_id     = analyst.id,
        incident_id    = req.incident_id,
        indicator      = req.indicator,
        indicator_type = ioc_result.get("type", "ip"),
        vt_malicious   = vt.get("malicious", 0),
        vt_suspicious  = vt.get("suspicious", 0),
        vt_total       = vt.get("total", 0),
        abuse_score    = abuse.get("abuse_score", 0),
        country        = abuse.get("country"),
        isp            = abuse.get("isp"),
        total_reports  = abuse.get("total_reports", 0),
        domain_age_days = whois.get("age_days"),
        registrar      = whois.get("registrar"),
        risk_score     = score_result.score,
        verdict        = score_result.verdict,
    )
    db.add(scan)

    # If linked to incident — add to timeline
    if req.incident_id:
        add_investigation_note(
            db, req.incident_id, analyst.id,
            analyst.display_name,
            "note_added",
            f"IOC check by {analyst.display_name}: "
            f"{req.indicator} — "
            f"{score_result.verdict} ({score_result.score}/100). "
            f"VT: {vt.get('malicious',0)}/{vt.get('total',0)} "
            f"AbuseIPDB: {abuse.get('abuse_score',0)}/100"
        )

    db.commit()

    return {
        "scan_id":      scan.id,
        "indicator":    req.indicator,
        "type":         ioc_result.get("type"),
        "score":        score_result.score,
        "verdict":      score_result.verdict,
        "risk_level":   score_result.risk_level,
        "colour":       score_result.colour,
        "flags":        score_result.flags,
        "virustotal": {
            "malicious":  vt.get("malicious", 0),
            "suspicious": vt.get("suspicious", 0),
            "total":      vt.get("total", 0),
        },
        "abuseipdb": {
            "score":         abuse.get("abuse_score", 0),
            "country":       abuse.get("country"),
            "isp":           abuse.get("isp"),
            "total_reports": abuse.get("total_reports", 0),
            "last_reported": abuse.get("last_reported"),
        },
        "whois": {
            "age_days":     whois.get("age_days"),
            "creation_date": whois.get("creation_date"),
            "age_risk":     whois.get("age_risk"),
            "registrar":    whois.get("registrar"),
        },
        "mitre": {
            "technique_id":   mitre_tag.technique_id,
            "technique_name": mitre_tag.technique_name,
            "tactic":         mitre_tag.tactic,
            "kill_chain":     mitre_tag.kill_chain,
            "severity":       mitre_tag.severity,
        },
        "linked_incident": req.incident_id,
        "analyst":         analyst.display_name,
    }


def _type_to_alert(indicator_type: str) -> str:
    mapping = {
        "ip":     "ip_reputation",
        "domain": "domain_check",
        "url":    "url_check",
        "hash":   "hash_check",
    }
    return mapping.get(indicator_type, "unknown")


@app.post("/toolkit/email")
async def toolkit_email(
    req: EmailRequest,
    analyst: Analyst = Depends(get_current_analyst),
    db: Session = Depends(get_db)
):
    """
    Email phishing analysis tool.
    Results saved to email_scans — NOT incidents.
    """
    from email_analyser import analyse_email

    print(f"\n{BLUE}[*] Email analysis by "
          f"{analyst.display_name}{RESET}")

    result = analyse_email(req.raw_headers)

    from database import EmailScan
    scan = EmailScan(
        analyst_id    = analyst.id,
        incident_id   = req.incident_id,
        from_address  = result.get("headers",{}).get("from"),
        reply_to      = result.get("headers",{}).get("reply_to"),
        subject       = result.get("headers",{}).get("subject"),
        sender_ip     = result.get("sender_ip"),
        reply_mismatch = result.get(
            "reply_mismatch",{}).get("mismatch", False),
        urls_found    = len(result.get("urls", [])),
        malicious_urls = len([
            u for u in result.get("url_results",[])
            if u.get("status") == "MALICIOUS"
        ]),
        domain_age_days = (result.get("whois_result") or {})
                          .get("age_days"),
        risk_score    = result.get("score", 0),
        verdict       = result.get("verdict", "UNKNOWN"),
    )
    db.add(scan)
    db.commit()

    return {
        "scan_id":       scan.id,
        "verdict":       result.get("verdict"),
        "score":         result.get("score"),
        "from":          result.get("headers",{}).get("from"),
        "subject":       result.get("headers",{}).get("subject"),
        "sender_ip":     result.get("sender_ip"),
        "reply_mismatch": result.get(
            "reply_mismatch",{}).get("mismatch", False),
        "spf":    (result.get("auth_result",{})
                   .get("spf",{}).get("status")),
        "dmarc":  (result.get("auth_result",{})
                   .get("dmarc",{}).get("status")),
        "urls_found":    len(result.get("urls", [])),
        "malicious_urls": scan.malicious_urls,
        "url_results":   result.get("url_results", []),
        "domain_age":    result.get(
            "whois_result",{}).get("age_days"),
        "analyst":       analyst.display_name,
    }


# ══════════════════════════════════════════════════════════════════
# STATS + INTELLIGENCE
# ══════════════════════════════════════════════════════════════════

@app.get("/stats")
async def get_dashboard_stats(
    analyst: Analyst = Depends(get_current_analyst),
    db: Session = Depends(get_db)
):
    """Dashboard metrics."""
    return get_stats(db)


@app.get("/mitre/heatmap")
async def mitre_heatmap(
    analyst: Analyst = Depends(get_current_analyst),
    db: Session = Depends(get_db)
):
    """ATT&CK technique counts."""
    incidents = db.query(Incident).filter(
        Incident.mitre_technique_id.isnot(None)).all()

    heatmap = {}
    for inc in incidents:
        tid = inc.mitre_technique_id
        if tid and tid not in ["Unknown", "T0000"]:
            if tid not in heatmap:
                heatmap[tid] = {
                    "count":  0,
                    "name":   inc.mitre_technique_name,
                    "tactic": inc.mitre_tactic,
                }
            heatmap[tid]["count"] += 1

    return {"heatmap": heatmap,
            "techniques": len(heatmap)}


@app.get("/analysts/active")
async def active_analysts(
    analyst: Analyst = Depends(get_current_analyst),
    db: Session = Depends(get_db)
):
    """Returns all active analysts."""
    analysts = db.query(Analyst).filter(
        Analyst.is_active == True).all()
    return {"analysts": [a.to_dict() for a in analysts]}


@app.get("/health")
async def health():
    return {
        "status":  "running",
        "tool":    TOOL_NAME,
        "version": VERSION,
        "author":  AUTHOR,
        "time":    datetime.utcnow().isoformat(),
    }


# ── Serve dashboard ───────────────────────────────────────────────
dashboard_dir = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "dashboard"
)
if os.path.exists(dashboard_dir):
    app.mount("/dashboard",
              StaticFiles(directory=dashboard_dir, html=True),
              name="dashboard")


# ── Run ───────────────────────────────────────────────────────────
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0",
                port=8000, reload=True)
