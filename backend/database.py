"""
AEGIS — Reconstructed Database
================================
Changes from original:
  - Added Analyst table (login/auth)
  - Added IOCScan table (separate from alerts)
  - Added EmailScan table (separate from alerts)
  - Alerts now only come from Wazuh/attack engine
  - Closed/escalated alerts tracked separately
  - Analyst attribution on every action
"""

from sqlalchemy import (
    create_engine, Column, Integer, String,
    Float, Text, DateTime, Boolean, ForeignKey
)
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from datetime import datetime
import bcrypt
import os, sys

# ── PATH SETUP ────────────────────────────────────────────────────
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "..", "data")
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH  = os.path.join(DATA_DIR, "aegis.db")

# ── ENGINE + BASE ─────────────────────────────────────────────────
engine     = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False}
)
Base         = declarative_base()
SessionLocal = sessionmaker(
    autocommit=False, autoflush=False, bind=engine)

# ── PASSWORD HASHING ──────────────────────────────────────────────
def hash_password(password: str) -> str:
    return bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    ).decode("utf-8")

def verify_password(plain: str, hashed: str) -> bool:
    return bcrypt.checkpw(
        plain.encode("utf-8"),
        hashed.encode("utf-8")
    )


# ══════════════════════════════════════════════════════════════════
# TABLE 1 — ANALYSTS (login system)
# ══════════════════════════════════════════════════════════════════

class Analyst(Base):
    """
    Stores analyst accounts.
    Every action in AEGIS is attributed to an analyst.
    """
    __tablename__ = "analysts"

    id           = Column(Integer, primary_key=True, index=True)
    created_at   = Column(DateTime, default=datetime.utcnow)
    username     = Column(String(50), unique=True, nullable=False,
                          index=True)
    display_name = Column(String(100), nullable=False)
    email        = Column(String(200), nullable=True)
    password_hash = Column(String(200), nullable=False)
    role         = Column(String(20), default="analyst")
    # roles: analyst, senior_analyst, admin
    is_active    = Column(Boolean, default=True)
    last_login   = Column(DateTime, nullable=True)

    # Stats
    alerts_investigated = Column(Integer, default=0)
    true_positives      = Column(Integer, default=0)
    false_positives     = Column(Integer, default=0)

    def to_dict(self):
        return {
            "id":           self.id,
            "username":     self.username,
            "display_name": self.display_name,
            "email":        self.email,
            "role":         self.role,
            "is_active":    self.is_active,
            "last_login":   self.last_login.isoformat()
                            if self.last_login else None,
            "stats": {
                "investigated":  self.alerts_investigated,
                "true_positives": self.true_positives,
                "false_positives": self.false_positives,
            }
        }


# ══════════════════════════════════════════════════════════════════
# TABLE 2 — INCIDENTS (from Wazuh/attack engine ONLY)
# ══════════════════════════════════════════════════════════════════

class Incident(Base):
    """
    Real security incidents — only populated by:
      - Wazuh alerts via Shuffle webhook
      - Attack engine detections
      - NOT by manual IOC checks

    This is the main alert queue analysts triage.
    Follows the Sentinel incident lifecycle:
      new → assigned → investigating → escalated/closed
    """
    __tablename__ = "incidents"

    id           = Column(Integer, primary_key=True, index=True)
    created_at   = Column(DateTime, default=datetime.utcnow)
    updated_at   = Column(DateTime, default=datetime.utcnow,
                          onupdate=datetime.utcnow)

    # ── Incident details ──────────────────────────────────────────
    title        = Column(String(200), nullable=False)
    # Human readable title: "SSH Brute Force from 185.220.101.47"
    alert_type   = Column(String(50), nullable=False)
    source       = Column(String(50), default="wazuh")
    # source: wazuh, attack_engine, manual_escalation
    severity     = Column(String(20), default="medium")
    # severity: critical, high, medium, low
    indicator    = Column(String(500), nullable=False)
    indicator_type = Column(String(20), default="ip")

    # ── Lifecycle status ──────────────────────────────────────────
    status       = Column(String(20), default="new")
    # new → assigned → investigating → escalated / closed_tp / closed_fp
    assigned_to  = Column(Integer, ForeignKey("analysts.id"),
                          nullable=True)
    assigned_at  = Column(DateTime, nullable=True)
    closed_at    = Column(DateTime, nullable=True)
    closed_by    = Column(Integer, ForeignKey("analysts.id"),
                          nullable=True)
    escalated_to = Column(String(100), nullable=True)
    # Name/ID of L2 analyst or team

    # ── Verdict ───────────────────────────────────────────────────
    is_true_positive = Column(Boolean, nullable=True)
    closing_note     = Column(Text, nullable=True)
    investigation_time_mins = Column(Integer, nullable=True)
    # Time from assigned_at to closed_at in minutes

    # ── Threat intel ──────────────────────────────────────────────
    risk_score     = Column(Integer, default=0)
    verdict        = Column(String(20), default="UNKNOWN")
    vt_malicious   = Column(Integer, default=0)
    vt_total       = Column(Integer, default=0)
    abuse_score    = Column(Integer, default=0)
    domain_age_days = Column(Integer, nullable=True)
    cve_id         = Column(String(20), nullable=True)
    cvss_score     = Column(Float, nullable=True)

    # ── MITRE ─────────────────────────────────────────────────────
    mitre_technique_id   = Column(String(20), nullable=True)
    mitre_technique_name = Column(String(100), nullable=True)
    mitre_tactic         = Column(String(50), nullable=True)
    kill_chain_stage     = Column(String(50), nullable=True)

    # ── AI report ─────────────────────────────────────────────────
    ai_report      = Column(Text, nullable=True)

    # ── Raw data ──────────────────────────────────────────────────
    raw_data       = Column(Text, nullable=True)
    wazuh_rule_id  = Column(String(20), nullable=True)
    thehive_case_id = Column(String(50), nullable=True)

    def to_dict(self):
        return {
            "id":             self.id,
            "created_at":     self.created_at.isoformat()
                              if self.created_at else None,
            "updated_at":     self.updated_at.isoformat()
                              if self.updated_at else None,
            "title":          self.title,
            "alert_type":     self.alert_type,
            "source":         self.source,
            "severity":       self.severity,
            "indicator":      self.indicator,
            "indicator_type": self.indicator_type,
            "status":         self.status,
            "assigned_to":    self.assigned_to,
            "closed_at":      self.closed_at.isoformat()
                              if self.closed_at else None,
            "closed_by":      self.closed_by,
            "is_true_positive": self.is_true_positive,
            "closing_note":   self.closing_note,
            "investigation_time_mins":
                              self.investigation_time_mins,
            "risk_score":     self.risk_score,
            "verdict":        self.verdict,
            "vt_malicious":   self.vt_malicious,
            "vt_total":       self.vt_total,
            "abuse_score":    self.abuse_score,
            "mitre_technique_id":   self.mitre_technique_id,
            "mitre_technique_name": self.mitre_technique_name,
            "mitre_tactic":         self.mitre_tactic,
            "kill_chain_stage":     self.kill_chain_stage,
            "ai_report":      self.ai_report,
            "cve_id":         self.cve_id,
            "cvss_score":     self.cvss_score,
            "thehive_case_id": self.thehive_case_id,
        }

    def __repr__(self):
        return (f"<Incident id={self.id} "
                f"type={self.alert_type} "
                f"status={self.status} "
                f"score={self.risk_score}>")


# ══════════════════════════════════════════════════════════════════
# TABLE 3 — INVESTIGATION NOTES (audit trail)
# ══════════════════════════════════════════════════════════════════

class InvestigationNote(Base):
    """
    Every note, action, or status change by an analyst.
    Creates a full audit trail for each incident.
    Shown in the incident timeline view.
    """
    __tablename__ = "investigation_notes"

    id           = Column(Integer, primary_key=True, index=True)
    created_at   = Column(DateTime, default=datetime.utcnow)
    incident_id  = Column(Integer, ForeignKey("incidents.id"),
                          nullable=False, index=True)
    analyst_id   = Column(Integer, ForeignKey("analysts.id"),
                          nullable=True)
    analyst_name = Column(String(100), nullable=True)
    # Stored directly so we can display even if analyst deleted
    action       = Column(String(50), nullable=False)
    # action: note_added, status_changed, escalated,
    #         closed_tp, closed_fp, ai_report_generated,
    #         assigned
    note         = Column(Text, nullable=False)

    def to_dict(self):
        return {
            "id":           self.id,
            "created_at":   self.created_at.isoformat()
                            if self.created_at else None,
            "incident_id":  self.incident_id,
            "analyst_id":   self.analyst_id,
            "analyst_name": self.analyst_name,
            "action":       self.action,
            "note":         self.note,
        }


# ══════════════════════════════════════════════════════════════════
# TABLE 4 — IOC SCANS (analyst toolkit — separate from incidents)
# ══════════════════════════════════════════════════════════════════

class IOCScan(Base):
    """
    Results from manual IOC checker tool.
    NEVER appears in the incident queue.
    Analyst uses this to investigate indicators.
    Can be linked to an incident (incident_id) if relevant.
    """
    __tablename__ = "ioc_scans"

    id             = Column(Integer, primary_key=True, index=True)
    created_at     = Column(DateTime, default=datetime.utcnow)
    analyst_id     = Column(Integer, ForeignKey("analysts.id"),
                            nullable=True)
    incident_id    = Column(Integer, ForeignKey("incidents.id"),
                            nullable=True)
    # If linked to an incident — shows in incident timeline

    indicator      = Column(String(500), nullable=False)
    indicator_type = Column(String(20))

    # VirusTotal
    vt_malicious   = Column(Integer, default=0)
    vt_suspicious  = Column(Integer, default=0)
    vt_total       = Column(Integer, default=0)
    vt_engines     = Column(Text, nullable=True)
    # JSON: which specific engines flagged it

    # AbuseIPDB
    abuse_score    = Column(Integer, default=0)
    country        = Column(String(10), nullable=True)
    isp            = Column(String(200), nullable=True)
    total_reports  = Column(Integer, default=0)

    # WHOIS
    domain_age_days = Column(Integer, nullable=True)
    registrar       = Column(String(200), nullable=True)
    creation_date   = Column(String(50), nullable=True)

    # Shodan (added later)
    open_ports     = Column(Text, nullable=True)
    # JSON: list of open ports/services

    # Passive DNS
    passive_dns    = Column(Text, nullable=True)
    # JSON: list of domains that resolved to this IP

    # Final assessment
    risk_score     = Column(Integer, default=0)
    verdict        = Column(String(20), default="UNKNOWN")
    analyst_note   = Column(Text, nullable=True)

    def to_dict(self):
        import json as _json
        return {
            "id":             self.id,
            "created_at":     self.created_at.isoformat()
                              if self.created_at else None,
            "analyst_id":     self.analyst_id,
            "incident_id":    self.incident_id,
            "indicator":      self.indicator,
            "indicator_type": self.indicator_type,
            "vt_malicious":   self.vt_malicious,
            "vt_suspicious":  self.vt_suspicious,
            "vt_total":       self.vt_total,
            "abuse_score":    self.abuse_score,
            "country":        self.country,
            "isp":            self.isp,
            "total_reports":  self.total_reports,
            "domain_age_days": self.domain_age_days,
            "registrar":      self.registrar,
            "open_ports":     _json.loads(self.open_ports)
                              if self.open_ports else [],
            "risk_score":     self.risk_score,
            "verdict":        self.verdict,
            "analyst_note":   self.analyst_note,
        }


# ══════════════════════════════════════════════════════════════════
# TABLE 5 — EMAIL SCANS (analyst toolkit)
# ══════════════════════════════════════════════════════════════════

class EmailScan(Base):
    """
    Results from email phishing analyser tool.
    NEVER appears in incident queue unless escalated.
    """
    __tablename__ = "email_scans"

    id              = Column(Integer, primary_key=True, index=True)
    created_at      = Column(DateTime, default=datetime.utcnow)
    analyst_id      = Column(Integer, ForeignKey("analysts.id"),
                             nullable=True)
    incident_id     = Column(Integer, ForeignKey("incidents.id"),
                             nullable=True)

    from_address    = Column(String(200), nullable=True)
    reply_to        = Column(String(200), nullable=True)
    subject         = Column(String(500), nullable=True)
    sender_ip       = Column(String(50), nullable=True)
    sending_domain  = Column(String(200), nullable=True)

    # Auth results
    spf_result      = Column(String(20), nullable=True)
    # pass / fail / softfail / none
    dkim_result     = Column(String(20), nullable=True)
    dmarc_result    = Column(String(20), nullable=True)
    dmarc_policy    = Column(String(20), nullable=True)
    reply_mismatch  = Column(Boolean, default=False)

    # URLs
    urls_found      = Column(Integer, default=0)
    malicious_urls  = Column(Integer, default=0)
    url_details     = Column(Text, nullable=True)
    # JSON: list of {url, verdict, vt_score}

    # Domain age
    domain_age_days = Column(Integer, nullable=True)

    # Sender IP reputation
    sender_abuse_score = Column(Integer, default=0)
    sender_country  = Column(String(10), nullable=True)

    # Final
    risk_score      = Column(Integer, default=0)
    verdict         = Column(String(20), default="UNKNOWN")
    analyst_note    = Column(Text, nullable=True)

    def to_dict(self):
        import json as _json
        return {
            "id":            self.id,
            "created_at":    self.created_at.isoformat()
                             if self.created_at else None,
            "from_address":  self.from_address,
            "reply_to":      self.reply_to,
            "subject":       self.subject,
            "sender_ip":     self.sender_ip,
            "spf_result":    self.spf_result,
            "dkim_result":   self.dkim_result,
            "dmarc_result":  self.dmarc_result,
            "reply_mismatch": self.reply_mismatch,
            "urls_found":    self.urls_found,
            "malicious_urls": self.malicious_urls,
            "url_details":   _json.loads(self.url_details)
                             if self.url_details else [],
            "domain_age_days": self.domain_age_days,
            "sender_abuse_score": self.sender_abuse_score,
            "risk_score":    self.risk_score,
            "verdict":       self.verdict,
        }


# ══════════════════════════════════════════════════════════════════
# DATABASE FUNCTIONS
# ══════════════════════════════════════════════════════════════════

def init_db():
    Base.metadata.create_all(bind=engine)
    _create_default_analyst()
    print(f"[✓] AEGIS database ready: {DB_PATH}")


def _create_default_analyst():
    """Creates a default admin analyst if none exist."""
    db = SessionLocal()
    try:
        exists = db.query(Analyst).first()
        if not exists:
            admin = Analyst(
                username     = "admin",
                display_name = "Admin Analyst",
                email        = "admin@aegis.local",
                password_hash = hash_password("aegis2025"),
                role         = "admin",
            )
            db.add(admin)
            db.commit()
            print("[✓] Default analyst created: "
                  "admin / aegis2025")
    finally:
        db.close()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


# ── Incident functions ────────────────────────────────────────────

def save_incident(db, data: dict):
    incident = Incident(**{
        k: v for k, v in data.items()
        if hasattr(Incident, k)
    })
    db.add(incident)
    db.commit()
    db.refresh(incident)
    return incident


def get_incidents(db, status_filter=None,
                  limit=100, offset=0):
    q = db.query(Incident)
    if status_filter:
        if isinstance(status_filter, list):
            q = q.filter(Incident.status.in_(status_filter))
        else:
            q = q.filter(Incident.status == status_filter)
    return (q.order_by(Incident.risk_score.desc(),
                       Incident.created_at.desc())
             .offset(offset).limit(limit).all())


def get_incident_by_id(db, incident_id: int):
    return db.query(Incident).filter(
        Incident.id == incident_id).first()


def add_investigation_note(db, incident_id: int,
                           analyst_id: int,
                           analyst_name: str,
                           action: str,
                           note: str):
    n = InvestigationNote(
        incident_id  = incident_id,
        analyst_id   = analyst_id,
        analyst_name = analyst_name,
        action       = action,
        note         = note,
    )
    db.add(n)
    db.commit()
    return n


def get_incident_timeline(db, incident_id: int):
    return (db.query(InvestigationNote)
              .filter(InvestigationNote.incident_id
                      == incident_id)
              .order_by(InvestigationNote.created_at.asc())
              .all())


# ── Analyst functions ─────────────────────────────────────────────

def get_analyst_by_username(db, username: str):
    return db.query(Analyst).filter(
        Analyst.username == username).first()


def get_analyst_by_id(db, analyst_id: int):
    return db.query(Analyst).filter(
        Analyst.id == analyst_id).first()


def create_analyst(db, username: str,
                   display_name: str,
                   password: str,
                   email: str = None,
                   role: str = "analyst"):
    analyst = Analyst(
        username      = username,
        display_name  = display_name,
        email         = email,
        password_hash = hash_password(password),
        role          = role,
    )
    db.add(analyst)
    db.commit()
    db.refresh(analyst)
    return analyst


# ── Stats functions ───────────────────────────────────────────────

def get_stats(db):
    total     = db.query(Incident).count()
    new       = db.query(Incident).filter(
                    Incident.status == "new").count()
    assigned  = db.query(Incident).filter(
                    Incident.status == "assigned").count()
    investing = db.query(Incident).filter(
                    Incident.status == "investigating").count()
    escalated = db.query(Incident).filter(
                    Incident.status == "escalated").count()
    closed_tp = db.query(Incident).filter(
                    Incident.status == "closed_tp").count()
    closed_fp = db.query(Incident).filter(
                    Incident.status == "closed_fp").count()
    high_risk = db.query(Incident).filter(
                    Incident.risk_score >= 70).count()

    fp_rate = 0
    closed  = closed_tp + closed_fp
    if closed > 0:
        fp_rate = round((closed_fp / closed) * 100, 1)

    mitre_counts = {}
    incidents = db.query(Incident).filter(
        Incident.mitre_technique_id.isnot(None)).all()
    for inc in incidents:
        tid = inc.mitre_technique_id
        if tid and tid != "Unknown":
            mitre_counts[tid] = mitre_counts.get(tid, 0) + 1

    return {
        "total":           total,
        "new":             new,
        "assigned":        assigned,
        "investigating":   investing,
        "escalated":       escalated,
        "closed_tp":       closed_tp,
        "closed_fp":       closed_fp,
        "high_risk":       high_risk,
        "fp_rate":         fp_rate,
        "open_count":      new + assigned + investing,
        "mitre_heatmap":   mitre_counts,
    }


# ── Test ──────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("Initialising reconstructed AEGIS database...")
    init_db()

    db = SessionLocal()

    # Test creating an incident
    inc = save_incident(db, {
        "title":       "SSH Brute Force from 185.220.101.47",
        "alert_type":  "brute_force",
        "source":      "wazuh",
        "severity":    "high",
        "indicator":   "185.220.101.47",
        "risk_score":  87,
        "verdict":     "MALICIOUS",
        "mitre_technique_id":   "T1110.001",
        "mitre_technique_name": "Brute Force: Password Guessing",
        "mitre_tactic":         "Credential Access",
        "kill_chain_stage":     "Exploitation",
        "vt_malicious": 13,
        "vt_total":     91,
        "abuse_score":  100,
    })
    print(f"[✓] Test incident: {inc}")

    # Test adding a note
    add_investigation_note(
        db, inc.id, 1, "admin",
        "note_added",
        "Incident created from Wazuh alert"
    )

    stats = get_stats(db)
    print(f"[✓] Stats: {stats}")
    db.close()
    print("\n[✓] Reconstructed database working correctly")
