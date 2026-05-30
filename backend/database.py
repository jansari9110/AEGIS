"""
AEGIS — Database Setup
======================
What this file does:
  Creates and manages the SQLite database for AEGIS.
  Every alert, every scan result, every analyst note
  gets stored here permanently.

  Database file: ~/aegis/data/aegis.db
  (one single file — no database server needed)

New Python concepts in this file:
  create_engine()         — connects Python to database
  declarative_base()      — base class for all database models
  sessionmaker()          — creates database sessions (connections)
  Column()                — defines a database column
  Integer, String, etc.   — column data types
  relationship()          — links two tables together
  datetime.utcnow         — current UTC time as default value
"""

from sqlalchemy import (
    create_engine, Column, Integer, String,
    Float, Text, DateTime, Boolean
)
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from datetime import datetime
import os

# ── DATABASE FILE PATH ────────────────────────────────────────────────────────
# os.path.dirname(__file__)  = directory of this file (backend/)
# os.path.join(...)          = builds path: backend/../data/aegis.db
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "..", "data")
os.makedirs(DATA_DIR, exist_ok=True)
# exist_ok=True means: create folder if missing, do nothing if it exists

DB_PATH = os.path.join(DATA_DIR, "aegis.db")

# ── CREATE ENGINE ─────────────────────────────────────────────────────────────
"""
NEW CONCEPT — create_engine():
  The engine is the connection between Python and the database.
  'sqlite:///' tells SQLAlchemy to use SQLite.
  The path after it is where the .db file lives.
  check_same_thread=False allows multiple requests at the same time.
"""
engine = create_engine(
    f"sqlite:///{DB_PATH}",
    connect_args={"check_same_thread": False}
)

# ── DECLARATIVE BASE ──────────────────────────────────────────────────────────
"""
NEW CONCEPT — declarative_base():
  Base is the parent class for all our database models.
  Every table we create inherits from Base.
  Think of it as a blueprint factory.
"""
Base = declarative_base()

# ── SESSION MAKER ─────────────────────────────────────────────────────────────
"""
NEW CONCEPT — sessionmaker():
  A session is like a temporary workspace for database operations.
  You open a session, do your reads/writes, then close it.
  autocommit=False means changes are not saved until you call commit()
  autoflush=False means changes are not sent to DB until you commit()
"""
SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine
)


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE MODELS — each class = one table in the database
# ══════════════════════════════════════════════════════════════════════════════

class Alert(Base):
    """
    The main alerts table.
    Every alert that comes into AEGIS gets one row here.

    NEW CONCEPT — Column():
      Defines one column in the database table.
      First argument = data type
      primary_key=True = this column uniquely identifies each row
      default= = value used when not specified
      nullable=True = column can be empty
      index=True = makes searching by this column faster
    """
    __tablename__ = "alerts"
    # __tablename__ tells SQLAlchemy what to call the table in the database

    # ── Primary key — unique ID for every alert ───────────────────────────────
    id = Column(Integer, primary_key=True, index=True)
    # Integer = whole number, auto-increments (1, 2, 3...)

    # ── When was this alert created ───────────────────────────────────────────
    created_at = Column(DateTime, default=datetime.utcnow)
    # datetime.utcnow (no brackets!) = function called at insert time
    # If you wrote datetime.utcnow() with brackets it would be called
    # once at startup and every row would have the same timestamp

    # ── What type of alert is this ────────────────────────────────────────────
    alert_type = Column(String(50), nullable=False)
    # Examples: "brute_force", "phishing", "port_scan", "malware"
    # String(50) = text up to 50 characters

    # ── Source of the alert ───────────────────────────────────────────────────
    source = Column(String(50), default="manual")
    # Examples: "manual", "wazuh", "attack_engine"

    # ── The main indicator being analysed ────────────────────────────────────
    indicator = Column(String(500), nullable=False)
    # The IP, URL, domain, hash, or email that triggered this alert

    indicator_type = Column(String(20), default="ip")
    # "ip", "url", "domain", "hash", "email"

    # ── Risk scoring ──────────────────────────────────────────────────────────
    risk_score = Column(Integer, default=0)
    # 0-100 — calculated by risk_scorer.py

    verdict = Column(String(20), default="UNKNOWN")
    # "CLEAN", "SUSPICIOUS", "MALICIOUS", "PHISHING"

    # ── MITRE ATT&CK mapping ──────────────────────────────────────────────────
    mitre_technique_id   = Column(String(20), nullable=True)
    # Example: "T1110.001"
    mitre_technique_name = Column(String(100), nullable=True)
    # Example: "Brute Force: Password Guessing"
    mitre_tactic         = Column(String(50), nullable=True)
    # Example: "Credential Access"
    kill_chain_stage     = Column(String(50), nullable=True)
    # Example: "Exploitation"

    # ── Threat intelligence results ───────────────────────────────────────────
    vt_malicious   = Column(Integer, default=0)
    # How many VirusTotal engines flagged it
    vt_total       = Column(Integer, default=0)
    # Total VirusTotal engines that scanned it
    abuse_score    = Column(Integer, default=0)
    # AbuseIPDB score 0-100
    domain_age_days = Column(Integer, nullable=True)
    # How many days old is the domain

    # ── CVE information ───────────────────────────────────────────────────────
    cve_id         = Column(String(20), nullable=True)
    # Example: "CVE-2024-1234"
    cvss_score     = Column(Float, nullable=True)
    # CVSS severity score 0.0-10.0

    # ── AI investigation report ───────────────────────────────────────────────
    ai_report      = Column(Text, nullable=True)
    # The Gemini-generated investigation summary
    # Text = unlimited length string (unlike String which has a limit)

    # ── Analyst actions ───────────────────────────────────────────────────────
    status = Column(String(20), default="open")
    # "open", "investigating", "escalated", "closed_tp", "closed_fp"

    analyst_notes  = Column(Text, nullable=True)
    # What the analyst wrote while investigating

    is_true_positive  = Column(Boolean, nullable=True)
    # True = real threat, False = false positive, None = not decided yet

    escalated      = Column(Boolean, default=False)
    # Has this been escalated to L2?

    # ── Raw data storage ──────────────────────────────────────────────────────
    raw_data = Column(Text, nullable=True)
    # Full JSON from all API calls stored as text
    # We can look up original results later if needed

    # ── TheHive case reference ────────────────────────────────────────────────
    thehive_case_id = Column(String(50), nullable=True)
    # ID of the case created in TheHive for this alert

    def to_dict(self):
        """
        Converts an Alert object to a Python dictionary.
        This is needed because FastAPI returns JSON —
        it cannot return a SQLAlchemy object directly.

        NEW CONCEPT — __dict__ alternative:
          We manually build the dict so we control exactly
          what fields are included and how dates are formatted.
        """
        return {
            "id":                   self.id,
            "created_at":           self.created_at.isoformat()
                                    if self.created_at else None,
            # .isoformat() converts datetime to string: "2025-01-15T10:30:00"
            # JSON cannot contain datetime objects — must be strings
            "alert_type":           self.alert_type,
            "source":               self.source,
            "indicator":            self.indicator,
            "indicator_type":       self.indicator_type,
            "risk_score":           self.risk_score,
            "verdict":              self.verdict,
            "mitre_technique_id":   self.mitre_technique_id,
            "mitre_technique_name": self.mitre_technique_name,
            "mitre_tactic":         self.mitre_tactic,
            "kill_chain_stage":     self.kill_chain_stage,
            "vt_malicious":         self.vt_malicious,
            "vt_total":             self.vt_total,
            "abuse_score":          self.abuse_score,
            "domain_age_days":      self.domain_age_days,
            "cve_id":               self.cve_id,
            "cvss_score":           self.cvss_score,
            "ai_report":            self.ai_report,
            "status":               self.status,
            "analyst_notes":        self.analyst_notes,
            "is_true_positive":     self.is_true_positive,
            "escalated":            self.escalated,
            "thehive_case_id":      self.thehive_case_id,
        }

    def __repr__(self):
        """
        NEW CONCEPT — __repr__():
          Special method Python calls when you print() an object.
          Without this, print(alert) shows something like:
          <Alert object at 0x7f8b2c3d4e5f>
          With this, it shows something useful.
        """
        return (f"<Alert id={self.id} "
                f"type={self.alert_type} "
                f"score={self.risk_score} "
                f"verdict={self.verdict}>")


class IOCScan(Base):
    """
    Stores individual IOC scan results.
    Each time ioc_checker.py runs, results are saved here.
    Linked to an Alert via alert_id.
    """
    __tablename__ = "ioc_scans"

    id           = Column(Integer, primary_key=True, index=True)
    created_at   = Column(DateTime, default=datetime.utcnow)
    alert_id     = Column(Integer, nullable=True)
    # Links to Alert.id — which alert triggered this scan

    indicator      = Column(String(500))
    indicator_type = Column(String(20))
    vt_malicious   = Column(Integer, default=0)
    vt_suspicious  = Column(Integer, default=0)
    vt_total       = Column(Integer, default=0)
    abuse_score    = Column(Integer, default=0)
    domain_age     = Column(Integer, nullable=True)
    risk_score     = Column(Integer, default=0)
    verdict        = Column(String(20))
    raw_vt         = Column(Text, nullable=True)
    raw_abuse      = Column(Text, nullable=True)

    def to_dict(self):
        return {
            "id":             self.id,
            "created_at":     self.created_at.isoformat()
                              if self.created_at else None,
            "alert_id":       self.alert_id,
            "indicator":      self.indicator,
            "indicator_type": self.indicator_type,
            "vt_malicious":   self.vt_malicious,
            "vt_total":       self.vt_total,
            "abuse_score":    self.abuse_score,
            "domain_age":     self.domain_age,
            "risk_score":     self.risk_score,
            "verdict":        self.verdict,
        }


class EmailScan(Base):
    """
    Stores phishing email analysis results.
    Each email_analyser.py run saves one row here.
    """
    __tablename__ = "email_scans"

    id              = Column(Integer, primary_key=True, index=True)
    created_at      = Column(DateTime, default=datetime.utcnow)
    alert_id        = Column(Integer, nullable=True)
    from_address    = Column(String(200), nullable=True)
    subject         = Column(String(500), nullable=True)
    sender_ip       = Column(String(50), nullable=True)
    reply_to        = Column(String(200), nullable=True)
    reply_mismatch  = Column(Boolean, default=False)
    spf_status      = Column(String(100), nullable=True)
    dmarc_status    = Column(String(100), nullable=True)
    urls_found      = Column(Integer, default=0)
    malicious_urls  = Column(Integer, default=0)
    domain_age_days = Column(Integer, nullable=True)
    risk_score      = Column(Integer, default=0)
    verdict         = Column(String(20), default="UNKNOWN")

    def to_dict(self):
        return {
            "id":             self.id,
            "created_at":     self.created_at.isoformat()
                              if self.created_at else None,
            "from_address":   self.from_address,
            "subject":        self.subject,
            "sender_ip":      self.sender_ip,
            "reply_mismatch": self.reply_mismatch,
            "spf_status":     self.spf_status,
            "dmarc_status":   self.dmarc_status,
            "urls_found":     self.urls_found,
            "malicious_urls": self.malicious_urls,
            "risk_score":     self.risk_score,
            "verdict":        self.verdict,
        }


class AnalystNote(Base):
    """
    Stores investigation notes written by the analyst.
    Linked to an alert.
    """
    __tablename__ = "analyst_notes"

    id         = Column(Integer, primary_key=True, index=True)
    created_at = Column(DateTime, default=datetime.utcnow)
    alert_id   = Column(Integer, nullable=False)
    note       = Column(Text, nullable=False)
    action     = Column(String(50), nullable=True)
    # "escalated", "closed_tp", "closed_fp", "note_added"


# ══════════════════════════════════════════════════════════════════════════════
# DATABASE HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def init_db():
    """
    Creates all tables in the database if they don't exist yet.
    Call this once when AEGIS starts.

    NEW CONCEPT — Base.metadata.create_all(engine):
      Looks at all classes that inherit from Base.
      For each one, creates the corresponding table in the database
      IF it does not already exist.
      Running this twice is safe — it never deletes existing data.
    """
    Base.metadata.create_all(bind=engine)
    print(f"[✓] AEGIS database ready: {DB_PATH}")


def get_db():
    """
    Creates and returns a database session.
    Used by FastAPI endpoints to get a DB connection.

    NEW CONCEPT — yield (generator function):
      'yield' is like return but the function can be resumed.
      FastAPI uses this pattern to:
        1. Create a session before the endpoint runs
        2. Give it to the endpoint (yield)
        3. Close it automatically after the endpoint finishes
      The try/finally ensures the session always closes
      even if an error occurs inside the endpoint.
    """
    db = SessionLocal()
    try:
        yield db        # give the session to whoever called get_db()
    finally:
        db.close()      # always close — even if exception occurred


def save_alert(db, alert_data: dict):
    """
    Saves a new alert to the database.

    Parameters:
      db         — database session from get_db()
      alert_data — dict with all alert fields

    Returns:
      The saved Alert object with its new ID assigned
    """
    # Create Alert object from dict using ** unpacking
    # NEW CONCEPT — **dict unpacking:
    #   Alert(**alert_data) is the same as writing:
    #   Alert(alert_type=alert_data["alert_type"],
    #         indicator=alert_data["indicator"], ...)
    #   ** spreads the dict keys as keyword arguments
    alert = Alert(**{k: v for k, v in alert_data.items()
                     if hasattr(Alert, k)})
    # hasattr(Alert, k) checks if Alert has a column named k
    # This prevents errors if extra keys are in the dict

    db.add(alert)       # stage the alert for saving
    db.commit()         # save to database
    db.refresh(alert)   # reload from DB to get the assigned ID
    return alert


def get_all_alerts(db, limit=100, offset=0):
    """
    Returns alerts sorted by risk score (highest first).

    NEW CONCEPT — query chaining:
      db.query(Alert)           — start a query on Alert table
      .order_by(...)            — sort results
      Alert.risk_score.desc()   — descending order (highest first)
      .offset(offset)           — skip first N results (for pagination)
      .limit(limit)             — return at most N results
      .all()                    — execute and return list
    """
    return (db.query(Alert)
              .order_by(Alert.risk_score.desc())
              .offset(offset)
              .limit(limit)
              .all())


def get_alert_by_id(db, alert_id: int):
    """
    Returns one alert by its ID.
    Returns None if not found.
    """
    return db.query(Alert).filter(Alert.id == alert_id).first()
    # .filter() = WHERE clause in SQL
    # .first()  = return first match or None


def get_stats(db):
    """
    Returns summary statistics for the dashboard metrics.

    NEW CONCEPT — db.query(Model).count():
      Counts how many rows match the query.
      Equivalent to SQL: SELECT COUNT(*) FROM alerts WHERE ...
    """
    total      = db.query(Alert).count()
    high_risk  = db.query(Alert).filter(Alert.risk_score >= 70).count()
    open_alerts = db.query(Alert).filter(Alert.status == "open").count()
    escalated  = db.query(Alert).filter(Alert.escalated == True).count()
    true_pos   = db.query(Alert).filter(
                    Alert.is_true_positive == True).count()
    false_pos  = db.query(Alert).filter(
                    Alert.is_true_positive == False).count()

    fp_rate = 0
    if (true_pos + false_pos) > 0:
        fp_rate = round((false_pos / (true_pos + false_pos)) * 100, 1)

    return {
        "total_alerts":  total,
        "high_risk":     high_risk,
        "open_alerts":   open_alerts,
        "escalated":     escalated,
        "true_positives": true_pos,
        "false_positives": false_pos,
        "fp_rate":       fp_rate,
    }


# ── RUN DIRECTLY TO TEST ──────────────────────────────────────────────────────
if __name__ == "__main__":
    print("Initialising AEGIS database...")
    init_db()

    # Test: create a sample alert
    db = SessionLocal()

    test_alert = save_alert(db, {
        "alert_type":    "test",
        "indicator":     "185.220.101.47",
        "indicator_type": "ip",
        "risk_score":    75,
        "verdict":       "MALICIOUS",
        "source":        "manual",
        "vt_malicious":  14,
        "vt_total":      72,
        "abuse_score":   88,
    })

    print(f"[✓] Test alert saved: {test_alert}")
    print(f"[✓] Alert ID: {test_alert.id}")

    stats = get_stats(db)
    print(f"[✓] Database stats: {stats}")

    db.close()
    print("\n[✓] database.py working correctly")
