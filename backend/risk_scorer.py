"""
AEGIS — Risk Scoring Engine
============================
What this file does:
  Takes raw results from all threat intel sources and
  calculates one final risk score from 0 to 100.

  Score breakdown:
    VirusTotal detections  = up to 40 points
    AbuseIPDB score        = up to 25 points
    MITRE technique severity = up to 15 points
    Domain age             = up to 10 points
    Time of day (off-hours)= up to 5 points
    Suspicious patterns    = up to 5 points (bonus)
    ─────────────────────────────────────────────
    Total possible         = 100 points

  Verdict thresholds:
    70 - 100 = HIGH    (red)
    40 - 69  = MEDIUM  (yellow)
    0  - 39  = LOW     (green)

New Python concepts in this file:
  dataclass         — cleaner way to define data container classes
  @dataclass        — decorator that auto-generates __init__ and __repr__
  Enum              — defines a fixed set of named constants
  TypedDict         — dict with defined key types (for type hints)
  round()           — rounds a float to N decimal places
  all()             — returns True if ALL items in iterable are truthy
  any()             — returns True if ANY item in iterable is truthy
  max()             — returns the largest value from multiple arguments
"""

from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime
from typing import Optional, Dict, Any
from datetime import datetime, timezone
import json


# ══════════════════════════════════════════════════════════════════════════════
# ENUMS — fixed sets of named constants
# ══════════════════════════════════════════════════════════════════════════════

class RiskLevel(Enum):
    """
    NEW CONCEPT — Enum:
      An Enum defines a fixed set of allowed values.
      Instead of using raw strings like "HIGH" everywhere
      (which can have typos), we use RiskLevel.HIGH.
      This prevents bugs from misspelling strings.

      RiskLevel.HIGH.value  = "HIGH"  (the string)
      RiskLevel.HIGH.name   = "HIGH"  (same here)
    """
    LOW    = "LOW"
    MEDIUM = "MEDIUM"
    HIGH   = "HIGH"


class Verdict(Enum):
    CLEAN      = "CLEAN"
    SUSPICIOUS = "SUSPICIOUS"
    MALICIOUS  = "MALICIOUS"
    PHISHING   = "PHISHING"
    UNKNOWN    = "UNKNOWN"


# ══════════════════════════════════════════════════════════════════════════════
# DATACLASS — clean data container
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ScoreResult:
    """
    NEW CONCEPT — @dataclass:
      A dataclass automatically creates __init__, __repr__, __eq__
      methods based on the fields you define.

      Without @dataclass you would have to write:
        def __init__(self, score, verdict, risk_level, ...):
            self.score = score
            self.verdict = verdict
            ...

      With @dataclass you just declare the fields and Python
      generates all that code automatically.

      field(default=...) sets a default value for a field.
      field(default_factory=list) creates a new empty list
      for each instance (not shared between instances).
    """
    score:          int               = 0
    verdict:        str               = "UNKNOWN"
    risk_level:     str               = "LOW"
    colour:         str               = "green"

    # Score breakdown — how many points from each source
    vt_points:      int               = 0
    abuse_points:   int               = 0
    mitre_points:   int               = 0
    age_points:     int               = 0
    time_points:    int               = 0
    bonus_points:   int               = 0

    # What triggered the score
    flags:          list              = field(default_factory=list)
    # field(default_factory=list) creates fresh [] for each instance
    # If you used flags: list = [] all instances would SHARE the same list

    def to_dict(self) -> dict:
        return {
            "score":        self.score,
            "verdict":      self.verdict,
            "risk_level":   self.risk_level,
            "colour":       self.colour,
            "breakdown": {
                "virustotal":  self.vt_points,
                "abuseipdb":   self.abuse_points,
                "mitre":       self.mitre_points,
                "domain_age":  self.age_points,
                "time_factor": self.time_points,
                "bonus":       self.bonus_points,
            },
            "flags": self.flags,
        }


# ══════════════════════════════════════════════════════════════════════════════
# MITRE SEVERITY MAP — technique ID to severity weight
# ══════════════════════════════════════════════════════════════════════════════

# Higher number = more severe technique
# Used to add points based on which attack technique was detected
MITRE_SEVERITY = {
    # Critical techniques — max points
    "T1566":   1.0,   # Phishing
    "T1190":   1.0,   # Exploit public-facing application
    "T1059":   0.9,   # Command execution
    "T1055":   0.9,   # Process injection
    "T1003":   0.9,   # Credential dumping
    "T1041":   0.9,   # Exfiltration over C2

    # High severity
    "T1110":   0.8,   # Brute force
    "T1021":   0.8,   # Remote services
    "T1078":   0.8,   # Valid accounts
    "T1486":   1.0,   # Data encrypted (ransomware)

    # Medium severity
    "T1595":   0.5,   # Active scanning / recon
    "T1046":   0.5,   # Network service discovery
    "T1083":   0.4,   # File discovery
    "T1518":   0.3,   # Software discovery
    "T1592":   0.4,   # Gather victim host info

    # Default for unknown techniques
    "DEFAULT": 0.5,
}


# ══════════════════════════════════════════════════════════════════════════════
# MAIN SCORING FUNCTION
# ══════════════════════════════════════════════════════════════════════════════

def calculate_score(
    vt_malicious:    int   = 0,
    vt_suspicious:   int   = 0,
    vt_total:        int   = 0,
    abuse_score:     int   = 0,
    domain_age_days: Optional[int] = None,
    mitre_id:        Optional[str] = None,
    alert_timestamp: Optional[datetime] = None,
    indicator_type:  str   = "ip",
    extra_flags:     list  = None,
) -> ScoreResult:
    """
    Calculates the final risk score for an alert.

    Parameters:
      vt_malicious    — number of VT engines that flagged malicious
      vt_suspicious   — number of VT engines that flagged suspicious
      vt_total        — total VT engines that scanned
      abuse_score     — AbuseIPDB confidence score 0-100
      domain_age_days — how many days old is the domain (None if IP)
      mitre_id        — MITRE ATT&CK technique ID (e.g. "T1110")
      alert_timestamp — when did the alert occur
      indicator_type  — "ip", "url", "domain", "hash"
      extra_flags     — additional flag strings to include

    Returns:
      ScoreResult dataclass with score, verdict, breakdown, flags
    """

    result = ScoreResult()
    if extra_flags:
        result.flags.extend(extra_flags)

    # ── Component 1: VirusTotal — up to 40 points ─────────────────────────────
    if vt_total > 0:
        # Calculate detection ratio — what fraction of engines flagged it
        mal_ratio = vt_malicious / vt_total
        sus_ratio = vt_suspicious / vt_total

        # Scale to 40 points maximum
        vt_points = int(mal_ratio * 36) + int(sus_ratio * 4)
        vt_points = min(vt_points, 40)  # cap at 40

        result.vt_points = vt_points

        if vt_malicious > 0:
            result.flags.append(
                f"VirusTotal: {vt_malicious}/{vt_total} engines "
                f"flagged malicious")

        if vt_malicious >= 10:
            result.flags.append(
                "Widely detected — high confidence threat")

    # ── Component 2: AbuseIPDB — up to 25 points ─────────────────────────────
    if abuse_score > 0:
        # AbuseIPDB is already 0-100, scale to 0-25
        abuse_points        = int(abuse_score * 0.25)
        result.abuse_points = min(abuse_points, 25)

        if abuse_score >= 80:
            result.flags.append(
                f"AbuseIPDB: {abuse_score}/100 — "
                f"highly malicious IP")
        elif abuse_score >= 40:
            result.flags.append(
                f"AbuseIPDB: {abuse_score}/100 — "
                f"suspicious IP with reports")

    # ── Component 3: MITRE technique severity — up to 15 points ──────────────
    if mitre_id:
        # Look up severity weight for this technique
        # Try exact match first, then prefix match, then default
        base_id  = mitre_id.split(".")[0]
        # T1110.001 → T1110 (base technique without sub-technique)

        severity = (MITRE_SEVERITY.get(mitre_id) or
                    MITRE_SEVERITY.get(base_id) or
                    MITRE_SEVERITY["DEFAULT"])
        # NEW CONCEPT — chained or:
        # Tries each .get() left to right, uses first truthy result

        mitre_points        = int(severity * 15)
        result.mitre_points = min(mitre_points, 15)

        if severity >= 0.8:
            result.flags.append(
                f"MITRE {mitre_id}: "
                f"high-severity technique")

    # ── Component 4: Domain age — up to 10 points ────────────────────────────
    if domain_age_days is not None:
        if domain_age_days < 7:
            result.age_points = 10
            result.flags.append(
                f"Domain only {domain_age_days} days old — "
                f"very high risk")
        elif domain_age_days < 30:
            result.age_points = 7
            result.flags.append(
                f"Domain {domain_age_days} days old — suspicious")
        elif domain_age_days < 90:
            result.age_points = 4
            result.flags.append(
                f"Domain {domain_age_days} days old — "
                f"relatively new")
        elif domain_age_days < 180:
            result.age_points = 2

    # ── Component 5: Time of day — up to 5 points ────────────────────────────
    """
    SOC concept:
      Attackers prefer to operate outside business hours.
      An alert at 3AM is more suspicious than the same
      alert at 2PM. This is called temporal analysis.
      We add bonus points for alerts during off-hours.
    """
    check_time = alert_timestamp or datetime.now(timezone.utc)
    hour       = check_time.hour

    # Off-hours: before 7AM or after 10PM
    if hour < 7 or hour >= 22:
        result.time_points = 5
        result.flags.append(
            f"Alert at {hour:02d}:00 UTC — "
            f"off-hours activity")
    elif hour < 9 or hour >= 18:
        # Early morning or evening — slightly suspicious
        result.time_points = 2

    # ── Component 6: Bonus flags — up to 5 points ────────────────────────────
    bonus = 0

    # Hash indicator — likely a file scan, add weight if detected
    if indicator_type == "hash" and vt_malicious > 0:
        bonus += 3
        result.flags.append("Malicious file hash detected")

    # Multiple sources agree — stronger confidence
    sources_flagging = sum([
        1 if vt_malicious > 0 else 0,
        1 if abuse_score > 50 else 0,
        1 if (domain_age_days is not None
              and domain_age_days < 30) else 0,
    ])
    # NEW CONCEPT — sum() with list comprehension:
    # Creates a list of 1s and 0s, then sums them
    # Counts how many sources flagged the indicator

    if sources_flagging >= 2:
        bonus += 2
        result.flags.append(
            f"Multiple sources flagging "
            f"({sources_flagging}/3 sources agree)")

    result.bonus_points = min(bonus, 5)

    # ── Calculate final score ─────────────────────────────────────────────────
    raw_score    = (result.vt_points    +
                    result.abuse_points +
                    result.mitre_points +
                    result.age_points   +
                    result.time_points  +
                    result.bonus_points)

    result.score = min(raw_score, 100)  # cap at 100

    # ── Determine verdict and visual properties ───────────────────────────────
    if result.score >= 70:
        result.verdict    = Verdict.MALICIOUS.value
        result.risk_level = RiskLevel.HIGH.value
        result.colour     = "red"
    elif result.score >= 40:
        result.verdict    = Verdict.SUSPICIOUS.value
        result.risk_level = RiskLevel.MEDIUM.value
        result.colour     = "amber"
    else:
        result.verdict    = Verdict.CLEAN.value
        result.risk_level = RiskLevel.LOW.value
        result.colour     = "green"

    return result


# ══════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTION — score from ioc_checker result dict
# ══════════════════════════════════════════════════════════════════════════════

def score_from_ioc_result(ioc_result: dict) -> ScoreResult:
    """
    Takes the dict returned by ioc_checker.check_ioc()
    and calculates the risk score.

    This is the bridge between ioc_checker.py and risk_scorer.py.
    Instead of passing 10 individual parameters, we pass
    the whole result dict and extract what we need.

    NEW CONCEPT — dict.get() with nested get():
      ioc_result.get("vt_result", {}).get("malicious", 0)
      If "vt_result" key missing → {} → .get("malicious",0) → 0
      Safely navigates nested dicts without crashing.
    """
    vt      = ioc_result.get("vt_result", {})
    abuse   = ioc_result.get("abuse_result") or {}
    whois_r = ioc_result.get("whois_result") or {}

    return calculate_score(
        vt_malicious    = vt.get("malicious", 0),
        vt_suspicious   = vt.get("suspicious", 0),
        vt_total        = vt.get("total", 0),
        abuse_score     = abuse.get("abuse_score", 0),
        domain_age_days = whois_r.get("age_days"),
        indicator_type  = ioc_result.get("type", "ip"),
    )


def score_from_email_result(email_result: dict) -> ScoreResult:
    """
    Takes the dict returned by email_analyser.analyse_email()
    and calculates the phishing risk score.
    """
    flags = []

    # Build extra flags from email-specific findings
    if email_result.get("reply_mismatch", {}).get("mismatch"):
        flags.append("Reply-To mismatch detected")

    url_results     = email_result.get("url_results", [])
    malicious_urls  = [u for u in url_results
                       if u.get("status") == "MALICIOUS"]
    if malicious_urls:
        flags.append(
            f"{len(malicious_urls)} malicious URL(s) in email body")

    # Get sender IP abuse score if available
    sender_ip_result = email_result.get("sender_ip_result") or {}
    abuse_score      = sender_ip_result.get("abuse_score", 0)

    # Get domain age from whois result
    whois_r          = email_result.get("whois_result") or {}
    domain_age       = whois_r.get("age_days")

    # Extra points for malicious URLs
    url_vt_malicious = sum(u.get("malicious", 0)
                           for u in malicious_urls)
    # NEW CONCEPT — sum() with generator expression:
    # Adds up "malicious" count from all malicious URL results

    result = calculate_score(
        vt_malicious    = url_vt_malicious,
        vt_total        = max(len(url_results), 1),
        abuse_score     = abuse_score,
        domain_age_days = domain_age,
        indicator_type  = "url",
        extra_flags     = flags,
    )

    # Override verdict to PHISHING if score is high enough
    if result.score >= 60:
        result.verdict = Verdict.PHISHING.value

    return result


# ══════════════════════════════════════════════════════════════════════════════
# DISPLAY HELPER
# ══════════════════════════════════════════════════════════════════════════════

def print_score_breakdown(result: ScoreResult):
    """
    Prints a formatted score breakdown in terminal.
    Useful for debugging and understanding scoring.
    """
    RED    = "\033[91m"
    YELLOW = "\033[93m"
    GREEN  = "\033[92m"
    BOLD   = "\033[1m"
    RESET  = "\033[0m"

    colour = RED if result.colour == "red" else (
             YELLOW if result.colour == "amber" else GREEN)

    print(f"\n  {'─'*45}")
    print(f"  {BOLD}Risk Score Breakdown{RESET}")
    print(f"  {'─'*45}")
    print(f"  VirusTotal     : {result.vt_points:>3} pts")
    print(f"  AbuseIPDB      : {result.abuse_points:>3} pts")
    print(f"  MITRE severity : {result.mitre_points:>3} pts")
    print(f"  Domain age     : {result.age_points:>3} pts")
    print(f"  Time factor    : {result.time_points:>3} pts")
    print(f"  Bonus          : {result.bonus_points:>3} pts")
    print(f"  {'─'*45}")
    print(f"  {BOLD}Total Score    : "
          f"{colour}{result.score}/100{RESET}")
    print(f"  {BOLD}Verdict        : "
          f"{colour}{result.verdict}{RESET}")

    if result.flags:
        print(f"\n  Flags:")
        for flag in result.flags:
            print(f"    • {flag}")
    print(f"  {'─'*45}\n")


# ══════════════════════════════════════════════════════════════════════════════
# TEST — run directly to verify scoring works
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":

    print("Testing AEGIS Risk Scorer...\n")

    # Test 1 — clearly malicious IP
    print("Test 1 — Malicious IP (high VT detections, high abuse score)")
    result1 = calculate_score(
        vt_malicious    = 45,
        vt_total        = 72,
        abuse_score     = 91,
        mitre_id        = "T1110",
        indicator_type  = "ip"
    )
    print_score_breakdown(result1)

    # Test 2 — suspicious new domain
    print("Test 2 — Suspicious new domain (3 days old, some detections)")
    result2 = calculate_score(
        vt_malicious    = 5,
        vt_total        = 72,
        abuse_score     = 20,
        domain_age_days = 3,
        indicator_type  = "domain"
    )
    print_score_breakdown(result2)

    # Test 3 — clean IP
    print("Test 3 — Clean IP (no detections)")
    result3 = calculate_score(
        vt_malicious    = 0,
        vt_total        = 91,
        abuse_score     = 0,
        indicator_type  = "ip"
    )
    print_score_breakdown(result3)

    # Test 4 — off-hours alert
    print("Test 4 — Off-hours alert (3AM, moderate detections)")
    result4 = calculate_score(
        vt_malicious    = 8,
        vt_total        = 72,
        abuse_score     = 35,
        alert_timestamp = datetime(2025, 1, 1, 3, 0, 0),
        indicator_type  = "ip"
    )
    print_score_breakdown(result4)

    print("[✓] risk_scorer.py working correctly")
