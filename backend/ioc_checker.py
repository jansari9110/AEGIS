"""
AEGIS — Feature 1: IOC Checker
================================
What this does:
  Takes any suspicious indicator (IP address, URL, domain, or file hash)
  and checks it against 3 free threat intelligence sources:
    1. VirusTotal  — checks against 70+ antivirus engines
    2. AbuseIPDB   — checks IP reputation score (0-100)
    3. WHOIS       — checks domain registration age

SOC concept this automates:
  This is exactly what an L1 analyst does manually every day.
  Instead of opening 3 browser tabs and copy-pasting,
  AEGIS does it in 3 seconds automatically.

How to run:
  python3 ioc_checker.py
  python3 ioc_checker.py 8.8.8.8
"""

# ── IMPORTS ───────────────────────────────────────────────────────────────────
# 'requests' lets Python make HTTP calls to APIs
import requests
import json
import sys
import re
import os
from datetime import datetime
from branding import BANNER, FOOTER
import whois

# Import API keys from config.py
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY

# ── COLOURS FOR TERMINAL OUTPUT ───────────────────────────────────────────────
# ANSI escape codes — make terminal text coloured
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


# ── FUNCTION 1: CHECK VIRUSTOTAL ─────────────────────────────────────────────
def check_virustotal(indicator, indicator_type):
    """
    Sends indicator to VirusTotal API.
    Checks against 70+ antivirus engines.
    Returns malicious count, total engines checked.

    SOC concept: VirusTotal is the most important
    threat intel tool an L1 analyst uses daily.
    """
    print(f"\n{BLUE}[*] Checking VirusTotal...{RESET}")

    base_url = "https://www.virustotal.com/api/v3"

    # API key goes in the headers — like showing ID at the door
    headers = {"x-apikey": VIRUSTOTAL_API_KEY}

    # Different indicator types use different API endpoints
    if indicator_type == "ip":
        url = f"{base_url}/ip_addresses/{indicator}"

    elif indicator_type == "domain":
        url = f"{base_url}/domains/{indicator}"

    elif indicator_type == "hash":
        url = f"{base_url}/files/{indicator}"

    elif indicator_type == "url":
        # URLs must be base64 encoded — VirusTotal requirement
        import base64
        url_id = base64.urlsafe_b64encode(
            indicator.encode()).decode().strip("=")
        url = f"{base_url}/urls/{url_id}"

    else:
        return {"error": "Unknown indicator type"}

    try:
        # Make the GET request — timeout after 10 seconds
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data  = response.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]

            malicious  = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            harmless   = stats.get("harmless", 0)
            undetected = stats.get("undetected", 0)
            total      = malicious + suspicious + harmless + undetected

            return {
                "malicious":  malicious,
                "suspicious": suspicious,
                "total":      total,
                "source":     "VirusTotal"
            }

        elif response.status_code == 404:
            return {
                "malicious":  0,
                "suspicious": 0,
                "total":      0,
                "note":       "Not found in VirusTotal — may be new or clean",
                "source":     "VirusTotal"
            }

        elif response.status_code == 429:
            return {"error": "VirusTotal rate limit — wait 1 minute"}

        else:
            return {"error": f"VirusTotal status: {response.status_code}"}

    except requests.exceptions.Timeout:
        return {"error": "VirusTotal timed out"}
    except requests.exceptions.ConnectionError:
        return {"error": "Cannot connect to VirusTotal"}
    except Exception as e:
        return {"error": f"VirusTotal error: {str(e)}"}


# ── FUNCTION 2: CHECK ABUSEIPDB ───────────────────────────────────────────────
def check_abuseipdb(ip_address):
    """
    Checks an IP address against AbuseIPDB.
    Returns an abuse confidence score 0-100.
      0   = no reports, likely clean
      100 = highly malicious, many abuse reports

    SOC concept: AbuseIPDB tells you if this IP
    has been reported for brute force, spam,
    scanning, or other malicious activity before.
    """
    print(f"{BLUE}[*] Checking AbuseIPDB...{RESET}")

    url     = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Accept": "application/json",
        "Key":    ABUSEIPDB_API_KEY
    }
    params  = {
        "ipAddress":    ip_address,
        "maxAgeInDays": "90"
    }

    try:
        response = requests.get(
            url, headers=headers, params=params, timeout=10)

        if response.status_code == 200:
            data = response.json()["data"]
            return {
                "abuse_score":   data.get("abuseConfidenceScore", 0),
                "country":       data.get("countryCode", "Unknown"),
                "isp":           data.get("isp", "Unknown"),
                "total_reports": data.get("totalReports", 0),
                "last_reported": data.get("lastReportedAt", "Never"),
                "source":        "AbuseIPDB"
            }
        else:
            return {"error": f"AbuseIPDB status: {response.status_code}"}

    except Exception as e:
        return {"error": f"AbuseIPDB error: {str(e)}"}


# ── FUNCTION 3: WHOIS DOMAIN AGE ─────────────────────────────────────────────
def check_domain_age(domain):
    """
    Checks when a domain was registered.
    Domains under 30 days old = major red flag.

    SOC concept: Attackers register fresh domains
    for phishing. A legitimate bank has a domain
    registered years ago. A phishing site may be
    registered 2 days ago.
    """
    print(f"{BLUE}[*] Checking domain age via WHOIS...{RESET}")

    try:
        w             = whois.whois(domain)
        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            age_days = (datetime.now() - creation_date).days

            if age_days < 30:
                age_risk = "HIGH — under 30 days old"
            elif age_days < 180:
                age_risk = "MEDIUM — under 6 months old"
            else:
                age_risk = "LOW — established domain"

            return {
                "age_days":      age_days,
                "creation_date": str(creation_date)[:10],
                "age_risk":      age_risk,
                "registrar":     str(w.registrar),
                "source":        "WHOIS"
            }
        else:
            return {"error": "Creation date not available"}

    except Exception as e:
        return {"error": f"WHOIS failed: {str(e)}"}


# ── FUNCTION 4: CALCULATE RISK SCORE ─────────────────────────────────────────
def calculate_risk_score(vt_result, abuse_result=None, whois_result=None):
    """
    Combines all results into one 0-100 risk score.

    Formula:
      VirusTotal  = up to 60 points
      AbuseIPDB   = up to 30 points
      Domain age  = up to 10 points

    Verdict:
      70-100 = MALICIOUS  (red)
      40-69  = SUSPICIOUS (yellow)
      0-39   = CLEAN      (green)
    """
    score = 0

    # VirusTotal — up to 60 points
    if "malicious" in vt_result and vt_result.get("total", 0) > 0:
        ratio  = vt_result["malicious"] / vt_result["total"]
        score += int(ratio * 60)
        if vt_result.get("suspicious", 0) > 0:
            score += 5

    # AbuseIPDB — up to 30 points
    if abuse_result and "abuse_score" in abuse_result:
        score += int(abuse_result["abuse_score"] * 0.30)

    # Domain age — up to 10 points
    if whois_result and "age_days" in whois_result:
        age = whois_result["age_days"]
        if age < 7:
            score += 10
        elif age < 30:
            score += 7
        elif age < 180:
            score += 3

    score = min(score, 100)

    if score >= 70:
        return score, "MALICIOUS",  RED
    elif score >= 40:
        return score, "SUSPICIOUS", YELLOW
    else:
        return score, "CLEAN",      GREEN


# ── FUNCTION 5: PRINT REPORT ──────────────────────────────────────────────────
def print_results(indicator, indicator_type,
                  vt_result, abuse_result=None, whois_result=None):
    """
    Prints a clean formatted analysis report in the terminal.
    """
    score, verdict, colour = calculate_risk_score(
        vt_result, abuse_result, whois_result)

    print(f"\n{'='*55}")
    print(f"{BOLD}  AEGIS — IOC Analysis Report{RESET}")
    print(f"{'='*55}")
    print(f"  Indicator : {BOLD}{indicator}{RESET}")
    print(f"  Type      : {indicator_type.upper()}")
    print(f"{'─'*55}")

    # VirusTotal section
    print(f"\n  {BOLD}[1] VirusTotal{RESET}")
    if "error" in vt_result:
        print(f"  {YELLOW}  ⚠  {vt_result['error']}{RESET}")
    else:
        m   = vt_result.get("malicious", 0)
        t   = vt_result.get("total", 0)
        s   = vt_result.get("suspicious", 0)
        col = RED if m > 0 else (YELLOW if s > 0 else GREEN)
        print(f"  {col}  Detections : {m}/{t} engines flagged malicious{RESET}")
        if s > 0:
            print(f"  {YELLOW}  Suspicious : {s}/{t} engines{RESET}")
        if "note" in vt_result:
            print(f"  {YELLOW}  Note       : {vt_result['note']}{RESET}")

    # AbuseIPDB section (IPs only)
    if abuse_result:
        print(f"\n  {BOLD}[2] AbuseIPDB{RESET}")
        if "error" in abuse_result:
            print(f"  {YELLOW}  ⚠  {abuse_result['error']}{RESET}")
        else:
            ab  = abuse_result["abuse_score"]
            col = RED if ab > 70 else (YELLOW if ab > 30 else GREEN)
            print(f"  {col}  Abuse score    : {ab}/100{RESET}")
            print(f"      Country        : {abuse_result.get('country','?')}")
            print(f"      ISP            : {abuse_result.get('isp','?')}")
            print(f"      Total reports  : {abuse_result.get('total_reports',0)}")

    # WHOIS section (domains only)
    if whois_result:
        print(f"\n  {BOLD}[3] WHOIS — Domain Age{RESET}")
        if "error" in whois_result:
            print(f"  {YELLOW}  ⚠  {whois_result['error']}{RESET}")
        else:
            ar  = whois_result.get("age_risk", "")
            col = RED if "HIGH" in ar else (YELLOW if "MEDIUM" in ar else GREEN)
            print(f"  {col}  Domain age  : {whois_result.get('age_days','?')} days old{RESET}")
            print(f"      Registered  : {whois_result.get('creation_date','?')}")
            print(f"      Risk level  : {whois_result.get('age_risk','?')}")

    # Final verdict
    print(f"\n{'─'*55}")
    print(f"  Risk Score : {colour}{BOLD}{score}/100{RESET}")
    print(f"  Verdict    : {colour}{BOLD}{'⚠  ' if score>=40 else '✓  '}{verdict}{RESET}")
    print(f"{'='*55}\n")

    return score, verdict


# ── FUNCTION 6: DETECT INDICATOR TYPE ────────────────────────────────────────
def detect_type(indicator):
    """
    Auto-detects what type of indicator was given.
    URL → url
    4 numbers with dots → ip
    32/40/64 hex chars → hash
    Anything else → domain
    """
    if indicator.startswith("http://") or indicator.startswith("https://"):
        return "url"

    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", indicator):
        return "ip"

    if re.match(r"^[a-fA-F0-9]{32}$", indicator): return "hash"
    if re.match(r"^[a-fA-F0-9]{40}$", indicator): return "hash"
    if re.match(r"^[a-fA-F0-9]{64}$", indicator): return "hash"

    return "domain"


# ── MAIN FUNCTION ─────────────────────────────────────────────────────────────
def check_ioc(indicator):
    """
    Orchestrates the full IOC check.
    1. Detect type
    2. Check VirusTotal
    3. Check AbuseIPDB (IPs only)
    4. Check WHOIS (domains only)
    5. Print report
    Returns a dict with all results — used by other AEGIS modules later.
    """
    print(f"\n{BOLD}{BLUE}  Analysing: {indicator}{RESET}")

    indicator_type = detect_type(indicator)
    print(f"  Type detected: {indicator_type.upper()}")

    # Always check VirusTotal
    vt_result = check_virustotal(indicator, indicator_type)

    # Only check AbuseIPDB for IP addresses
    abuse_result = None
    if indicator_type == "ip":
        abuse_result = check_abuseipdb(indicator)

    # Only check WHOIS for domains
    whois_result = None
    if indicator_type == "domain":
        domain = indicator.replace("https://","").replace("http://","").split("/")[0]
        whois_result = check_domain_age(domain)

    # Print report and get score
    score, verdict = print_results(
        indicator, indicator_type,
        vt_result, abuse_result, whois_result
    )

    # Return dict — this gets used by FastAPI backend later
    return {
        "indicator":    indicator,
        "type":         indicator_type,
        "score":        score,
        "verdict":      verdict,
        "vt_result":    vt_result,
        "abuse_result": abuse_result,
        "whois_result": whois_result
    }


# ── ENTRY POINT ───────────────────────────────────────────────────────────────
if __name__ == "__main__":

    print(f"{BOLD}{BLUE}{BANNER}{RESET}")

    # Command line mode: python3 ioc_checker.py 8.8.8.8
    if len(sys.argv) > 1:
        check_ioc(sys.argv[1])

    else:
        # Interactive mode — keep asking for indicators
        print(f"  {BOLD}Enter any IP, domain, URL, or file hash.{RESET}")
        print(f"  Type 'quit' to exit.\n")
        while True:
            try:
                indicator = input(f"  {BOLD}AEGIS > {RESET}").strip()

                if indicator.lower() in ["quit", "exit", "q"]:
                    print(f"\n  {GREEN}AEGIS session ended.{RESET}\n")
                    break

                if not indicator:
                    continue

                check_ioc(indicator)

            except KeyboardInterrupt:
                print(f"\n\n  {GREEN}AEGIS interrupted.{RESET}\n")
                break
