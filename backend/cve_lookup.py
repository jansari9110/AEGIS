"""
AEGIS — CVE Lookup Engine
==========================
What this file does:
  Queries the NVD (National Vulnerability Database) API
  for known CVEs related to detected software/services.

  NVD is maintained by NIST (US government).
  It contains every publicly known vulnerability.
  API is completely free — no key needed.

  Example:
    AEGIS detects Apache 2.4.49 running on target
    → CVE lookup finds CVE-2021-41773 (path traversal)
    → CVSS score: 9.8 (CRITICAL)
    → Patch available since Oct 2021
    → Analyst knows exactly what to fix

SOC concept:
  A detection without context is just noise.
  A detection with CVE ID + CVSS score + patch status
  is an actionable security finding.
  This is what vulnerability management teams produce
  in real companies — AEGIS automates it.

NVD API docs: https://nvd.nist.gov/developers/vulnerabilities
No API key required — completely free.

New Python concepts in this file:
  time.sleep()      — pauses execution for N seconds
  urllib.parse      — builds URL query strings safely
  sorted()          — sorts a list by a key
  list comprehension with condition — filters + transforms in one line
  round()           — rounds float to N decimal places
  .get() chaining   — safely navigates deeply nested JSON
"""

import requests
import time
import json
import os
import sys
from datetime import datetime
from typing import Optional

sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# ── COLOURS ───────────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# NVD API base URL — no key needed
NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limit — NVD allows 5 requests per 30 seconds without API key
# We wait 6 seconds between requests to stay safe
NVD_RATE_LIMIT_SECONDS = 6


# ══════════════════════════════════════════════════════════════════════════════
# CVSS SEVERITY HELPERS
# ══════════════════════════════════════════════════════════════════════════════

def cvss_to_severity(score: float) -> tuple:
    """
    Converts a CVSS score to a severity label and colour.

    CVSS (Common Vulnerability Scoring System) ranges:
      9.0 - 10.0 = CRITICAL  (red)
      7.0 - 8.9  = HIGH      (orange/red)
      4.0 - 6.9  = MEDIUM    (yellow)
      0.1 - 3.9  = LOW       (green)
      0.0        = NONE

    NEW CONCEPT — tuple return:
      A function can return multiple values as a tuple.
      severity, colour = cvss_to_severity(9.8)
      Python unpacks the tuple into two variables.
    """
    if score >= 9.0:
        return "CRITICAL", RED
    elif score >= 7.0:
        return "HIGH", "\033[91m"
    elif score >= 4.0:
        return "MEDIUM", YELLOW
    elif score > 0:
        return "LOW", GREEN
    else:
        return "NONE", RESET


# ══════════════════════════════════════════════════════════════════════════════
# CORE NVD API FUNCTION
# ══════════════════════════════════════════════════════════════════════════════

def search_cves(keyword: str,
                max_results: int = 5) -> list:
    """
    Searches NVD for CVEs matching a keyword.

    Parameters:
      keyword     — software name, e.g. "apache 2.4.49"
      max_results — how many CVEs to return (default 5)

    Returns:
      List of CVE dicts with id, description, cvss score, etc.

    NEW CONCEPT — urllib.parse.urlencode():
      Safely encodes query parameters for a URL.
      "apache 2.4.49" becomes "apache+2.4.49" in the URL.
      Without encoding, spaces and special chars break URLs.
    """
    print(f"\n{BLUE}[*] Searching NVD for: {keyword}{RESET}")

    # Build query parameters
    params = {
        "keywordSearch":  keyword,
        "resultsPerPage": max_results,
        "startIndex":     0,
    }

    # Headers — identify our tool to NVD
    headers = {
        "User-Agent": "AEGIS-SOC-Tool/1.0"
    }

    try:
        # Rate limiting — wait before request
        # NEW CONCEPT — time.sleep(n):
        #   Pauses Python execution for n seconds.
        #   We use this to respect NVD's rate limit.
        #   Without it, rapid requests get blocked (HTTP 429).
        time.sleep(NVD_RATE_LIMIT_SECONDS)

        response = requests.get(
            NVD_API_BASE,
            params=params,
            headers=headers,
            timeout=15
        )

        if response.status_code == 200:
            data          = response.json()
            total_results = data.get("totalResults", 0)
            vulnerabilities = data.get("vulnerabilities", [])

            print(f"  Found {total_results} CVEs "
                  f"(showing top {len(vulnerabilities)})")

            return parse_cve_results(vulnerabilities)

        elif response.status_code == 403:
            print(f"  {YELLOW}NVD rate limit hit — "
                  f"waiting 30 seconds...{RESET}")
            time.sleep(30)
            return []

        elif response.status_code == 404:
            print(f"  {GREEN}No CVEs found for: {keyword}{RESET}")
            return []

        else:
            print(f"  {YELLOW}NVD returned status "
                  f"{response.status_code}{RESET}")
            return []

    except requests.exceptions.Timeout:
        print(f"  {YELLOW}NVD request timed out{RESET}")
        return []
    except requests.exceptions.ConnectionError:
        print(f"  {YELLOW}Cannot connect to NVD — "
              f"check internet connection{RESET}")
        return []
    except Exception as e:
        print(f"  {YELLOW}NVD error: {str(e)}{RESET}")
        return []


def lookup_cve_by_id(cve_id: str) -> Optional[dict]:
    """
    Looks up a specific CVE by its ID.
    Example: lookup_cve_by_id("CVE-2021-41773")

    Returns full CVE details or None if not found.
    """
    print(f"\n{BLUE}[*] Looking up {cve_id}...{RESET}")

    params  = {"cveId": cve_id}
    headers = {"User-Agent": "AEGIS-SOC-Tool/1.0"}

    try:
        time.sleep(NVD_RATE_LIMIT_SECONDS)
        response = requests.get(
            NVD_API_BASE,
            params=params,
            headers=headers,
            timeout=15
        )

        if response.status_code == 200:
            data  = response.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                results = parse_cve_results(vulns)
                return results[0] if results else None

        return None

    except Exception as e:
        print(f"  {YELLOW}CVE lookup error: {str(e)}{RESET}")
        return None


# ══════════════════════════════════════════════════════════════════════════════
# PARSE NVD RESPONSE
# ══════════════════════════════════════════════════════════════════════════════

def parse_cve_results(vulnerabilities: list) -> list:
    """
    Parses the raw NVD API response into clean dicts.

    The NVD JSON is deeply nested — this function extracts
    only what AEGIS needs:
      cve_id, description, cvss_score, severity,
      published_date, patch_available, references

    NEW CONCEPT — list comprehension with condition:
      [expression for item in list if condition]
      Filters AND transforms in one line.
      More Pythonic than a for loop with append().

    NEW CONCEPT — chained .get():
      data.get("a", {}).get("b", {}).get("c", 0)
      If "a" missing → {} → .get("b",{}) → {} → .get("c",0) → 0
      Never crashes even with missing nested keys.
    """
    results = []

    for vuln in vulnerabilities:
        try:
            cve = vuln.get("cve", {})

            # ── CVE ID ────────────────────────────────────────────────────────
            cve_id = cve.get("id", "Unknown")

            # ── Description — get English description ─────────────────────────
            descriptions = cve.get("descriptions", [])
            # NEW CONCEPT — list comprehension with condition:
            # Gets all descriptions where lang == "en"
            english_descs = [
                d.get("value", "")
                for d in descriptions
                if d.get("lang") == "en"
            ]
            description = (english_descs[0][:200] + "..."
                          if english_descs and
                          len(english_descs[0]) > 200
                          else (english_descs[0]
                                if english_descs
                                else "No description"))

            # ── CVSS Score — try v3.1 first, then v3.0, then v2 ──────────────
            metrics      = cve.get("metrics", {})
            cvss_score   = 0.0
            cvss_version = "N/A"

            # Try CVSS v3.1 first (most recent)
            cvss_v31 = metrics.get("cvssMetricV31", [])
            cvss_v30 = metrics.get("cvssMetricV30", [])
            cvss_v2  = metrics.get("cvssMetricV2", [])

            if cvss_v31:
                cvss_data    = (cvss_v31[0]
                                .get("cvssData", {}))
                cvss_score   = cvss_data.get(
                    "baseScore", 0.0)
                cvss_version = "3.1"
            elif cvss_v30:
                cvss_data    = (cvss_v30[0]
                                .get("cvssData", {}))
                cvss_score   = cvss_data.get(
                    "baseScore", 0.0)
                cvss_version = "3.0"
            elif cvss_v2:
                cvss_data    = (cvss_v2[0]
                                .get("cvssData", {}))
                cvss_score   = cvss_data.get(
                    "baseScore", 0.0)
                cvss_version = "2.0"

            severity, _ = cvss_to_severity(cvss_score)

            # ── Published date ────────────────────────────────────────────────
            published = cve.get("published", "Unknown")
            if published != "Unknown" and len(published) >= 10:
                published = published[:10]
                # "2021-10-05T00:00:00.000" → "2021-10-05"

            # ── Check if patch/fix exists ─────────────────────────────────────
            # NVD marks CVEs as "patched" in configurations
            # We check if the CVE has any weaknesses listed
            # as a proxy for maturity/patch availability
            weaknesses = cve.get("weaknesses", [])
            references = cve.get("references", [])

            # Look for patch/fix references
            patch_urls = [
                r.get("url", "")
                for r in references
                if any(tag in r.get("tags", [])
                       for tag in ["Patch", "Vendor Advisory",
                                   "Release Notes"])
            ]
            patch_available = len(patch_urls) > 0

            results.append({
                "cve_id":          cve_id,
                "description":     description,
                "cvss_score":      round(cvss_score, 1),
                "cvss_version":    cvss_version,
                "severity":        severity,
                "published":       published,
                "patch_available": patch_available,
                "patch_urls":      patch_urls[:2],
                # Only keep first 2 patch URLs
                "weaknesses":      len(weaknesses),
            })

        except Exception as e:
            # Skip malformed CVE entries silently
            continue

    # Sort by CVSS score — highest first
    # NEW CONCEPT — sorted() with key and reverse:
    #   sorted(list, key=function, reverse=True)
    #   key=    defines what value to sort by
    #   reverse=True means highest first (descending)
    results = sorted(
        results,
        key=lambda x: x["cvss_score"],
        reverse=True
    )

    return results


# ══════════════════════════════════════════════════════════════════════════════
# SERVICE → CVE KEYWORD MAPPING
# ══════════════════════════════════════════════════════════════════════════════

# Maps service/tool names to NVD search keywords
# When AEGIS detects a service, it looks up this mapping
SERVICE_KEYWORDS = {
    # Web servers
    "apache":       "Apache HTTP Server",
    "nginx":        "nginx",
    "iis":          "Microsoft IIS",
    "tomcat":       "Apache Tomcat",

    # Databases
    "mysql":        "MySQL",
    "postgresql":   "PostgreSQL",
    "mssql":        "Microsoft SQL Server",
    "mongodb":      "MongoDB",

    # SSH / Remote access
    "openssh":      "OpenSSH",
    "ssh":          "OpenSSH",
    "rdp":          "Remote Desktop Protocol",
    "vnc":          "RealVNC",

    # File sharing
    "samba":        "Samba",
    "smb":          "Windows SMB",
    "ftp":          "vsftpd",

    # Web apps
    "dvwa":         "DVWA web application",
    "wordpress":    "WordPress",
    "drupal":       "Drupal",
    "joomla":       "Joomla",
    "phpmyadmin":   "phpMyAdmin",

    # Frameworks
    "php":          "PHP",
    "python":       "Python",
    "java":         "Java JDK",

    # Network services
    "telnet":       "Telnet",
    "smtp":         "Postfix SMTP",
    "dns":          "BIND DNS",
}


def lookup_service_cves(service_name: str,
                        version: Optional[str] = None,
                        max_results: int = 3) -> list:
    """
    Looks up CVEs for a detected service.

    Parameters:
      service_name — detected service (e.g. "apache", "openssh")
      version      — version string if known (e.g. "2.4.49")
      max_results  — how many CVEs to return

    Returns:
      List of top CVEs sorted by CVSS score (highest first)

    Example:
      lookup_service_cves("apache", "2.4.49")
      → finds CVE-2021-41773 CVSS 9.8 CRITICAL
    """
    service_lower = service_name.lower().strip()

    # Get the NVD search keyword for this service
    keyword = SERVICE_KEYWORDS.get(service_lower, service_name)

    # Append version if provided
    if version:
        keyword = f"{keyword} {version}"

    return search_cves(keyword, max_results)


# ══════════════════════════════════════════════════════════════════════════════
# PRINT CVE REPORT
# ══════════════════════════════════════════════════════════════════════════════

def print_cve_report(cves: list, service: str = ""):
    """
    Prints a formatted CVE report in the terminal.
    """
    if not cves:
        print(f"  {GREEN}No CVEs found for {service}{RESET}")
        return

    print(f"\n{'='*55}")
    print(f"{BOLD}  AEGIS — CVE Report{' for ' + service if service else ''}{RESET}")
    print(f"{'='*55}")

    for i, cve in enumerate(cves, 1):
        severity, colour = cvss_to_severity(cve["cvss_score"])

        print(f"\n  [{i}] {BOLD}{cve['cve_id']}{RESET}")
        print(f"      CVSS Score    : "
              f"{colour}{BOLD}{cve['cvss_score']}"
              f" ({severity}){RESET}")
        print(f"      CVSS Version  : {cve['cvss_version']}")
        print(f"      Published     : {cve['published']}")
        print(f"      Patch available: "
              f"{GREEN+'Yes' if cve['patch_available'] else RED+'No'}"
              f"{RESET}")
        print(f"      Description   : "
              f"{cve['description'][:100]}...")

        if cve.get("patch_urls"):
            print(f"      Patch URL     : {cve['patch_urls'][0]}")

    print(f"\n{'='*55}")
    print(f"  {BOLD}Total CVEs found: {len(cves)}{RESET}")

    # Highlight most critical
    critical = [c for c in cves if c["cvss_score"] >= 9.0]
    if critical:
        print(f"  {RED}{BOLD}⚠  {len(critical)} CRITICAL "
              f"CVE(s) require immediate attention{RESET}")

    print(f"{'='*55}\n")


# ══════════════════════════════════════════════════════════════════════════════
# INTEGRATION FUNCTION — called by main.py for each alert
# ══════════════════════════════════════════════════════════════════════════════

def enrich_alert_with_cves(alert_type: str,
                           indicator: str = "",
                           service: str = "") -> dict:
    """
    Main integration point — called when AEGIS processes an alert.
    Determines what CVEs are relevant to this alert.

    Returns a dict with cve data to attach to the alert record.
    """
    cves     = []
    searched = ""

    # Determine what to search based on alert type
    alert_lower = alert_type.lower()

    if any(kw in alert_lower for kw in
           ["sql", "sqli", "injection", "web_exploit"]):
        # SQL injection — look for DVWA or MySQL CVEs
        cves     = lookup_service_cves("dvwa")
        searched = "web application (SQL injection target)"

    elif any(kw in alert_lower for kw in
             ["ssh", "brute", "password"]):
        # SSH brute force — look for OpenSSH CVEs
        cves     = lookup_service_cves("openssh")
        searched = "OpenSSH"

    elif any(kw in alert_lower for kw in
             ["smb", "samba", "enum4linux"]):
        cves     = lookup_service_cves("samba")
        searched = "Samba/SMB"

    elif any(kw in alert_lower for kw in
             ["ftp"]):
        cves     = lookup_service_cves("ftp")
        searched = "FTP service"

    elif service:
        # Specific service provided
        cves     = lookup_service_cves(service)
        searched = service

    # Build result dict
    result = {
        "cves_found":    len(cves),
        "searched_for":  searched,
        "top_cve_id":    cves[0]["cve_id"] if cves else None,
        "top_cvss":      cves[0]["cvss_score"] if cves else None,
        "top_severity":  cves[0]["severity"] if cves else None,
        "patch_available": cves[0]["patch_available"]
                           if cves else None,
        "all_cves":      cves,
    }

    return result


# ══════════════════════════════════════════════════════════════════════════════
# TEST
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":

    print(f"""{BOLD}{BLUE}
  ╔══════════════════════════════════════════╗

          AEGIS — CVE Lookup  v1.0
          NVD API — no key required

  ╚══════════════════════════════════════════╝
{RESET}""")

    print("Testing CVE lookups...\n")
    print(f"{YELLOW}Note: NVD rate limit = "
          f"5 req/30s — tests include delays{RESET}\n")

    # Test 1 — OpenSSH CVEs (relevant to brute force attacks)
    print(f"{BOLD}Test 1 — OpenSSH CVEs "
          f"(brute force target){RESET}")
    cves1 = lookup_service_cves("openssh", max_results=3)
    print_cve_report(cves1, "OpenSSH")

    # Test 2 — Apache CVEs (web server exploitation)
    print(f"{BOLD}Test 2 — Apache HTTP CVEs "
          f"(web exploit target){RESET}")
    cves2 = lookup_service_cves("apache", max_results=3)
    print_cve_report(cves2, "Apache HTTP")

    print(f"{BOLD}{GREEN}[✓] cve_lookup.py working correctly{RESET}\n")
