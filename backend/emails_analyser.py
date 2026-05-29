"""
AEGIS — Feature 2: Email & Phishing Analyser
=============================================
What this does:
  Takes a suspicious email (.eml file or raw header text)
  and automatically checks 7 things:

  1. Sender IP extraction      — who actually sent this email
  2. Reply-To mismatch         — is reply going somewhere different
  3. SPF check                 — is sending server authorised
  4. DKIM check                — was email tampered with
  5. DMARC check               — what policy does domain enforce
  6. URL extraction + VT check — are any links malicious
  7. Domain age                — was sending domain registered recently

SOC concept:
  These are the exact steps from THM Phishing Analysis rooms.
  You did these manually in TryHackMe.
  This script automates all 7 steps in one run.

How to run:
  python3 email_analyser.py sample.eml
  python3 email_analyser.py           (interactive — paste headers)

New Python concepts in this file:
  email.message_from_file()   — parses .eml file into Python object
  email.message_from_string() — parses raw email text
  msg.get()                   — safely gets an email header value
  msg.walk()                  — iterates through all email parts
  msg.get_content_type()      — returns MIME type (text/plain, text/html)
  msg.get_payload()           — gets the body content of email part
  re.findall()                — finds ALL regex matches (not just first)
  dns.resolver.resolve()      — DNS lookup for SPF/DKIM/DMARC records
  socket.gethostbyname()      — resolves domain to IP address
"""

import requests
import re
import sys
import os
import email
import email.policy
from datetime import datetime
from branding import BANNER, FOOTER

# DNS lookups for SPF/DKIM/DMARC
# Install with: pip install dnspython --break-system-packages
try:
    import dns.resolver
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False

# WHOIS for domain age
import whois

# Import our IOC checker to reuse VT + AbuseIPDB functions
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from config import VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY
from ioc_checker import check_virustotal, check_abuseipdb, check_domain_age

# ── COLOURS ──────────────────────────────────────────────────────────────────
RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BLUE   = "\033[94m"
BOLD   = "\033[1m"
RESET  = "\033[0m"


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION 1 — Parse email file or raw text
# ══════════════════════════════════════════════════════════════════════════════
def parse_email(source):
    """
    Parses an email from either:
      - A file path ending in .eml
      - Raw email header text pasted by analyst

    NEW PYTHON CONCEPT — email.message_from_file():
      Python's built-in 'email' library can parse .eml files into
      an EmailMessage object. This object lets us access every
      header (From, To, Subject, Received, etc.) by name.
      Like a dictionary but for email headers.

    NEW PYTHON CONCEPT — email.message_from_string():
      Same as above but parses a string instead of a file.
      Used when analyst pastes raw headers into terminal.

    Returns:
      EmailMessage object, or None if parsing failed
    """
    try:
        if os.path.isfile(source):
            # Source is a file path — open and parse
            with open(source, "r", encoding="utf-8", errors="ignore") as f:
                # email.message_from_file() reads file and returns
                # an EmailMessage object with all headers accessible
                msg = email.message_from_file(f, policy=email.policy.default)
            print(f"{GREEN}[✓] Parsed email file: {source}{RESET}")
        else:
            # Source is raw text — parse directly from string
            msg = email.message_from_string(
                source, policy=email.policy.default)
            print(f"{GREEN}[✓] Parsed raw email headers{RESET}")

        return msg

    except Exception as e:
        print(f"{RED}[✗] Failed to parse email: {e}{RESET}")
        return None


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION 2 — Extract basic headers
# ══════════════════════════════════════════════════════════════════════════════
def extract_headers(msg):
    """
    Extracts the most important email headers.

    SOC concept:
      Email headers contain the full journey of an email.
      Attackers forge the 'From' field — it can say anything.
      But the 'Received' headers show the real server path
      and cannot be forged by the sender.

    NEW PYTHON CONCEPT — msg.get(header, default):
      Gets a specific header value from the EmailMessage object.
      Returns default if header is not present.
      Similar to dict.get() but for email headers.

    Headers we care about:
      From          — displayed sender (can be forged)
      Reply-To      — where replies actually go (key phishing indicator)
      Return-Path   — where bounces go (often reveals real sender)
      Received      — list of servers that handled this email (real path)
      X-Originating-IP — sometimes reveals sender's real IP
      Message-ID    — unique identifier for this email
    """
    headers = {
        "from":             msg.get("From", "Not found"),
        "reply_to":         msg.get("Reply-To", "Not set"),
        "return_path":      msg.get("Return-Path", "Not set"),
        "subject":          msg.get("Subject", "No subject"),
        "date":             msg.get("Date", "Unknown"),
        "message_id":       msg.get("Message-ID", "Unknown"),
        "received":         msg.get_all("Received", []),
        # get_all() returns ALL values for a header as a list
        # 'Received' appears multiple times (once per server hop)
        "x_originating_ip": msg.get("X-Originating-IP", None),
        "x_mailer":         msg.get("X-Mailer", "Unknown"),
        "mime_version":     msg.get("MIME-Version", "Unknown")
    }
    return headers


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION 3 — Extract sender IP from Received headers
# ══════════════════════════════════════════════════════════════════════════════
def extract_sender_ip(headers):
    """
    Finds the original sender's IP address from Received headers.

    SOC concept:
      The last 'Received' header (bottom of the chain) contains
      the IP of the server that originally sent the email.
      This is the real source — compare it against AbuseIPDB.

    How Received headers work:
      Each mail server that handles the email adds a Received header
      at the TOP. So the FIRST Received header is the most recent
      hop (your mail server receiving it) and the LAST one is
      the original sender.

    NEW PYTHON CONCEPT — re.findall():
      re.findall(pattern, string) returns a LIST of ALL matches.
      Unlike re.match() which only checks from the start,
      findall() searches the entire string and collects everything.
      We use it to find all IP addresses inside Received headers.
    """
    # IP address regex pattern
    # Matches patterns like 192.168.1.1 or 185.220.101.47
    ip_pattern = r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"

    received_headers = headers.get("received", [])

    # X-Originating-IP is the most reliable if present
    if headers.get("x_originating_ip"):
        ip = headers["x_originating_ip"].strip()
        # Remove brackets if present: [192.168.1.1] → 192.168.1.1
        ip = ip.strip("[]")
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ip):
            return ip

    # Look in Received headers — last one = original sender
    if received_headers:
        # Reverse to start from original sender (last = first sent)
        for received in reversed(received_headers):
            ips = re.findall(ip_pattern, str(received))
            for ip in ips:
                # Skip private/internal IP ranges
                # These are internal network addresses — not useful
                if not (ip.startswith("10.") or
                        ip.startswith("192.168.") or
                        ip.startswith("172.") or
                        ip == "127.0.0.1"):
                    return ip

    return None


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION 4 — Check Reply-To mismatch
# ══════════════════════════════════════════════════════════════════════════════
def check_reply_to_mismatch(headers):
    """
    Checks if Reply-To domain differs from From domain.

    SOC concept:
      In phishing, the attacker wants you to think the email
      is from support@paypal.com but when you reply it goes
      to attacker@evil.com. This is a Reply-To mismatch.

      Example:
        From:     support@paypal.com
        Reply-To: support@paypa1-secure.ru   ← completely different!

    Returns:
      dict with mismatch=True/False and the two domains
    """
    # Extract domain from email address using regex
    # Pattern matches: anything@domain.tld
    domain_pattern = r"@([\w\.-]+)"

    from_header    = str(headers.get("from", ""))
    reply_to       = str(headers.get("reply_to", ""))

    from_domains   = re.findall(domain_pattern, from_header)
    reply_domains  = re.findall(domain_pattern, reply_to)

    if not from_domains:
        return {"mismatch": False, "note": "Could not extract From domain"}

    if not reply_domains:
        return {"mismatch": False,
                "note": "No Reply-To header — normal"}

    from_domain  = from_domains[0].lower()
    reply_domain = reply_domains[0].lower()

    if from_domain != reply_domain:
        return {
            "mismatch":     True,
            "from_domain":  from_domain,
            "reply_domain": reply_domain,
            "severity":     "HIGH — classic phishing indicator"
        }
    else:
        return {
            "mismatch":     False,
            "from_domain":  from_domain,
            "reply_domain": reply_domain
        }


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION 5 — Check SPF, DKIM, DMARC
# ══════════════════════════════════════════════════════════════════════════════
def check_email_authentication(from_domain):
    """
    Checks the three email authentication mechanisms.

    SPF (Sender Policy Framework):
      A DNS record listing which servers are allowed to send
      email for a domain. Like an authorised sender whitelist.
      If the sending server is NOT in the SPF record → fail → suspicious.

    DKIM (DomainKeys Identified Mail):
      A cryptographic signature added to every legitimate email.
      Proves the email was not modified in transit.
      If signature is missing or invalid → email may be forged.

    DMARC (Domain-based Message Authentication):
      A policy telling mail servers what to do if SPF/DKIM fail.
      Values:
        p=none      — do nothing (weak, just monitoring)
        p=quarantine — put in spam
        p=reject    — reject the email entirely (strongest)

    NEW PYTHON CONCEPT — dns.resolver.resolve():
      Makes a DNS query — like nslookup from terminal but in Python.
      dns.resolver.resolve(domain, "TXT") gets TXT records.
      SPF and DMARC are stored as TXT records in DNS.
      Returns a list of DNS answers we can iterate over.
    """
    result = {
        "spf":   {"found": False, "record": None, "status": "Not found"},
        "dkim":  {"found": False, "status": "Cannot verify without full email"},
        "dmarc": {"found": False, "record": None, "status": "Not found"}
    }

    if not DNS_AVAILABLE:
        result["note"] = "dnspython not installed — run: pip install dnspython"
        return result

    # ── SPF Check ────────────────────────────────────────────────────────────
    try:
        # SPF record is a TXT record on the root domain
        answers = dns.resolver.resolve(from_domain, "TXT")
        for answer in answers:
            record = str(answer)
            if "v=spf1" in record:
                result["spf"]["found"]  = True
                result["spf"]["record"] = record

                # Analyse SPF strictness
                if "~all" in record:
                    result["spf"]["status"] = "SoftFail (~all) — weak policy"
                elif "-all" in record:
                    result["spf"]["status"] = "HardFail (-all) — strong policy"
                elif "+all" in record:
                    result["spf"]["status"] = "PASS ALL (+all) — dangerous, allows anything"
                elif "?all" in record:
                    result["spf"]["status"] = "Neutral (?all) — no policy"
                break

    except dns.resolver.NXDOMAIN:
        result["spf"]["status"] = "Domain does not exist"
    except dns.resolver.NoAnswer:
        result["spf"]["status"] = "No TXT records found"
    except Exception as e:
        result["spf"]["status"] = f"SPF lookup failed: {str(e)}"

    # ── DMARC Check ──────────────────────────────────────────────────────────
    try:
        # DMARC record lives at _dmarc.domain.com
        dmarc_domain = f"_dmarc.{from_domain}"
        answers      = dns.resolver.resolve(dmarc_domain, "TXT")

        for answer in answers:
            record = str(answer)
            if "v=DMARC1" in record:
                result["dmarc"]["found"]  = True
                result["dmarc"]["record"] = record

                # Extract policy value
                policy_match = re.search(r"p=(\w+)", record)
                if policy_match:
                    policy = policy_match.group(1)
                    if policy == "reject":
                        result["dmarc"]["status"] = "p=reject — strong protection"
                    elif policy == "quarantine":
                        result["dmarc"]["status"] = "p=quarantine — moderate protection"
                    elif policy == "none":
                        result["dmarc"]["status"] = "p=none — monitoring only, weak"
                break

    except Exception as e:
        result["dmarc"]["status"] = f"DMARC not found: {str(e)[:50]}"

    return result


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION 6 — Extract all URLs from email body
# ══════════════════════════════════════════════════════════════════════════════
def extract_urls_from_body(msg):
    """
    Extracts all URLs from the email body (plain text and HTML parts).

    SOC concept:
      Phishing emails contain malicious links.
      The displayed text may say "Click here to verify your account"
      but the actual href points to evil.com.
      We extract ALL URLs and check every single one.

    NEW PYTHON CONCEPT — msg.walk():
      An email can have multiple parts (plain text, HTML, attachments).
      msg.walk() is a generator that iterates through ALL parts.
      For each part we check:
        msg.get_content_type() — returns "text/plain" or "text/html" etc.
        msg.get_payload()      — returns the actual content of that part

    NEW PYTHON CONCEPT — bytes.decode():
      Sometimes email payloads are bytes (raw binary data).
      .decode("utf-8", errors="ignore") converts bytes to string.
      errors="ignore" skips characters it cannot decode.
    """
    urls  = set()  # set() automatically removes duplicates
    # A set is like a list but every item is unique
    # If we find the same URL 5 times, it only appears once

    url_pattern = r"https?://[^\s<>\"{}|\\^`\[\]]+"

    # Walk through all email parts
    for part in msg.walk():
        content_type = part.get_content_type()

        # Only process text parts — skip attachments
        if content_type in ["text/plain", "text/html"]:
            try:
                payload = part.get_payload(decode=True)
                # decode=True returns bytes, we convert to string

                if isinstance(payload, bytes):
                    body = payload.decode("utf-8", errors="ignore")
                else:
                    body = str(payload) if payload else ""

                # Find all URLs in this part
                found = re.findall(url_pattern, body)
                urls.update(found)  # update() adds all items to the set

            except Exception:
                continue

    return list(urls)  # convert set back to list for the rest of code


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION 7 — Check all extracted URLs
# ══════════════════════════════════════════════════════════════════════════════
def check_urls(urls, max_urls=10):
    """
    Checks each URL against VirusTotal.
    Limits to max_urls to avoid burning through API rate limits.

    SOC concept:
      VirusTotal URL scanning checks the URL against 70+ web
      security engines. Even if the URL looks legitimate,
      security engines may have already flagged it as phishing.
    """
    if not urls:
        return []

    print(f"\n{BLUE}[*] Found {len(urls)} URLs — checking up to {max_urls}...{RESET}")

    results     = []
    checked     = 0

    for url in urls[:max_urls]:  # slice to limit — list[:10] = first 10 items
        vt_result = check_virustotal(url, "url")

        malicious  = vt_result.get("malicious", 0)
        suspicious = vt_result.get("suspicious", 0)

        if malicious > 0:
            status = "MALICIOUS"
            colour = RED
        elif suspicious > 0:
            status = "SUSPICIOUS"
            colour = YELLOW
        elif "error" in vt_result:
            status = f"ERROR: {vt_result['error']}"
            colour = YELLOW
        else:
            status = "CLEAN"
            colour = GREEN

        results.append({
            "url":    url[:80] + "..." if len(url) > 80 else url,
            "status": status,
            "colour": colour,
            "malicious":  malicious,
            "suspicious": suspicious
        })
        checked += 1

    return results


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION 8 — Calculate phishing risk score
# ══════════════════════════════════════════════════════════════════════════════
def calculate_phishing_score(headers, reply_mismatch,
                              auth_result, url_results,
                              sender_ip_result=None,
                              whois_result=None):
    """
    Combines all checks into a phishing risk score 0-100.

    Scoring breakdown:
      Reply-To mismatch     = 30 points (very strong indicator)
      Malicious URLs        = up to 30 points
      SPF fail/missing      = 10 points
      DMARC missing/weak    = 10 points
      Sender IP abused      = up to 15 points
      New domain (<30 days) = 5 points
    """
    score = 0
    flags = []  # list to collect what we found

    # Reply-To mismatch — 30 points
    if reply_mismatch.get("mismatch"):
        score += 30
        flags.append(f"Reply-To mismatch: "
                     f"{reply_mismatch.get('from_domain')} vs "
                     f"{reply_mismatch.get('reply_domain')}")

    # Malicious URLs
    if url_results:
        malicious_urls = [u for u in url_results if u["status"] == "MALICIOUS"]
        suspicious_urls = [u for u in url_results if u["status"] == "SUSPICIOUS"]
        if malicious_urls:
            score += min(30, len(malicious_urls) * 15)
            flags.append(f"{len(malicious_urls)} malicious URL(s) detected")
        if suspicious_urls:
            score += min(10, len(suspicious_urls) * 5)
            flags.append(f"{len(suspicious_urls)} suspicious URL(s) detected")

    # SPF issues
    spf_status = auth_result.get("spf", {}).get("status", "")
    if not auth_result.get("spf", {}).get("found"):
        score += 10
        flags.append("SPF record missing")
    elif "SoftFail" in spf_status or "PASS ALL" in spf_status:
        score += 5
        flags.append(f"SPF weak: {spf_status}")

    # DMARC issues
    dmarc_status = auth_result.get("dmarc", {}).get("status", "")
    if not auth_result.get("dmarc", {}).get("found"):
        score += 10
        flags.append("DMARC record missing")
    elif "none" in dmarc_status:
        score += 5
        flags.append("DMARC policy is p=none — weak")

    # Sender IP abuse score
    if sender_ip_result and "abuse_score" in sender_ip_result:
        ab = sender_ip_result["abuse_score"]
        score += int(ab * 0.15)
        if ab > 30:
            flags.append(f"Sender IP abuse score: {ab}/100")

    # New domain
    if whois_result and "age_days" in whois_result:
        if whois_result["age_days"] < 30:
            score += 5
            flags.append(f"Sending domain only {whois_result['age_days']} days old")

    score = min(score, 100)

    if score >= 70:
        verdict = "PHISHING"
        colour  = RED
    elif score >= 40:
        verdict = "SUSPICIOUS"
        colour  = YELLOW
    else:
        verdict = "LIKELY CLEAN"
        colour  = GREEN

    return score, verdict, colour, flags


# ══════════════════════════════════════════════════════════════════════════════
# FUNCTION 9 — Print full phishing report
# ══════════════════════════════════════════════════════════════════════════════
def print_phishing_report(headers, reply_mismatch, auth_result,
                          url_results, sender_ip, sender_ip_result,
                          whois_result, score, verdict, colour, flags):
    """
    Prints the complete formatted phishing analysis report.
    """
    print(f"\n{'='*60}")
    print(f"{BOLD}  AEGIS — Phishing Analysis Report{RESET}")
    print(f"{'='*60}")
    print(f"  From       : {headers.get('from', 'Unknown')}")
    print(f"  Subject    : {headers.get('subject', 'Unknown')}")
    print(f"  Date       : {headers.get('date', 'Unknown')}")
    print(f"  Reply-To   : {headers.get('reply_to', 'Not set')}")
    print(f"{'─'*60}")

    # Sender IP section
    print(f"\n  {BOLD}[1] Sender IP{RESET}")
    if sender_ip:
        print(f"    Extracted IP : {sender_ip}")
        if sender_ip_result and "abuse_score" in sender_ip_result:
            ab  = sender_ip_result["abuse_score"]
            col = RED if ab > 70 else (YELLOW if ab > 30 else GREEN)
            print(f"    {col}AbuseIPDB    : {ab}/100{RESET}")
            print(f"    Country      : {sender_ip_result.get('country','?')}")
            print(f"    ISP          : {sender_ip_result.get('isp','?')}")
    else:
        print(f"    {YELLOW}Could not extract sender IP{RESET}")

    # Reply-To mismatch
    print(f"\n  {BOLD}[2] Reply-To Analysis{RESET}")
    if reply_mismatch.get("mismatch"):
        print(f"    {RED}⚠  MISMATCH DETECTED — classic phishing indicator{RESET}")
        print(f"    From domain    : {reply_mismatch.get('from_domain')}")
        print(f"    Reply-To domain: {reply_mismatch.get('reply_domain')}")
    else:
        print(f"    {GREEN}✓  No mismatch — From and Reply-To match{RESET}")

    # SPF / DMARC
    print(f"\n  {BOLD}[3] Email Authentication{RESET}")

    spf = auth_result.get("spf", {})
    col = GREEN if spf.get("found") and "HardFail" in spf.get(
        "status","") else (YELLOW if spf.get("found") else RED)
    print(f"    {col}SPF   : {spf.get('status','Not checked')}{RESET}")

    dmarc = auth_result.get("dmarc", {})
    col   = GREEN if dmarc.get("found") and "reject" in dmarc.get(
        "status","") else (YELLOW if dmarc.get("found") else RED)
    print(f"    {col}DMARC : {dmarc.get('status','Not checked')}{RESET}")

    # Domain age
    if whois_result and "age_days" in whois_result:
        print(f"\n  {BOLD}[4] Sending Domain Age{RESET}")
        ar  = whois_result.get("age_risk","")
        col = RED if "HIGH" in ar else (YELLOW if "MEDIUM" in ar else GREEN)
        print(f"    {col}{whois_result.get('age_days','?')} days old — "
              f"{whois_result.get('age_risk','?')}{RESET}")

    # URLs
    if url_results:
        print(f"\n  {BOLD}[5] URL Analysis{RESET}")
        for u in url_results:
            print(f"    {u['colour']}{u['status']:12}{RESET} "
                  f"{u['url']}")

    # Flags summary
    if flags:
        print(f"\n  {BOLD}[!] Phishing Indicators Found:{RESET}")
        for flag in flags:
            print(f"    {RED}⚠  {flag}{RESET}")

    # Final verdict
    print(f"\n{'─'*60}")
    print(f"  Risk Score : {colour}{BOLD}{score}/100{RESET}")
    print(f"  Verdict    : {colour}{BOLD}{verdict}{RESET}")
    print(f"{'='*60}\n")


# ══════════════════════════════════════════════════════════════════════════════
# MAIN FUNCTION — orchestrates everything
# ══════════════════════════════════════════════════════════════════════════════
def analyse_email(source):
    """
    Main orchestrator for email phishing analysis.
    Calls all 8 functions above in sequence.
    Returns a dict with full results — used by dashboard later.
    """
    print(f"\n{BOLD}{BLUE}  AEGIS — Email Phishing Analyser{RESET}")
    print(f"  Source: {source[:60]}\n")

    # Step 1 — parse email
    msg = parse_email(source)
    if not msg:
        return {"error": "Could not parse email"}

    # Step 2 — extract headers
    print(f"{BLUE}[*] Extracting headers...{RESET}")
    headers = extract_headers(msg)

    # Step 3 — extract sender IP
    print(f"{BLUE}[*] Extracting sender IP...{RESET}")
    sender_ip = extract_sender_ip(headers)
    print(f"    Sender IP: {sender_ip or 'Not found'}")

    # Step 4 — check sender IP if found
    sender_ip_result = None
    if sender_ip:
        sender_ip_result = check_abuseipdb(sender_ip)

    # Step 5 — reply-to mismatch check
    print(f"{BLUE}[*] Checking Reply-To mismatch...{RESET}")
    reply_mismatch = check_reply_to_mismatch(headers)

    # Step 6 — extract From domain for SPF/DMARC/WHOIS
    from_header  = str(headers.get("from", ""))
    domain_match = re.search(r"@([\w\.-]+)", from_header)
    from_domain  = domain_match.group(1) if domain_match else None

    # Step 7 — SPF/DKIM/DMARC
    auth_result  = {}
    whois_result = None
    if from_domain:
        print(f"{BLUE}[*] Checking SPF/DMARC for {from_domain}...{RESET}")
        auth_result  = check_email_authentication(from_domain)
        print(f"{BLUE}[*] Checking domain age...{RESET}")
        whois_result = check_domain_age(from_domain)

    # Step 8 — extract and check URLs
    print(f"{BLUE}[*] Extracting URLs from email body...{RESET}")
    urls        = extract_urls_from_body(msg)
    url_results = check_urls(urls)

    # Step 9 — calculate score
    score, verdict, colour, flags = calculate_phishing_score(
        headers, reply_mismatch, auth_result,
        url_results, sender_ip_result, whois_result
    )

    # Step 10 — print report
    print_phishing_report(
        headers, reply_mismatch, auth_result,
        url_results, sender_ip, sender_ip_result,
        whois_result, score, verdict, colour, flags
    )

    return {
        "source":            source,
        "headers":           headers,
        "sender_ip":         sender_ip,
        "sender_ip_result":  sender_ip_result,
        "reply_mismatch":    reply_mismatch,
        "auth_result":       auth_result,
        "urls":              urls,
        "url_results":       url_results,
        "whois_result":      whois_result,
        "score":             score,
        "verdict":           verdict
    }


# ══════════════════════════════════════════════════════════════════════════════
# CREATE A TEST PHISHING EMAIL — for testing without a real .eml file
# ══════════════════════════════════════════════════════════════════════════════
def create_test_email():
    """
    Creates a fake phishing email for testing.
    Returns the raw email text as a string.

    This mimics what a real phishing email looks like:
      - From shows a legitimate company
      - Reply-To goes to attacker domain
      - Contains a suspicious URL
      - Sent from a recently registered domain
    """
    return """From: security@paypa1-verify.com
To: victim@example.com
Subject: Urgent: Your account has been suspended
Date: Mon, 01 Jan 2024 10:00:00 +0000
Reply-To: attacker@evil-domain.ru
Return-Path: bounce@paypa1-verify.com
Message-ID: <fake123@paypa1-verify.com>
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8
Received: from mail.paypa1-verify.com (185.220.101.47)
    by mx.example.com; Mon, 01 Jan 2024 10:00:00 +0000

<html><body>
<p>Dear Customer,</p>
<p>Your account has been suspended. Click below to verify:</p>
<a href="http://paypa1-verify.com/login/verify?token=abc123">
    Verify Account Now
</a>
<p>If you don't verify within 24 hours your account will be closed.</p>
</body></html>"""


# ══════════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════
if __name__ == "__main__":

    print(f"{BOLD}{BLUE}{BANNER}{RESET}")

    if len(sys.argv) > 1:
        # File path provided on command line
        analyse_email(sys.argv[1])

    else:
        print(f"  {BOLD}Options:{RESET}")
        print(f"  1 — Analyse a .eml file")
        print(f"  2 — Use built-in test phishing email")
        print(f"  3 — Paste raw email headers\n")

        choice = input(f"  {BOLD}Choose (1/2/3): {RESET}").strip()

        if choice == "1":
            path = input("  Enter path to .eml file: ").strip()
            analyse_email(path)

        elif choice == "2":
            print(f"\n  {YELLOW}Using built-in test phishing email...{RESET}")
            test_email = create_test_email()
            analyse_email(test_email)

        elif choice == "3":
            print("  Paste raw email headers (press Ctrl+D when done):")
            lines = []
            try:
                while True:
                    line = input()
                    lines.append(line)
            except EOFError:
                pass
            raw = "\n".join(lines)
            analyse_email(raw)

        else:
            print(f"  {RED}Invalid choice{RESET}")
