"""
AEGIS — Gemini AI Investigation Report Generator
=================================================
What this file does:
  When an analyst clicks "Generate Investigation Summary"
  on any alert, this module sends all enrichment data
  to Google Gemini API and receives a structured
  investigation summary using the 6W framework:

    WHO   — who is the attacker (IP, ISP, country, reputation)
    WHAT  — what attack technique was used (MITRE mapping)
    WHERE — where did it come from, where was it going
    WHEN  — when did it happen, time context
    WHY   — why is this suspicious (evidence summary)
    HOW   — how should the analyst respond (recommended action)

SOC concept:
  Every real incident report follows this structure.
  L1 analysts currently write this manually — takes 20-30 mins.
  AEGIS generates it in 3 seconds using Gemini AI.
  Analyst reviews and approves — human in the loop.

New Python concepts in this file:
  google.generativeai    — Gemini API library
  genai.configure()      — sets up API key
  model.generate_content() — sends prompt, gets response
  response.text          — the AI's response as string
  textwrap.dedent()      — removes indentation from multiline strings
  str.format_map()       — formats string with a dictionary
"""

import os
import sys
import json
import textwrap
from datetime import datetime
from typing import Optional

# Google Gemini AI library
# Install: pip install google-generativeai --break-system-packages
import google.generativeai as genai

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
from config import GEMINI_API_KEY

# ── COLOURS ───────────────────────────────────────────────────────
GREEN  = "\033[92m"
BLUE   = "\033[94m"
YELLOW = "\033[93m"
RED    = "\033[91m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

# ── CONFIGURE GEMINI ──────────────────────────────────────────────
"""
NEW CONCEPT — genai.configure():
  Sets up the Gemini API with your API key.
  Must be called once before making any requests.
  Similar to how we pass headers with API keys in requests.get()
  but here the library handles it globally.
"""
genai.configure(api_key=GEMINI_API_KEY)

# Use Gemini 1.5 Flash — fast, free tier, good quality
MODEL_NAME = "gemini-1.5-flash"


# ══════════════════════════════════════════════════════════════════
# PROMPT TEMPLATE — the 6W investigation framework
# ══════════════════════════════════════════════════════════════════

"""
NEW CONCEPT — textwrap.dedent():
  When you write a multiline string inside a function,
  Python includes all the leading whitespace/indentation.
  textwrap.dedent() removes the common leading whitespace
  so the string starts clean from the left margin.
  This makes the prompt cleaner when sent to Gemini.
"""

INVESTIGATION_PROMPT = textwrap.dedent("""
You are a senior SOC analyst writing an investigation report.
Analyse the following security alert and produce a structured
investigation summary using the 6W framework.

=== ALERT DATA ===
Alert Type      : {alert_type}
Indicator       : {indicator}
Indicator Type  : {indicator_type}
Risk Score      : {risk_score}/100
Verdict         : {verdict}
Time            : {timestamp}

=== THREAT INTELLIGENCE ===
VirusTotal      : {vt_malicious}/{vt_total} engines flagged malicious
AbuseIPDB Score : {abuse_score}/100
Country         : {country}
ISP             : {isp}
Total Reports   : {total_reports}

=== MITRE ATT&CK ===
Technique ID    : {mitre_id}
Technique Name  : {mitre_name}
Tactic          : {mitre_tactic}
Kill Chain Stage: {kill_chain}

=== CVE INFORMATION ===
Top CVE         : {cve_id}
CVSS Score      : {cvss_score}

=== INSTRUCTIONS ===
Write a concise investigation summary with exactly these
6 sections. Each section: one clear sentence.
Be specific — use the actual data provided above.
Write like a professional analyst, not a student.
Do not add any extra sections or preamble.

WHO:
(One sentence about the attacker — IP, country, ISP,
 reputation score, known threat actor if applicable)

WHAT:
(One sentence about the attack technique —
 MITRE technique name and what it does)

WHERE:
(One sentence about source and destination —
 where attack came from, what was targeted)

WHEN:
(One sentence about timing —
 when it happened, any time-based observations)

WHY:
(One sentence summarising the evidence —
 why this is confirmed suspicious/malicious)

HOW:
(One sentence recommended action —
 exactly what the analyst should do next)
""").strip()


# ══════════════════════════════════════════════════════════════════
# MAIN REPORT GENERATION FUNCTION
# ══════════════════════════════════════════════════════════════════

def generate_investigation_report(alert_data: dict) -> dict:
    """
    Generates a full 6W investigation summary using Gemini AI.

    Parameters:
      alert_data — dict containing all alert enrichment data
                   (from database Alert.to_dict() or raw pipeline)

    Returns:
      dict with:
        report      — full 6W formatted text
        who         — individual WHO section
        what        — individual WHAT section
        where       — individual WHERE section
        when        — individual WHEN section
        why         — individual WHY section
        how         — individual HOW section
        generated_at — timestamp
        model       — which Gemini model was used
        error       — None if success, error message if failed
    """

    print(f"\n{BLUE}[*] Generating Gemini investigation report...{RESET}")

    # ── Extract data from alert ───────────────────────────────────
    # Use .get() with defaults so missing fields don't crash
    raw_data = {}
    if alert_data.get("raw_data"):
        try:
            raw_data = json.loads(alert_data["raw_data"])
        except (json.JSONDecodeError, TypeError):
            raw_data = {}

    ioc_data   = raw_data.get("ioc", {})
    abuse      = ioc_data.get("abuse_result") or {}
    vt         = ioc_data.get("vt_result") or {}
    cve_data   = raw_data.get("cve", {})

    # Build the prompt variables
    prompt_vars = {
        "alert_type":    alert_data.get("alert_type", "Unknown"),
        "indicator":     alert_data.get("indicator", "Unknown"),
        "indicator_type":alert_data.get("indicator_type", "ip"),
        "risk_score":    alert_data.get("risk_score", 0),
        "verdict":       alert_data.get("verdict", "Unknown"),
        "timestamp":     _format_timestamp(
                           alert_data.get("created_at")),
        "vt_malicious":  alert_data.get("vt_malicious", 0),
        "vt_total":      alert_data.get("vt_total", 0),
        "abuse_score":   alert_data.get("abuse_score", 0),
        "country":       abuse.get("country", "Unknown"),
        "isp":           abuse.get("isp", "Unknown"),
        "total_reports": abuse.get("total_reports", 0),
        "mitre_id":      alert_data.get(
                           "mitre_technique_id", "Unknown"),
        "mitre_name":    alert_data.get(
                           "mitre_technique_name", "Unknown"),
        "mitre_tactic":  alert_data.get("mitre_tactic", "Unknown"),
        "kill_chain":    alert_data.get(
                           "kill_chain_stage", "Unknown"),
        "cve_id":        alert_data.get("cve_id") or "None found",
        "cvss_score":    alert_data.get("cvss_score") or "N/A",
    }

    # ── Build the prompt ──────────────────────────────────────────
    """
    NEW CONCEPT — str.format_map(dict):
      Like str.format(**dict) but uses a mapping object.
      Replaces {key} placeholders with dict values.
      More flexible than .format() for large dicts.
      If a key is missing, raises KeyError — so we ensure
      all keys exist in prompt_vars above.
    """
    try:
        prompt = INVESTIGATION_PROMPT.format_map(prompt_vars)
    except KeyError as e:
        return _error_result(f"Prompt building failed: {e}")

    # ── Call Gemini API ───────────────────────────────────────────
    try:
        """
        NEW CONCEPT — genai.GenerativeModel():
          Creates a model instance with specific settings.
          generation_config controls the AI's behaviour:
            temperature  — creativity (0=precise, 1=creative)
                           We use 0.3 for consistent reports
            max_output_tokens — maximum words in response
        """
        model = genai.GenerativeModel(
            model_name = MODEL_NAME,
            generation_config = genai.GenerationConfig(
                temperature        = 0.3,
                # Low temperature = more factual, consistent output
                max_output_tokens  = 500,
                # Enough for 6 sentences
            )
        )

        print(f"  Sending to Gemini {MODEL_NAME}...")

        """
        NEW CONCEPT — model.generate_content():
          Sends the prompt to Gemini and waits for response.
          This is a synchronous call — it blocks until
          Gemini replies (usually 2-5 seconds).
          response.text contains the AI's reply as a string.
        """
        response = model.generate_content(prompt)
        raw_text = response.text.strip()

        print(f"  {GREEN}[✓] Gemini response received{RESET}")

        # ── Parse the 6W sections from response ──────────────────
        sections = _parse_6w_sections(raw_text)

        # Build full formatted report
        full_report = _format_full_report(sections,
                                          alert_data,
                                          prompt_vars)

        return {
            "report":       full_report,
            "who":          sections.get("WHO", ""),
            "what":         sections.get("WHAT", ""),
            "where":        sections.get("WHERE", ""),
            "when":         sections.get("WHEN", ""),
            "why":          sections.get("WHY", ""),
            "how":          sections.get("HOW", ""),
            "raw_response": raw_text,
            "generated_at": datetime.utcnow().isoformat(),
            "model":        MODEL_NAME,
            "error":        None,
        }

    except Exception as e:
        error_msg = str(e)
        print(f"  {YELLOW}[!] Gemini API error: {error_msg}{RESET}")
        return _error_result(error_msg, prompt_vars)


# ══════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ══════════════════════════════════════════════════════════════════

def _parse_6w_sections(text: str) -> dict:
    """
    Parses Gemini's response into individual 6W sections.

    Gemini returns text like:
      WHO:
      Source IP 185.220.101.47...

      WHAT:
      SSH brute force attack...

    We split on the section headers and extract each part.
    """
    sections = {}
    current_key  = None
    current_lines = []

    for line in text.split("\n"):
        line = line.strip()
        if not line:
            continue

        # Check if this line is a section header
        # NEW CONCEPT — str.startswith() with tuple:
        #   Checks if string starts with ANY of the items.
        #   More efficient than multiple or conditions.
        is_header = False
        for key in ["WHO:", "WHAT:", "WHERE:",
                    "WHEN:", "WHY:", "HOW:"]:
            if line.upper().startswith(key):
                # Save previous section
                if current_key and current_lines:
                    sections[current_key] = " ".join(
                        current_lines).strip()

                current_key   = key.rstrip(":")
                # Get any text on the same line as the header
                rest = line[len(key):].strip()
                current_lines = [rest] if rest else []
                is_header     = True
                break

        if not is_header and current_key:
            current_lines.append(line)

    # Save last section
    if current_key and current_lines:
        sections[current_key] = " ".join(current_lines).strip()

    return sections


def _format_full_report(sections: dict,
                        alert_data: dict,
                        vars: dict) -> str:
    """
    Formats the parsed sections into a clean report string.
    This is what gets saved to the database and shown
    in the dashboard.
    """
    score   = alert_data.get("risk_score", 0)
    verdict = alert_data.get("verdict", "UNKNOWN")
    level   = ("🔴 CRITICAL" if score >= 80 else
               "🟠 HIGH"     if score >= 70 else
               "🟡 MEDIUM"   if score >= 40 else
               "🟢 LOW")

    lines = [
        f"AEGIS Investigation Summary",
        f"{'─' * 40}",
        f"Risk Level : {level}",
        f"Verdict    : {verdict} ({score}/100)",
        f"Generated  : {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        f"{'─' * 40}",
        "",
    ]

    for key in ["WHO", "WHAT", "WHERE", "WHEN", "WHY", "HOW"]:
        value = sections.get(key, "Not determined")
        lines.append(f"{key}: {value}")
        lines.append("")

    lines.append(f"{'─' * 40}")
    lines.append(f"Generated by AEGIS v1.0 | Built by Jigar")

    return "\n".join(lines)


def _format_timestamp(ts_str: Optional[str]) -> str:
    """Formats ISO timestamp to readable format."""
    if not ts_str:
        return datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", ""))
        return dt.strftime("%Y-%m-%d %H:%M UTC")
    except Exception:
        return ts_str


def _error_result(error_msg: str,
                  vars: dict = None) -> dict:
    """
    Returns a fallback report when Gemini API fails.
    Uses local data to generate a basic report
    so the analyst still gets something useful.
    """
    fallback = ""
    if vars:
        score   = vars.get("risk_score", 0)
        verdict = vars.get("verdict", "UNKNOWN")
        level   = ("CRITICAL" if score >= 80 else
                   "HIGH"     if score >= 70 else
                   "MEDIUM"   if score >= 40 else
                   "LOW")

        fallback = "\n".join([
            f"AEGIS Investigation Summary (Offline Mode)",
            f"{'─' * 40}",
            f"Risk Level : {level} ({score}/100)",
            f"{'─' * 40}",
            f"",
            f"WHO: Source {vars.get('indicator','unknown')} "
            f"from {vars.get('country','unknown')} "
            f"({vars.get('isp','unknown ISP')}) with "
            f"AbuseIPDB score {vars.get('abuse_score',0)}/100.",
            f"",
            f"WHAT: {vars.get('mitre_name','Unknown technique')} "
            f"({vars.get('mitre_id','unknown')}) detected — "
            f"{vars.get('vt_malicious',0)}/{vars.get('vt_total',0)} "
            f"VirusTotal engines flagged malicious.",
            f"",
            f"WHERE: Attack originated from "
            f"{vars.get('indicator','unknown')} "
            f"targeting this network.",
            f"",
            f"WHEN: Alert triggered at "
            f"{vars.get('timestamp', 'unknown time')}.",
            f"",
            f"WHY: Risk score {score}/100 based on "
            f"VirusTotal detections, AbuseIPDB reputation, "
            f"and MITRE technique severity.",
            f"",
            f"HOW: {'Block IP and escalate to L2 immediately.' if score >= 70 else 'Investigate further before taking action.'}",
            f"",
            f"{'─' * 40}",
            f"Note: Gemini AI unavailable — "
            f"report generated from local data.",
        ])

    return {
        "report":       fallback,
        "who":          "",
        "what":         "",
        "where":        "",
        "when":         "",
        "why":          "",
        "how":          "",
        "raw_response": "",
        "generated_at": datetime.utcnow().isoformat(),
        "model":        "offline",
        "error":        error_msg,
    }


# ══════════════════════════════════════════════════════════════════
# PRINT REPORT TO TERMINAL
# ══════════════════════════════════════════════════════════════════

def print_report(result: dict):
    """Prints the investigation report in the terminal."""
    if result.get("error") and not result.get("report"):
        print(f"\n{YELLOW}[!] Report generation failed: "
              f"{result['error']}{RESET}")
        return

    print(f"\n{BOLD}{GREEN}")
    print(result.get("report", "No report generated"))
    print(f"{RESET}")

    if result.get("error"):
        print(f"{YELLOW}Note: Used offline fallback "
              f"({result['error']}){RESET}")


# ══════════════════════════════════════════════════════════════════
# TEST
# ══════════════════════════════════════════════════════════════════

if __name__ == "__main__":

    print(f"""{BOLD}{BLUE}
  ╔══════════════════════════════════════════╗

      AEGIS — Gemini AI Reporter v1.0
      6W Investigation Summary Generator

  ╚══════════════════════════════════════════╝
{RESET}""")

    # Test with a realistic brute force alert
    test_alert = {
        "id":                   99,
        "alert_type":           "brute_force",
        "indicator":            "185.220.101.47",
        "indicator_type":       "ip",
        "risk_score":           87,
        "verdict":              "MALICIOUS",
        "created_at":           datetime.utcnow().isoformat(),
        "mitre_technique_id":   "T1110.001",
        "mitre_technique_name": "Brute Force: Password Guessing",
        "mitre_tactic":         "Credential Access",
        "kill_chain_stage":     "Exploitation",
        "vt_malicious":         13,
        "vt_total":             91,
        "abuse_score":          100,
        "cve_id":               "CVE-2023-38408",
        "cvss_score":           9.8,
        "raw_data": json.dumps({
            "ioc": {
                "abuse_result": {
                    "abuse_score":   100,
                    "country":       "DE",
                    "isp":           "Network for Tor-Exit traffic",
                    "total_reports": 98,
                }
            }
        })
    }

    print("Generating 6W investigation summary for test alert...")
    print(f"Indicator: {test_alert['indicator']}")
    print(f"Risk score: {test_alert['risk_score']}/100\n")

    result = generate_investigation_report(test_alert)
    print_report(result)

    if not result.get("error"):
        print(f"{GREEN}[✓] llm_reporter.py working correctly{RESET}")
    else:
        print(f"{YELLOW}[!] Gemini failed — "
              f"offline report shown above{RESET}")
        print(f"Error: {result['error']}")
