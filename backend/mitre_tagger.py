"""
AEGIS — MITRE ATT&CK Tagger + Kill Chain Mapper
=================================================
What this file does:
  Automatically tags every alert with:
    1. MITRE ATT&CK technique ID   (e.g. T1110.001)
    2. MITRE ATT&CK technique name (e.g. Brute Force: Password Guessing)
    3. MITRE ATT&CK tactic         (e.g. Credential Access)
    4. Kill chain stage            (e.g. Exploitation)
    5. Tactic description          (what this means in plain English)

SOC concept:
  MITRE ATT&CK is the industry standard framework for
  categorising attacker behaviour. Every attack technique
  has a unique ID. When you tag an alert with T1110 you
  are saying "this alert matches a known brute force pattern."
  This helps analysts understand what the attacker is trying
  to do — not just what happened technically.

  Kill chain maps the alert to the attack lifecycle stage:
  Reconnaissance → Weaponisation → Delivery →
  Exploitation → Installation → C2 → Actions on Objectives

New Python concepts in this file:
  dict of dicts        — nested dictionary as a lookup table
  tuple                — immutable ordered collection
  .items()             — iterates key-value pairs of a dict
  str.upper()          — converts to uppercase for comparison
  str.lower()          — converts to lowercase for comparison
  in operator          — checks membership in list/dict/string
  any() + list comp    — checks if any item matches a condition
"""

from typing import Optional
from dataclasses import dataclass, field


# ══════════════════════════════════════════════════════════════════════════════
# DATACLASS — holds the complete MITRE tag for one alert
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class MitreTag:
    """
    Holds the complete MITRE ATT&CK tagging for one alert.
    All fields start empty — filled in by tag_alert().
    """
    technique_id:   str = "Unknown"
    technique_name: str = "Unknown"
    tactic:         str = "Unknown"
    tactic_id:      str = "Unknown"
    kill_chain:     str = "Unknown"
    description:    str = ""
    severity:       str = "medium"
    # severity: "critical", "high", "medium", "low"

    def to_dict(self) -> dict:
        return {
            "technique_id":   self.technique_id,
            "technique_name": self.technique_name,
            "tactic":         self.tactic,
            "tactic_id":      self.tactic_id,
            "kill_chain":     self.kill_chain,
            "description":    self.description,
            "severity":       self.severity,
        }


# ══════════════════════════════════════════════════════════════════════════════
# MITRE ATT&CK KNOWLEDGE BASE
# This is a dict of dicts — the outer key is the technique ID,
# the inner dict contains all information about that technique.
# ══════════════════════════════════════════════════════════════════════════════

MITRE_TECHNIQUES = {

    # ── Initial Access ────────────────────────────────────────────────────────
    "T1566": {
        "name":       "Phishing",
        "tactic":     "Initial Access",
        "tactic_id":  "TA0001",
        "kill_chain": "Delivery",
        "severity":   "high",
        "description": "Attacker sends malicious emails to gain "
                       "access to victim systems.",
        "keywords":   ["phish", "email", "malicious attachment",
                       "spearphish", "reply-to mismatch",
                       "spf fail", "dmarc fail"],
    },
    "T1566.001": {
        "name":       "Phishing: Spearphishing Attachment",
        "tactic":     "Initial Access",
        "tactic_id":  "TA0001",
        "kill_chain": "Delivery",
        "severity":   "high",
        "description": "Targeted phishing email with malicious "
                       "attachment to specific individual.",
        "keywords":   ["spearphish", "attachment", "malicious file",
                       "macro", ".doc", ".xls", ".pdf attachment"],
    },
    "T1566.002": {
        "name":       "Phishing: Spearphishing Link",
        "tactic":     "Initial Access",
        "tactic_id":  "TA0001",
        "kill_chain": "Delivery",
        "severity":   "high",
        "description": "Targeted phishing email with malicious "
                       "link to credential harvesting page.",
        "keywords":   ["phishing link", "malicious url",
                       "credential harvest", "fake login"],
    },
    "T1190": {
        "name":       "Exploit Public-Facing Application",
        "tactic":     "Initial Access",
        "tactic_id":  "TA0001",
        "kill_chain": "Exploitation",
        "severity":   "critical",
        "description": "Exploitation of a weakness in a public-facing "
                       "application such as a web server or database.",
        "keywords":   ["sql injection", "sqlmap", "sqli",
                       "web exploit", "rce", "remote code execution",
                       "dvwa", "webshell"],
    },

    # ── Execution ─────────────────────────────────────────────────────────────
    "T1059": {
        "name":       "Command and Scripting Interpreter",
        "tactic":     "Execution",
        "tactic_id":  "TA0002",
        "kill_chain": "Exploitation",
        "severity":   "high",
        "description": "Attacker uses command-line interface or "
                       "scripting to execute commands.",
        "keywords":   ["command execution", "shell", "bash",
                       "cmd", "terminal", "script execution"],
    },
    "T1059.004": {
        "name":       "Command and Scripting Interpreter: Unix Shell",
        "tactic":     "Execution",
        "tactic_id":  "TA0002",
        "kill_chain": "Exploitation",
        "severity":   "high",
        "description": "Attacker uses Unix shell (bash/sh) to "
                       "execute commands on compromised system.",
        "keywords":   ["bash", "sh", "unix shell", "reverse shell",
                       "netcat", "nc -e", "/bin/bash"],
    },

    # ── Persistence ───────────────────────────────────────────────────────────
    "T1053": {
        "name":       "Scheduled Task/Job",
        "tactic":     "Persistence",
        "tactic_id":  "TA0003",
        "kill_chain": "Installation",
        "severity":   "medium",
        "description": "Attacker creates scheduled task or cron job "
                       "to maintain persistent access.",
        "keywords":   ["cron", "crontab", "scheduled task",
                       "persistence", "at command"],
    },
    "T1078": {
        "name":       "Valid Accounts",
        "tactic":     "Defense Evasion",
        "tactic_id":  "TA0005",
        "kill_chain": "Exploitation",
        "severity":   "high",
        "description": "Attacker uses legitimate credentials to "
                       "access systems and avoid detection.",
        "keywords":   ["valid account", "legitimate credentials",
                       "account misuse", "crackmapexec",
                       "successful login after brute force"],
    },

    # ── Privilege Escalation ──────────────────────────────────────────────────
    "T1055": {
        "name":       "Process Injection",
        "tactic":     "Privilege Escalation",
        "tactic_id":  "TA0004",
        "kill_chain": "Exploitation",
        "severity":   "critical",
        "description": "Attacker injects malicious code into running "
                       "processes to escalate privileges.",
        "keywords":   ["process injection", "dll injection",
                       "shellcode", "code injection"],
    },

    # ── Credential Access ─────────────────────────────────────────────────────
    "T1110": {
        "name":       "Brute Force",
        "tactic":     "Credential Access",
        "tactic_id":  "TA0006",
        "kill_chain": "Exploitation",
        "severity":   "high",
        "description": "Attacker attempts to gain access by trying "
                       "many passwords against an account.",
        "keywords":   ["brute force", "hydra", "failed login",
                       "multiple failed", "password attack",
                       "authentication failure", "login attempt"],
    },
    "T1110.001": {
        "name":       "Brute Force: Password Guessing",
        "tactic":     "Credential Access",
        "tactic_id":  "TA0006",
        "kill_chain": "Exploitation",
        "severity":   "high",
        "description": "Systematic guessing of passwords against "
                       "login services like SSH, RDP, web forms.",
        "keywords":   ["ssh brute", "rdp brute", "ftp brute",
                       "hydra ssh", "hydra ftp", "password guess",
                       "multiple authentication failures"],
    },
    "T1110.003": {
        "name":       "Brute Force: Password Spraying",
        "tactic":     "Credential Access",
        "tactic_id":  "TA0006",
        "kill_chain": "Exploitation",
        "severity":   "high",
        "description": "Using one or few passwords against many "
                       "accounts to avoid lockout policies.",
        "keywords":   ["password spray", "spraying",
                       "multiple accounts same password"],
    },
    "T1003": {
        "name":       "OS Credential Dumping",
        "tactic":     "Credential Access",
        "tactic_id":  "TA0006",
        "kill_chain": "Exploitation",
        "severity":   "critical",
        "description": "Attacker attempts to dump credentials from "
                       "operating system memory or files.",
        "keywords":   ["credential dump", "hash dump", "lsass",
                       "john the ripper", "hashcat", "mimikatz",
                       "shadow file", "passwd file"],
    },

    # ── Discovery ─────────────────────────────────────────────────────────────
    "T1595": {
        "name":       "Active Scanning",
        "tactic":     "Reconnaissance",
        "tactic_id":  "TA0043",
        "kill_chain": "Reconnaissance",
        "severity":   "medium",
        "description": "Attacker scans victim infrastructure to "
                       "gather information before attacking.",
        "keywords":   ["nmap", "port scan", "network scan",
                       "host discovery", "service scan",
                       "vulnerability scan"],
    },
    "T1592": {
        "name":       "Gather Victim Host Information",
        "tactic":     "Reconnaissance",
        "tactic_id":  "TA0043",
        "kill_chain": "Reconnaissance",
        "severity":   "low",
        "description": "Attacker gathers information about victim "
                       "hosts including OS and software versions.",
        "keywords":   ["os fingerprint", "banner grab",
                       "version detection", "nmap -O",
                       "service version"],
    },
    "T1046": {
        "name":       "Network Service Discovery",
        "tactic":     "Discovery",
        "tactic_id":  "TA0007",
        "kill_chain": "Reconnaissance",
        "severity":   "medium",
        "description": "Attacker discovers services running on "
                       "remote hosts in the network.",
        "keywords":   ["service discovery", "port scan",
                       "network discovery", "nmap -sV",
                       "subnet scan"],
    },
    "T1083": {
        "name":       "File and Directory Discovery",
        "tactic":     "Discovery",
        "tactic_id":  "TA0007",
        "kill_chain": "Reconnaissance",
        "severity":   "low",
        "description": "Attacker enumerates files and directories "
                       "on a target system or web server.",
        "keywords":   ["gobuster", "dirb", "dirbuster",
                       "directory enum", "file enum",
                       "web directory", "path traversal"],
    },
    "T1201": {
        "name":       "Password Policy Discovery",
        "tactic":     "Discovery",
        "tactic_id":  "TA0007",
        "kill_chain": "Reconnaissance",
        "severity":   "low",
        "description": "Attacker discovers the password policy of "
                       "a target to craft better attacks.",
        "keywords":   ["password policy", "enum4linux",
                       "smb enum", "account policy"],
    },
    "T1518": {
        "name":       "Software Discovery",
        "tactic":     "Discovery",
        "tactic_id":  "TA0007",
        "kill_chain": "Reconnaissance",
        "severity":   "low",
        "description": "Attacker enumerates software installed on "
                       "the system to identify targets.",
        "keywords":   ["software discovery", "banner",
                       "version info", "installed software"],
    },

    # ── Lateral Movement ──────────────────────────────────────────────────────
    "T1021": {
        "name":       "Remote Services",
        "tactic":     "Lateral Movement",
        "tactic_id":  "TA0008",
        "kill_chain": "Actions on Objectives",
        "severity":   "high",
        "description": "Attacker uses remote services like SSH or "
                       "RDP to move laterally through the network.",
        "keywords":   ["lateral movement", "remote service",
                       "ssh lateral", "rdp lateral",
                       "multiple hosts", "internal ssh"],
    },
    "T1021.004": {
        "name":       "Remote Services: SSH",
        "tactic":     "Lateral Movement",
        "tactic_id":  "TA0008",
        "kill_chain": "Actions on Objectives",
        "severity":   "high",
        "description": "Using SSH to log into remote machines "
                       "for lateral movement.",
        "keywords":   ["ssh", "secure shell", "ssh login",
                       "ssh connection", "internal ssh"],
    },

    # ── Collection ────────────────────────────────────────────────────────────
    "T1040": {
        "name":       "Network Sniffing",
        "tactic":     "Collection",
        "tactic_id":  "TA0009",
        "kill_chain": "Actions on Objectives",
        "severity":   "medium",
        "description": "Attacker captures network traffic to "
                       "collect sensitive information.",
        "keywords":   ["sniff", "tcpdump", "wireshark",
                       "packet capture", "arp poison",
                       "ettercap", "man in the middle", "mitm"],
    },

    # ── Exfiltration ──────────────────────────────────────────────────────────
    "T1041": {
        "name":       "Exfiltration Over C2 Channel",
        "tactic":     "Exfiltration",
        "tactic_id":  "TA0010",
        "kill_chain": "Actions on Objectives",
        "severity":   "critical",
        "description": "Attacker steals data by sending it out "
                       "through the command and control channel.",
        "keywords":   ["exfil", "data transfer", "data theft",
                       "large outbound", "netcat transfer",
                       "unusual upload", "c2 channel"],
    },

    # ── Impact ────────────────────────────────────────────────────────────────
    "T1499": {
        "name":       "Endpoint Denial of Service",
        "tactic":     "Impact",
        "tactic_id":  "TA0040",
        "kill_chain": "Actions on Objectives",
        "severity":   "high",
        "description": "Attacker disrupts availability of a host "
                       "through flooding or resource exhaustion.",
        "keywords":   ["dos", "denial of service", "flood",
                       "hping", "syn flood", "ddos",
                       "service unavailable"],
    },

    # ── Credential Access via network ─────────────────────────────────────────
    "T1557": {
        "name":       "Adversary-in-the-Middle",
        "tactic":     "Credential Access",
        "tactic_id":  "TA0006",
        "kill_chain": "Exploitation",
        "severity":   "high",
        "description": "Attacker positions themselves between two "
                       "devices to intercept and modify traffic.",
        "keywords":   ["arp spoof", "arp poison", "mitm",
                       "man in the middle", "ettercap",
                       "ssl strip", "traffic intercept"],
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# KILL CHAIN STAGES — Lockheed Martin Cyber Kill Chain
# ══════════════════════════════════════════════════════════════════════════════

KILL_CHAIN_STAGES = [
    "Reconnaissance",
    "Weaponisation",
    "Delivery",
    "Exploitation",
    "Installation",
    "Command & Control",
    "Actions on Objectives",
]

# Maps MITRE tactic names to kill chain stages
TACTIC_TO_KILL_CHAIN = {
    "Reconnaissance":      "Reconnaissance",
    "Resource Development": "Weaponisation",
    "Initial Access":      "Delivery",
    "Execution":           "Exploitation",
    "Persistence":         "Installation",
    "Privilege Escalation": "Exploitation",
    "Defense Evasion":     "Exploitation",
    "Credential Access":   "Exploitation",
    "Discovery":           "Reconnaissance",
    "Lateral Movement":    "Actions on Objectives",
    "Collection":          "Actions on Objectives",
    "Command and Control": "Command & Control",
    "Exfiltration":        "Actions on Objectives",
    "Impact":              "Actions on Objectives",
}


# ══════════════════════════════════════════════════════════════════════════════
# MAIN TAGGING FUNCTIONS
# ══════════════════════════════════════════════════════════════════════════════

def tag_by_id(technique_id: str) -> MitreTag:
    """
    Returns a MitreTag for a known technique ID.
    Used when we already know the MITRE ID
    (e.g. from Wazuh rule mapping).

    NEW CONCEPT — dict.get() with fallback dict:
      If technique_id not in MITRE_TECHNIQUES,
      returns a default "Unknown" MitreTag.
    """
    technique_id = technique_id.upper().strip()

    if technique_id in MITRE_TECHNIQUES:
        t = MITRE_TECHNIQUES[technique_id]
        return MitreTag(
            technique_id   = technique_id,
            technique_name = t["name"],
            tactic         = t["tactic"],
            tactic_id      = t["tactic_id"],
            kill_chain     = t.get("kill_chain", "Unknown"),
            description    = t.get("description", ""),
            severity       = t.get("severity", "medium"),
        )

    # Try base technique if sub-technique not found
    # e.g. T1110.999 → try T1110
    base_id = technique_id.split(".")[0]
    if base_id in MITRE_TECHNIQUES:
        return tag_by_id(base_id)

    return MitreTag(
        technique_id   = technique_id,
        technique_name = "Unknown Technique",
        tactic         = "Unknown",
        tactic_id      = "Unknown",
        kill_chain     = "Unknown",
    )


def tag_by_alert_type(alert_type: str) -> MitreTag:
    """
    Maps common alert type strings to MITRE techniques.
    Used when we know what kind of alert it is
    but not the specific MITRE ID.

    NEW CONCEPT — dict as lookup table:
      Instead of a long if/elif chain, we use a dict.
      alert_type → technique_id
      Then call tag_by_id() to get full details.
      Much cleaner and easier to extend.
    """
    # Normalise to lowercase for comparison
    alert_lower = alert_type.lower().strip()

    # Direct mapping — alert type to technique ID
    TYPE_MAP = {
        # Brute force variants
        "brute_force":          "T1110",
        "brute force":          "T1110",
        "ssh_brute_force":      "T1110.001",
        "ssh brute force":      "T1110.001",
        "ftp_brute_force":      "T1110.001",
        "rdp_brute_force":      "T1110.001",
        "password_spray":       "T1110.003",
        "http_brute_force":     "T1110.003",

        # Scanning / recon
        "port_scan":            "T1595",
        "port scan":            "T1595",
        "network_scan":         "T1046",
        "network scan":         "T1046",
        "service_discovery":    "T1046",
        "dir_scan":             "T1083",
        "directory_scan":       "T1083",
        "web_scan":             "T1083",
        "os_fingerprint":       "T1592",

        # Exploitation
        "sql_injection":        "T1190",
        "sqli":                 "T1190",
        "web_exploit":          "T1190",
        "rce":                  "T1059",
        "command_execution":    "T1059",
        "reverse_shell":        "T1059.004",

        # Phishing
        "phishing":             "T1566",
        "spearphishing":        "T1566.001",
        "phishing_link":        "T1566.002",
        "malicious_email":      "T1566",

        # Credential access
        "credential_dump":      "T1003",
        "hash_crack":           "T1003",
        "password_dump":        "T1003",
        "valid_accounts":       "T1078",

        # Lateral movement
        "lateral_movement":     "T1021",
        "ssh_lateral":          "T1021.004",

        # Exfiltration
        "data_exfil":           "T1041",
        "exfiltration":         "T1041",
        "large_transfer":       "T1041",
        "c2":                   "T1041",

        # Network attacks
        "mitm":                 "T1557",
        "arp_spoof":            "T1557",
        "sniffing":             "T1040",
        "packet_capture":       "T1040",

        # DoS
        "dos":                  "T1499",
        "flood":                "T1499",
        "syn_flood":            "T1499",

        # Persistence
        "cron_job":             "T1053",
        "scheduled_task":       "T1053",

        # Malware / general
        "malware":              "T1059",
        "malicious_file":       "T1059",
        "process_injection":    "T1055",
    }

    # Check exact match first
    if alert_lower in TYPE_MAP:
        return tag_by_id(TYPE_MAP[alert_lower])

    # Check if alert_type contains any key as substring
    # NEW CONCEPT — any() with generator expression:
    # any(condition for item in iterable)
    # Returns True as soon as one condition is True
    # More efficient than building a full list first
    for key, technique_id in TYPE_MAP.items():
        # NEW CONCEPT — .items():
        # Iterates over dict as (key, value) pairs
        # key = alert type string
        # technique_id = MITRE ID string
        if key in alert_lower or alert_lower in key:
            return tag_by_id(technique_id)

    return tag_by_keyword(alert_type)


def tag_by_keyword(text: str) -> MitreTag:
    """
    Last resort — searches the text for keywords
    that match any technique's keyword list.
    Returns the best matching technique.

    NEW CONCEPT — scoring with dict:
      We score each technique by how many of its
      keywords appear in the text.
      The technique with the highest score wins.
      This is a simple relevance scoring algorithm.
    """
    text_lower = text.lower()
    scores     = {}
    # scores = {technique_id: match_count}

    for tech_id, tech_data in MITRE_TECHNIQUES.items():
        keywords = tech_data.get("keywords", [])
        count    = sum(1 for kw in keywords if kw in text_lower)
        # sum(1 for ...) counts how many keywords match
        # Generator expression — no list created in memory
        if count > 0:
            scores[tech_id] = count

    if not scores:
        # Nothing matched — return unknown
        return MitreTag()

    # Get technique with highest keyword match count
    # NEW CONCEPT — max() with key parameter:
    # max(iterable, key=function)
    # key= defines what to compare — here we compare scores[id]
    # Returns the technique_id with the maximum score value
    best_id = max(scores, key=lambda x: scores[x])
    return tag_by_id(best_id)


def tag_alert(alert_type: str,
              mitre_id: Optional[str] = None,
              description: Optional[str] = None) -> MitreTag:
    """
    Main entry point — tags an alert using best available info.

    Priority order:
      1. If mitre_id given directly — use it (most accurate)
      2. Try to match alert_type to known type
      3. Search description text for keywords

    Parameters:
      alert_type  — e.g. "brute_force", "port_scan", "phishing"
      mitre_id    — if already known (e.g. from Wazuh rule)
      description — full text to keyword-search if needed
    """
    # Priority 1: direct MITRE ID provided
    if mitre_id and mitre_id.upper().startswith("T"):
        tag = tag_by_id(mitre_id)
        if tag.technique_id != "Unknown":
            return tag

    # Priority 2: match by alert type string
    if alert_type:
        tag = tag_by_alert_type(alert_type)
        if tag.technique_id != "Unknown":
            return tag

    # Priority 3: keyword search in description
    if description:
        tag = tag_by_keyword(description)
        if tag.technique_id != "Unknown":
            return tag

    # Nothing matched
    return MitreTag(
        technique_id   = "T0000",
        technique_name = "Unclassified",
        tactic         = "Unknown",
        kill_chain     = "Unknown",
    )


# ══════════════════════════════════════════════════════════════════════════════
# HELPER — get kill chain stage from tactic name
# ══════════════════════════════════════════════════════════════════════════════

def get_kill_chain_stage(tactic: str) -> str:
    """
    Returns kill chain stage for a given MITRE tactic.
    Falls back to "Unknown" if not in mapping.
    """
    return TACTIC_TO_KILL_CHAIN.get(tactic, "Unknown")


def get_severity_colour(severity: str) -> str:
    """
    Returns terminal colour code for severity level.
    Used when printing MITRE tags in terminal.
    """
    colours = {
        "critical": "\033[91m",   # Red
        "high":     "\033[93m",   # Yellow
        "medium":   "\033[94m",   # Blue
        "low":      "\033[92m",   # Green
    }
    return colours.get(severity.lower(), "\033[0m")


def get_all_techniques() -> list:
    """
    Returns list of all technique IDs in our knowledge base.
    Used by dashboard ATT&CK heatmap.
    """
    return list(MITRE_TECHNIQUES.keys())


# ══════════════════════════════════════════════════════════════════════════════
# TEST — run directly to verify tagging works
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":

    RESET = "\033[0m"
    BOLD  = "\033[1m"
    BLUE  = "\033[94m"

    print(f"\n{BOLD}Testing AEGIS MITRE Tagger...{RESET}\n")

    test_cases = [
        # (alert_type, mitre_id, description)
        ("ssh_brute_force",  None,       None),
        ("port_scan",        None,       None),
        ("phishing",         None,       None),
        ("sql_injection",    None,       None),
        ("data_exfil",       None,       None),
        ("unknown_alert",    "T1003",    None),
        ("weird_alert",      None,
         "hydra detected making multiple login attempts"),
        ("brute_force",      None,       None),
        ("lateral_movement", None,       None),
        ("reverse_shell",    None,       None),
    ]

    for alert_type, mitre_id, desc in test_cases:
        tag = tag_alert(alert_type, mitre_id, desc)
        col = get_severity_colour(tag.severity)

        print(f"  Alert type : {BOLD}{alert_type}{RESET}")
        print(f"  MITRE ID   : {BLUE}{tag.technique_id}{RESET}")
        print(f"  Technique  : {tag.technique_name}")
        print(f"  Tactic     : {tag.tactic}")
        print(f"  Kill Chain : {tag.kill_chain}")
        print(f"  Severity   : {col}{tag.severity.upper()}{RESET}")
        print(f"  {'─'*45}")

    print(f"\n{BOLD}[✓] mitre_tagger.py working correctly{RESET}\n")
