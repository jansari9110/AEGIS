"""
AEGIS — Branding & Attribution
This file is imported by every AEGIS module.
Your name and credits appear everywhere.
"""

TOOL_NAME    = "AEGIS"
FULL_NAME    = "Automated Exploit & Guard Intelligence System"
VERSION      = "v0.1"
AUTHOR       = "Jigar"
GITHUB       = "github.com/jansari9110/AEGIS"
RIGHTS       = f"© 2026 {AUTHOR} — All rights reserved"
TAGLINE      = "AI-Powered SOC Analyst Toolkit"

# This banner prints in terminal whenever AEGIS starts
BANNER = f"""
  ╔═════════════════════════════════════════════════╗

      {TOOL_NAME} — {FULL_NAME[:35]}
      {TAGLINE:<44}
      {VERSION:<10} Built by {AUTHOR:<33}

  ╚═════════════════════════════════════════════════╝

  {RIGHTS} ║ {GITHUB}
"""

# Short one-line credit for dashboard footer
FOOTER = f"AEGIS {VERSION} — Built by {AUTHOR} | {GITHUB}"
