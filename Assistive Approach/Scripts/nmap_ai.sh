#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <TARGET_IP>"
    exit 2
fi

TARGET="$1"
TS="$(date +%Y%m%d-%H%M%S)"
SCAN_FILE="scan_${TARGET}.nmap"
REPORT_FILE="scan_${TARGET}__report.md"

echo "[*] Scanning $TARGET ..."
nmap -sV --script vuln -T4 -oN "$SCAN_FILE" "$TARGET"

read -r -d '' PROMPT <<'EOF'
Analyze this Nmap + Vulners output.

For each open port/service:
- Product & version
- CVEs (ID, CVSS, short description)
- Known exploits (Metasploit/Exploit-DB)
- Verification steps
- Remediation

End with:
- Prioritized attack path
- Quick-win checklist

Format as Markdown.
EOF

echo "[*] Generating AI report ..."
cat "$SCAN_FILE" | sgpt --model gpt-4o-mini --no-interactive "$PROMPT" | tee "$REPORT_FILE"

echo
echo "[√] Done."
echo "    Scan   : $SCAN_FILE"
echo "    Report : $REPORT_FILE"
