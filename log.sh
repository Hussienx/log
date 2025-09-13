#!/usr/bin/env bash
# collect_ssh_audit.sh
# Usage: sudo ./collect_ssh_audit.sh /path/to/output_dir [--include-keys]
# Example: sudo ./collect_ssh_audit.sh /root/ssh_audit_reports --include-keys

set -euo pipefail

OUTBASE="${1:-./ssh_audit_reports}"
INCLUDE_KEYS=false
if [[ "${2:-}" == "--include-keys" ]]; then
  INCLUDE_KEYS=true
fi

TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
HOSTNAME=$(hostname --fqdn 2>/dev/null || hostname)
OUTDIR="${OUTBASE}/${HOSTNAME}_${TIMESTAMP}"
mkdir -p "${OUTDIR}"

echo "[*] create file res: ${OUTDIR}"

# Helper to copy if exists
copy_if_exists() {
  local src="$1"
  local dest="$2"
  if [[ -e "$src" ]]; then
    cp -a --parents "$src" "${dest}" 2>/dev/null || cp -a "$src" "${dest}" 2>/dev/null || true
  fi
}

# System snapshot
{
  echo "=== Host: ${HOSTNAME} ==="
  date
  uname -a
  lsb_release -a 2>/dev/null || true
  cat /etc/os-release 2>/dev/null || true
  echo
  echo "---- Uptime ----"
  uptime
  echo
  echo "---- Who / Users ----"
  who
  echo
  echo "---- last (summary) ----"
  last -n 50 || true
  echo
  echo "---- lastb (failed) ----"
  lastb -n 50 || true
  echo
  echo "---- Currently logged in processes (ps) ----"
  ps aux --sort=-%cpu | head -n 20
  echo
  echo "---- Listening / Established SSH sockets ----"
  if command -v ss >/dev/null 2>&1; then
    ss -tnpa | grep ssh || ss -tnpa
  else
    netstat -tnpa | grep ssh || netstat -tnpa
  fi
} > "${OUTDIR}/system_snapshot.txt" 2>&1

# Copy common log files (support different distros)
LOG_FILES=(
  /var/log/auth.log
  /var/log/secure
  /var/log/syslog
  /var/log/messages
  /var/log/daemon.log
  /var/log/audit/audit.log
  /var/log/wtmp
  /var/log/btmp
  /var/log/lastlog
)

for f in "${LOG_FILES[@]}"; do
  if [[ -e "$f" ]]; then
    echo "[*] Copying $f"
    mkdir -p "${OUTDIR}/logs"
    cp -a "$f" "${OUTDIR}/logs/" 2>/dev/null || true
  fi
done

# Copy rotated logs (auth.* secure.*)
echo "[*] Copying rotated logs patterns"
shopt -s nullglob
for pattern in /var/log/auth.* /var/log/secure.* /var/log/syslog.* /var/log/messages.* /var/log/audit/audit.*; do
  for file in $pattern; do
    [[ -e "$file" ]] && cp -a "$file" "${OUTDIR}/logs/" 2>/dev/null || true
  done
done
shopt -u nullglob

# Export journalctl for sshd/ssh unit and _COMM=sshd
echo "[*] Exporting journalctl entries (if systemd)"
if command -v journalctl >/dev/null 2>&1; then
  journalctl --no-pager -o short-iso -u ssh.service -u sshd.service > "${OUTDIR}/journal_ssh_unit.txt" 2>/dev/null || true
  journalctl --no-pager -o short-iso _COMM=sshd > "${OUTDIR}/journal_comm_sshd.txt" 2>/dev/null || true
  # last 1000 ssh related messages
  journalctl --no-pager -o short-iso | grep -iE "sshd|ssh" | tail -n 1000 > "${OUTDIR}/journal_ssh_tail.txt" 2>/dev/null || true
fi

# Grep important ssh/auth patterns into dedicated files
echo "[*] Extracting patterns from available logs"
PATTERNS=(
  "Accepted password"
  "Accepted publickey"
  "Failed password"
  "Invalid user"
  "authentication failure"
  "session opened"
  "session closed"
  "Connection closed"
  "Received disconnect"
)

# Parse through copied log files first
LOGS_DIR="${OUTDIR}/logs"
mkdir -p "${OUTDIR}/extracted"
if [[ -d "${LOGS_DIR}" ]]; then
  for pat in "${PATTERNS[@]}"; do
    grep -i --line-buffered -r --no-messages "${pat}" "${LOGS_DIR}" > "${OUTDIR}/extracted/$(echo "${pat}" | tr ' /' '__' | tr -dc '[:alnum:]_').log" 2>/dev/null || true
  done
fi

# Also parse journal exports if present
if [[ -f "${OUTDIR}/journal_ssh_unit.txt" ]]; then
  for pat in "${PATTERNS[@]}"; do
    grep -i "${pat}" "${OUTDIR}/journal_ssh_unit.txt" > "${OUTDIR}/extracted/journal_$(echo "${pat}" | tr ' /' '__' | tr -dc '[:alnum:]_').log" 2>/dev/null || true
  done
fi

# Copy SSH config and keys (optional)
echo "[*] Copying SSH configuration files"
SSH_FILES=(
  /etc/ssh/sshd_config
  /etc/ssh/ssh_config
  /etc/ssh/moduli
)
mkdir -p "${OUTDIR}/etc_ssh"
for s in "${SSH_FILES[@]}"; do
  copy_if_exists "$s" "${OUTDIR}/etc_ssh"
done

if [[ "${INCLUDE_KEYS}" == "true" ]]; then
  echo "[!] --include-keys: copying user authorized_keys and known_hosts (sensitive)"
  mkdir -p "${OUTDIR}/users_keys"
  # iterate users with home dirs
  awk -F: '{ if ($6 ~ /^\/home/ || $6 ~ /^\/root/) print $1 ":" $6 }' /etc/passwd | while IFS=: read -r user home; do
    for file in "${home}/.ssh/authorized_keys" "${home}/.ssh/known_hosts" "${home}/.ssh/authorized_keys2"; do
      if [[ -e "$file" ]]; then
        mkdir -p "${OUTDIR}/users_keys/${user}"
        cp -a "$file" "${OUTDIR}/users_keys/${user}/" 2>/dev/null || true
      fi
    done
  done
fi

# Sudo logs (in auth logs) + auditd parsing
if [[ -e /var/log/audit/audit.log ]]; then
  echo "[*] Parsing audit.log for ssh"
  grep -i ssh /var/log/audit/audit.log > "${OUTDIR}/extracted/audit_ssh.log" 2>/dev/null || true
fi

# Summaries: counts of patterns
echo "[*] Creating quick counts"
{
  echo "Counts for patterns in available logs"
  for pat in "${PATTERNS[@]}"; do
    cnt=0
    if [[ -d "${LOGS_DIR}" ]]; then
      cnt=$(grep -i -r --no-messages "${pat}" "${LOGS_DIR}" | wc -l || true)
    fi
    # also journal
    if [[ -f "${OUTDIR}/journal_ssh_unit.txt" ]]; then
      cnt=$((cnt + $(grep -i "${pat}" "${OUTDIR}/journal_ssh_unit.txt" | wc -l || true)))
    fi
    printf "%-30s : %d\n" "${pat}" "${cnt}"
  done
} > "${OUTDIR}/pattern_counts.txt"

# Collect relevant command outputs
echo "[*] Dumping command outputs"
{
  date
  echo "---- sshd process ----"
  pgrep -a sshd || ps aux | grep [s]shd || true
  echo
  echo "---- /etc/passwd (first 200 lines) ----"
  head -n 200 /etc/passwd
  echo
  echo "---- /etc/group (first 200 lines) ----"
  head -n 200 /etc/group
  echo
  echo "---- Firewall rules (iptables/nft) ----"
  if command -v iptables >/dev/null 2>&1; then
    iptables -L -n -v || true
  fi
  if command -v nft >/dev/null 2>&1; then
    nft list ruleset || true
  fi
  echo
  echo "---- SSH related packages (dpkg/rpm) ----"
  if command -v dpkg >/dev/null 2>&1; then
    dpkg -l | grep -i openssh || true
  fi
  if command -v rpm >/dev/null 2>&1; then
    rpm -qa | grep -i openssh || true
  fi
} > "${OUTDIR}/commands_snapshot.txt" 2>&1

# Create archive
ARCHIVE="${OUTBASE}/${HOSTNAME}_ssh_audit_${TIMESTAMP}.tar.gz"
echo "[*] Creating archive ${ARCHIVE}"
tar -czf "${ARCHIVE}" -C "${OUTBASE}" "${HOSTNAME}_${TIMESTAMP}" || true

# Compute checksum
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum "${ARCHIVE}" > "${ARCHIVE}.sha256"
fi

echo "[*] Done. Archive: ${ARCHIVE}"
echo "[*] Checksum: ${ARCHIVE}.sha256 (if exists)"

# Optional: print recommended secure copy command (user can run manually)
echo
echo "=== Usage notes ==="
echo "Run as root (sudo) to capture all logs. Sensitive files included if --include-keys used."
echo "To copy to remote host (example):"
echo "scp ${ARCHIVE} user@remoteserver:/path/to/store/"
echo
exit 0

