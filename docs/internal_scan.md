#!/usr/bin/env bash
# triage_v4.sh - FULL FEATURES + STABLE CONNECTION
# Fix: Da them lai History, Cron, Docker, Bash Payload check

SSH_USER="root"
DEFAULT_PORT="22"
CONCURRENCY="${CONCURRENCY:-10}"
# SSH Options: BatchMode de khong hoi pass, ConnectTimeout de khong treo lau
SSH_OPTS_BASE="-o BatchMode=yes -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15"

TS="$(date +%Y%m%d_%H%M%S)"
OUTDIR="triage_v4_${TS}"
RAW_DIR="${OUTDIR}/raw"
RPT_DIR="${OUTDIR}/report"
mkdir -p "${RAW_DIR}" "${RPT_DIR}"

# Regex tim dau hieu ma doc
IOC_REGEX="(
nohup[[:space:]]+\\./bash[[:space:]]+-connect|
\\./bash[[:space:]]+-connect|
wget[[:space:]]+http://[0-9\\.]+:[0-9]+/\\.bash|
curl[[:space:]]+http://[0-9\\.]+:[0-9]+/\\.bash|
chmod[[:space:]]+\\+x[[:space:]]+\\.bash|
/usr/tmp/\\.tmp|
/tmp/\\.sshd\\.log|
cat[[:space:]]+\\.env|
curl[[:space:]].*/api/decrypt|
docker[[:space:]]+container[[:space:]]+restart|
docker[[:space:]]+restart|
authorized_keys
)"

usage() {
  echo "Usage:"
  echo "  Batch mode : $0 hosts.ini"
  echo "  Single host (key)     : $0 --host <IP> [--user root] --key <path_to_key> [--token <passphrase>] [--port 22]"
  echo "  Single host (password): $0 --host <IP> [--user root] --password <password> [--port 22]"
}
log() { echo "[$(date +'%F %T')] $*"; }

SERVERS_FILE=""
SINGLE_HOST=""
SINGLE_PORT=""
KEY_FILE=""
KEY_TOKEN=""
SSH_PASSWORD=""
AGENT_STARTED=0

if [[ $# -eq 1 && "$1" != --* ]]; then
  # Cach dung cu: batch mode voi hosts.ini
  SERVERS_FILE="$1"
  [[ -f "${SERVERS_FILE}" ]] || { echo "File not found: ${SERVERS_FILE}"; exit 1; }
else
  # Che do single-host qua CLI arguments
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --host) SINGLE_HOST="$2"; shift 2 ;;
      --user) SSH_USER="$2"; shift 2 ;;
      --key) KEY_FILE="$2"; shift 2 ;;
      --token) KEY_TOKEN="$2"; shift 2 ;;
      --password) SSH_PASSWORD="$2"; shift 2 ;;
      --port) SINGLE_PORT="$2"; shift 2 ;;
      -h|--help) usage; exit 0 ;;
      *) echo "Unknown argument: $1"; usage; exit 1 ;;
    esac
  done

  [[ -z "${SINGLE_HOST}" ]] && { echo "Missing --host"; usage; exit 1; }
  [[ -z "${KEY_FILE}" && -z "${SSH_PASSWORD}" ]] && { echo "Missing --key or --password"; usage; exit 1; }
  [[ -n "${KEY_FILE}" && ! -f "${KEY_FILE}" ]] && { echo "Key file not found: ${KEY_FILE}"; exit 1; }
fi

# ==============================================================================
# REMOTE SCRIPT (Noi dung chay tren server)
# ==============================================================================
read -r -d '' REMOTE_SCRIPT <<'RS'
# Ham ls an toan
ls_time() { ls -la --time-style="+%d-%m-%Y %H:%M:%S" "$@" 2>/dev/null || ls -la "$@" 2>/dev/null; }

echo "==== BASIC ===="
echo "Hostname: $(hostname -f 2>/dev/null || hostname)"
echo "Date: $(date '+%d-%m-%Y %H:%M:%S')"
echo "Uptime: $(uptime -p 2>/dev/null || true)"
echo "IP (brief):"; ip -br a 2>/dev/null || ifconfig -a 2>/dev/null || true
echo

echo "==== USERS / SSH ===="
echo "--- root authorized_keys ---"
if [[ -f /root/.ssh/authorized_keys ]]; then
  ls_time /root/.ssh/authorized_keys
  sed -n '1,200p' /root/.ssh/authorized_keys
else echo "No authorized_keys"; fi
echo

echo "==== SUSPICIOUS PATHS ===="
for d in /usr/tmp/.tmp /tmp/.tmp /var/tmp /dev/shm /tmp; do
  if [[ -d "$d" ]]; then
    echo "[DIR] $d exists - Content:"
    ls_time "$d" | head -n 200 || true
    echo
  fi
done
echo

echo "==== Check .bash payload ===="
for p in /usr /usr/local /usr/tmp/.tmp /tmp /var/tmp /root /home; do
  if [[ -f "$p/.bash" ]]; then
    echo "[FOUND] $p/.bash"
    ls_time "$p/.bash" || true
    file "$p/.bash" 2>/dev/null || true
    echo
  fi
done
echo

echo "==== HISTORIES (User Activity) ===="
for u in root bo-service bo-portal rabbitmq-service bopartner-service wmspartner-service postgres mysql; do
  # Tim home dir cua user
  home_dir="$(getent passwd "$u" | cut -d: -f6 || true)"
  [[ -z "$home_dir" ]] && continue
  
  for hf in "$home_dir/.bash_history" "$home_dir/.zsh_history" "$home_dir/.mysql_history" "$home_dir/.psql_history"; do
    if [[ -f "$hf" ]]; then
      echo "--- History: $hf ($u) ---"
      tail -n 200 "$hf" 2>/dev/null || true
      echo
    fi
  done
done
echo

echo "==== CRON / PERSISTENCE ===="
echo "--- crontab -l (root) ---"
crontab -l 2>/dev/null || echo "no crontab for root"
echo
echo "--- spool crons ---"
ls_time /etc/cron* /var/spool/cron 2>/dev/null || true
if [[ -d /var/spool/cron ]]; then
  for f in /var/spool/cron/*; do
    [[ -f "$f" ]] || continue
    echo "### Content of $f"
    cat "$f" 2>/dev/null || true
    echo
  done
fi
echo

echo "==== PROCESSES (START TIME) ===="
echo "PID, START, USER, CPU, CMD"
# Thu nhieu lenh ps khac nhau de tuong thich cac loai Linux cu/moi
ps -eo pid,lstart,user,%cpu,cmd --sort=-pcpu 2>/dev/null | head -n 100 || ps auxf | head -n 100
echo

echo "==== NETWORK ===="
echo "--- Established ---"; ss -antup 2>/dev/null | grep ESTAB || netstat -antp 2>/dev/null | grep ESTABLISHED || true
echo "--- Listening ---"; ss -lntup 2>/dev/null || netstat -lntp 2>/dev/null || true
echo

echo "==== SSHD LOGS ===="
if command -v journalctl >/dev/null 2>&1; then
  journalctl -u sshd --since "2 days ago" --no-pager -o short-iso | tail -n 250 || true
else
  tail -n 250 /var/log/secure 2>/dev/null || tail -n 250 /var/log/auth.log 2>/dev/null || true
fi
echo

echo "==== DOCKER (if present) ===="
if command -v docker >/dev/null 2>&1; then
  echo "--- docker ps ---"
  docker ps --format "table {{.ID}}\t{{.Image}}\t{{.CreatedAt}}\t{{.Status}}\t{{.Names}}" 2>/dev/null || docker ps
else
  echo "docker not found"
fi
echo
RS
# ==============================================================================

summarize_one() {
  local host="$1" raw="$2" out="$3"
  {
    echo "HOST: ${host}"
    grep -qE "/usr/tmp/\\.tmp|/tmp/\\.tmp" "$raw" && echo "[IOC] Hidden tmp dir FOUND"
    grep -qE "\\[FOUND\\] .*/\\.bash" "$raw" && echo "[IOC] payload .bash FOUND"
    
    echo; echo "[PROCESS CHECK]"; 
    grep -E "node |/tmp/|bash -connect|xmrig" "$raw" | grep -v "grep" | head -n 10 || true
    
    echo; echo "[TOP IOC HITS]"; 
    grep -nE "${IOC_REGEX}" "$raw" | tail -n 50 || true
  } > "$out"
}

run_one_host() {
  local host="$1"
  local port="$2"
  local raw_file="${RAW_DIR}/${host}.txt"
  local rpt_file="${RPT_DIR}/${host}.report.txt"

  # Neu khong co port thi dung mac dinh 22
  [[ -z "$port" ]] && port="${DEFAULT_PORT}"

  log "Scanning ${host} on port ${port}..."

  if [[ "${SSH_AUTH_MODE:-key}" == "password" ]]; then
    # Mat khau khong tuong tac qua SSH_ASKPASS; setsid de bo tty (bat buoc ssh dung askpass)
    # Neu khong co setsid (vd: Windows/Git Bash) thi chay truc tiep, dua vao stdin=/dev/null
    local setsid_cmd=()
    command -v setsid >/dev/null 2>&1 && setsid_cmd=(setsid)
    if SSH_ASKPASS="${PW_ASKPASS_SCRIPT}" SSH_ASKPASS_REQUIRE=force DISPLAY=":0" "${setsid_cmd[@]}" ssh ${SSH_OPTS_PW} -p "${port}" "${SSH_USER}@${host}" "bash -lc $(printf %q "$REMOTE_SCRIPT")" >"${raw_file}" 2>&1 </dev/null; then
      summarize_one "${host}" "${raw_file}" "${rpt_file}"
      echo "OK: ${host}"
    else
      echo "FAIL: ${host}"
      echo "SSH Failed. Check password/Firewall." > "${rpt_file}"
      tail -n 2 "${raw_file}" >> "${rpt_file}"
    fi
  else
    if ssh ${SSH_OPTS_BASE} -p "${port}" "${SSH_USER}@${host}" "bash -lc $(printf %q "$REMOTE_SCRIPT")" >"${raw_file}" 2>&1; then
      summarize_one "${host}" "${raw_file}" "${rpt_file}"
      echo "OK: ${host}"
    else
      echo "FAIL: ${host}"
      echo "SSH Failed. Check Key/Firewall." > "${rpt_file}"
      # In ra 2 dong cuoi cung cua loi de debug
      tail -n 2 "${raw_file}" >> "${rpt_file}"
    fi
  fi
}

export -f run_one_host summarize_one
export SSH_USER DEFAULT_PORT SSH_OPTS_BASE OUTDIR RAW_DIR RPT_DIR REMOTE_SCRIPT IOC_REGEX SSH_AUTH_MODE SSH_OPTS_PW PW_ASKPASS_SCRIPT
export -f log

SSH_OPTS_PW="-o PreferredAuthentications=password,keyboard-interactive -o PubkeyAuthentication=no -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=15"
SSH_AUTH_MODE="key"
PW_ASKPASS_SCRIPT=""

# Neu co key file, nap vao ssh-agent tam thoi (ho tro ca key co passphrase/token)
setup_ssh_agent() {
  local key="$1" token="$2"
  eval "$(ssh-agent -s)" >/dev/null
  AGENT_STARTED=1

  if [[ -n "$token" ]]; then
    local askpass_script
    askpass_script="$(mktemp)"
    printf '#!/bin/sh\necho "%s"\n' "$token" > "$askpass_script"
    chmod 700 "$askpass_script"
    DISPLAY=":0" SSH_ASKPASS="$askpass_script" SSH_ASKPASS_REQUIRE=force ssh-add "$key" </dev/null >/dev/null 2>&1
    rm -f "$askpass_script"
  else
    ssh-add "$key" </dev/null >/dev/null 2>&1
  fi
}

# Nap mat khau vao script askpass tam thoi (ho tro auth bang password thay vi key)
setup_password_askpass() {
  local pwd="$1"
  PW_ASKPASS_SCRIPT="$(mktemp)"
  printf '#!/bin/sh\necho "%s"\n' "$pwd" > "${PW_ASKPASS_SCRIPT}"
  chmod 700 "${PW_ASKPASS_SCRIPT}"
  SSH_AUTH_MODE="password"
}

cleanup_ssh_agent() {
  [[ "${AGENT_STARTED}" -eq 1 ]] && ssh-agent -k >/dev/null 2>&1
  [[ -n "${PW_ASKPASS_SCRIPT}" ]] && rm -f "${PW_ASKPASS_SCRIPT}"
  return 0
}
trap cleanup_ssh_agent EXIT

log "Output Directory: ${OUTDIR}"

# Tao danh sach tam thoi: IP và PORT
HOSTS_LIST="${OUTDIR}/hosts_list.txt"

if [[ -n "${SINGLE_HOST}" ]]; then
  if [[ -n "${SSH_PASSWORD}" ]]; then
    # Che do single-host bang password: nap password vao script askpass tam thoi
    setup_password_askpass "${SSH_PASSWORD}"
  else
    # Che do single-host bang key: nap key (+ token passphrase neu co) vao ssh-agent
    setup_ssh_agent "${KEY_FILE}" "${KEY_TOKEN}"
  fi
  export SSH_AUTH_MODE SSH_OPTS_PW PW_ASKPASS_SCRIPT
  echo "${SINGLE_HOST} ${SINGLE_PORT}" >> "${HOSTS_LIST}"
else
  # Đọc file hosts.ini thông minh hơn để lấy cả IP và Port
  grep -vE '^\s*#|^\s*\[' "${SERVERS_FILE}" | while read -r line; do
      # Lay IP (cot dau tien)
      ip=$(echo "$line" | awk '{print $1}')
      [[ -z "$ip" ]] && continue

      # Tim port (ansible_port=XXXX)
      port=$(echo "$line" | grep -o 'ansible_port=[0-9]*' | cut -d= -f2)

      echo "$ip $port" >> "${HOSTS_LIST}"
  done
fi

# Chay song song
cat "${HOSTS_LIST}" | xargs -I{} -P "${CONCURRENCY}" bash -c 'run_one_host {}'

# Gop bao cao
REPORT_ALL="${OUTDIR}/REPORT.txt"
echo "=== TRIAGE REPORT GENERATED AT $(date) ===" > "${REPORT_ALL}"
for f in "${RPT_DIR}"/*.report.txt; do
    [[ -f "$f" ]] || continue
    echo "" >> "${REPORT_ALL}"
    cat "$f" >> "${REPORT_ALL}"
done

log "DONE! Report saved to: ${REPORT_ALL}"
# In ra duong dan tuyet doi de de copy
echo "Full Report Path: $(pwd)/${REPORT_ALL}"
