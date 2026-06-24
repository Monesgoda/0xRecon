#!/bin/bash
# ╔══════════════════════════════════════════════════════════════════════╗
# ║        0xRecon — Automated Reconnaissance Framework  v7.0           ║
# ║        © 2026 0xmones. All Rights Reserved.                         ║
# ╠══════════════════════════════════════════════════════════════════════╣
# ║  v7.0 — Refactored Architecture:                                     ║
# ║  Phase 1 : Passive Recon (OSINT, subdomains, DNS)                    ║
# ║  Phase 2 : Active Recon (ports, probing, URL collection)             ║
# ║  Phase 3 : Heavy Vulnerability Scanning (Nuclei)                     ║
# ║  FEAT    : Critical assets JSON aggregation                           ║
# ║  CLEANUP : No empty files, concise output, removed bloat             ║
# ╚══════════════════════════════════════════════════════════════════════╝

set -uo pipefail

SCRIPT_TMPDIR=$(mktemp -d)
trap 'rm -rf "$SCRIPT_TMPDIR"' EXIT

INSTALL_FAILED_DIR="${HOME}/.0xrecon_failed"
mkdir -p "$INSTALL_FAILED_DIR"
already_failed() { [ -f "${INSTALL_FAILED_DIR}/$1" ]; }
mark_failed()    { touch "${INSTALL_FAILED_DIR}/$1"; }
clear_failed()   { rm -f "${INSTALL_FAILED_DIR}/$1"; }

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  COLOR PALETTE                                                      ║
# ╚══════════════════════════════════════════════════════════════════════╝

RESET='\033[0m';     BOLD='\033[1m';       DIM='\033[2m'
ITALIC='\033[3m';    UNDERLINE='\033[4m'
RED='\033[0;31m';    GREEN='\033[0;32m';   YELLOW='\033[1;33m'
BLUE='\033[0;34m';   CYAN='\033[0;36m';   MAGENTA='\033[0;35m'
WHITE='\033[1;37m'
BR='\033[1;31m';  BG='\033[1;32m';  BY='\033[1;33m'
BB='\033[1;34m';  BM='\033[1;35m';  BC='\033[1;36m'
BW='\033[1;37m'
SEV_CRIT='\033[1;37m\033[41m'
SEV_HIGH='\033[1;31m'
SEV_MED='\033[1;33m'
SEV_LOW='\033[1;36m'
SEV_INFO='\033[1;34m'
SEV_OK='\033[1;32m'

D_TL='╔'; D_TR='╗'; D_BL='╚'; D_BR='╝'
D_H='═';  D_V='║';  D_ML='╠'; D_MR='╣'
S_TL='┌'; S_TR='┐'; S_BL='└'; S_BR='┘'
S_H='─';  S_V='│';  S_ML='├'; S_MR='┤'; S_BT='┴'; S_TP='┬'; S_CR='┼'
R_TL='╭'; R_TR='╮'; R_BL='╰'; R_BR='╯'
R_H='─';  R_V='│'
PB_ON='█'; PB_MID='▓'; PB_OFF='░'
SEP='━'

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  LOGGING & OUTPUT ENGINE                                             ║
# ╚══════════════════════════════════════════════════════════════════════╝

LOG_FILE="/dev/null"
_log() { echo "$(date '+%H:%M:%S') $*" >> "$LOG_FILE" 2>/dev/null || true; }

info()    { echo -e "  ${BC}[*]${RESET} $*";           _log "[INFO]  $*"; }
success() { echo -e "  ${BG}[✔]${RESET} $*";           _log "[OK]    $*"; }
warn()    { echo -e "  ${BY}[!]${RESET} $*";           _log "[WARN]  $*"; }
error()   { echo -e "  ${BR}[✘]${RESET} $*" >&2;      _log "[ERR]   $*"; }
skip()    { echo -e "  ${DIM}[~] SKIP — $*${RESET}";  _log "[SKIP]  $*"; }
step()    { echo -e "    ${BB}↳${RESET} ${DIM}$*${RESET}"; _log "[STEP]  $*"; }

find_critical() { echo -e "  ${SEV_CRIT} CRITICAL ${RESET} $*"; _log "[CRIT] $*"; }
find_high()     { echo -e "  ${SEV_HIGH}[HIGH]${RESET}     $*"; _log "[HIGH] $*"; }
find_medium()   { echo -e "  ${SEV_MED}[MEDIUM]${RESET}   $*"; _log "[MED]  $*"; }
find_low()      { echo -e "  ${SEV_LOW}[LOW]${RESET}      $*"; _log "[LOW]  $*"; }
find_ok()       { echo -e "  ${SEV_OK}[SECURE]${RESET}   $*"; _log "[SEC]  $*"; }
find_info()     { echo -e "  ${SEV_INFO}[INFO]${RESET}     $*"; _log "[INFO] $*"; }

title() {
  local label="$*"
  local line; printf -v line '%.0s'"${SEP}" {1..60}
  echo ""
  echo -e "${BOLD}${BM}${line}${RESET}"
  echo -e "${BOLD}${BC}   ⚙  ${label}${RESET}"
  echo -e "${BOLD}${BM}${line}${RESET}"
  _log "══════ PHASE: ${label} ══════"
}

hline() {
  local char="${1:-${S_H}}"; local w="${2:-60}"
  local line; printf -v line "%${w}s" ''; echo -e "${DIM}${line// /$char}${RESET}"
}

count() {
  [ -f "$1" ] && wc -l < "$1" 2>/dev/null || echo 0
}

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  UI COMPONENTS                                                       ║
# ╚══════════════════════════════════════════════════════════════════════╝

panel_box() {
  local title="$1"; shift
  local w=58
  local pad; printf -v pad "%$(( w - 2 ))s" ''
  local hbar="${pad// /${R_H}}"
  echo -e "  ${BC}${R_TL}${hbar}${R_TR}${RESET}"
  printf "  ${BC}${R_V}${RESET} ${BOLD}${BY} %-$(( w - 3 ))s${RESET}${BC}${R_V}${RESET}\n" "$title"
  local mbar; printf -v mbar "%$(( w - 2 ))s" ''; mbar="${mbar// /${S_H}}"
  echo -e "  ${DIM}${S_ML}${mbar}${S_MR}${RESET}"
  for line in "$@"; do
    printf "  ${BC}${R_V}${RESET}  %-$(( w - 4 ))s ${BC}${R_V}${RESET}\n" "$line"
  done
  echo -e "  ${BC}${R_BL}${hbar}${R_BR}${RESET}"
}

progress_bar() {
  local cur="$1" tot="$2" label="${3:-}"
  local w=30
  [ "$tot" -le 0 ] && tot=1
  local filled=$(( cur * w / tot ))
  local empty=$(( w - filled ))
  local bar=''
  local i
  for (( i=0; i<filled; i++ )); do bar+="${PB_ON}"; done
  for (( i=0; i<empty;  i++ )); do bar+="${PB_OFF}"; done
  printf "  ${DIM}[${RESET}${BG}%s${RESET}${DIM}]${RESET} ${DIM}%d/%d %s${RESET}\r" \
    "$bar" "$cur" "$tot" "$label"
}

tree_leaf() {
  local label="$1" count="$2" col="${3:-}"
  local num_color
  if [ -n "$col" ]; then
    num_color="$col"
  elif [ "$count" -gt 0 ]; then
    num_color="${BG}"
  else
    num_color="${DIM}"
  fi
  printf "  ${DIM}│  ├─${RESET} ${DIM}%-30s${RESET} ${num_color}%s${RESET}\n" "$label" "$count"
}

tree_leaf_warn() {
  local label="$1" count="$2"
  local col="${DIM}"
  [ "$count" -gt 0 ] && col="${BY}"
  tree_leaf "$label" "$count" "$col"
}

tree_leaf_crit() {
  local label="$1" count="$2"
  local col="${DIM}"
  [ "$count" -gt 0 ] && col="${BR}"
  tree_leaf "$label" "$count" "$col"
}

grade_badge() {
  local grade="$1"
  case "$grade" in
    A+|A) echo -e "${BG}[ ${grade} ]${RESET}" ;;
    B)    echo -e "${BY}[ ${grade} ]${RESET}" ;;
    C|D)  echo -e "${SEV_MED}[ ${grade} ]${RESET}" ;;
    F)    echo -e "${SEV_HIGH}[ ${grade} ]${RESET}" ;;
    *)    echo -e "${DIM}[ ? ]${RESET}" ;;
  esac
}

severity_row() {
  local sev="$1" count="$2" file="$3"
  local color
  case "${sev,,}" in
    critical) color="${SEV_CRIT}" ;;
    high)     color="${SEV_HIGH}" ;;
    medium)   color="${SEV_MED}"  ;;
    low)      color="${SEV_LOW}"  ;;
    *)        color="${DIM}"      ;;
  esac
  if [ "$count" -gt 0 ]; then
    printf "  ${color}%-12s${RESET}  ${BOLD}%-8s${RESET}  ${DIM}%s${RESET}\n" "$sev" "$count" "$file"
  else
    printf "  ${DIM}%-12s  %-8s  %s${RESET}\n" "$sev" "$count" "$file"
  fi
}

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  ASCII BANNER                                                        ║
# ╚══════════════════════════════════════════════════════════════════════╝

show_banner() {
  clear
  echo ""
  echo -e "${BOLD}${BR}"
  cat << 'BANNER'
   ██████╗ ██╗  ██╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔═████╗╚██╗██╔╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██║██╔██║ ╚███╔╝ ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ████╔╝██║ ██╔██╗ ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ╚██████╔╝██╔╝ ██╗██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
   ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝╚═╝  ╚═══╝
BANNER
  echo -e "${RESET}"
  echo -e "  ${BOLD}${BC}    Automated Reconnaissance Framework${RESET}  ${BY}v7.0${RESET}  ${DIM}│  Refactored${RESET}"
  local line; printf -v line '%*s' 62 ''; echo -e "  ${DIM}${line// /─}${RESET}"
  printf "  ${DIM}%-18s${RESET} ${BW}%s${RESET}\n"  "Author"    "0xmones"
  printf "  ${DIM}%-18s${RESET} ${DIM}%s${RESET}\n" "Copyright" "© 2026 0xmones. All Rights Reserved."
  local line2; printf -v line2 '%*s' 62 ''; echo -e "  ${DIM}${line2// /─}${RESET}"
  echo ""
}

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  PATHS & GLOBAL CONFIG                                               ║
# ╚══════════════════════════════════════════════════════════════════════╝

BASE_DIR="${HOME}"
CONFIG_FILE="${HOME}/.0xrecon.conf"
LINKFINDER_PY="/opt/LinkFinder/linkfinder.py"
NUCLEI_TEMPLATES="${HOME}/nuclei-templates"
WORDLIST_SUBS="/usr/share/SecLists/Discovery/DNS/subdomains-top1million-5000.txt"
RESOLVERS="/usr/share/SecLists/Discovery/DNS/resolvers.txt"

GOPATH="${GOPATH:-$HOME/go}"
GO_BIN="${GOPATH}/bin"
export PATH="$PATH:$GO_BIN:/usr/local/bin"

declare -a UA_POOL=(
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36"
  "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15"
  "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0"
  "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0"
  "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 Version/17.5 Mobile/15E148 Safari/604.1"
  "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 Chrome/124.0.6367.82 Mobile Safari/537.36"
  "curl/8.7.1"
)
random_ua() { echo "${UA_POOL[$(( RANDOM % ${#UA_POOL[@]} ))]}"; }

declare -a CDN_PATTERNS=(
  "^104\.(1[6-9]|2[0-9]|3[01])\."
  "^151\.101\."
  "^184\.(2[89]|3[01])\."
  "^13\.3[25]\."
  "^23\."
  "^64\.252\."
  "^205\.251\."
  "^199\.27\.12[89]\."
)

is_cdn_ip() {
  local ip="$1"
  for pat in "${CDN_PATTERNS[@]}"; do
    echo "$ip" | grep -qE "$pat" && return 0
  done
  return 1
}

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  WAF-BYPASS CURL WRAPPER                                             ║
# ╚══════════════════════════════════════════════════════════════════════╝

waf_curl() {
  local url="$1"; shift
  local ua; ua=$(random_ua)
  local xff; xff="$(( RANDOM % 223 + 1 )).$(( RANDOM % 255 )).$(( RANDOM % 255 )).$(( RANDOM % 255 ))"
  curl -sL \
    --max-time 20 --connect-timeout 8 \
    --retry 2 --retry-delay 2 \
    --retry-all-errors \
    -k \
    -A "$ua" \
    -H "X-Forwarded-For: ${xff}"   \
    -H "X-Real-IP: ${xff}"         \
    -H "X-Originating-IP: ${xff}"  \
    -H "True-Client-IP: ${xff}"    \
    -H "CF-Connecting-IP: ${xff}"  \
    -H "Forwarded: for=${xff}"     \
    -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" \
    -H "Accept-Language: en-US,en;q=0.5" \
    -H "Accept-Encoding: gzip, deflate"  \
    -H "Connection: keep-alive"          \
    "$@" "$url" 2>/dev/null
}

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  FREE OSINT API FUNCTIONS                                            ║
# ╚══════════════════════════════════════════════════════════════════════╝

internetdb_lookup() {
  local ip="$1"
  local out_file="${OUT}/origin/internetdb_${ip//./_}.json"
  local data
  data=$(waf_curl "https://internetdb.shodan.io/${ip}" 2>/dev/null) || true
  if echo "$data" | python3 -c "import sys,json; json.load(sys.stdin)" 2>/dev/null; then
    echo "$data" > "$out_file"
    local ports cves tags
    ports=$(echo "$data" | python3 -c "
import sys,json
d=json.load(sys.stdin)
p=d.get('ports',[])
print(','.join(map(str,p)) if p else 'none')
" 2>/dev/null || echo "none")
    cves=$(echo "$data" | python3 -c "
import sys,json
d=json.load(sys.stdin)
v=d.get('vulns',[])
print(' '.join(v[:5]) if v else 'none')
" 2>/dev/null || echo "none")
    tags=$(echo "$data" | python3 -c "
import sys,json
d=json.load(sys.stdin)
t=d.get('tags',[])
print(','.join(t) if t else 'none')
" 2>/dev/null || echo "none")
    step "InternetDB [${ip}]  ports: ${ports}  CVEs: ${cves}  tags: ${tags}"
    if [ "$cves" != "none" ]; then
      for cve in $cves; do
        find_high "[InternetDB] ${ip} → ${cve}"
        echo "[InternetDB-CVE] ${ip} | ${cve}" >> "${OUT}/origin/cve_findings.txt"
      done
    fi
  fi
}

ipapi_lookup() {
  local ip="$1"
  local fields="status,country,regionName,city,isp,org,as,query,hosting,proxy"
  local data
  data=$(waf_curl "http://ip-api.com/json/${ip}?fields=${fields}" 2>/dev/null) || true
  local status
  status=$(echo "$data" | python3 -c \
    "import sys,json; print(json.load(sys.stdin).get('status','fail'))" 2>/dev/null || echo "fail")
  if [ "$status" = "success" ]; then
    python3 - <<PYEOF 2>/dev/null
import sys, json
data = json.loads('''${data}''')
country  = data.get('country','?')
city     = data.get('city','?')
isp      = data.get('isp','?')
asn      = data.get('as','?')
hosting  = data.get('hosting', False)
proxy    = data.get('proxy', False)
flag = '⚠ HOSTING/DC' if hosting else ('⚠ PROXY' if proxy else '')
print(f"  ${BB}GeoIP${RESET}  {country} / {city}  |  ASN: {asn}  |  ISP: {isp}  ${BY}{flag}${RESET}")
PYEOF
    echo "$data" > "${OUT}/origin/geoip_${ip//./_}.json"
  fi
}

bgpview_lookup() {
  local ip="$1"
  local data
  data=$(waf_curl "https://api.bgpview.io/ip/${ip}" 2>/dev/null) || true
  python3 - <<PYEOF 2>/dev/null
import sys, json
try:
    d = json.loads('''${data}''')
    prefixes = d.get('data',{}).get('prefixes',[])
    if prefixes:
        asn_info = prefixes[0].get('asn',{})
        asn  = asn_info.get('asn','?')
        name = asn_info.get('description','?')
        pfx  = prefixes[0].get('prefix','?')
        cc   = asn_info.get('country_code','?')
        print(f"  ${DIM}BGPView${RESET}  {ip} → ASN{asn} ({name})  Prefix: {pfx}  Country: {cc}")
except Exception:
    pass
PYEOF
}

ssl_cert_check() {
  local domain="$1"
  if ! command -v openssl &>/dev/null; then
    skip "openssl not found — skipping SSL cert check"
    return 0
  fi
  local cert_info
  cert_info=$(echo | openssl s_client -connect "${domain}:443" -servername "$domain" \
    2>/dev/null | openssl x509 -noout -dates -subject -issuer 2>/dev/null) || true
  if [ -z "$cert_info" ]; then
    return 0
  fi
  local not_after issuer subject
  not_after=$(echo "$cert_info" | grep 'notAfter'  | cut -d= -f2)
  subject=$(echo "$cert_info"   | grep 'subject'   | sed 's/subject=//')
  issuer=$(echo "$cert_info"    | grep 'issuer'    | sed 's/issuer=//')
  local expiry_epoch now_epoch days_left
  expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null || \
                 date -j -f "%b %d %T %Y %Z" "$not_after" +%s 2>/dev/null || echo 0)
  now_epoch=$(date +%s)
  days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
  if [ "$days_left" -le 0 ]; then
    find_critical "SSL CERT EXPIRED on ${domain}!"
  elif [ "$days_left" -le 14 ]; then
    find_high    "SSL cert expires in ${days_left} days → ${domain}"
  elif [ "$days_left" -le 30 ]; then
    find_medium  "SSL cert expires in ${days_left} days → ${domain}"
  else
    find_ok      "SSL cert valid for ${days_left} days → ${domain}"
  fi
}

http_headers_check() {
  local url="$1"
  local hdrs
  hdrs=$(curl -sIL --max-time 10 -A "$(random_ua)" -k "$url" 2>/dev/null) || true
  if [ -z "$hdrs" ]; then
    return 0
  fi
  local score=0
  declare -A hdr_present
  local header_list=(
    "Strict-Transport-Security"
    "X-Content-Type-Options"
    "X-Frame-Options"
    "Content-Security-Policy"
    "Referrer-Policy"
    "Permissions-Policy"
    "X-XSS-Protection"
  )
  for h in "${header_list[@]}"; do
    if echo "$hdrs" | grep -qi "^${h}:"; then
      hdr_present[$h]="✔"
      score=$(( score + 1 ))
    else
      hdr_present[$h]="✘"
    fi
  done
  local grade
  if   [ "$score" -ge 7 ]; then grade="A+"
  elif [ "$score" -ge 6 ]; then grade="A"
  elif [ "$score" -ge 5 ]; then grade="B"
  elif [ "$score" -ge 4 ]; then grade="C"
  elif [ "$score" -ge 2 ]; then grade="D"
  else                          grade="F"
  fi
  local server_hdr xpowered
  server_hdr=$(echo "$hdrs" | grep -i "^Server:"     | head -1 | cut -d: -f2- | xargs)
  xpowered=$(echo "$hdrs"   | grep -i "^X-Powered-By:" | head -1 | cut -d: -f2- | xargs)
  local host; host=$(echo "$url" | sed 's|https\?://||;s|/.*||')
  local grade_color
  case "$grade" in
    A+|A) grade_color="${BG}" ;;
    B)    grade_color="${BY}" ;;
    C|D)  grade_color="${SEV_MED}" ;;
    F)    grade_color="${SEV_HIGH}" ;;
    *)    grade_color="${DIM}" ;;
  esac
  printf "  ${DIM}%-45s${RESET}  ${grade_color}Grade: %s${RESET}  ${DIM}(%d/7 headers)${RESET}\n" \
    "$host" "$grade" "$score"
  for h in "${header_list[@]}"; do
    if [ "${hdr_present[$h]}" = "✘" ]; then
      echo "[MISSING-HEADER] ${url} | ${h}" >> "${OUT}/recon/missing_headers.txt"
    fi
  done
  if [ -n "$server_hdr" ]; then
    echo "  ${DIM}   Server: ${server_hdr}${RESET}"
    echo "[SERVER-DISCLOSURE] ${url} | Server: ${server_hdr}" >> "${OUT}/recon/header_disclosures.txt"
  fi
  if [ -n "$xpowered" ]; then
    find_medium "[Header-Disclosure] X-Powered-By: ${xpowered} → ${url}"
    echo "[XPOWEREDBY-DISCLOSURE] ${url} | ${xpowered}" >> "${OUT}/recon/header_disclosures.txt"
  fi
  if [ "$grade" = "F" ]; then
    find_high   "[Security-Headers] Grade F on ${url}"
  elif [ "$grade" = "D" ] || [ "$grade" = "C" ]; then
    find_medium "[Security-Headers] Grade ${grade} on ${url}"
  fi
  echo "${url} | Grade: ${grade} (${score}/7) | Server: ${server_hdr:-hidden}" \
    >> "${OUT}/recon/headers_grade.txt"
}

hackertarget_emails() {
  local domain="$1"
  waf_curl "https://api.hackertarget.com/findemail/?q=${domain}" 2>/dev/null \
    | grep -oE '[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}' \
    | sort -u || true
}

hackertarget_reverseip() {
  local ip="$1"
  waf_curl "https://api.hackertarget.com/reverseiplookup/?q=${ip}" 2>/dev/null \
    | grep -v "^error\|^API" | sort -u || true
}

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  CONFIG & API KEY MANAGEMENT                                         ║
# ╚══════════════════════════════════════════════════════════════════════╝

load_config() {
  [ -f "$CONFIG_FILE" ] && source "$CONFIG_FILE" 2>/dev/null || true
  SHODAN_KEY="${SHODAN_KEY:-}"
  CENSYS_ID="${CENSYS_ID:-}"; CENSYS_SECRET="${CENSYS_SECRET:-}"
  GITHUB_TOKEN="${GITHUB_TOKEN:-}"
  HUNTER_KEY="${HUNTER_API_KEY:-}"
  VIRUSTOTAL_KEY="${VIRUSTOTAL_KEY:-}"
  URLSCAN_KEY="${URLSCAN_KEY:-}"
  OTX_KEY="${OTX_KEY:-}"
  SECURITYTRAILS_KEY="${SECURITYTRAILS_KEY:-}"
  FULLHUNT_KEY="${FULLHUNT_KEY:-}"
  CHAOS_KEY="${CHAOS_KEY:-}"
  BEVIGIL_KEY="${BEVIGIL_KEY:-}"
  FOFA_EMAIL="${FOFA_EMAIL:-}"; FOFA_KEY="${FOFA_KEY:-}"
  LEAKIX_KEY="${LEAKIX_KEY:-}"
}

save_config() {
  cat > "$CONFIG_FILE" <<EOF
# 0xRecon API Configuration — $(date)
SHODAN_KEY="${SHODAN_KEY}"
CENSYS_ID="${CENSYS_ID}"; CENSYS_SECRET="${CENSYS_SECRET}"
GITHUB_TOKEN="${GITHUB_TOKEN}"
HUNTER_API_KEY="${HUNTER_KEY}"
VIRUSTOTAL_KEY="${VIRUSTOTAL_KEY}"
URLSCAN_KEY="${URLSCAN_KEY}"
OTX_KEY="${OTX_KEY}"
SECURITYTRAILS_KEY="${SECURITYTRAILS_KEY}"
FULLHUNT_KEY="${FULLHUNT_KEY}"
CHAOS_KEY="${CHAOS_KEY}"
BEVIGIL_KEY="${BEVIGIL_KEY}"
FOFA_EMAIL="${FOFA_EMAIL}"; FOFA_KEY="${FOFA_KEY}"
LEAKIX_KEY="${LEAKIX_KEY}"
EOF
  chmod 600 "$CONFIG_FILE"
  success "Config saved → ${CONFIG_FILE}"
}

build_subfinder_config() {
  local sf_conf="${HOME}/.config/subfinder/provider-config.yaml"
  mkdir -p "$(dirname "$sf_conf")"
  > "$sf_conf"
  [ -n "$VIRUSTOTAL_KEY" ]     && printf "virustotal:\n  - %s\n"     "$VIRUSTOTAL_KEY"     >> "$sf_conf"
  [ -n "$SHODAN_KEY" ]         && printf "shodan:\n  - %s\n"         "$SHODAN_KEY"         >> "$sf_conf"
  [ -n "$GITHUB_TOKEN" ]       && printf "github:\n  - %s\n"         "$GITHUB_TOKEN"       >> "$sf_conf"
  [ -n "$URLSCAN_KEY" ]        && printf "urlscan:\n  - %s\n"        "$URLSCAN_KEY"        >> "$sf_conf"
  [ -n "$OTX_KEY" ]            && printf "alienvault:\n  - %s\n"     "$OTX_KEY"            >> "$sf_conf"
  [ -n "$SECURITYTRAILS_KEY" ] && printf "securitytrails:\n  - %s\n" "$SECURITYTRAILS_KEY" >> "$sf_conf"
  [ -n "$FULLHUNT_KEY" ]       && printf "fullhunt:\n  - %s\n"       "$FULLHUNT_KEY"       >> "$sf_conf"
  [ -n "$CHAOS_KEY" ]          && printf "chaos:\n  - %s\n"          "$CHAOS_KEY"          >> "$sf_conf"
  [ -n "$BEVIGIL_KEY" ]        && printf "bevigil:\n  - %s\n"        "$BEVIGIL_KEY"        >> "$sf_conf"
  [ -n "$LEAKIX_KEY" ]         && printf "leakix:\n  - %s\n"         "$LEAKIX_KEY"         >> "$sf_conf"
  if [ -n "$CENSYS_ID" ] && [ -n "$CENSYS_SECRET" ]; then
    printf "censys:\n  - %s:%s\n" "$CENSYS_ID" "$CENSYS_SECRET" >> "$sf_conf"
  fi
  if [ -n "$FOFA_EMAIL" ] && [ -n "$FOFA_KEY" ]; then
    printf "fofa:\n  - %s:%s\n" "$FOFA_EMAIL" "$FOFA_KEY" >> "$sf_conf"
  fi
  local keys_set
  keys_set=$(grep -c '  - ' "$sf_conf" 2>/dev/null || echo 0)
  success "subfinder config — ${keys_set} optional API sources configured"
}

setup_api_keys() {
  title "Optional API Keys Setup"
  panel_box "All keys are OPTIONAL — tool runs 100% free without them" \
    "Free APIs used by default:" \
    "  • internetdb.shodan.io — ports + CVEs (no key)" \
    "  • ip-api.com           — GeoIP + ASN  (no key)" \
    "  • bgpview.io           — BGP prefix   (no key)" \
    "  • crt.sh / hackertarget / otx / urlscan / riddler"
  echo ""
  local _fields=(
    "Shodan API Key        |SHODAN_KEY"
    "Censys API ID         |CENSYS_ID"
    "Censys API Secret     |CENSYS_SECRET"
    "GitHub Token          |GITHUB_TOKEN"
    "Hunter.io Key         |HUNTER_KEY"
    "VirusTotal Key        |VIRUSTOTAL_KEY"
    "URLScan.io Key        |URLSCAN_KEY"
    "AlienVault OTX Key    |OTX_KEY"
    "SecurityTrails Key    |SECURITYTRAILS_KEY"
    "FullHunt Key          |FULLHUNT_KEY"
    "Chaos Key             |CHAOS_KEY"
    "BeVigil Key           |BEVIGIL_KEY"
    "Fofa Email            |FOFA_EMAIL"
    "Fofa Key              |FOFA_KEY"
    "LeakIX Key            |LEAKIX_KEY"
  )
  for _f in "${_fields[@]}"; do
    local _label="${_f%%|*}" _var="${_f##*|}"
    local _cur="${!_var:-}"
    printf "\n  ${BOLD}%s${RESET}  ${DIM}(current: %s)${RESET}\n" "$_label" "${_cur:-(not set)}"
    read -rp "  → New value [Enter to skip]: " _inp
    [ -n "$_inp" ] && printf -v "$_var" '%s' "$_inp"
  done
  save_config
  build_subfinder_config
}

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  TOOL CHECK & AUTO-INSTALL                                           ║
# ╚══════════════════════════════════════════════════════════════════════╝

install_go_tool() {
  local name="$1" pkg="$2"
  already_failed "$name" && skip "${name} — skipped (failed previously)" && return 0
  info "Installing ${name} via go install..."
  if go install "$pkg" 2>/dev/null; then
    clear_failed "$name"; success "${name} installed"
  else
    mark_failed "$name"
    warn "${name} install failed — marked. Manual: go install ${pkg}"
  fi
  return 0
}

install_pip_tool() {
  local name="$1" pkg="$2"
  already_failed "pip_${name}" && skip "${name} — skipped (pip failed previously)" && return 0
  info "Installing ${name} via pip3..."
  if pip3 install "$pkg" --quiet 2>/dev/null; then
    clear_failed "pip_${name}"; success "${name} installed"
  else
    mark_failed "pip_${name}"; warn "${name} pip install failed"
  fi
  return 0
}

check_and_install_tools() {
  title "Tool Check & Auto-Install"

  declare -A GO_TOOLS=(
    [subfinder]="github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest"
    [assetfinder]="github.com/tomnomnom/assetfinder@latest"
    [shuffledns]="github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest"
    [dnsx]="github.com/projectdiscovery/dnsx/cmd/dnsx@latest"
    [naabu]="github.com/projectdiscovery/naabu/v2/cmd/naabu@latest"
    [httpx]="github.com/projectdiscovery/httpx/cmd/httpx@latest"
    [gau]="github.com/lc/gau/v2/cmd/gau@latest"
    [uro]="github.com/s0md3v/uro@latest"
    [katana]="github.com/projectdiscovery/katana/cmd/katana@latest"
    [nuclei]="github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
    [anew]="github.com/tomnomnom/anew@latest"
    [subzy]="github.com/PentestPad/subzy@latest"
  )

  local has_go=0; command -v go &>/dev/null && has_go=1

  for tool in "${!GO_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
      success "${tool} — present"
    elif [ "$has_go" -eq 1 ]; then
      install_go_tool "$tool" "${GO_TOOLS[$tool]}"
    else
      skip "${tool} — Go not found"
    fi
  done

  for tool in nmap jq curl git python3 wget openssl; do
    if command -v "$tool" &>/dev/null; then
      success "${tool} — present"
    elif command -v apt-get &>/dev/null; then
      sudo apt-get install -y "$tool" -qq 2>/dev/null \
        && success "${tool} installed" \
        || warn "${tool} apt install failed"
    fi
  done

  if ! command -v trufflehog &>/dev/null; then
    if ! already_failed "trufflehog"; then
      curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
        2>/dev/null | sudo sh -s -- -b /usr/local/bin 2>/dev/null \
        && success "trufflehog installed" \
        || { mark_failed "trufflehog"; warn "trufflehog install failed"; }
    else
      skip "trufflehog — previously failed"
    fi
  else
    success "trufflehog — present"
  fi

  if ! command -v js-beautify &>/dev/null; then
    if ! already_failed "js-beautify"; then
      if command -v npm &>/dev/null; then
        npm install -g js-beautify 2>/dev/null \
          && success "js-beautify installed" \
          || { mark_failed "js-beautify"; warn "js-beautify npm install failed"; }
      elif command -v pip3 &>/dev/null; then
        install_pip_tool "js-beautify" "jsbeautifier"
      fi
    else
      skip "js-beautify — previously failed"
    fi
  else
    success "js-beautify — present"
  fi

  for _pt in "shodan:shodan" "censys:censys" "theHarvester:theHarvester"; do
    local ptname="${_pt%%:*}" ptpkg="${_pt##*:}"
    command -v "$ptname" &>/dev/null \
      && success "${ptname} — present" \
      || install_pip_tool "$ptname" "$ptpkg"
  done

  if [ ! -f "$LINKFINDER_PY" ]; then
    if ! already_failed "linkfinder"; then
      sudo mkdir -p /opt/LinkFinder 2>/dev/null || mkdir -p /opt/LinkFinder
      git clone --quiet https://github.com/GerbenJavado/LinkFinder.git /opt/LinkFinder 2>/dev/null \
        && pip3 install -r /opt/LinkFinder/requirements.txt -q 2>/dev/null \
        && success "LinkFinder installed" \
        || { mark_failed "linkfinder"; warn "LinkFinder install failed"; }
    else
      skip "LinkFinder — previously failed"
    fi
  else
    success "linkfinder.py — present"
  fi

  if command -v nuclei &>/dev/null; then
    [ ! -d "$NUCLEI_TEMPLATES" ] && nuclei -update-templates 2>/dev/null || true
  fi

  if [ ! -f "$WORDLIST_SUBS" ]; then
    sudo mkdir -p "$(dirname "$WORDLIST_SUBS")" 2>/dev/null || true
    wget -q "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt" \
      -O "$WORDLIST_SUBS" 2>/dev/null || warn "SecLists wordlist download failed"
  fi

  build_subfinder_config

  LINKFINDER_OK=0;  [ -f "$LINKFINDER_PY" ] && command -v python3 &>/dev/null && LINKFINDER_OK=1
  JS_BEAUTIFY_OK=0; command -v js-beautify &>/dev/null && JS_BEAUTIFY_OK=1
  SHODAN_OK=0;      command -v shodan &>/dev/null && [ -n "$SHODAN_KEY" ] && SHODAN_OK=1
  CENSYS_OK=0;      command -v censys &>/dev/null && [ -n "$CENSYS_ID" ] && [ -n "$CENSYS_SECRET" ] && CENSYS_OK=1

  success "Tool check complete"
}

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  MODE SELECTION MENU                                                 ║
# ╚══════════════════════════════════════════════════════════════════════╝

select_mode() {
  local w=56
  local pad; printf -v pad "%$(( w - 2 ))s" ''
  local dbar="${pad// /${D_H}}"

  echo ""
  echo -e "  ${BY}${D_TL}${dbar}${D_TR}${RESET}"
  printf  "  ${BY}${D_V}${RESET}${BOLD}  %-$(( w - 2 ))s${RESET}${BY}${D_V}${RESET}\n" \
    "     SELECT RECONNAISSANCE MODE"
  echo -e "  ${BY}${D_ML}${dbar}${D_MR}${RESET}"
  printf  "  ${BY}${D_V}${RESET}  ${BC}[1]${RESET} ${BOLD}Passive${RESET}       — Phase 1: OSINT, subdomains, DNS only ${BY}${D_V}${RESET}\n"
  printf  "  ${BY}${D_V}${RESET}      ${DIM}(no active scans, safe, stealthy)${RESET}                  ${BY}${D_V}${RESET}\n"
  printf  "  ${BY}${D_V}${RESET}  ${BC}[2]${RESET} ${BOLD}Full Recon${RESET}    — Phases 1→3: Passive + Active + Vuln Scan ${BY}${D_V}${RESET}\n"
  printf  "  ${BY}${D_V}${RESET}      ${DIM}(ports, URLs, JS analysis, Nuclei)${RESET}                  ${BY}${D_V}${RESET}\n"
  printf  "  ${BY}${D_V}${RESET}  ${BC}[3]${RESET} ${BOLD}Setup API Keys${RESET} (optional — all free APIs)        ${BY}${D_V}${RESET}\n"
  echo -e "  ${BY}${D_BL}${dbar}${D_BR}${RESET}"
  echo ""
  read -rp "  Enter choice [1-3]: " RECON_MODE

  case "$RECON_MODE" in
    1) echo -e "  ${BC}[*]${RESET} Mode: ${BOLD}PASSIVE${RESET}" ;;
    2) echo -e "  ${BC}[*]${RESET} Mode: ${BOLD}FULL RECON${RESET}" ;;
    3) setup_api_keys; select_mode; return ;;
    *) echo -e "  ${BY}[!]${RESET} Invalid — defaulting to Mode 2"; RECON_MODE=2 ;;
  esac
  echo ""
}

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  POST-PROCESSING                                                     ║
# ╚══════════════════════════════════════════════════════════════════════╝

postprocess_outputs() {
  find "${OUT}" -type f \( -name "*.txt" -o -name "*.json" \) -empty -delete 2>/dev/null
}

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  CRITICAL PORTS AGGREGATION                                          ║
# ╚══════════════════════════════════════════════════════════════════════╝

CRITICAL_PORTS=(21 22 23 25 53 110 143 389 445 636 1433 1521 2049 2375 3306 3389 5432 5900 6379 8080 8443 27017)

aggregate_critical_assets() {
  local services_file="${OUT}/ports/services_info.txt"
  local critical_json="${OUT}/ports/critical_assets.json"
  local critical_tmp="${SCRIPT_TMPDIR}/critical_assets.txt"

  > "$critical_tmp"

  if [ ! -f "$services_file" ] || [ ! -s "$services_file" ]; then
    return 0
  fi

  # Parse nmap output for critical ports
  local current_ip=""
  local in_host=0
  local os_family=""

  while IFS= read -r _line; do
    # Extract IP from nmap header: Nmap scan report for 1.2.3.4 or hostname (1.2.3.4)
    if echo "$_line" | grep -q "^Nmap scan report for "; then
      current_ip=$(echo "$_line" | grep -oP '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1)
      os_family=""
      in_host=1
      continue
    fi

    # Check for critical port entry
    if [ -n "$current_ip" ] && echo "$_line" | grep -qE '^[0-9]+/tcp'; then
      local port
      port=$(echo "$_line" | cut -d'/' -f1)
      local is_critical=0
      for cp in "${CRITICAL_PORTS[@]}"; do
        if [ "$port" = "$cp" ]; then
          is_critical=1
          break
        fi
      done
      if [ "$is_critical" -eq 1 ]; then
        local service_name service_version
        # Typical nmap format: PORT/STATE SERVICE VERSION
        service_name=$(echo "$_line" | awk '{print $3}')
        service_version=$(echo "$_line" | awk '{$1=$2=$3=""; sub(/^[ \t]+/, ""); print}')
        echo "${current_ip}|${port}|${service_name}|${service_version}" >> "$critical_tmp"
      fi
    fi

    # OS detection
    if [ -n "$current_ip" ] && echo "$_line" | grep -qi "^OS details"; then
      os_family=$(echo "$_line" | sed 's/^OS details: //' | sed 's/ .*//')
    fi
    if [ -n "$current_ip" ] && echo "$_line" | grep -qi "^Aggressive OS guesses"; then
      os_family=$(echo "$_line" | sed 's/^Aggressive OS guesses: //' | sed 's/,.*//' | sed 's/ .*//')
    fi
  done < "$services_file"

  if [ ! -s "$critical_tmp" ]; then
    return 0
  fi

  # Build JSON array of critical assets
  python3 - <<PYEOF 2>/dev/null
import json
from collections import OrderedDict

assets = {}
try:
    with open("$critical_tmp") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            parts = line.split("|", 3)
            if len(parts) < 3:
                continue
            ip = parts[0]
            port = parts[1]
            svc = parts[2]
            ver = parts[3] if len(parts) > 3 else ""
            if ip not in assets:
                assets[ip] = {
                    "ip": ip,
                    "ports_open": [],
                    "services": {},
                    "domain_association": "$domain",
                    "os_detection": "Unknown",
                    "last_scanned": "$(date '+%Y-%m-%d')"
                }
            assets[ip]["ports_open"].append(int(port))
            assets[ip]["services"][port] = {
                "service_name": svc,
                "version": ver
            }

    result = sorted(assets.values(), key=lambda x: x["ip"])
    with open("$critical_json", "w") as out:
        json.dump(result, out, indent=2)

    count = len(result)
    with open("${SCRIPT_TMPDIR}/critical_count.txt", "w") as c:
        c.write(str(count))
    print(f"  {BG}[CRITICAL ASSETS] {count} IP(s) with critical ports → ports/critical_assets.json{RESET}")
except Exception as e:
    print(f"  {BY}[!] Error building critical assets JSON: {e}{RESET}")
PYEOF
}

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  MAIN ENTRY POINT & DOMAIN VALIDATION                                ║
# ╚══════════════════════════════════════════════════════════════════════╝

main() {
domain="${1:-}"
load_config

if [ -z "$domain" ]; then
  echo -e "${BR}[✘]${RESET} Usage: $0 <domain.com>" >&2
  exit 1
fi

domain=$(echo "$domain" \
  | sed 's|^https\?://||' \
  | sed 's|/.*||' \
  | sed 's|:.*||' \
  | tr '[:upper:]' '[:lower:]' \
  | xargs)

if ! echo "$domain" | grep -qE '^[a-z0-9]([a-z0-9_-]*\.)+[a-z]{2,}$'; then
  echo -e "${BR}[✘]${RESET} Invalid domain after sanitisation: '${domain}'" >&2
  exit 1
fi

show_banner
select_mode
check_and_install_tools

OUT="${BASE_DIR}/${domain}"
_base="${domain%%.*}"

LOG_FILE="${OUT}/0xrecon.log"
mkdir -p "${OUT}"/{subs,ports,alive,urls,js,params,nuclei,origin,interesting,recon}
mkdir -p "${OUT}/subs/interesting"
> "$LOG_FILE"

panel_box "Scan Configuration" \
  "Target  : ${domain}" \
  "Mode    : ${RECON_MODE}" \
  "Output  : ${OUT}/" \
  "Started : $(date '+%Y-%m-%d %H:%M:%S')" \
  "Log     : ${LOG_FILE}"
echo ""
echo -e "  ${DIM}Tip: tail -f ${LOG_FILE}${RESET}"
echo ""

if [ ! -f "$RESOLVERS" ]; then
  warn "Resolvers missing — downloading..."
  wget -q "https://raw.githubusercontent.com/janmasarik/resolvers/master/resolvers.txt" \
    -O "$RESOLVERS" 2>/dev/null || warn "Could not fetch resolvers — continuing without"
fi

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  PHASE 1 — PASSIVE RECONNAISSANCE (OSINT)                            ║
# ╚══════════════════════════════════════════════════════════════════════╝

title "PHASE 1 — Passive Reconnaissance (OSINT)"

# ── 1A. Subdomain Enumeration ─────────────────────────────────────────

touch "${OUT}/subs/all.txt"

if command -v subfinder &>/dev/null; then
  info "[subfinder] Multi-source passive enum..."
  subfinder -d "$domain" -all -silent -timeout 30 2>/dev/null \
    | grep -F ".${domain}" \
    | anew "${OUT}/subs/all.txt" > /dev/null; true
  success "subfinder → $(count "${OUT}/subs/all.txt") subs"
else
  skip "subfinder not available"
fi

if command -v assetfinder &>/dev/null; then
  info "[assetfinder] Asset-based passive..."
  assetfinder --subs-only "$domain" 2>/dev/null \
    | grep -F ".${domain}" \
    | anew "${OUT}/subs/all.txt" > /dev/null; true
  success "assetfinder → $(count "${OUT}/subs/all.txt") subs"
else
  skip "assetfinder not available"
fi

info "[crt.sh] Certificate transparency logs..."
{
  waf_curl "https://crt.sh/?q=%.${domain}&output=json" \
    | python3 -c "import sys,json; [print(x['name_value']) for x in json.load(sys.stdin)]" 2>/dev/null \
    || waf_curl "https://crt.sh/?q=%.${domain}&output=json" \
      | grep -oP '"name_value":"[^"]+"' | cut -d'"' -f4
} | sed 's/\*\.//g;s/\\n/\n/g' \
  | tr ',' '\n' \
  | grep -F ".${domain}" \
  | sort -u \
  | anew "${OUT}/subs/all.txt" > /dev/null; true
success "crt.sh → $(count "${OUT}/subs/all.txt") subs"

info "[hackertarget] Passive DNS..."
waf_curl "https://api.hackertarget.com/hostsearch/?q=${domain}" \
  | cut -d',' -f1 \
  | grep -F ".${domain}" \
  | anew "${OUT}/subs/all.txt" > /dev/null; true

info "[rapiddns] Free passive DNS..."
waf_curl "https://rapiddns.io/subdomain/${domain}?full=1&down=1" \
  | grep -oE "[a-zA-Z0-9._-]+\.${domain}" \
  | sort -u \
  | anew "${OUT}/subs/all.txt" > /dev/null; true

info "[bufferover] Passive TLS DNS..."
waf_curl "https://tls.bufferover.run/dns?q=.${domain}" \
  | python3 -c "import sys,json; d=json.load(sys.stdin); [print(x) for x in d.get('FDNS_A',[])+d.get('RDNS',[])]" 2>/dev/null \
  | cut -d',' -f2 \
  | grep -F ".${domain}" \
  | anew "${OUT}/subs/all.txt" > /dev/null; true

info "[urlscan] Historical scans..."
if [ -n "$URLSCAN_KEY" ]; then
  waf_curl "https://urlscan.io/api/v1/search/?q=domain:${domain}&size=10000" \
    -H "API-Key: ${URLSCAN_KEY}" \
    | grep -oE "[a-zA-Z0-9._-]+\.${domain}" | sort -u \
    | anew "${OUT}/subs/all.txt" > /dev/null; true
else
  waf_curl "https://urlscan.io/api/v1/search/?q=domain:${domain}&size=10000" \
    | grep -oE "[a-zA-Z0-9._-]+\.${domain}" | sort -u \
    | anew "${OUT}/subs/all.txt" > /dev/null; true
fi

info "[alienvault] OTX passive DNS..."
if [ -n "$OTX_KEY" ]; then
  waf_curl "https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns" \
    -H "X-OTX-API-KEY: ${OTX_KEY}" \
    | python3 -c "import sys,json; [print(x.get('hostname','')) for x in json.load(sys.stdin).get('passive_dns',[])]" 2>/dev/null \
    | grep -F ".${domain}" | anew "${OUT}/subs/all.txt" > /dev/null; true
else
  waf_curl "https://otx.alienvault.com/api/v1/indicators/domain/${domain}/passive_dns" \
    | python3 -c "import sys,json; [print(x.get('hostname','')) for x in json.load(sys.stdin).get('passive_dns',[])]" 2>/dev/null \
    | grep -F ".${domain}" | anew "${OUT}/subs/all.txt" > /dev/null; true
fi

if [ -n "$VIRUSTOTAL_KEY" ]; then
  info "[virustotal] Subdomain search..."
  waf_curl "https://www.virustotal.com/vtapi/v2/domain/report?apikey=${VIRUSTOTAL_KEY}&domain=${domain}" \
    | python3 -c "import sys,json; d=json.load(sys.stdin); [print(x) for x in d.get('subdomains',[])]" 2>/dev/null \
    | grep -F ".${domain}" | anew "${OUT}/subs/all.txt" > /dev/null; true
else
  skip "VirusTotal — set key in [3] for broader coverage (optional)"
fi

if [ -n "$FULLHUNT_KEY" ]; then
  info "[fullhunt] Subdomain discovery..."
  waf_curl "https://fullhunt.io/api/v1/domain/${domain}/subdomains" \
    -H "X-API-KEY: ${FULLHUNT_KEY}" \
    | python3 -c "import sys,json; [print(x) for x in json.load(sys.stdin).get('hosts',[])]" 2>/dev/null \
    | anew "${OUT}/subs/all.txt" > /dev/null; true
else
  skip "FullHunt — optional (set key in [3])"
fi

if [ -n "$LEAKIX_KEY" ]; then
  info "[leakix] Service discovery..."
  waf_curl "https://leakix.net/api/subdomains/${domain}" \
    -H "api-key: ${LEAKIX_KEY}" \
    | python3 -c "import sys,json; [print(x.get('subdomain','')) for x in json.load(sys.stdin)]" 2>/dev/null \
    | grep -F ".${domain}" | anew "${OUT}/subs/all.txt" > /dev/null; true
fi

info "[riddler] Free passive DNS..."
waf_curl "https://riddler.io/search/exportcsv?q=pld:${domain}" \
  | cut -d',' -f6 \
  | grep -F ".${domain}" \
  | anew "${OUT}/subs/all.txt" > /dev/null; true

if [ -n "$CHAOS_KEY" ] && command -v chaos &>/dev/null; then
  info "[chaos] ProjectDiscovery dataset..."
  chaos -d "$domain" -key "$CHAOS_KEY" -silent 2>/dev/null \
    | anew "${OUT}/subs/all.txt" > /dev/null; true
fi

if command -v shuffledns &>/dev/null && [ -f "$WORDLIST_SUBS" ] && [ -f "$RESOLVERS" ]; then
  info "[shuffledns] Active DNS bruteforce..."
  shuffledns -d "$domain" \
    -w "$WORDLIST_SUBS" -r "$RESOLVERS" \
    -mode bruteforce -silent 2>/dev/null \
    | anew "${OUT}/subs/all.txt" > /dev/null; true
  success "shuffledns done"
else
  skip "shuffledns/wordlist/resolvers not available"
fi

grep -F ".${domain}" "${OUT}/subs/all.txt" 2>/dev/null \
  | grep -v '^\*' \
  | grep -vE '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' \
  | sort -u > "${SCRIPT_TMPDIR}/subs_clean.txt" || touch "${SCRIPT_TMPDIR}/subs_clean.txt"
mv "${SCRIPT_TMPDIR}/subs_clean.txt" "${OUT}/subs/all.txt"

success "Phase 1A — Subdomain Enumeration → ${BG}$(count "${OUT}/subs/all.txt")${RESET} unique subdomains"

# ── 1B. DNS Resolution & Classification ────────────────────────────────

title "PHASE 1 — Continued: DNS Resolution & Classification"

info "[dnsx] Resolving A + CNAME records..."
dnsx -l "${OUT}/subs/all.txt" -a -cname -resp -silent 2>/dev/null \
  -o "${OUT}/subs/resolved_full.txt" || true

info "[dnsx] Building clean resolved list..."
dnsx -l "${OUT}/subs/all.txt" -silent 2>/dev/null | sort -u \
  > "${OUT}/subs/resolved.txt"
success "DNS done → ${BG}$(count "${OUT}/subs/resolved.txt")${RESET} live subdomains"

info "[dnsx] Extracting MX + TXT + NS records..."
dnsx -l "${OUT}/subs/all.txt" -mx  -silent 2>/dev/null > "${OUT}/subs/mx_records.txt"  || true
dnsx -l "${OUT}/subs/all.txt" -txt -silent 2>/dev/null > "${OUT}/subs/txt_records.txt" || true
grep -oE 'ip4:[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' "${OUT}/subs/txt_records.txt" 2>/dev/null \
  | cut -d: -f2 > "${OUT}/origin/spf_ips.txt" || touch "${OUT}/origin/spf_ips.txt"

info "[classify] Isolating high-value subdomains..."
declare -A INTERESTING_PATTERNS=(
  [dev]="^dev\.|\.dev\."     [staging]="stag|^stage\."    [uat]="^uat\.|\.uat\."
  [test]="^test\."            [preprod]="pre[-_]?prod"     [beta]="^beta\."
  [alpha]="^alpha\."          [old]="^old\.|\.old\."       [backup]="^bak\.|^backup\."
  [git]="^git\.|\.git\."     [svn]="^svn\."               [jenkins]="^jenkins\.|jenkins"
  [gitlab]="^gitlab\.|gitlab" [jira]="^jira\.|jira"        [admin]="^admin\.|\.admin\."
  [panel]="^panel\.|cpanel\." [api]="^api\.|\.api\."       [internal]="^internal\.|^intranet\."
  [vpn]="^vpn\.|^remote\."   [db]="^db\.|^database\.|^mysql\.|^redis\."
  [kibana]="^kibana\."        [grafana]="^grafana\.|^monitor\."
  [ftp]="^ftp\.|^sftp\."     [mail]="^mail\.|^smtp\.|^webmail\."
  [s3]="^s3\.|bucket|storage" [phpmyadmin]="phpmyadmin|pma\." [wp]="^wp\.|wordpress"
  [confluence]="confluence"   [sonar]="sonarqube"
)

> "${OUT}/interesting/high_value_all.txt"
for label in "${!INTERESTING_PATTERNS[@]}"; do
  pat="${INTERESTING_PATTERNS[$label]}"
  grep -iE "$pat" "${OUT}/subs/resolved.txt" 2>/dev/null \
    > "${OUT}/interesting/${label}.txt" || true
  local _cnt; _cnt=$(count "${OUT}/interesting/${label}.txt")
  if [ "$_cnt" -gt 0 ]; then
    printf "  ${BY}[!]${RESET} ${DIM}[%-12s]${RESET} ${BY}%s${RESET} high-value subdomains\n" "$label" "$_cnt"
    cat "${OUT}/interesting/${label}.txt" >> "${OUT}/interesting/high_value_all.txt"
  fi
done
sort -u "${OUT}/interesting/high_value_all.txt" -o "${OUT}/interesting/high_value_all.txt"
success "High-value subdomains → ${BY}$(count "${OUT}/interesting/high_value_all.txt")${RESET} total"

# ── 1C. Subdomain Takeover Check ──────────────────────────────────────

title "PHASE 1 — Continued: Subdomain Takeover Check"

if command -v subzy &>/dev/null; then
  info "[subzy] Checking for takeover vulnerabilities..."
  subzy run \
    --targets "${OUT}/subs/resolved.txt" \
    --concurrency 20 --verify \
    --output "${OUT}/takeover/takeover_raw.json" 2>/dev/null || true

  if [ -f "${OUT}/takeover/takeover_raw.json" ] && [ -s "${OUT}/takeover/takeover_raw.json" ]; then
    jq -r '.[] | select(.vulnerable == true) | "\(.subdomain)  →  \(.service)  [\(.status)]"' \
      "${OUT}/takeover/takeover_raw.json" 2>/dev/null \
      > "${OUT}/takeover/vulnerable.txt" || true
  fi

  local _tk; _tk=$(count "${OUT}/takeover/vulnerable.txt")
  if [ "$_tk" -gt 0 ]; then
    find_high "TAKEOVER: ${_tk} vulnerable → takeover/vulnerable.txt"
    while IFS= read -r line; do find_critical "$line"; done < "${OUT}/takeover/vulnerable.txt"
  else
    find_ok "No subdomain takeovers detected"
  fi
else
  skip "subzy not available"
fi

# ── 1D. Origin IP Discovery ───────────────────────────────────────────

title "PHASE 1 — Continued: Origin IP Discovery & IP Intelligence"

ORIGIN_FILE="${OUT}/origin/candidate_ips.txt"
> "$ORIGIN_FILE"

[ -f "${OUT}/origin/spf_ips.txt" ] && cat "${OUT}/origin/spf_ips.txt" | anew "$ORIGIN_FILE" > /dev/null

info "[1] HackerTarget — historical DNS..."
waf_curl "https://api.hackertarget.com/hostsearch/?q=${domain}" \
  | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
  | anew "$ORIGIN_FILE" > /dev/null; true

info "[2] SecurityTrails — passive DNS..."
waf_curl "https://securitytrails.com/domain/${domain}/history/a" \
  | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
  | anew "$ORIGIN_FILE" > /dev/null; true

info "[3] ViewDNS — IP history..."
waf_curl "https://viewdns.info/iphistory/?domain=${domain}" \
  | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
  | anew "$ORIGIN_FILE" > /dev/null; true

info "[4] DNSDumpster — passive DNS..."
local _csrf_tmp="${SCRIPT_TMPDIR}/csrf.tmp"
waf_curl "https://dnsdumpster.com" | grep -oE "csrf_token[^']*'[^']*'" 2>/dev/null > "$_csrf_tmp" || true
if [ -s "$_csrf_tmp" ]; then
  local _csrf; _csrf=$(grep -oP "value='[^']+'" "$_csrf_tmp" | head -1 | cut -d"'" -f2)
  [ -n "$_csrf" ] && waf_curl "https://dnsdumpster.com" \
    -X POST -d "csrfmiddlewaretoken=${_csrf}&targetip=${domain}" \
    -H "Referer: https://dnsdumpster.com" \
    | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
    | anew "$ORIGIN_FILE" > /dev/null; true
fi

if [ "$SHODAN_OK" -eq 1 ]; then
  info "[5] Shodan CLI — certificate + hostname search..."
  shodan search --fields ip_str "ssl.cert.subject.cn:\"${domain}\"" 2>/dev/null \
    | anew "$ORIGIN_FILE" > /dev/null; true
  shodan search --fields ip_str "hostname:\"${domain}\"" 2>/dev/null \
    | anew "$ORIGIN_FILE" > /dev/null; true
else
  skip "[5] Shodan CLI — no key set (InternetDB free enrichment used below)"
fi

if [ "$CENSYS_OK" -eq 1 ]; then
  info "[6] Censys — certificate search..."
  censys search "parsed.names: ${domain}" --fields ip 2>/dev/null \
    | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
    | anew "$ORIGIN_FILE" > /dev/null; true
else
  skip "[6] Censys — no key set (optional)"
fi

info "[7] dig — direct DNS lookups..."
for _sub in mail ftp smtp pop imap ns1 ns2 cpanel autodiscover; do
  dig +short "${_sub}.${domain}" 2>/dev/null \
    | grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' \
    | anew "$ORIGIN_FILE" > /dev/null; true
done

> "${OUT}/origin/non_cdn_ips.txt"
while IFS= read -r _ip; do
  is_cdn_ip "$_ip" || echo "$_ip" >> "${OUT}/origin/non_cdn_ips.txt"
done < "$ORIGIN_FILE"

local _orig_count; _orig_count=$(count "${OUT}/origin/non_cdn_ips.txt")
[ "$_orig_count" -gt 0 ] \
  && warn "${_orig_count} candidate origin IPs (non-CDN) → origin/non_cdn_ips.txt" \
  || info "No non-CDN origin IPs found via passive methods."

if [ -s "${OUT}/origin/non_cdn_ips.txt" ]; then
  info "[probe] Probing origin IPs directly with Host header..."
  > "${OUT}/origin/direct_responses.txt"
  while IFS= read -r _ip; do
    local _https; _https=$(curl -sk --max-time 8 \
      -H "Host: ${domain}" -A "$(random_ua)" -o /dev/null -w "%{http_code}" \
      "https://${_ip}/" 2>/dev/null || echo "000")
    local _http; _http=$(curl -sk --max-time 8 \
      -H "Host: ${domain}" -A "$(random_ua)" -o /dev/null -w "%{http_code}" \
      "http://${_ip}/"  2>/dev/null || echo "000")
    echo "${_ip} — HTTPS:${_https}  HTTP:${_http}" >> "${OUT}/origin/direct_responses.txt"
    step "${_ip} → HTTPS:${_https} HTTP:${_http}"
  done < "${OUT}/origin/non_cdn_ips.txt"
fi

info "[InternetDB] — ports + CVEs per IP (no key)..."
touch "${OUT}/origin/cve_findings.txt"
local _idb_count=0
while IFS= read -r _ip; do
  [ -z "$_ip" ] && continue
  [ "$_idb_count" -ge 10 ] && break
  internetdb_lookup "$_ip"
  _idb_count=$(( _idb_count + 1 ))
  sleep 0.5
done < "${OUT}/origin/non_cdn_ips.txt"

info "[ip-api] GeoIP + ASN + hosting flag (free)..."
while IFS= read -r _ip; do
  [ -z "$_ip" ] && continue
  ipapi_lookup "$_ip"
  sleep 1.5
done < "${OUT}/origin/non_cdn_ips.txt"

info "[BGPView] ASN + BGP prefix (free)..."
while IFS= read -r _ip; do
  [ -z "$_ip" ] && continue
  bgpview_lookup "$_ip"
  sleep 0.5
done < "${OUT}/origin/non_cdn_ips.txt"

# ── Passive mode ends here ─────────────────────────────────────────────
if [ "$RECON_MODE" -eq 1 ]; then
  success "Phase 1 — Passive Recon complete."
  info "Results → ${OUT}/subs/  &  ${OUT}/origin/  &  ${OUT}/interesting/"
  postprocess_outputs
  exit 0
fi

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  PHASE 2 — ACTIVE RECONNAISSANCE                                     ║
# ╚══════════════════════════════════════════════════════════════════════╝

title "PHASE 2 — Active Reconnaissance"

# ── 2A. Port Scanning ─────────────────────────────────────────────────

title "PHASE 2 — 2A: Port Scanning (naabu + nmap)"

info "[naabu] Fast top-1000 port scan..."
naabu \
  -list "${OUT}/subs/resolved.txt" \
  -top-ports 1000 -c 20 -rate 300 \
  -silent 2>/dev/null \
  -o "${OUT}/ports/open_ports.txt" || true
success "naabu → ${BG}$(count "${OUT}/ports/open_ports.txt")${RESET} open ports"

info "[nmap] Service & version detection..."
{
  echo "# 0xRecon — Nmap Service Detection"
  echo "# Target: ${domain}"
  echo "# Date: $(date)"
  echo ""
} > "${OUT}/ports/services_info.txt"

if [ -f "${OUT}/ports/open_ports.txt" ] && [ -s "${OUT}/ports/open_ports.txt" ]; then
  declare -A host_ports_map
  while IFS=: read -r _h _p; do
    [ -z "$_h" ] || [ -z "$_p" ] && continue
    if [ -n "${host_ports_map[$_h]+_}" ]; then
      host_ports_map[$_h]="${host_ports_map[$_h]},${_p}"
    else
      host_ports_map[$_h]="${_p}"
    fi
  done < "${OUT}/ports/open_ports.txt"

  local _nmap_count=0
  for _host in "${!host_ports_map[@]}"; do
    _ports="${host_ports_map[$_host]}"
    step "nmap -sV -sC -T3 -p ${_ports} ${_host}"
    nmap -sV -sC -T3 --open \
      --script-timeout 10s \
      -p "$_ports" "$_host" \
      -oN - 2>/dev/null \
      | sed "s/^/[${_host}] /" \
      >> "${OUT}/ports/services_info.txt" || true
    _nmap_count=$(( _nmap_count + 1 ))
    sleep 1
  done
  success "nmap done → ${_nmap_count} hosts scanned"

  # ── Critical Ports Aggregation ──────────────────────────────────────
  aggregate_critical_assets
else
  warn "No open ports found — nmap skipped"
fi

# ── 2B. HTTP Probing & Tech Detection ─────────────────────────────────

title "PHASE 2 — 2B: HTTP Probing & Technology Detection"

info "[httpx] Probing all subdomains..."
httpx \
  -l "${OUT}/subs/resolved.txt" \
  -follow-redirects -random-agent \
  -rl 5 -timeout 10 -silent 2>/dev/null \
  -o "${OUT}/alive/hosts.txt" || true
success "httpx → ${BG}$(count "${OUT}/alive/hosts.txt")${RESET} live HTTP hosts"

info "[httpx] Detailed scan (status, title, tech-detect)..."
httpx \
  -l "${OUT}/alive/hosts.txt" \
  -status-code -title -tech-detect -content-length \
  -follow-redirects -random-agent -rl 5 -silent 2>/dev/null \
  -o "${OUT}/alive/hosts_detailed.txt" || true

grep -i "block override\|web filter\|forbidden\|access denied" \
  "${OUT}/alive/hosts_detailed.txt" 2>/dev/null \
  > "${OUT}/alive/waf_blocked.txt" || true
grep -v -i "block override\|web filter\|forbidden\|access denied" \
  "${OUT}/alive/hosts.txt" 2>/dev/null \
  > "${OUT}/alive/hosts_clean.txt" || cp "${OUT}/alive/hosts.txt" "${OUT}/alive/hosts_clean.txt"

local _waf; _waf=$(count "${OUT}/alive/waf_blocked.txt")
[ "$_waf" -gt 0 ] && warn "${_waf} hosts blocked by WAF → alive/waf_blocked.txt"

grep -iE '(dev\.|staging\.|uat\.|admin\.|jenkins\.|git\.|api\.|internal\.|backup\.|test\.)' \
  "${OUT}/alive/hosts_clean.txt" 2>/dev/null \
  > "${OUT}/alive/hosts_interesting.txt" || true
local _hi; _hi=$(count "${OUT}/alive/hosts_interesting.txt")
[ "$_hi" -gt 0 ] && warn "${_hi} interesting live hosts → alive/hosts_interesting.txt"

if [ -s "${OUT}/alive/hosts_clean.txt" ]; then
  info "[headers] Grading security headers..."
  echo ""
  printf "  ${BOLD}${BC}%-45s  %-10s  %s${RESET}\n" "Host" "Grade" "Headers"
  hline "─" 70
  touch "${OUT}/recon/missing_headers.txt"
  touch "${OUT}/recon/header_disclosures.txt"
  touch "${OUT}/recon/headers_grade.txt"
  local _hc=0
  while IFS= read -r _hurl; do
    [ "$_hc" -ge 10 ] && break
    http_headers_check "$_hurl"
    _hc=$(( _hc + 1 ))
    sleep 0.3
  done < "${OUT}/alive/hosts_clean.txt"
  echo ""
  success "Headers check → $(count "${OUT}/recon/headers_grade.txt") hosts graded"
fi

info "[ssl] Checking SSL certificate expiry..."
ssl_cert_check "$domain"

if [ ! -s "${OUT}/alive/hosts_clean.txt" ]; then
  warn "No accessible hosts after WAF filtering. Skipping URL/JS/Email phases."
  postprocess_outputs
  exit 0
fi

# ── 2C. URL Collection & Crawling ─────────────────────────────────────

title "PHASE 2 — 2C: URL Collection & Crawling"

info "[gau] Historical URL archive..."
sed -E 's|https?://||' "${OUT}/alive/hosts_clean.txt" \
  | xargs -I{} -P5 gau --threads 3 {} 2>/dev/null \
  | sort -u | anew "${OUT}/urls/gau.txt" > /dev/null; true

info "[katana] Live crawl (JS eval, XHR, depth 4)..."
katana \
  -list "${OUT}/alive/hosts_clean.txt" \
  -d 4 -jsl -xhr -rl 5 -random-agent -silent 2>/dev/null \
  -o "${OUT}/urls/katana.txt" || true

info "[uro] Merging + deduplication..."
cat "${OUT}/urls/gau.txt" "${OUT}/urls/katana.txt" 2>/dev/null \
  | sort -u | uro > "${OUT}/urls/all_urls.txt" 2>/dev/null || \
  cat "${OUT}/urls/gau.txt" "${OUT}/urls/katana.txt" 2>/dev/null \
  | sort -u > "${OUT}/urls/all_urls.txt"

grep -E '\.(php|asp|aspx|jsp|cfm|cgi)(\?|$)'           "${OUT}/urls/all_urls.txt" > "${OUT}/urls/dynamic.txt"       2>/dev/null || true
grep -E '\.php(\?|$)'                                    "${OUT}/urls/all_urls.txt" > "${OUT}/urls/php_endpoints.txt" 2>/dev/null || true
grep '\?'                                                 "${OUT}/urls/all_urls.txt" > "${OUT}/urls/with_params.txt"  2>/dev/null || true
grep '\?'                                                 "${OUT}/urls/gau.txt"      | sort -u > "${OUT}/params/all_params.txt" 2>/dev/null || true
grep -Ei '\.(js)([/?]|$)'                                 "${OUT}/urls/all_urls.txt" | sort -u | head -n 300 > "${OUT}/js/js_urls.txt" 2>/dev/null || true
grep -iE '/(api|v[0-9]|rest|graphql|grpc)/'              "${OUT}/urls/all_urls.txt" > "${OUT}/urls/api_endpoints.txt" 2>/dev/null || true
grep -iE '\.(env|config|conf|cfg|bak|backup|sql|log|xml|json|yaml|yml|git|svn|htpasswd|htaccess)(\?|$)' \
  "${OUT}/urls/all_urls.txt" > "${OUT}/urls/sensitive_extensions.txt" 2>/dev/null || true
grep -iE '(admin|manager|dashboard|phpmyadmin|wp-admin|cpanel|webmail|jenkins|gitlab|console|debug)' \
  "${OUT}/urls/all_urls.txt" > "${OUT}/urls/admin_panels.txt" 2>/dev/null || true

echo ""
printf "  ${BOLD}${BC}%-28s  ${BY}%s${RESET}\n" "Category" "Count"
hline "─" 38
printf "  ${DIM}%-28s${RESET}  ${BW}%s${RESET}\n" "All URLs"          "$(count "${OUT}/urls/all_urls.txt")"
printf "  ${DIM}%-28s${RESET}  ${BR}%s${RESET}\n" "PHP endpoints"     "$(count "${OUT}/urls/php_endpoints.txt")"
printf "  ${DIM}%-28s${RESET}  ${BY}%s${RESET}\n" "Dynamic pages"     "$(count "${OUT}/urls/dynamic.txt")"
printf "  ${DIM}%-28s${RESET}  ${BW}%s${RESET}\n" "Parameterized URLs""$(count "${OUT}/urls/with_params.txt")"
printf "  ${DIM}%-28s${RESET}  ${BC}%s${RESET}\n" "JS files"          "$(count "${OUT}/js/js_urls.txt")"
printf "  ${DIM}%-28s${RESET}  ${BC}%s${RESET}\n" "API endpoints"     "$(count "${OUT}/urls/api_endpoints.txt")"
printf "  ${DIM}%-28s${RESET}  ${BR}%s${RESET}\n" "Sensitive files"   "$(count "${OUT}/urls/sensitive_extensions.txt")"
printf "  ${DIM}%-28s${RESET}  ${BY}%s${RESET}\n" "Admin panels"      "$(count "${OUT}/urls/admin_panels.txt")"
hline "─" 38
echo ""

# ── 2D. JS Analysis ──────────────────────────────────────────────────

title "PHASE 2 — 2D: JavaScript Analysis"

if [ ! -s "${OUT}/js/js_urls.txt" ]; then
  warn "No JS files found — skipping JS analysis."
else
  JS_WORK="${SCRIPT_TMPDIR}/js_work"
  mkdir -p "$JS_WORK"
  JS_TOTAL=$(count "${OUT}/js/js_urls.txt")
  info "Processing ${JS_TOTAL} JS files..."
  local _js_idx=0

  while IFS= read -r _jsurl; do
    [ -z "$_jsurl" ] && continue
    _js_idx=$(( _js_idx + 1 ))
    progress_bar "$_js_idx" "$JS_TOTAL" "$(basename "$_jsurl")"
    (
      local _label; _label=$(echo "$_jsurl" | grep -oP '[^/?#]+\.js' | head -1 || echo "noname.js")
      local _jid="${BASHPID}"
      local _raw="${JS_WORK}/raw_${_jid}.js"
      local _pretty="${JS_WORK}/pretty_${_jid}.js"
      waf_curl "$_jsurl" -H "Referer: https://${domain}/" -o "$_raw" || exit 0
      [ ! -s "$_raw" ] && exit 0
      if [ "${JS_BEAUTIFY_OK}" -eq 1 ]; then
        js-beautify --indent-size 2 --wrap-line-length 0 "$_raw" > "$_pretty" 2>/dev/null \
          || cp "$_raw" "$_pretty"
      else
        cp "$_raw" "$_pretty"
      fi
      if [ "${LINKFINDER_OK}" -eq 1 ]; then
        python3 "$LINKFINDER_PY" -i "$_pretty" -o cli 2>/dev/null \
          | grep -v '^$\|Usage:\|Error:' \
          | sed "s|^|[${_label}] |" \
          >> "${JS_WORK}/links_${_jid}.txt" || true
      fi
      trufflehog filesystem "$_pretty" --json --no-update 2>/dev/null \
        | sed "s|^|[${_label}] |" \
        >> "${JS_WORK}/secrets_${_jid}.txt" || true
      grep -oE '(api[_-]?key|secret|password|token|bearer|aws_|AKIA)[A-Za-z0-9_\/+=]{10,}' \
        "$_pretty" 2>/dev/null \
        | sed "s|^|[${_label}][REGEX] |" \
        >> "${JS_WORK}/secrets_${_jid}.txt" || true
    ) &
    while [ "$(jobs -r | wc -l)" -ge 10 ]; do sleep 0.5; done
  done < "${OUT}/js/js_urls.txt"
  wait || true
  echo ""

  cat "${JS_WORK}"/links_*.txt   2>/dev/null | grep -v '^$' | sort -u > "${OUT}/js/linkfinder.txt"   || true
  cat "${JS_WORK}"/secrets_*.txt 2>/dev/null | grep -v '^$'           > "${OUT}/js/secrets.txt"      || true

  success "LinkFinder → $(count "${OUT}/js/linkfinder.txt") endpoints extracted"
  local _sec_count; _sec_count=$(count "${OUT}/js/secrets.txt")
  if [ "$_sec_count" -gt 0 ]; then
    find_critical "SECRETS FOUND (${_sec_count}) → js/secrets.txt  ⚠ ROTATE CREDENTIALS NOW"
  else
    find_ok "No secrets or tokens found in JS files"
  fi
fi

# ── 2E. Email Harvesting ─────────────────────────────────────────────

title "PHASE 2 — 2E: Email Harvesting"

if command -v theHarvester &>/dev/null; then
  step "theHarvester -d ${domain} -b bing,certspotter,hackertarget,urlscan,crtsh..."
  theHarvester -d "$domain" \
    -b bing,certspotter,hackertarget,urlscan,crtsh \
    -l 500 -f "${SCRIPT_TMPDIR}/harvester_raw" 2>/dev/null || true
  if [ -f "${SCRIPT_TMPDIR}/harvester_raw.xml" ]; then
    grep -oP '(?<=<email>)[^<]+' "${SCRIPT_TMPDIR}/harvester_raw.xml" 2>/dev/null \
      | sort -u > "${OUT}/recon/emails_harvester.txt" || true
  fi
else
  skip "theHarvester not available"
fi

info "[hackertarget] Email finder..."
hackertarget_emails "$domain" \
  | sort -u > "${OUT}/recon/emails_hackertarget.txt" 2>/dev/null || true

info "[crt.sh] Email scrape from certificate data..."
waf_curl "https://crt.sh/?q=${domain}&output=json" \
  | jq -r '.[].name_value' 2>/dev/null \
  | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' \
  | sort -u > "${OUT}/recon/emails_crtsh.txt" 2>/dev/null || true

if [ -n "$HUNTER_KEY" ]; then
  info "[hunter.io] Email search..."
  waf_curl "https://api.hunter.io/v2/domain-search?domain=${domain}&api_key=${HUNTER_KEY}&limit=100" \
    | jq -r '.data.emails[].value' 2>/dev/null \
    | sort -u > "${OUT}/recon/emails_hunter.txt" || true
else
  skip "Hunter.io — optional key (free alternatives used above)"
fi

cat "${OUT}/recon/emails_harvester.txt" \
    "${OUT}/recon/emails_hackertarget.txt" \
    "${OUT}/recon/emails_crtsh.txt" \
    "${OUT}/recon/emails_hunter.txt" \
    2>/dev/null \
  | grep -iF "@${domain}" | sort -u > "${OUT}/recon/emails.txt" || true

cat "${OUT}/recon/emails_harvester.txt" \
    "${OUT}/recon/emails_hackertarget.txt" \
    "${OUT}/recon/emails_crtsh.txt" \
    "${OUT}/recon/emails_hunter.txt" \
    2>/dev/null | sort -u > "${OUT}/recon/emails_all.txt" || true

success "Email harvesting → ${BC}$(count "${OUT}/recon/emails.txt")${RESET} @${domain}  |  ${BC}$(count "${OUT}/recon/emails_all.txt")${RESET} total"

# ── 2F. Wayback Machine ──────────────────────────────────────────────

title "PHASE 2 — 2F: Wayback Machine"

info "[wayback] Fetching historical robots.txt..."
waf_curl "https://web.archive.org/cdx/search/cdx?url=${domain}/robots.txt&output=text&fl=timestamp,original&limit=5&collapse=digest" \
  | while read -r _ts _url_wb; do
      [ -z "$_ts" ] && continue
      waf_curl "https://web.archive.org/web/${_ts}/${_url_wb}" \
        | grep -iE '^(Disallow|Allow|Sitemap):' \
        | sed "s|^|[robots@${_ts}] |"
    done 2>/dev/null \
  > "${OUT}/recon/wayback_robots.txt" || true

grep -i 'Disallow:' "${OUT}/recon/wayback_robots.txt" 2>/dev/null \
  | grep -oP 'Disallow:\s*\K\S+' | grep -v '^\*$' | sort -u \
  > "${OUT}/recon/robots_disallow.txt" || true

if [ -s "${OUT}/recon/robots_disallow.txt" ]; then
  while IFS= read -r _path; do
    echo "https://${domain}${_path}"
  done < "${OUT}/recon/robots_disallow.txt" > "${OUT}/recon/robots_disallow_urls.txt"
  cat "${OUT}/recon/robots_disallow_urls.txt" | anew "${OUT}/urls/all_urls.txt" > /dev/null; true
fi

info "[wayback] CDX full URL dump..."
waf_curl "https://web.archive.org/cdx/search/cdx?url=*.${domain}/*&output=text&fl=original&collapse=urlkey&limit=50000" \
  | grep -v '^$' \
  | grep -viE '\.(css|png|jpg|jpeg|gif|ico|woff|woff2|svg|ttf|eot)(\?|$)' \
  | sort -u \
  > "${OUT}/recon/wayback_all_urls.txt" || true
[ -s "${OUT}/recon/wayback_all_urls.txt" ] && \
  cat "${OUT}/recon/wayback_all_urls.txt" | anew "${OUT}/urls/all_urls.txt" > /dev/null; true

# ── 2G. Cloud Bucket Enumeration ─────────────────────────────────────

title "PHASE 2 — 2G: Cloud Bucket Enumeration"

info "[buckets] Probing name permutations across AWS/Azure/GCS..."

declare -a BUCKET_PERMS=(
  "$_base" "${_base}-dev" "${_base}-staging" "${_base}-prod"
  "${_base}-backup" "${_base}-data" "${_base}-assets" "${_base}-static"
  "${_base}-media" "${_base}-cdn" "${_base}-logs" "${_base}-admin"
  "${_base}-uploads" "${_base}-files" "${_base}-images" "${_base}-archive"
  "${_base}-test" "${_base}-uat" "${_base}.com"
  "dev-${_base}" "staging-${_base}" "backup-${_base}"
  "assets-${_base}" "static-${_base}" "cdn-${_base}"
)

declare -A BUCKET_PROVIDERS=(
  [s3]="https://%s.s3.amazonaws.com"
  [s3_us]="https://%s.s3.us-east-1.amazonaws.com"
  [azure]="https://%s.blob.core.windows.net"
  [gcs]="https://storage.googleapis.com/%s"
  [do]="https://%s.nyc3.digitaloceanspaces.com"
)

> "${OUT}/recon/buckets_open.txt"
> "${OUT}/recon/buckets_all.txt"

local _bucket_total=$(( ${#BUCKET_PERMS[@]} * ${#BUCKET_PROVIDERS[@]} ))
local _bi=0

for _name in "${BUCKET_PERMS[@]}"; do
  for _prov in "${!BUCKET_PROVIDERS[@]}"; do
    _bi=$(( _bi + 1 ))
    progress_bar "$_bi" "$_bucket_total" "${_name} @ ${_prov}"
    local _burl; _burl=$(printf "${BUCKET_PROVIDERS[$_prov]}" "$_name")
    local _code
    _code=$(curl -sk --max-time 8 -A "$(random_ua)" \
      -o /dev/null -w "%{http_code}" "$_burl" 2>/dev/null || echo "000")
    echo "[${_prov}] ${_burl} → ${_code}" >> "${OUT}/recon/buckets_all.txt"
    case "$_code" in
      200)
        local _body; _body=$(waf_curl "$_burl" | head -c 500)
        if echo "$_body" | grep -qiE 'ListBucketResult|<Contents>|<Blobs>'; then
          find_critical "[BUCKET-OPEN-LIST] ${_burl} — PUBLIC LISTING ENABLED"
          echo "[OPEN-LIST] ${_burl}" >> "${OUT}/recon/buckets_open.txt"
        else
          echo "[OPEN-NLIST] ${_burl}" >> "${OUT}/recon/buckets_open.txt"
          find_medium "[BUCKET-200] ${_burl} — accessible (no directory listing)"
        fi
        ;;
      404)
        if waf_curl "$_burl" | grep -qiE 'NoSuchBucket|does not exist'; then
          echo "[TAKEOVER?] ${_burl}" >> "${OUT}/recon/buckets_open.txt"
          find_low "[BUCKET-TAKEOVER?] ${_burl}"
        fi
        ;;
    esac
    sleep 0.15
  done
done
echo ""

local _open; _open=$(count "${OUT}/recon/buckets_open.txt")
[ "$_open" -gt 0 ] \
  && warn "${_open} bucket findings → recon/buckets_open.txt" \
  || find_ok "Bucket check complete — no open or claimable buckets"

# ── 2H. GitHub Dorking ───────────────────────────────────────────────

title "PHASE 2 — 2H: GitHub Dorking"

declare -a GH_DORKS=(
  "${domain} password"           "${domain} secret"
  "${domain} api_key"            "${domain} apikey"
  "${domain} token"              "${domain} DB_PASSWORD"
  "${domain} db_pass"            "${domain} connectionstring"
  "${domain} SMTP_PASS"          "${domain} private_key"
  "${domain} BEGIN RSA"          "${domain} filename:.env"
  "${domain} filename:config.php"       "${domain} filename:database.yml"
  "${domain} filename:wp-config.php"    "${domain} filename:.htpasswd"
  "${domain} filename:id_rsa"           "${domain} filename:credentials"
  "${_base} internal"                   "${_base} staging password"
)

> "${OUT}/recon/github_findings.txt"

[ -z "$GITHUB_TOKEN" ] && warn "GITHUB_TOKEN not set — rate limited to 10 req/min"

info "[github] Dorking ${#GH_DORKS[@]} queries..."
local _gh_count=0

for _dork in "${GH_DORKS[@]}"; do
  local _encoded
  _encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${_dork}'))" 2>/dev/null \
    || echo "$_dork" | sed 's| |+|g')
  local _result
  _result=$(curl -sk --max-time 15 \
    -H "Accept: application/vnd.github.v3+json" \
    ${GITHUB_TOKEN:+-H "Authorization: token ${GITHUB_TOKEN}"} \
    -A "$(random_ua)" \
    "https://api.github.com/search/code?q=${_encoded}&per_page=5" 2>/dev/null || true)
  local _total
  _total=$(echo "$_result" | jq -r '.total_count' 2>/dev/null || echo "0")
  [ "$_total" = "null" ] || [ -z "$_total" ] && _total=0
  if [ "$_total" -gt 0 ] 2>/dev/null; then
    warn "[GH-FOUND] \"${_dork}\" → ${_total} results"
    echo "$_result" | jq -r '.items[]? | "[\(.repository.full_name)] \(.path) — \(.html_url)"' 2>/dev/null \
      | sed "s|^|[DORK: ${_dork}] |" \
      >> "${OUT}/recon/github_findings.txt" || true
    _gh_count=$(( _gh_count + 1 ))
  fi
  [ -z "$GITHUB_TOKEN" ] && sleep 7 || sleep 2
done

local _gf; _gf=$(count "${OUT}/recon/github_findings.txt")
[ "$_gf" -gt 0 ] \
  && find_high "${_gf} GitHub exposures → recon/github_findings.txt" \
  || find_ok "GitHub dork done — no exposed repositories found"

success "Phase 2 — Active Recon complete."

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  PHASE 3 — HEAVY VULNERABILITY SCANNING (NUCLEI)                     ║
# ╚══════════════════════════════════════════════════════════════════════╝

title "PHASE 3 — Heavy Vulnerability Scanning (Nuclei)"

touch "${OUT}/nuclei/results.txt"
N_FLAGS="-rl 6 -c 8 -bulk-size 4 -timeout 15 -retries 1 -no-interactsh -no-color -silent"

if [ -s "${OUT}/alive/hosts_clean.txt" ]; then
  info "[nuclei] Misconfig/Exposure on live hosts..."
  nuclei -l "${OUT}/alive/hosts_clean.txt" \
    -tags "misconfig,exposure,default-login,takeover,headers,cors" \
    -severity medium,high,critical \
    $N_FLAGS \
    -o "${SCRIPT_TMPDIR}/nuclei_a.txt" 2>/dev/null || true
  cat "${SCRIPT_TMPDIR}/nuclei_a.txt" >> "${OUT}/nuclei/results.txt" 2>/dev/null || true
  success "Nuclei A → $(count "${SCRIPT_TMPDIR}/nuclei_a.txt") findings"
fi

if [ -s "${OUT}/urls/php_endpoints.txt" ]; then
  info "[nuclei] Tech detection on PHP endpoints..."
  nuclei -l "${OUT}/urls/php_endpoints.txt" \
    -tags "exposure,tech,php,config" \
    -severity low,medium,high,critical \
    $N_FLAGS \
    -o "${SCRIPT_TMPDIR}/nuclei_b.txt" 2>/dev/null || true
  cat "${SCRIPT_TMPDIR}/nuclei_b.txt" >> "${OUT}/nuclei/results.txt" 2>/dev/null || true
  success "Nuclei B → $(count "${SCRIPT_TMPDIR}/nuclei_b.txt") findings"
fi

if [ -s "${OUT}/js/linkfinder.txt" ]; then
  grep -oE 'https?://[^ ]+' "${OUT}/js/linkfinder.txt" | sort -u \
    > "${SCRIPT_TMPDIR}/nuclei_c_targets.txt"
  if [ -s "${SCRIPT_TMPDIR}/nuclei_c_targets.txt" ]; then
    info "[nuclei] Exposure scan on JS-extracted endpoints..."
    nuclei -l "${SCRIPT_TMPDIR}/nuclei_c_targets.txt" \
      -tags "exposure,token,jwt,cors,api-key,secret" \
      -severity low,medium,high,critical \
      $N_FLAGS \
      -o "${SCRIPT_TMPDIR}/nuclei_c.txt" 2>/dev/null || true
    cat "${SCRIPT_TMPDIR}/nuclei_c.txt" >> "${OUT}/nuclei/results.txt" 2>/dev/null || true
    success "Nuclei C → $(count "${SCRIPT_TMPDIR}/nuclei_c.txt") findings"
  fi
fi

if [ -s "${OUT}/urls/sensitive_extensions.txt" ]; then
  info "[nuclei] Sensitive file detection..."
  nuclei -l "${OUT}/urls/sensitive_extensions.txt" \
    -tags "exposure,backup,config,files" \
    -severity medium,high,critical \
    $N_FLAGS \
    -o "${SCRIPT_TMPDIR}/nuclei_d.txt" 2>/dev/null || true
  cat "${SCRIPT_TMPDIR}/nuclei_d.txt" >> "${OUT}/nuclei/results.txt" 2>/dev/null || true
  success "Nuclei D → $(count "${SCRIPT_TMPDIR}/nuclei_d.txt") findings"
fi

sort -u "${OUT}/nuclei/results.txt" -o "${OUT}/nuclei/results.txt"

echo ""
printf "  ${BOLD}${BC}%-12s  %-8s  %s${RESET}\n" "Severity" "Count" "File"
hline "─" 55
for _sev in critical high medium low; do
  grep -i "\[${_sev}\]" "${OUT}/nuclei/results.txt" 2>/dev/null \
    > "${OUT}/nuclei/${_sev}.txt" || true
  local _cnt; _cnt=$(count "${OUT}/nuclei/${_sev}.txt")
  severity_row "${_sev^^}" "$_cnt" "nuclei/${_sev}.txt"
done
hline "─" 55
echo ""

success "Nuclei total → ${BG}$(count "${OUT}/nuclei/results.txt")${RESET} findings"
[ "$(count "${OUT}/nuclei/critical.txt")" -gt 0 ] && find_critical "CRITICAL nuclei findings → nuclei/critical.txt"
[ "$(count "${OUT}/nuclei/high.txt")"     -gt 0 ] && find_high     "HIGH nuclei findings → nuclei/high.txt"

# ╔══════════════════════════════════════════════════════════════════════╗
# ║  FINAL SUMMARY                                                       ║
# ╚══════════════════════════════════════════════════════════════════════╝

echo ""
local _line; printf -v _line '%*s' 64 ''; _line="${_line// /═}"
echo -e "${BOLD}${BG}"
echo -e "  ${D_TL}${_line}${D_TR}"
printf  "  ${D_V}%-64s${D_V}\n" ""
printf  "  ${D_V}    ✔  0xRecon COMPLETE  •  v7.0  •  0xmones             ${D_V}\n"
printf  "  ${D_V}    © 2026 0xmones. All Rights Reserved.                 ${D_V}\n"
printf  "  ${D_V}%-64s${D_V}\n" ""
echo -e "  ${D_BL}${_line}${D_BR}${RESET}"
echo ""
printf  "  ${DIM}Target   :${RESET} ${BOLD}${domain}${RESET}\n"
printf  "  ${DIM}Mode     :${RESET} ${BOLD}${RECON_MODE}${RESET}\n"
printf  "  ${DIM}Output   :${RESET} ${BOLD}${OUT}/${RESET}\n"
printf  "  ${DIM}Finished :${RESET} $(date '+%Y-%m-%d %H:%M:%S')\n"
echo ""

echo -e "  ${BOLD}${BC}📁 ${OUT}/${RESET}"
printf  "  ${DIM}│${RESET}\n"

printf  "  ${DIM}├─${RESET} ${BOLD}subs/${RESET}\n"
tree_leaf      "discovered"              "$(count "${OUT}/subs/all.txt")"
tree_leaf      "resolved"               "$(count "${OUT}/subs/resolved.txt")"
tree_leaf_warn "high-value"             "$(count "${OUT}/interesting/high_value_all.txt")"

printf  "  ${DIM}├─${RESET} ${BOLD}origin/${RESET}\n"
tree_leaf_warn "candidate IPs (non-CDN)" "$(count "${OUT}/origin/non_cdn_ips.txt")"
tree_leaf_crit "CVE findings"           "$(count "${OUT}/origin/cve_findings.txt")"

printf  "  ${DIM}├─${RESET} ${BOLD}takeover/${RESET}\n"
tree_leaf_crit "vulnerable"             "$(count "${OUT}/takeover/vulnerable.txt")"

printf  "  ${DIM}├─${RESET} ${BOLD}ports/${RESET}\n"
tree_leaf      "open ports"             "$(count "${OUT}/ports/open_ports.txt")"
local _ca_printed
_ca_printed=$(find "${OUT}/ports/critical_assets.json" -type f 2>/dev/null | head -1 | xargs -I{} sh -c 'jq length "{}"' 2>/dev/null || echo "0")
printf  "  ${DIM}│  ├─${RESET} ${DIM}%-30s${RESET} ${BR}%s${RESET}\n" "critical assets (JSON)" "$_ca_printed"

printf  "  ${DIM}├─${RESET} ${BOLD}alive/${RESET}\n"
tree_leaf      "accessible hosts"       "$(count "${OUT}/alive/hosts_clean.txt")"
tree_leaf_warn "interesting hosts"      "$(count "${OUT}/alive/hosts_interesting.txt")"
tree_leaf_warn "WAF-blocked"            "$(count "${OUT}/alive/waf_blocked.txt")"

printf  "  ${DIM}├─${RESET} ${BOLD}urls/${RESET}\n"
tree_leaf      "all_urls"               "$(count "${OUT}/urls/all_urls.txt")"
tree_leaf_crit "php_endpoints"          "$(count "${OUT}/urls/php_endpoints.txt")"
tree_leaf_crit "sensitive_files"        "$(count "${OUT}/urls/sensitive_extensions.txt")"
tree_leaf_warn "admin_panels"           "$(count "${OUT}/urls/admin_panels.txt")"
tree_leaf      "api_endpoints"          "$(count "${OUT}/urls/api_endpoints.txt")"

printf  "  ${DIM}├─${RESET} ${BOLD}js/${RESET}\n"
tree_leaf      "js_files"               "$(count "${OUT}/js/js_urls.txt")"
tree_leaf_warn "endpoints_found"        "$(count "${OUT}/js/linkfinder.txt")"
tree_leaf_crit "secrets"                "$(count "${OUT}/js/secrets.txt")"

printf  "  ${DIM}├─${RESET} ${BOLD}nuclei/${RESET}\n"
tree_leaf_crit "critical"               "$(count "${OUT}/nuclei/critical.txt")"
tree_leaf_crit "high"                   "$(count "${OUT}/nuclei/high.txt")"
tree_leaf_warn "medium"                 "$(count "${OUT}/nuclei/medium.txt")"
tree_leaf      "low"                    "$(count "${OUT}/nuclei/low.txt")"

printf  "  ${DIM}├─${RESET} ${BOLD}recon/${RESET}\n"
tree_leaf      "emails"                 "$(count "${OUT}/recon/emails.txt")"
tree_leaf      "headers graded"         "$(count "${OUT}/recon/headers_grade.txt")"
tree_leaf_warn "missing headers"        "$(count "${OUT}/recon/missing_headers.txt")"
tree_leaf_crit "header disclosures"     "$(count "${OUT}/recon/header_disclosures.txt")"
tree_leaf_warn "robots hidden paths"    "$(count "${OUT}/recon/robots_disallow.txt")"
tree_leaf_crit "open buckets"           "$(count "${OUT}/recon/buckets_open.txt")"
tree_leaf_crit "github exposures"       "$(count "${OUT}/recon/github_findings.txt")"
echo ""

# ── Priority Actions ────────────────────────────────────────────────────
_has_priority=0
echo ""
echo -e "  ${BOLD}${BR}⚡ PRIORITY ACTIONS${RESET}"
hline "═" 62

_show_action() {
  local sev="$1" msg="$2"
  case "$sev" in
    CRITICAL) echo -e "  ${SEV_CRIT} CRITICAL ${RESET}  ${BOLD}$msg${RESET}" ;;
    HIGH)     echo -e "  ${SEV_HIGH}[HIGH]${RESET}      ${BOLD}$msg${RESET}" ;;
    MEDIUM)   echo -e "  ${SEV_MED}[MEDIUM]${RESET}    $msg" ;;
    LOW)      echo -e "  ${SEV_LOW}[LOW]${RESET}       ${DIM}$msg${RESET}" ;;
  esac
}

[ "$(count "${OUT}/nuclei/critical.txt")"            -gt 0 ] && { _show_action CRITICAL "Nuclei critical findings → nuclei/critical.txt"; _has_priority=1; }
[ "$(count "${OUT}/js/secrets.txt")"                 -gt 0 ] && { _show_action CRITICAL "JS SECRETS found → js/secrets.txt  (ROTATE NOW)"; _has_priority=1; }
[ "$(count "${OUT}/origin/cve_findings.txt")"        -gt 0 ] && { _show_action CRITICAL "CVEs found via InternetDB → origin/cve_findings.txt"; _has_priority=1; }
[ "$(count "${OUT}/takeover/vulnerable.txt")"        -gt 0 ] && { _show_action HIGH     "Subdomain takeover vulnerable → takeover/vulnerable.txt"; _has_priority=1; }
[ "$(count "${OUT}/recon/github_findings.txt")"      -gt 0 ] && { _show_action HIGH     "GitHub exposures → recon/github_findings.txt"; _has_priority=1; }
[ "$(count "${OUT}/recon/buckets_open.txt")"         -gt 0 ] && { _show_action HIGH     "Open cloud buckets → recon/buckets_open.txt"; _has_priority=1; }
[ "$(count "${OUT}/nuclei/high.txt")"                -gt 0 ] && { _show_action HIGH     "Nuclei high findings → nuclei/high.txt"; _has_priority=1; }
[ -f "${OUT}/ports/critical_assets.json" ] && [ -s "${OUT}/ports/critical_assets.json" ] && { _show_action HIGH     "Critical assets found → ports/critical_assets.json"; _has_priority=1; }
[ "$(count "${OUT}/urls/sensitive_extensions.txt")"  -gt 0 ] && { _show_action MEDIUM   "Sensitive files exposed → urls/sensitive_extensions.txt"; _has_priority=1; }
[ "$(count "${OUT}/recon/header_disclosures.txt")"   -gt 0 ] && { _show_action MEDIUM   "Server tech disclosed → recon/header_disclosures.txt"; _has_priority=1; }
[ "$(count "${OUT}/recon/robots_disallow.txt")"      -gt 0 ] && { _show_action LOW      "Hidden paths (robots.txt) → recon/robots_disallow.txt"; _has_priority=1; }
[ "$(count "${OUT}/recon/emails.txt")"               -gt 0 ] && { _show_action LOW      "Harvested emails → recon/emails.txt"; _has_priority=1; }
[ "$(count "${OUT}/interesting/high_value_all.txt")" -gt 0 ] && { _show_action LOW      "High-value subdomains → interesting/high_value_all.txt"; _has_priority=1; }

[ "$_has_priority" -eq 0 ] && echo -e "  ${BG}No critical findings detected — target surface looks clean.${RESET}"
hline "═" 62
echo ""
echo -e "  ${DIM}${BG}© 2026 0xmones. All Rights Reserved.${RESET}  ${DIM}Results: ${OUT}/${RESET}"
echo ""

echo -e "  ${DIM}[~] Post-processing: pruning empty files...${RESET}"
postprocess_outputs
echo -e "  ${DIM}[~] Done.${RESET}"
echo ""
}

main "$@"
