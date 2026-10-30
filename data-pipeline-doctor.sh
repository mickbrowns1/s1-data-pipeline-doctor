#!/usr/bin/env bash
set -uo pipefail

# ============================================================
#  Data Pipeline Doctor — Interactive K8s + Docker Diagnostic & Repair Tool
# ============================================================

NAMESPACE="observo-client"
RELEASE_NAME="observo-site"
KUBECONFIG="${KUBECONFIG:-}"
HOST_CA_PATH=""
DETECTED_ISSUES=()
DP_EXTRA_MOUNTS=()   # set by a caller before _dp_build_run_cmd to add -v mounts; consumed (cleared) by it
DP_EXTRA_ENV=()       # set by a caller before _dp_build_run_cmd to add KEY=value env lines; consumed (cleared) by it
WEF_MODE=false        # does this host manage WEF/WEC-forwarding sites? asked once at startup, saved to a profile file
DP_WEF_FIPS_ON=false  # set by _dp_wef_check
DP_NEW_SITE_WEF=false # set when docker_setup_new_site built this site WEF-ready this run

# --- Site type (kubernetes | docker) ---
SITE_TYPE=""                                     # chosen at startup
SITE_TYPE_OVERRIDE="${OBSERVO_SITE_TYPE:-}"      # --site-type flag / env override
DOCKER_CONTAINER=""                              # resolved observo-standalone-site container
DOCKER_IMAGE_MATCH="observo-standalone-site"     # substring used to find the container
DOCKER_SVCS=()                                   # cached s6 service names
DOCKER_ENDPOINTS=()                              # host:port derived from container env
OBSERVO_SITE_ID=""                               # from container env, for display
SITE_TOKEN_FILE_PATH=""                          # from container env
GATEWAY_TLS_SECURED=""                           # from container env
API_GATEWAY_ENDPOINT_VAL=""                       # manager/gateway endpoint (from container env)
PIPELINE_NAME_MAP=()                               # "entityid|Human Name" entries (bash 3.2-safe; no assoc arrays)

# --- Host OS discovery (for the Docker install guide) ---
DPD_OS_FAMILY=""                                   # mac|windows|wsl|debian|rhel|fedora|amazon|unknown
DPD_OS_ID=""                                       # /etc/os-release ID (ubuntu, rocky, amzn, ...)
DPD_OS_VER=""                                      # /etc/os-release VERSION_ID

# --- Colors & formatting ---
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; PURPLE='\033[1;35m'
BOLD='\033[1m'; DIM='\033[2m'; NC='\033[0m'

log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[ OK ]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_err()   { echo -e "${RED}[FAIL]${NC}  $*"; }
log_fix()   { echo -e "${GREEN}[FIX ]${NC}  $*"; }

kc() { kubectl ${KUBECONFIG:+--kubeconfig "$KUBECONFIG"} "$@"; }

# True if $1 (a log blob) has a connection-refused/timeout/etc. line that
# isn't Vector's own internal self-scrape. The prometheus_metrics source
# scrapes an internal metrics listener on loopback (127.0.0.x); when that
# listener isn't up, Vector logs the exact same connection-refused/timeout
# text a real outbound failure to the Data Pipeline control plane would use
# — sometimes across two log lines (a WARN summary plus an ERROR with the
# loopback URL), so both the loopback address and the component tag are
# excluded. Without this, a healthy site that's actively reporting in can
# still get flagged with a misleading "outbound connection failures" finding.
_dp_has_outbound_failure() {
    echo "$1" | grep -iE "connection refused|dial tcp.*timeout|no such host|network is unreachable|connection timed out|i/o timeout" \
        | grep -qvE "127\.0\.0\.[0-9]+|\[?::1\]?|localhost|component_id=prometheus_metrics|component_type=prometheus_scrape"
}

# --- Docker primitives (Docker standalone site backend) ---
dk()        { docker "$@"; }
dexec()     { docker exec "$DOCKER_CONTAINER" "$@"; }
dexec_it()  { docker exec -it "$DOCKER_CONTAINER" "$@"; }
dinspect()  { docker inspect --format "$1" "$DOCKER_CONTAINER" 2>/dev/null; }

# Container env value lookup (e.g. dk_env AUTH_DOMAIN_URL)
dk_env() {
    dinspect '{{range .Config.Env}}{{println .}}{{end}}' \
        | grep "^${1}=" | head -1 | cut -d= -f2-
}

# Generate a UUID for tagging a test event. Falls back across common sources.
# BSD logger lacks -n/-P/-T; GNU util-linux logger supports network targets.
_dp_gen_uuid() {
    if command -v uuidgen >/dev/null 2>&1; then
        uuidgen | tr 'A-Z' 'a-z'
    elif [[ -r /proc/sys/kernel/random/uuid ]]; then
        cat /proc/sys/kernel/random/uuid
    elif command -v python3 >/dev/null 2>&1; then
        python3 -c 'import uuid; print(uuid.uuid4())'
    else
        printf 'dpd-%s-%s\n' "$(date +%s)" "$RANDOM$RANDOM"
    fi
}

# Build an RFC3164 syslog line for a category, with uuid embedded in the message body.
# $1 = category key (fw|auth|dns|web|generic)   $2 = uuid
# IPs use TEST-NET (RFC 5737) so events are obviously synthetic.
# Returns "num_pri|logger_pri_name|tag|body" for a syslog test event.
# Keeping the PRI numeric and name separate lets the logger path use native flags
# (no double-encoding) while the nc path builds its own RFC3164 header.
# IPs use TEST-NET (RFC 5737) so events are obviously synthetic.
_dp_syslog_event() {
    local cat="$1" uuid="$2"
    case "$cat" in
        fw)   printf '134|local0.info|firewall|action=DENY proto=TCP src=203.0.113.10 dst=198.51.100.5 dpt=443 test-id=%s' "$uuid" ;;
        auth) printf '38|auth.info|sshd[4242]|Failed password for invalid user admin from 203.0.113.10 port 52311 ssh2 test-id=%s' "$uuid" ;;
        dns)  printf '142|local1.info|named[990]|query: example.test IN A from 203.0.113.10 test-id=%s' "$uuid" ;;
        web)  printf '134|local0.info|nginx|203.0.113.10 - - "GET /healthz HTTP/1.1" 200 12 test-id=%s' "$uuid" ;;
        *)    printf '134|local0.info|dpd-syslog-test|synthetic test event test-id=%s' "$uuid" ;;
    esac
}

# Send a syslog test event to localhost:<port>.
# $1 = event string from _dp_syslog_event ("num_pri|logger_pri|tag|body")
# $2 = port   $3 = proto (tcp|udp)
#
# Sender priority:
#   1. GNU logger — Linux (util-linux); uses -p/-t so logger owns the RFC3164 header (no double-encoding)
#   2. Host nc — builds its own RFC3164 packet from the event parts
#   3. docker run ghcr.io/sva-s1/alpine-nc:main — macOS dev fallback
#
# DPD_OS_FAMILY is set by _dpd_detect_os at startup; "mac" skips the GNU logger attempt.
# Run a command with a hard wall-clock timeout so a sender that never
# returns (e.g. BusyBox nc's UDP -w, which doesn't always honor the flag)
# can't hang the interactive menu.
_dp_timeout() {
    local secs="$1"; shift
    if command -v timeout >/dev/null 2>&1; then
        timeout "$secs" "$@"
    elif command -v gtimeout >/dev/null 2>&1; then
        gtimeout "$secs" "$@"
    else
        "$@" &
        local pid=$! rc watcher
        ( sleep "$secs" 2>/dev/null; kill -9 "$pid" 2>/dev/null ) &
        watcher=$!
        wait "$pid" 2>/dev/null; rc=$?
        kill "$watcher" 2>/dev/null; wait "$watcher" 2>/dev/null
        return $rc
    fi
}

_dp_send_syslog() {
    local event="$1" port="$2" proto="$3" rc
    local num_pri pri_name tag body
    IFS='|' read -r num_pri pri_name tag body <<< "$event"

    # 1. GNU logger (Linux only — BSD logger on macOS lacks -n/-P/-T)
    if [[ "${DPD_OS_FAMILY:-}" != "mac" ]] && \
       command -v logger >/dev/null 2>&1 && \
       logger --help 2>&1 | grep -q -- '-P'; then
        if [[ "$proto" == "udp" ]]; then
            logger -n localhost -P "$port" -d --rfc3164 -p "$pri_name" -t "$tag" -- "$body"
        else
            logger -n localhost -P "$port" -T --rfc3164 -p "$pri_name" -t "$tag" -- "$body"
        fi
        rc=$?
        if [[ $rc -eq 0 ]]; then
            return 0
        fi
        # -P support doesn't guarantee --rfc3164/-T support (older util-linux,
        # e.g. RHEL 7) — don't blame the port, just fall through to nc.
        log_warn "logger exited $rc (may not support --rfc3164/-T on this util-linux version) — falling back to nc."
    fi

    # nc and docker paths send a raw RFC3164 packet built here.
    # Force C locale — a localized month name here (e.g. from LC_TIME) would
    # produce a malformed RFC3164 timestamp.
    local ts rfc_host raw_pkt
    ts="$(LC_ALL=C date '+%b %e %H:%M:%S')"
    rfc_host="$(hostname 2>/dev/null || echo dpd-tester)"
    raw_pkt="$(printf '<%s>%s %s %s: %s' "$num_pri" "$ts" "$rfc_host" "$tag" "$body")"

    # 2. Host nc (hard-timeout guards against BusyBox nc's unreliable -w on UDP)
    if command -v nc >/dev/null 2>&1; then
        if [[ "$proto" == "udp" ]]; then
            printf '%s'   "$raw_pkt" | _dp_timeout 5 nc -u -w1 localhost "$port"
        else
            printf '%s\n' "$raw_pkt" | _dp_timeout 5 nc    -w1 localhost "$port"
        fi
        rc=$?
        [[ $rc -eq 0 ]] && return 0
        log_err "nc exited $rc — check that the port is published and a listener is up on localhost:${port}."
        return 1
    fi

    # 3. Docker alpine-nc (macOS dev fallback — requires Docker Desktop)
    if command -v docker >/dev/null 2>&1; then
        log_info "No host nc found — using ghcr.io/sva-s1/alpine-nc:main via Docker..."

        # Pull explicitly first so a registry-unreachable/offline host gets a
        # clear message instead of a generic "port not reachable" — the nc
        # step below would otherwise fail the same way and mislead the user.
        if ! docker image inspect ghcr.io/sva-s1/alpine-nc:main >/dev/null 2>&1; then
            if ! docker pull ghcr.io/sva-s1/alpine-nc:main >/dev/null 2>&1; then
                log_err "Could not pull ghcr.io/sva-s1/alpine-nc:main — this host looks offline or air-gapped (registry unreachable), not a port problem. No fallback sender is available; install nc locally to test without internet access."
                return 1
            fi
        fi

        # --network host is a no-op on Docker Desktop for Mac (it runs in a
        # VM), so "localhost" inside the container isn't the Mac's localhost.
        # Use Docker Desktop's host.docker.internal alias there instead.
        local dp_docker_target="localhost"
        [[ "${DPD_OS_FAMILY:-}" == "mac" ]] && dp_docker_target="host.docker.internal"

        if [[ "$proto" == "udp" ]]; then
            printf '%s'   "$raw_pkt" | _dp_timeout 5 docker run --rm -i --network host \
                ghcr.io/sva-s1/alpine-nc:main nc -u -w1 "$dp_docker_target" "$port"
        else
            printf '%s\n' "$raw_pkt" | _dp_timeout 5 docker run --rm -i --network host \
                ghcr.io/sva-s1/alpine-nc:main nc -w1 "$dp_docker_target" "$port"
        fi
        rc=$?
        [[ $rc -eq 0 ]] && return 0
        log_err "docker alpine-nc exited $rc — check that the port is reachable on ${dp_docker_target}:${port}."
        return 1
    fi

    log_err "No sender available: install nc (or ensure Docker is running for the macOS fallback)."
    return 1
}

# List s6 service names into DOCKER_SVCS (cached). Empty => "unknown", not healthy.
svc_list() {
    if [[ ${#DOCKER_SVCS[@]} -gt 0 ]]; then
        printf '%s\n' "${DOCKER_SVCS[@]}"
        return 0
    fi
    local out
    out=$(dexec ls /run/service 2>/dev/null || true)
    [[ -z "$out" ]] && out=$(dexec s6-rc -a list 2>/dev/null || true)
    # Keep only real Data Pipeline services (drop s6 internal dirs)
    while IFS= read -r s; do
        [[ -z "$s" ]] && continue
        case "$s" in
            s6-*|s6rc-*) continue ;;
        esac
        DOCKER_SVCS+=("$s")
    done <<< "$out"
    [[ ${#DOCKER_SVCS[@]} -gt 0 ]] && printf '%s\n' "${DOCKER_SVCS[@]}"
}

# Raw s6 status line for a service (e.g. "up (pid 123) 400 seconds" / "down (not started yet)")
svc_status_raw() {
    dexec s6-svstat "/run/service/$1" 2>/dev/null \
        || dexec s6-svstat "/var/run/service/$1" 2>/dev/null
}

hr() { echo -e "${DIM}$(printf '%.0s─' {1..50})${NC}"; }

# Full-screen launch splash — shown once at startup.
splash() {
    clear
    echo ""
    echo -e "${BOLD}${PURPLE}"
    echo " ███████╗ ██╗    ██████╗  █████╗ ████████╗ █████╗"
    echo " ██╔════╝███║    ██╔══██╗██╔══██╗╚══██╔══╝██╔══██╗"
    echo " ███████╗╚██║    ██║  ██║███████║   ██║   ███████║"
    echo " ╚════██║ ██║    ██║  ██║██╔══██║   ██║   ██╔══██║"
    echo " ███████║ ██║    ██████╔╝██║  ██║   ██║   ██║  ██║"
    echo " ╚══════╝ ╚═╝    ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝"
    echo " ██████╗ ██╗██████╗ ███████╗██╗     ██╗███╗   ██╗███████╗███████╗"
    echo " ██╔══██╗██║██╔══██╗██╔════╝██║     ██║████╗  ██║██╔════╝██╔════╝"
    echo " ██████╔╝██║██████╔╝█████╗  ██║     ██║██╔██╗ ██║█████╗  ███████╗"
    echo " ██╔═══╝ ██║██╔═══╝ ██╔══╝  ██║     ██║██║╚██╗██║██╔══╝  ╚════██║"
    echo " ██║     ██║██║     ███████╗███████╗██║██║ ╚████║███████╗███████║"
    echo " ╚═╝     ╚═╝╚═╝     ╚══════╝╚══════╝╚═╝╚═╝  ╚═══╝╚══════╝╚══════╝"
    echo -e "${NC}${BOLD}${CYAN}"
    echo " ══════════════════════════════════════════   ♥  Doctor v1.6"
    echo -e "${NC}${DIM}   Site diagnostics & remediation  ·  K8s + Docker  ·  SentinelOne${NC}"
    echo ""
    read -rp "  Press Enter to begin..." _ || _dpd_eof_exit
}

# Slim nameplate — redrawn on every menu screen.
banner() {
    clear
    echo ""
    echo -e "  ${BOLD}${PURPLE}S1 DATA PIPELINES${NC} ${DIM}·${NC} ${BOLD}${CYAN}Doctor${NC} ${DIM}v1.6${NC}    ${CYAN}♥${NC}"
    echo -e "  ${DIM}K8s + Docker site diagnostics · Built by SentinelOne Architecture Team${NC}"
    hr
    echo ""
}

# stdin closed (piped input ran out, Ctrl-D, ssh dropped) — exit instead of
# letting a menu loop redraw forever on a read that can never succeed.
_dpd_eof_exit() {
    echo ""
    log_info "Input closed — exiting."
    exit 0
}

pause() {
    echo ""
    read -rp "  Press Enter to continue..." _ || _dpd_eof_exit
}

confirm() {
    local msg="${1:-Apply this fix?}"
    echo ""
    read -rp "  ${msg} [y/N] " ans || _dpd_eof_exit
    [[ "$ans" =~ ^[Yy]$ ]]
}

# Same as confirm, but Enter means yes — for the recommended next step.
confirm_yes() {
    local msg="$1"
    echo ""
    read -rp "  ${msg} [Y/n] " ans || _dpd_eof_exit
    [[ -z "$ans" || "$ans" =~ ^[Yy]$ ]]
}

pick_one() {
    local prompt="$1"; shift
    local options=("$@")
    echo "" >&2
    echo -e "  ${BOLD}${prompt}${NC}" >&2
    echo "" >&2
    for i in "${!options[@]}"; do
        echo -e "    ${CYAN}$((i+1)))${NC} ${options[$i]}" >&2
    done
    echo "" >&2
    local choice
    read -rp "  Choose [1-${#options[@]}]: " choice || _dpd_eof_exit
    echo "$choice"
}

# ============================================================
#  Argument parsing
# ============================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --namespace)   NAMESPACE="$2"; shift 2 ;;
            --kubeconfig)  KUBECONFIG="$2"; shift 2 ;;
            --release)     RELEASE_NAME="$2"; shift 2 ;;
            --site-type)   SITE_TYPE_OVERRIDE="$2"; shift 2 ;;
            --container)   DOCKER_CONTAINER="$2"; SITE_TYPE_OVERRIDE="docker"; shift 2 ;;
            -h|--help)
                echo "Usage: data-pipeline-doctor.sh [--site-type kubernetes|docker] [--container NAME]"
                echo "                         [--namespace NS] [--kubeconfig PATH] [--release NAME]"
                exit 0 ;;
            *) shift ;;
        esac
    done
}

# Detect host CA bundle (shared by both backends)
detect_host_ca() {
    for ca in /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-bundle.crt /etc/pki/tls/certs/ca-bundle.crt; do
        [[ -f "$ca" ]] && HOST_CA_PATH="$ca" && break
    done
}

# ============================================================
#  Site type selection
# ============================================================
choose_site_type() {
    if [[ -n "$SITE_TYPE_OVERRIDE" ]]; then
        case "$SITE_TYPE_OVERRIDE" in
            kubernetes|k8s) SITE_TYPE="kubernetes" ;;
            docker)         SITE_TYPE="docker" ;;
            *) log_err "Unknown --site-type '$SITE_TYPE_OVERRIDE' (use kubernetes|docker)"; exit 1 ;;
        esac
        return
    fi

    banner
    local choice
    choice=$(pick_one "What kind of Data Pipeline site are you managing?" \
        "Kubernetes / K3s cluster" \
        "Docker standalone site (single container)")
    case "$choice" in
        1) SITE_TYPE="kubernetes" ;;
        2) SITE_TYPE="docker" ;;
        *) log_err "Invalid choice. Exiting."; exit 1 ;;
    esac
}

# ============================================================
#  Preflight — route to the chosen backend
# ============================================================
preflight() {
    splash
    _dpd_detect_os   # sets DPD_OS_FAMILY early — reusable by all menus (e.g. syslog tester sender)
    choose_site_type
    if [[ "$SITE_TYPE" == "docker" ]]; then
        _dpd_load_wef_mode || _dpd_ask_wef_mode   # WEF/WEC support is Docker-only; ask once, then remember
        docker_preflight
        _dpd_wef_startup_check
    else
        preflight_k8s
    fi
}

# --- Kubernetes preflight (detect cluster and validate access) ---
preflight_k8s() {
    if [[ -z "$KUBECONFIG" && -f /etc/rancher/k3s/k3s.yaml ]]; then
        KUBECONFIG="/etc/rancher/k3s/k3s.yaml"
    fi

    if ! kc cluster-info &>/dev/null; then
        log_err "Cannot connect to Kubernetes cluster"
        echo "  Set KUBECONFIG or pass the path when prompted."
        read -rp "  Kubeconfig path: " KUBECONFIG || _dpd_eof_exit
        if ! kc cluster-info &>/dev/null; then
            log_err "Still cannot connect. Exiting."
            exit 1
        fi
    fi

    detect_host_ca
}

# ============================================================
#  Main menu
# ============================================================
main_menu() {
    while true; do
        banner
        echo -e "  ${DIM}Cluster:${NC}   $(kc config current-context 2>/dev/null || echo 'default')"
        echo -e "  ${DIM}Namespace:${NC} ${NAMESPACE}"
        echo ""
        echo -e "  ${BOLD}Diagnostics${NC}"
        hr
        printf "    ${CYAN}%2s)${NC} %-30s ${CYAN}%2s)${NC} %s\n" 1 "Full diagnostic scan" 2 "Pod health"
        printf "    ${CYAN}%2s)${NC} %-30s ${CYAN}%2s)${NC} %s\n" 3 "Node health" 4 "TLS & certificates"
        printf "    ${CYAN}%2s)${NC} %-30s ${CYAN}%2s)${NC} %s\n" 5 "DNS resolution" 6 "Storage & PVCs"
        printf "    ${CYAN}%2s)${NC} %-30s ${CYAN}%2s)${NC} %s\n" 7 "Resource usage" 8 "Recent events"
        echo ""
        echo -e "  ${BOLD}Tools${NC}"
        hr
        printf "    ${CYAN}%2s)${NC} %-30s ${CYAN}%2s)${NC} %s\n" 9 "Pod debugger" 10 "Restart deployment"
        printf "    ${CYAN}%2s)${NC} %-30s ${CYAN}%2s)${NC} %s\n" 11 "Change namespace" 12 "Tail sources & destinations"
        printf "    ${CYAN}%2s)${NC} %s\n" 13 "Proxy & connectivity"
        echo ""
        hr
        echo ""
        echo -e "    ${CYAN} 0)${NC} Exit"
        echo ""
        local choice
        read -rp "  Choose [0-13]: " choice || { echo ""; log_info "Goodbye."; exit 0; }

        case "$choice" in
            1)  full_scan ;;
            2)  menu_pod_health ;;
            3)  menu_node_health ;;
            4)  menu_tls_certs ;;
            5)  menu_dns ;;
            6)  menu_storage ;;
            7)  menu_resources ;;
            8)  menu_events ;;
            9)  menu_pod_debugger ;;
            10) menu_restart ;;
            11) menu_change_namespace ;;
            12) menu_dataplane_tap ;;
            13) menu_proxy_connectivity ;;
            0)  echo ""; log_info "Goodbye."; exit 0 ;;
            *)  ;;
        esac
    done
}

# ============================================================
#  1) Full diagnostic scan
# ============================================================
full_scan() {
    banner
    echo -e "  ${BOLD}Running full diagnostic scan...${NC}"
    echo ""
    DETECTED_ISSUES=()

    scan_nodes
    hr
    scan_pods
    hr
    scan_tls
    hr
    scan_dns
    hr
    scan_storage
    hr
    scan_resources
    hr
    scan_init_panics
    hr

    echo ""
    if [[ ${#DETECTED_ISSUES[@]} -eq 0 ]]; then
        log_ok "No issues detected — cluster looks healthy"
    else
        echo -e "  ${RED}${BOLD}Issues found: ${#DETECTED_ISSUES[@]}${NC}"
        echo ""
        for i in "${!DETECTED_ISSUES[@]}"; do
            echo -e "    ${RED}$((i+1)).${NC} ${DETECTED_ISSUES[$i]}"
        done
        echo ""
        if confirm "Attempt to fix these issues?"; then
            run_all_fixes
        fi
    fi
    pause
}

# ============================================================
#  2) Pod health
# ============================================================
_pod_has_issue() {
    local pod="$1"
    for issue in "${DETECTED_ISSUES[@]}"; do
        [[ "$issue" == *": $pod"* ]] && return 0
    done
    return 1
}

scan_pods() {
    log_info "Pod health — $NAMESPACE"
    echo ""

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local name ready status restarts age
        name=$(echo "$line" | awk '{print $1}')
        ready=$(echo "$line" | awk '{print $2}')
        status=$(echo "$line" | awk '{print $3}')
        restarts=$(echo "$line" | awk '{print $4}')
        age=$(echo "$line" | awk '{print $5}')

        [[ "$status" == "Completed" ]] && continue

        local cur tot
        cur=$(echo "$ready" | cut -d/ -f1)
        tot=$(echo "$ready" | cut -d/ -f2)

        if [[ "$status" == "Running" && "$cur" == "$tot" ]]; then
            log_ok "$name ($ready) ${DIM}age: $age${NC}"
        elif [[ "$status" == "CrashLoopBackOff" ]]; then
            log_err "$name — CrashLoopBackOff (restarts: $restarts)"
            scan_pod_containers "$name"
            _pod_has_issue "$name" || DETECTED_ISSUES+=("crashloop: $name is in CrashLoopBackOff (restarts: $restarts)")
        elif [[ "$status" == "Error" || "$status" == "Init:Error" || "$status" == "Init:CrashLoopBackOff" ]]; then
            log_err "$name — $status (restarts: $restarts)"
            scan_pod_containers "$name"
            _pod_has_issue "$name" || DETECTED_ISSUES+=("error-state: $name is in $status (restarts: $restarts)")
        elif [[ "$status" == "ImagePullBackOff" || "$status" == "ErrImagePull" ]]; then
            log_err "$name — $status"
            DETECTED_ISSUES+=("image-pull: $name cannot pull image")
        elif [[ "$status" == "Pending" ]]; then
            log_warn "$name — Pending"
            local reason
            reason=$(kc describe pod "$name" -n "$NAMESPACE" 2>/dev/null | grep -A2 "Events:" | tail -1)
            [[ -n "$reason" ]] && echo -e "        ${DIM}$reason${NC}"
            DETECTED_ISSUES+=("pending: $name stuck in Pending state")
        elif [[ "$cur" != "$tot" ]]; then
            log_warn "$name ($ready) $status — restarts: $restarts"
            scan_pod_containers "$name"
            _pod_has_issue "$name" || DETECTED_ISSUES+=("not-ready: $name has $cur/$tot containers ready ($status)")
        else
            log_ok "$name ($ready) $status"
        fi
    done < <(kc get pods -n "$NAMESPACE" --no-headers 2>/dev/null)
}

scan_pod_containers() {
    local pod="$1"

    # Init containers
    local inits
    inits=$(kc get pod "$pod" -n "$NAMESPACE" \
        -o jsonpath='{range .status.initContainerStatuses[*]}{.name}{" "}{.state.terminated.exitCode}{" "}{.ready}{"\n"}{end}' 2>/dev/null || true)

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local cname
        cname=$(echo "$line" | awk '{print $1}')
        scan_container_errors "$pod" "$cname"
    done <<< "$inits"

    # Main containers
    local conts
    conts=$(kc get pod "$pod" -n "$NAMESPACE" \
        -o jsonpath='{range .status.containerStatuses[*]}{.name}{" "}{.ready}{" "}{.restartCount}{"\n"}{end}' 2>/dev/null || true)

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local cname cready
        cname=$(echo "$line" | awk '{print $1}')
        cready=$(echo "$line" | awk '{print $2}')
        [[ "$cready" == "false" ]] && scan_container_errors "$pod" "$cname"
    done <<< "$conts"
}

scan_container_errors() {
    local pod="$1" container="$2"
    local logs
    logs=$(kc logs "$pod" -n "$NAMESPACE" -c "$container" --tail=80 2>&1 || true)

    # TLS CA trust
    if echo "$logs" | grep -q "certificate signed by unknown authority"; then
        log_err "  [$container] TLS CA trust failure"
        DETECTED_ISSUES+=("tls-ca-trust: $pod/$container cannot verify Data Pipeline cloud TLS")
    fi

    # Malformed token
    if echo "$logs" | grep -q "token is malformed\|invalid number of segments"; then
        log_err "  [$container] Auth token malformed (init likely failed to authenticate)"
        DETECTED_ISSUES+=("malformed-token: $pod/$container bad auth token")
    fi

    # Internal cert verify
    if echo "$logs" | grep -q "certificate verify failed.*unable to get local issuer certificate"; then
        log_warn "  [$container] Internal TLS cert verify failures"
    fi

    # OOM
    local oom
    oom=$(kc get pod "$pod" -n "$NAMESPACE" \
        -o jsonpath="{.status.containerStatuses[?(@.name=='$container')].lastState.terminated.reason}" 2>/dev/null || true)
    if [[ "$oom" == "OOMKilled" ]]; then
        local limit
        limit=$(kc get pod "$pod" -n "$NAMESPACE" \
            -o jsonpath="{.spec.containers[?(@.name=='$container')].resources.limits.memory}" 2>/dev/null || echo "unknown")
        log_err "  [$container] OOMKilled (limit: $limit)"
        DETECTED_ISSUES+=("oom: $pod/$container was OOMKilled (limit: $limit)")
    fi

    # Permission denied / RBAC
    if echo "$logs" | grep -qi "forbidden\|cannot list\|cannot get\|unauthorized"; then
        log_err "  [$container] Possible RBAC / permission error"
        DETECTED_ISSUES+=("rbac: $pod/$container may have insufficient permissions")
    fi

    # Connection failures (proxy/firewall blocking outbound)
    if _dp_has_outbound_failure "$logs"; then
        log_err "  [$container] Outbound connection failures detected"
        DETECTED_ISSUES+=("connectivity: $pod/$container has outbound connection failures")
    fi
}

menu_pod_health() {
    banner
    echo -e "  ${BOLD}Pod Health Check${NC}"
    echo ""
    DETECTED_ISSUES=()
    scan_pods

    if [[ ${#DETECTED_ISSUES[@]} -gt 0 ]]; then
        echo ""
        hr
        echo -e "  ${RED}Issues found: ${#DETECTED_ISSUES[@]}${NC}"
        for issue in "${DETECTED_ISSUES[@]}"; do
            echo -e "    ${RED}•${NC} $issue"
        done
        echo ""
        if confirm "Attempt to fix detected issues?"; then
            run_all_fixes
        fi
    fi
    pause
}

# ============================================================
#  3) Node health
# ============================================================
scan_nodes() {
    log_info "Node health"
    echo ""

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local name status roles age version
        name=$(echo "$line" | awk '{print $1}')
        status=$(echo "$line" | awk '{print $2}')
        roles=$(echo "$line" | awk '{print $3}')
        age=$(echo "$line" | awk '{print $4}')
        version=$(echo "$line" | awk '{print $5}')

        if [[ "$status" == "Ready" ]]; then
            log_ok "$name ($roles) — $version, age: $age"
        else
            log_err "$name ($roles) — $status"
            DETECTED_ISSUES+=("node: $name is $status")
        fi

        # Check conditions
        local conditions
        conditions=$(kc get node "$name" -o jsonpath='{range .status.conditions[*]}{.type}{" "}{.status}{"\n"}{end}' 2>/dev/null || true)

        while IFS= read -r cond; do
            [[ -z "$cond" ]] && continue
            local ctype cstatus
            ctype=$(echo "$cond" | awk '{print $1}')
            cstatus=$(echo "$cond" | awk '{print $2}')

            case "$ctype" in
                MemoryPressure|DiskPressure|PIDPressure)
                    if [[ "$cstatus" == "True" ]]; then
                        log_err "  $name has $ctype"
                        DETECTED_ISSUES+=("node-pressure: $name has $ctype")
                    fi
                    ;;
            esac
        done <<< "$conditions"
    done < <(kc get nodes --no-headers 2>/dev/null)
}

menu_node_health() {
    banner
    echo -e "  ${BOLD}Node Health Check${NC}"
    echo ""
    DETECTED_ISSUES=()
    scan_nodes
    pause
}

# ============================================================
#  4) TLS & certificates
# ============================================================
scan_tls() {
    log_info "TLS & certificate checks"
    echo ""

    # Host CA bundle
    if [[ -n "$HOST_CA_PATH" ]]; then
        local count
        count=$(grep -c "BEGIN CERTIFICATE" "$HOST_CA_PATH" 2>/dev/null || echo 0)
        log_ok "Host CA bundle: $HOST_CA_PATH ($count certs)"
    else
        log_err "No host CA bundle found"
        DETECTED_ISSUES+=("no-host-ca: Host has no CA certificate bundle")
    fi

    # Outbound TLS to Data Pipeline endpoints
    local vals endpoints=()
    vals=$(helm get values "$RELEASE_NAME" -n "$NAMESPACE" -a ${KUBECONFIG:+--kubeconfig "$KUBECONFIG"} 2>/dev/null || true)
    if [[ -n "$vals" ]]; then
        while IFS= read -r ep; do
            [[ -n "$ep" ]] && endpoints+=("$ep")
        done < <(echo "$vals" | grep -oP 'p01-[a-z]+\.observo\.ai' | sort -u)
    fi
    [[ ${#endpoints[@]} -eq 0 ]] && endpoints=("p01-auth.observo.ai" "p01-api.observo.ai")

    for ep in "${endpoints[@]}"; do
        local result
        result=$(openssl s_client -connect "${ep}:443" </dev/null 2>&1)
        if echo "$result" | grep -q "verify return:1"; then
            local issuer
            issuer=$(echo "$result" | grep "issuer=" | head -1 | sed 's/.*CN = //')
            log_ok "TLS ${ep}:443 — issued by ${issuer:-unknown}"
        else
            log_err "TLS ${ep}:443 — verification failed from host"
            DETECTED_ISSUES+=("tls-host: Cannot verify ${ep} from host")
        fi
    done

    # Data plane cert
    local cert_data
    cert_data=$(kc get secret ob-data-plane-cert -n "$NAMESPACE" -o jsonpath='{.data.tls\.crt}' 2>/dev/null || true)
    if [[ -n "$cert_data" ]]; then
        local subj enddate
        subj=$(echo "$cert_data" | base64 -d 2>/dev/null | openssl x509 -noout -subject 2>/dev/null | sed 's/subject=//')
        enddate=$(echo "$cert_data" | base64 -d 2>/dev/null | openssl x509 -noout -enddate 2>/dev/null | cut -d= -f2)
        log_ok "Data plane cert: $subj (expires: $enddate)"
    else
        log_warn "Data plane cert secret not found"
    fi

    # cert-manager
    local cm_healthy=true
    local cm_pods
    cm_pods=$(kc get pods -n cert-manager --no-headers 2>/dev/null || true)
    if [[ -n "$cm_pods" ]]; then
        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            [[ "$(echo "$line" | awk '{print $3}')" != "Running" ]] && cm_healthy=false
        done <<< "$cm_pods"
        $cm_healthy && log_ok "cert-manager healthy" || { log_err "cert-manager unhealthy"; DETECTED_ISSUES+=("cert-manager: unhealthy pods"); }
    else
        log_warn "cert-manager not installed"
    fi

    # Check if control-agent has CA mount
    local ca_mounted
    ca_mounted=$(kc get deployment control-agent -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.volumes[*].name}' 2>/dev/null || true)
    if echo "$ca_mounted" | grep -q "host-ca-certs"; then
        log_ok "CA bundle mounted in control-agent"
    else
        log_warn "CA bundle NOT mounted in control-agent"
    fi
}

menu_tls_certs() {
    banner
    echo -e "  ${BOLD}TLS & Certificate Check${NC}"
    echo ""
    DETECTED_ISSUES=()
    scan_tls

    if [[ ${#DETECTED_ISSUES[@]} -gt 0 ]]; then
        echo ""
        for issue in "${DETECTED_ISSUES[@]}"; do
            echo -e "    ${RED}•${NC} $issue"
        done
        if confirm "Attempt to fix TLS issues?"; then
            run_all_fixes
        fi
    fi
    pause
}

# ============================================================
#  5) DNS resolution
# ============================================================
scan_dns() {
    log_info "DNS resolution checks"
    echo ""

    # Check CoreDNS
    local coredns_pods
    coredns_pods=$(kc get pods -n kube-system -l k8s-app=kube-dns --no-headers 2>/dev/null || true)
    if [[ -z "$coredns_pods" ]]; then
        coredns_pods=$(kc get pods -n kube-system --no-headers 2>/dev/null | grep coredns || true)
    fi

    if [[ -n "$coredns_pods" ]]; then
        local dns_ready
        dns_ready=$(echo "$coredns_pods" | awk '{print $2, $3}' | head -1)
        if echo "$dns_ready" | grep -q "Running"; then
            log_ok "CoreDNS is running"
        else
            log_err "CoreDNS is not healthy: $dns_ready"
            DETECTED_ISSUES+=("dns: CoreDNS is not healthy")
        fi
    fi

    # External DNS from host
    for host in p01-auth.observo.ai p01-api.observo.ai; do
        if nslookup "$host" &>/dev/null || dig +short "$host" 2>/dev/null | grep -q .; then
            log_ok "Resolves: $host"
        else
            log_err "Cannot resolve: $host"
            DETECTED_ISSUES+=("dns: Cannot resolve $host from host")
        fi
    done

    # In-cluster DNS via a running pod
    local test_pod
    test_pod=$(kc get pods -n "$NAMESPACE" --no-headers 2>/dev/null | grep Running | head -1 | awk '{print $1}')
    if [[ -n "$test_pod" ]]; then
        local svc_dns
        svc_dns=$(kc exec "$test_pod" -n "$NAMESPACE" -- nslookup kubernetes.default.svc.cluster.local 2>&1 || true)
        if echo "$svc_dns" | grep -q "Address"; then
            log_ok "In-cluster DNS working (from $test_pod)"
        else
            log_warn "In-cluster DNS may have issues"
        fi
    fi
}

menu_dns() {
    banner
    echo -e "  ${BOLD}DNS Resolution Check${NC}"
    echo ""
    DETECTED_ISSUES=()
    scan_dns
    pause
}

# ============================================================
#  6) Storage & PVCs
# ============================================================
scan_storage() {
    log_info "Storage & PVCs — $NAMESPACE"
    echo ""

    local pvcs
    pvcs=$(kc get pvc -n "$NAMESPACE" --no-headers 2>/dev/null || true)

    if [[ -z "$pvcs" ]]; then
        log_ok "No PVCs in namespace (stateless deployment)"
        return
    fi

    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        local name status vol capacity sc
        name=$(echo "$line" | awk '{print $1}')
        status=$(echo "$line" | awk '{print $2}')
        vol=$(echo "$line" | awk '{print $3}')
        capacity=$(echo "$line" | awk '{print $4}')
        sc=$(echo "$line" | awk '{print $6}')

        if [[ "$status" == "Bound" ]]; then
            log_ok "$name — Bound ($capacity, sc: $sc)"
        elif [[ "$status" == "Pending" ]]; then
            log_err "$name — Pending"
            local events
            events=$(kc describe pvc "$name" -n "$NAMESPACE" 2>/dev/null | grep -A3 "Events:" | tail -2)
            [[ -n "$events" ]] && echo -e "        ${DIM}$events${NC}"
            DETECTED_ISSUES+=("pvc-pending: $name is stuck in Pending")
        else
            log_warn "$name — $status"
        fi
    done <<< "$pvcs"

    # Check storage classes
    local scs
    scs=$(kc get sc --no-headers 2>/dev/null || true)
    if [[ -n "$scs" ]]; then
        local default_sc
        default_sc=$(echo "$scs" | grep "(default)" | awk '{print $1}' || true)
        if [[ -n "$default_sc" ]]; then
            log_ok "Default StorageClass: $default_sc"
        else
            log_warn "No default StorageClass set"
        fi
    fi
}

menu_storage() {
    banner
    echo -e "  ${BOLD}Storage & PVC Check${NC}"
    echo ""
    DETECTED_ISSUES=()
    scan_storage
    pause
}

# ============================================================
#  7) Resource usage
# ============================================================
scan_resources() {
    log_info "Resource usage"
    echo ""

    # Node resources
    if kc top nodes &>/dev/null; then
        echo -e "  ${BOLD}Nodes:${NC}"
        kc top nodes 2>/dev/null | while IFS= read -r line; do
            echo "    $line"
        done
        echo ""
    else
        log_warn "Metrics server not available (kubectl top won't work)"
    fi

    # Pod resources in namespace
    if kc top pods -n "$NAMESPACE" &>/dev/null; then
        echo -e "  ${BOLD}Pods (${NAMESPACE}):${NC}"
        kc top pods -n "$NAMESPACE" 2>/dev/null | while IFS= read -r line; do
            echo "    $line"
        done
    fi
}

menu_resources() {
    banner
    echo -e "  ${BOLD}Resource Usage${NC}"
    echo ""
    scan_resources
    pause
}

# ============================================================
#  8) Recent events
# ============================================================
menu_events() {
    banner
    echo -e "  ${BOLD}Recent Events — ${NAMESPACE}${NC}"
    echo ""

    local choice
    choice=$(pick_one "Show events from:" "Namespace ($NAMESPACE)" "All namespaces" "Warnings only ($NAMESPACE)" "Warnings only (all)")

    echo ""
    case "$choice" in
        1) kc get events -n "$NAMESPACE" --sort-by='.lastTimestamp' 2>/dev/null | tail -30 ;;
        2) kc get events -A --sort-by='.lastTimestamp' 2>/dev/null | tail -30 ;;
        3) kc get events -n "$NAMESPACE" --field-selector type=Warning --sort-by='.lastTimestamp' 2>/dev/null | tail -30 ;;
        4) kc get events -A --field-selector type=Warning --sort-by='.lastTimestamp' 2>/dev/null | tail -30 ;;
        *) ;;
    esac
    pause
}

# ============================================================
#  9) Interactive pod debugger
# ============================================================
menu_pod_debugger() {
    banner
    echo -e "  ${BOLD}Interactive Pod Debugger${NC}"
    echo ""

    # List pods
    local pods=()
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        pods+=("$(echo "$line" | awk '{printf "%-45s %-6s %-20s restarts:%-4s age:%s", $1, $2, $3, $4, $5}')")
    done < <(kc get pods -n "$NAMESPACE" --no-headers 2>/dev/null)

    if [[ ${#pods[@]} -eq 0 ]]; then
        log_warn "No pods found in $NAMESPACE"
        pause; return
    fi

    local choice
    choice=$(pick_one "Select a pod:" "${pods[@]}")
    [[ -z "$choice" || "$choice" -lt 1 || "$choice" -gt ${#pods[@]} ]] 2>/dev/null && return

    local pod_name
    pod_name=$(echo "${pods[$((choice-1))]}" | awk '{print $1}')

    pod_debug_menu "$pod_name"
}

pod_debug_menu() {
    local pod="$1"

    while true; do
        banner
        echo -e "  ${BOLD}Debugging: ${CYAN}${pod}${NC}"
        echo ""

        local status
        status=$(kc get pod "$pod" -n "$NAMESPACE" --no-headers 2>/dev/null | awk '{print $2, $3, "restarts:"$4}')
        echo -e "  Status: $status"
        echo ""
        hr
        echo ""
        echo -e "    ${CYAN}1)${NC}  Show all container logs"
        echo -e "    ${CYAN}2)${NC}  Show logs for specific container"
        echo -e "    ${CYAN}3)${NC}  Show previous crash logs"
        echo -e "    ${CYAN}4)${NC}  Describe pod"
        echo -e "    ${CYAN}5)${NC}  Exec into container"
        echo -e "    ${CYAN}6)${NC}  Check environment variables"
        echo -e "    ${CYAN}7)${NC}  Check mounted volumes"
        echo -e "    ${CYAN}8)${NC}  Check resource limits vs usage"
        echo -e "    ${CYAN}9)${NC}  Scan for known errors"
        echo ""
        echo -e "    ${CYAN}0)${NC}  Back"
        echo ""
        echo -e "    ${DIM}Tip: Press q to exit log/describe views${NC}"
        echo ""

        local action
        read -rp "  Choose [0-9]: " action || _dpd_eof_exit

        case "$action" in
            1)
                echo ""
                echo -e "  ${DIM}── Press q to quit, arrow keys to scroll, / to search ──${NC}"
                kc logs "$pod" -n "$NAMESPACE" --all-containers --tail=50 2>&1 | less -R
                ;;
            2)
                local containers=()
                while IFS= read -r c; do
                    [[ -n "$c" ]] && containers+=("$c")
                done < <(kc get pod "$pod" -n "$NAMESPACE" -o jsonpath='{range .spec.initContainers[*]}{.name}{"\n"}{end}{range .spec.containers[*]}{.name}{"\n"}{end}' 2>/dev/null)

                if [[ ${#containers[@]} -eq 0 ]]; then
                    log_warn "No containers found"
                    pause; continue
                fi

                local cc
                cc=$(pick_one "Select container:" "${containers[@]}")
                [[ -z "$cc" || "$cc" -lt 1 || "$cc" -gt ${#containers[@]} ]] 2>/dev/null && continue
                echo ""
                echo -e "  ${DIM}── Press q to quit, arrow keys to scroll, / to search ──${NC}"
                kc logs "$pod" -n "$NAMESPACE" -c "${containers[$((cc-1))]}" --tail=80 2>&1 | less -R
                ;;
            3)
                echo ""
                echo -e "  ${DIM}── Press q to quit, arrow keys to scroll, / to search ──${NC}"
                kc logs "$pod" -n "$NAMESPACE" --all-containers --previous --tail=50 2>&1 | less -R
                ;;
            4)
                echo ""
                echo -e "  ${DIM}── Press q to quit, arrow keys to scroll, / to search ──${NC}"
                kc describe pod "$pod" -n "$NAMESPACE" 2>&1 | less -R
                ;;
            5)
                local containers=()
                while IFS= read -r c; do
                    [[ -n "$c" ]] && containers+=("$c")
                done < <(kc get pod "$pod" -n "$NAMESPACE" -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' 2>/dev/null)

                if [[ ${#containers[@]} -eq 0 ]]; then
                    log_warn "No containers found"
                    pause; continue
                fi

                local cc
                cc=$(pick_one "Select container:" "${containers[@]}")
                [[ -z "$cc" || "$cc" -lt 1 || "$cc" -gt ${#containers[@]} ]] 2>/dev/null && continue

                echo ""
                echo -e "  ${DIM}── Type 'exit' or press Ctrl+D to leave the shell ──${NC}"
                kc exec -it "$pod" -n "$NAMESPACE" -c "${containers[$((cc-1))]}" -- bash 2>/dev/null \
                    || kc exec -it "$pod" -n "$NAMESPACE" -c "${containers[$((cc-1))]}" -- sh 2>/dev/null \
                    || log_err "Cannot exec into container"
                ;;
            6)
                echo ""
                echo -e "  ${BOLD}Environment variables:${NC}"
                echo ""
                kc get pod "$pod" -n "$NAMESPACE" -o jsonpath='{range .spec.containers[*]}  Container: {.name}{"\n"}{range .env[*]}    {.name}={.value}{"\n"}{end}{"\n"}{end}' 2>/dev/null
                echo ""
                echo -e "  ${BOLD}Init container env:${NC}"
                echo ""
                kc get pod "$pod" -n "$NAMESPACE" -o jsonpath='{range .spec.initContainers[*]}  Container: {.name}{"\n"}{range .env[*]}    {.name}={.value}{"\n"}{end}{"\n"}{end}' 2>/dev/null
                echo ""
                pause
                ;;
            7)
                echo ""
                echo -e "  ${BOLD}Volumes:${NC}"
                kc get pod "$pod" -n "$NAMESPACE" -o json 2>/dev/null | \
                    python3 -c "
import json, sys
pod = json.load(sys.stdin)
for v in pod['spec'].get('volumes', []):
    name = v['name']
    if 'hostPath' in v: src = 'hostPath: ' + v['hostPath']['path']
    elif 'secret' in v: src = 'secret: ' + v['secret']['secretName']
    elif 'configMap' in v: src = 'configMap: ' + v['configMap']['name']
    elif 'emptyDir' in v: src = 'emptyDir'
    elif 'projected' in v: src = 'projected'
    elif 'persistentVolumeClaim' in v: src = 'pvc: ' + v['persistentVolumeClaim']['claimName']
    else: src = str(list(v.keys()))
    print(f'    {name}: {src}')
" 2>/dev/null || echo "    (requires python3 for formatted output)"
                echo ""
                echo -e "  ${BOLD}Container mounts:${NC}"
                kc get pod "$pod" -n "$NAMESPACE" -o json 2>/dev/null | \
                    python3 -c "
import json, sys
pod = json.load(sys.stdin)
for ctype in ['initContainers', 'containers']:
    for c in pod['spec'].get(ctype, []):
        print(f'    [{c[\"name\"]}]')
        for m in c.get('volumeMounts', []):
            ro = ' (ro)' if m.get('readOnly') else ''
            print(f'      {m[\"mountPath\"]} <- {m[\"name\"]}{ro}')
" 2>/dev/null || echo "    (requires python3 for formatted output)"
                echo ""
                pause
                ;;
            8)
                echo ""
                echo -e "  ${BOLD}Resource requests / limits:${NC}"
                kc get pod "$pod" -n "$NAMESPACE" -o json 2>/dev/null | \
                    python3 -c "
import json, sys
pod = json.load(sys.stdin)
for c in pod['spec'].get('containers', []):
    res = c.get('resources', {})
    req = res.get('requests', {})
    lim = res.get('limits', {})
    print(f'    {c[\"name\"]}:')
    print(f'      CPU:    request={req.get(\"cpu\", \"-\"):>8s}  limit={lim.get(\"cpu\", \"-\"):>8s}')
    print(f'      Memory: request={req.get(\"memory\", \"-\"):>8s}  limit={lim.get(\"memory\", \"-\"):>8s}')
" 2>/dev/null || echo "    (requires python3 for formatted output)"
                echo ""
                if kc top pod "$pod" -n "$NAMESPACE" --containers &>/dev/null; then
                    echo -e "  ${BOLD}Current usage:${NC}"
                    kc top pod "$pod" -n "$NAMESPACE" --containers 2>/dev/null | sed 's/^/    /'
                fi
                echo ""
                pause
                ;;
            9)
                DETECTED_ISSUES=()
                echo ""
                scan_pod_containers "$pod"
                if [[ ${#DETECTED_ISSUES[@]} -gt 0 ]]; then
                    echo ""
                    for issue in "${DETECTED_ISSUES[@]}"; do
                        echo -e "    ${RED}•${NC} $issue"
                    done
                    if confirm "Attempt fixes?"; then
                        run_all_fixes
                    fi
                else
                    log_ok "No known error patterns found"
                fi
                pause
                ;;
            0) return ;;
            *) ;;
        esac
    done
}

# ============================================================
#  10) Restart a deployment
# ============================================================
menu_restart() {
    banner
    echo -e "  ${BOLD}Restart a Deployment${NC}"
    echo ""

    local deployments=()
    while IFS= read -r line; do
        [[ -z "$line" ]] && continue
        deployments+=("$(echo "$line" | awk '{printf "%-40s ready:%-10s age:%s", $1, $2, $5}')")
    done < <(kc get deployments -n "$NAMESPACE" --no-headers 2>/dev/null)

    if [[ ${#deployments[@]} -eq 0 ]]; then
        log_warn "No deployments found"
        pause; return
    fi

    local choice
    choice=$(pick_one "Select deployment to restart:" "${deployments[@]}")
    [[ -z "$choice" || "$choice" -lt 1 || "$choice" -gt ${#deployments[@]} ]] 2>/dev/null && return

    local dep_name
    dep_name=$(echo "${deployments[$((choice-1))]}" | awk '{print $1}')

    if confirm "Restart deployment $dep_name?"; then
        kc rollout restart deployment/"$dep_name" -n "$NAMESPACE"
        log_fix "Restarting $dep_name..."
        kc rollout status deployment/"$dep_name" -n "$NAMESPACE" --timeout=120s 2>/dev/null || true
    fi
    pause
}

# ============================================================
#  11) Change namespace
# ============================================================
menu_change_namespace() {
    banner
    echo -e "  ${BOLD}Change Namespace${NC}"
    echo ""
    echo -e "  Current: ${CYAN}${NAMESPACE}${NC}"

    local namespaces=()
    while IFS= read -r ns; do
        [[ -n "$ns" ]] && namespaces+=("$ns")
    done < <(kc get namespaces --no-headers 2>/dev/null | awk '{print $1}')

    if [[ ${#namespaces[@]} -eq 0 ]]; then
        log_warn "Cannot list namespaces"
        pause; return
    fi

    local choice
    choice=$(pick_one "Select namespace:" "${namespaces[@]}")
    [[ -z "$choice" || "$choice" -lt 1 || "$choice" -gt ${#namespaces[@]} ]] 2>/dev/null && return

    NAMESPACE="${namespaces[$((choice-1))]}"
    log_ok "Switched to: $NAMESPACE"
    pause
}

# ============================================================
#  12) Tail sources & destinations (via dataplane tap)
# ============================================================
find_dataplane_pod() {
    kc get pods -n "$NAMESPACE" --no-headers 2>/dev/null \
        | grep -i "data.plane" \
        | grep -v "collector" \
        | grep "Running" \
        | head -1 \
        | awk '{print $1}'
}

menu_dataplane_tap() {
    banner
    echo -e "  ${BOLD}Tail Sources & Destinations${NC}"
    echo -e "  ${DIM}Powered by dataplane tap${NC}"
    echo ""

    local dp_pod
    dp_pod=$(find_dataplane_pod)

    if [[ -z "$dp_pod" ]]; then
        log_err "No running dataplane pod found in $NAMESPACE"
        log_info "Looking for pods matching 'dataplane' or 'data-plane'..."
        kc get pods -n "$NAMESPACE" --no-headers 2>/dev/null | sed 's/^/    /'
        pause; return
    fi

    log_ok "Dataplane pod: ${CYAN}${dp_pod}${NC}"
    echo ""

    # Read data_plane_config.yaml from inside the pod
    local worker_yaml
    worker_yaml=$(kc exec "$dp_pod" -n "$NAMESPACE" -- cat /etc/dataplane/data_plane_config.yaml 2>&1)

    if [[ $? -ne 0 || -z "$worker_yaml" ]]; then
        log_err "Could not read /etc/dataplane/data_plane_config.yaml from $dp_pod"
        echo -e "    ${DIM}${worker_yaml}${NC}"
        pause; return
    fi

    # Parse sources and sinks (destinations) from the YAML
    local sources=() sinks=()

    while IFS= read -r src; do
        [[ -n "$src" ]] && sources+=("$src")
    done < <(echo "$worker_yaml" | python3 -c "
import sys, yaml
try:
    data = yaml.safe_load(sys.stdin.read())
    for key in sorted(data.get('sources', {}).keys()):
        kind = data['sources'][key].get('type', 'unknown')
        print(f'{key} ({kind})')
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
" 2>/dev/null)

    while IFS= read -r snk; do
        [[ -n "$snk" ]] && sinks+=("$snk")
    done < <(echo "$worker_yaml" | python3 -c "
import sys, yaml
try:
    data = yaml.safe_load(sys.stdin.read())
    for key in sorted(data.get('sinks', {}).keys()):
        kind = data['sinks'][key].get('type', 'unknown')
        print(f'{key} ({kind})')
except Exception as e:
    print(f'ERROR: {e}', file=sys.stderr)
" 2>/dev/null)

    if [[ ${#sources[@]} -eq 0 && ${#sinks[@]} -eq 0 ]]; then
        log_warn "No sources or destinations found in data_plane_config.yaml"
        echo ""
        echo -e "  ${DIM}Raw YAML (first 30 lines):${NC}"
        echo "$worker_yaml" | head -30 | sed 's/^/    /'
        pause; return
    fi

    # Build combined menu
    local all_items=() item_ids=()

    if [[ ${#sources[@]} -gt 0 ]]; then
        echo -e "  ${BOLD}Sources:${NC}"
        for i in "${!sources[@]}"; do
            local id
            id=$(echo "${sources[$i]}" | awk '{print $1}')
            all_items+=("${GREEN}[source]${NC} ${sources[$i]}")
            item_ids+=("$id")
            echo -e "    ${CYAN}$((${#all_items[@]})))${NC} ${GREEN}[source]${NC} ${sources[$i]}"
        done
        echo ""
    fi

    if [[ ${#sinks[@]} -gt 0 ]]; then
        echo -e "  ${BOLD}Destinations (sinks):${NC}"
        for i in "${!sinks[@]}"; do
            local id
            id=$(echo "${sinks[$i]}" | awk '{print $1}')
            all_items+=("${YELLOW}[sink]${NC}   ${sinks[$i]}")
            item_ids+=("$id")
            echo -e "    ${CYAN}$((${#all_items[@]})))${NC} ${YELLOW}[sink]${NC}   ${sinks[$i]}"
        done
        echo ""
    fi

    hr
    echo ""
    echo -e "    ${CYAN}0)${NC}  Back"
    echo ""

    local choice
    read -rp "  Select component to tap [0-${#all_items[@]}]: " choice || _dpd_eof_exit

    [[ "$choice" == "0" || -z "$choice" ]] && return
    if ! [[ "$choice" =~ ^[0-9]+$ ]] || [[ "$choice" -lt 1 || "$choice" -gt ${#all_items[@]} ]]; then
        log_warn "Invalid selection"
        pause; return
    fi

    local tap_id="${item_ids[$((choice-1))]}"

    echo ""
    hr
    echo ""
    echo -e "  ${BOLD}Tail: ${CYAN}${tap_id}${NC}"
    echo -e "  ${DIM}via dataplane tap${NC}"
    echo ""
    echo -e "    ${CYAN}1)${NC}  All events"
    echo -e "    ${CYAN}2)${NC}  Errors & warnings only"
    echo ""
    echo -e "    ${CYAN}0)${NC}  Back"
    echo ""

    local mode
    read -rp "  Choose [0-2]: " mode || _dpd_eof_exit

    case "$mode" in
        1)
            echo ""
            log_info "Tailing ${BOLD}${tap_id}${NC}..."
            echo -e "  ${DIM}── Press Ctrl+C to stop ──${NC}"
            echo ""
            kc exec -it "$dp_pod" -n "$NAMESPACE" -- bin/dataplane tap "$tap_id" 2>&1 || {
                echo ""
                log_warn "Tap exited. The component ID may need a different format."
                echo -e "  ${DIM}Tried: bin/dataplane tap ${tap_id}${NC}"
            }
            ;;
        2)
            echo ""
            read -rp "  Duration in seconds [60]: " duration || _dpd_eof_exit
            duration="${duration:-60}"

            echo ""
            log_info "Tailing ${BOLD}${tap_id}${NC} — errors/warnings only (${duration}s)..."
            echo -e "  ${DIM}── Press Ctrl+C to stop early ──${NC}"
            echo ""

            local err_count=0
            local start_ts
            start_ts=$(date +%s)

            kc exec "$dp_pod" -n "$NAMESPACE" -- bin/dataplane tap "$tap_id" 2>&1 | \
            while IFS= read -r line; do
                local now
                now=$(date +%s)
                local elapsed=$(( now - start_ts ))
                if [[ $elapsed -ge $duration ]]; then
                    break
                fi

                if echo "$line" | grep -qiE 'error|err|fail|fatal|panic|warn|critical|exception|refused|timeout|rejected|dropped'; then
                    ((err_count++)) || true
                    local ts
                    ts=$(date '+%H:%M:%S')
                    echo -e "  ${RED}[${ts}]${NC} $line"
                fi
            done

            echo ""
            hr
            log_info "Tap finished after ${duration}s"
            ;;
        0) return ;;
        *) return ;;
    esac
    pause
}

# ============================================================
#  13) Proxy & connectivity check
# ============================================================
CONTENT_BASE_URL="${CONTENT_BASE_URL:-https://contents.observo.ai}"

# Required external endpoints for Data Pipeline install & runtime
OBSERVO_ENDPOINTS=(
    "https://contents.observo.ai|CDN — binaries, images, charts"
    "https://p01-auth.observo.ai|Data Pipeline cloud auth"
    "https://p01-api.observo.ai|Data Pipeline cloud API"
    "http://checkip.amazonaws.com|Public IP detection (TLS cert gen)"
)

test_endpoint() {
    local url="$1" label="$2" proxy_url="$3"
    local curl_opts=(-s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10)

    if [[ -n "$proxy_url" ]]; then
        curl_opts+=(--proxy "$proxy_url")
    fi

    local code
    code=$(curl "${curl_opts[@]}" "$url" 2>/dev/null || echo "000")

    if [[ "$code" == "000" ]]; then
        log_err "$label — connection failed (timeout/refused)"
        return 1
    elif [[ "$code" =~ ^[5] ]]; then
        log_warn "$label — HTTP $code (server error)"
        return 1
    else
        # Any HTTP response (2xx, 3xx, 4xx) = endpoint is reachable
        # 302 = auth redirect, 401/403 = auth required, 415 = wrong content-type
        # All prove connectivity is working
        log_ok "$label — HTTP $code"
        return 0
    fi
}

test_endpoint_tls() {
    local host="$1" port="${2:-443}"
    local result
    result=$(echo | openssl s_client -connect "${host}:${port}" -servername "$host" 2>&1)

    if echo "$result" | grep -q "Verify return code: 0"; then
        local issuer
        issuer=$(echo "$result" | grep "issuer=" | head -1 | sed 's/.*CN = //')
        log_ok "TLS ${host}:${port} — verified (${issuer:-unknown})"
        return 0
    elif echo "$result" | grep -q "verify return:1"; then
        log_ok "TLS ${host}:${port} — verified"
        return 0
    else
        local err
        err=$(echo "$result" | grep "verify error" | head -1 | sed 's/.*://' || true)
        log_err "TLS ${host}:${port} — verification failed${err:+ ($err)}"
        return 1
    fi
}

menu_proxy_connectivity() {
    banner
    echo -e "  ${BOLD}Proxy & Connectivity Check${NC}"
    echo ""

    local total_pass=0 total_fail=0

    # --- Proxy environment ---
    echo -e "  ${BOLD}1. Proxy Environment${NC}"
    echo ""

    local proxy_detected=false
    local active_proxy=""
    for var in HTTP_PROXY http_proxy HTTPS_PROXY https_proxy ALL_PROXY all_proxy; do
        local val="${!var:-}"
        if [[ -n "$val" ]]; then
            log_info "$var = $val"
            proxy_detected=true
            [[ -z "$active_proxy" ]] && active_proxy="$val"
        fi
    done

    local no_proxy="${NO_PROXY:-${no_proxy:-}}"
    if [[ -n "$no_proxy" ]]; then
        log_info "NO_PROXY = $no_proxy"
    fi

    if $proxy_detected; then
        log_warn "Proxy detected — will test with and without proxy"
    else
        log_ok "No proxy environment variables set"
    fi
    echo ""

    # --- DNS resolution ---
    echo -e "  ${BOLD}2. DNS Resolution${NC}"
    echo ""

    for pair in "${OBSERVO_ENDPOINTS[@]}"; do
        local url="${pair%%|*}"
        local host
        host=$(echo "$url" | sed 's|https\?://||' | cut -d/ -f1)

        if nslookup "$host" &>/dev/null 2>&1 || dig +short "$host" 2>/dev/null | grep -q .; then
            log_ok "Resolves: $host"
            ((total_pass++)) || true
        else
            log_err "Cannot resolve: $host"
            ((total_fail++)) || true
        fi
    done
    echo ""

    # --- Direct endpoint connectivity ---
    echo -e "  ${BOLD}3. Endpoint Connectivity (direct)${NC}"
    echo ""

    for pair in "${OBSERVO_ENDPOINTS[@]}"; do
        local url="${pair%%|*}"
        local label="${pair##*|}"

        if test_endpoint "$url" "$label" ""; then
            ((total_pass++)) || true
        else
            ((total_fail++)) || true
        fi
    done
    echo ""

    # --- Via proxy if detected ---
    if $proxy_detected; then
        echo -e "  ${BOLD}4. Endpoint Connectivity (via proxy: ${active_proxy})${NC}"
        echo ""

        for pair in "${OBSERVO_ENDPOINTS[@]}"; do
            local url="${pair%%|*}"
            local label="${pair##*|}"

            if test_endpoint "$url" "${label} [proxied]" "$active_proxy"; then
                ((total_pass++)) || true
            else
                ((total_fail++)) || true
            fi
        done
        echo ""
    fi

    # --- TLS verification ---
    echo -e "  ${BOLD}$( $proxy_detected && echo "5" || echo "4"). TLS Certificate Verification${NC}"
    echo ""

    for host in contents.observo.ai p01-auth.observo.ai p01-api.observo.ai; do
        if test_endpoint_tls "$host"; then
            ((total_pass++)) || true
        else
            ((total_fail++)) || true
        fi
    done
    echo ""

    # --- CDN token validation ---
    local section_num
    $proxy_detected && section_num=6 || section_num=5
    echo -e "  ${BOLD}${section_num}. CDN Token Validation${NC}"
    echo ""

    local cdn_token="${CDN_TOKEN:-}"
    if [[ -z "$cdn_token" ]]; then
        read -rp "  Enter CDN token (or press Enter to skip): " cdn_token || _dpd_eof_exit
    fi

    if [[ -n "$cdn_token" ]]; then
        local response
        response=$(curl -sf -X POST "${CONTENT_BASE_URL}/v1/auth/validate-token" \
            -H "Content-Type: application/json" \
            -d "{\"token\": \"${cdn_token}\"}" \
            --connect-timeout 10 --max-time 15 2>&1 || echo "CURL_FAILED")

        if [[ "$response" == "CURL_FAILED" ]]; then
            log_err "CDN token endpoint unreachable"
            ((total_fail++)) || true
        elif echo "$response" | grep -q '"valid"[[:space:]]*:[[:space:]]*true'; then
            local auth_as expires
            auth_as=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('authenticated_as','unknown'))" 2>/dev/null || echo "unknown")
            expires=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('expires_at','unknown'))" 2>/dev/null || echo "unknown")
            log_ok "CDN token valid — authenticated as: ${auth_as}, expires: ${expires}"
            ((total_pass++)) || true

            # Test a signed download
            local signature
            signature=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('signature',''))" 2>/dev/null || echo "")

            if [[ -n "$signature" && "$signature" != "CLOUDFRONT_SIGNING_NOT_CONFIGURED" ]]; then
                local test_url="${CONTENT_BASE_URL}/charts/site/v2.22.0/?${signature}"
                local dl_code
                dl_code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 "$test_url" 2>/dev/null || echo "000")
                if [[ "$dl_code" =~ ^[23] ]]; then
                    log_ok "Signed CDN download works (HTTP $dl_code)"
                    ((total_pass++)) || true
                else
                    log_warn "Signed CDN download returned HTTP $dl_code"
                    ((total_fail++)) || true
                fi
            fi
        else
            local msg
            msg=$(echo "$response" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('message','invalid token'))" 2>/dev/null || echo "invalid or expired")
            log_err "CDN token invalid — ${msg}"
            ((total_fail++)) || true
        fi
    else
        log_info "Skipped (no token provided)"
    fi
    echo ""

    # --- Helm values proxy config ---
    ((section_num++))
    echo -e "  ${BOLD}${section_num}. Helm Values — Proxy Configuration${NC}"
    echo ""

    local helm_vals
    helm_vals=$(helm get values "$RELEASE_NAME" -n "$NAMESPACE" -a ${KUBECONFIG:+--kubeconfig "$KUBECONFIG"} 2>/dev/null || true)

    if [[ -n "$helm_vals" ]]; then
        local helm_proxy
        helm_proxy=$(echo "$helm_vals" | grep -iE "HTTP_PROXY|HTTPS_PROXY|NO_PROXY|ALL_PROXY" || true)
        if [[ -n "$helm_proxy" ]]; then
            log_ok "Proxy env vars found in Helm values:"
            echo "$helm_proxy" | sed 's/^/        /'
        else
            if $proxy_detected; then
                log_err "Proxy detected on host but NO proxy config in Helm values"
                echo -e "        ${DIM}Pods will not inherit host proxy settings${NC}"
                echo -e "        ${DIM}control-agent and data-plane cannot reach the remote manager${NC}"
                ((total_fail++)) || true
            else
                log_info "No proxy config in Helm values (none needed if direct access)"
            fi
        fi
    else
        log_warn "Could not read Helm values (release: $RELEASE_NAME)"
    fi
    echo ""

    # --- Per-pod hybrid connectivity ---
    ((section_num++))
    echo -e "  ${BOLD}${section_num}. Pod -> Remote Manager Connectivity${NC}"
    echo ""

    # Critical pods that need outbound to the remote manager
    local critical_pods=("control-agent" "data-plane" "observo-collector" "pattern-extractor")
    local remote_endpoints=("https://p01-auth.observo.ai" "https://p01-api.observo.ai")

    for pod_pattern in "${critical_pods[@]}"; do
        local pod_name
        pod_name=$(kc get pods -n "$NAMESPACE" --no-headers 2>/dev/null \
            | grep -i "$pod_pattern" | grep -v "collector" | grep "Running" | head -1 | awk '{print $1}')

        # For observo-collector, we do want the collector
        if [[ "$pod_pattern" == "observo-collector" ]]; then
            pod_name=$(kc get pods -n "$NAMESPACE" --no-headers 2>/dev/null \
                | grep -i "observo-collector" | grep "Running" | head -1 | awk '{print $1}')
        fi

        [[ -z "$pod_name" ]] && continue

        echo -e "  ${BOLD}${pod_name}:${NC}"

        # Check proxy env vars inside the pod
        local pod_proxy_env
        pod_proxy_env=$(kc exec "$pod_name" -n "$NAMESPACE" -- \
            sh -c 'for v in HTTP_PROXY http_proxy HTTPS_PROXY https_proxy NO_PROXY no_proxy; do
                eval val=\$$v
                [ -n "$val" ] && echo "    $v=$val"
            done' 2>/dev/null || true)

        if [[ -n "$pod_proxy_env" ]]; then
            log_ok "Proxy env configured inside pod:"
            echo "$pod_proxy_env"
        else
            echo -e "    ${DIM}No proxy env vars inside pod${NC}"
        fi

        # Test each remote endpoint from inside the pod
        for ep in "${remote_endpoints[@]}"; do
            local ep_host
            ep_host=$(echo "$ep" | sed 's|https\?://||')
            local code
            code=$(kc exec "$pod_name" -n "$NAMESPACE" -- \
                curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 --max-time 10 \
                "$ep" 2>/dev/null || echo "no-curl")

            if [[ "$code" == "no-curl" ]]; then
                # Try wget fallback
                kc exec "$pod_name" -n "$NAMESPACE" -- \
                    wget -q --spider --timeout=5 "$ep" 2>/dev/null && code="200" || code="000"
            fi

            if [[ "$code" == "000" || "$code" == "no-curl" ]]; then
                log_err "  -> ${ep_host} — BLOCKED (timeout/connection refused)"
                ((total_fail++)) || true
            elif [[ "$code" =~ ^[5] ]]; then
                log_warn "  -> ${ep_host} — HTTP $code (server error)"
                ((total_fail++)) || true
            else
                log_ok "  -> ${ep_host} — HTTP $code"
                ((total_pass++)) || true
            fi
        done

        # For control-agent, also check recent logs for auth failures
        if [[ "$pod_pattern" == "control-agent" ]]; then
            local auth_errors
            auth_errors=$(kc logs "$pod_name" -n "$NAMESPACE" --tail=100 2>/dev/null \
                | grep -iE "certificate signed by unknown authority|connection refused|connect: connection timed out|no such host|dial tcp.*timeout|token.*malformed|unauthorized|forbidden|cannot authenticate|failed to authenticate|TLS handshake" \
                | tail -5 || true)

            if [[ -n "$auth_errors" ]]; then
                log_err "  Recent auth/connection errors in logs:"
                echo "$auth_errors" | while IFS= read -r errline; do
                    echo -e "        ${RED}${errline}${NC}"
                done
                ((total_fail++)) || true
            else
                log_ok "  No auth/connection errors in recent logs"
                ((total_pass++)) || true
            fi
        fi

        echo ""
    done

    # --- K3s systemd proxy check ---
    ((section_num++))
    echo -e "  ${BOLD}${section_num}. K3s Service Proxy Config${NC}"
    echo ""

    local k3s_env="/etc/systemd/system/k3s.service.env"
    if [[ -f "$k3s_env" ]]; then
        local k3s_proxy
        k3s_proxy=$(grep -i "PROXY" "$k3s_env" 2>/dev/null || true)
        if [[ -n "$k3s_proxy" ]]; then
            log_ok "K3s proxy config found in $k3s_env:"
            echo "$k3s_proxy" | sed 's/^/        /'
        else
            if $proxy_detected; then
                log_err "Proxy detected but K3s has no proxy config"
                echo -e "        ${DIM}K3s pods will not route through the proxy${NC}"
                ((total_fail++)) || true
            else
                log_ok "No proxy config (none needed)"
            fi
        fi
    else
        if $proxy_detected; then
            log_err "$k3s_env does not exist — K3s has no proxy config"
            ((total_fail++)) || true
        else
            log_info "$k3s_env not found (may not be K3s, or direct access)"
        fi
    fi

    # Also check k3s.service drop-in overrides
    local k3s_override="/etc/systemd/system/k3s.service.d/"
    if [[ -d "$k3s_override" ]]; then
        local override_proxy
        override_proxy=$(grep -r -i "PROXY" "$k3s_override" 2>/dev/null || true)
        if [[ -n "$override_proxy" ]]; then
            log_ok "K3s drop-in proxy override found:"
            echo "$override_proxy" | sed 's/^/        /'
        fi
    fi
    echo ""

    # --- Summary ---
    hr
    echo ""
    echo -e "  ${BOLD}Summary:${NC} ${GREEN}${total_pass} passed${NC}, ${RED}${total_fail} failed${NC}"
    echo ""

    if [[ $total_fail -gt 0 ]]; then
        echo -e "  ${YELLOW}${BOLD}Recommendations:${NC}"
        echo ""

        if $proxy_detected; then
            echo -e "  ${YELLOW}${BOLD}A) Proxy detected on host but pods may not be configured.${NC}"
        else
            echo -e "  ${YELLOW}${BOLD}A) Host can reach endpoints but pods cannot?${NC}"
            echo -e "     This usually means an external/network proxy or firewall is"
            echo -e "     blocking pod egress. Pods need explicit proxy configuration."
        fi
        echo ""
        echo -e "  ${BOLD}  1. K3s service (so containerd/kubelet route through proxy):${NC}"
        echo -e "        ${DIM}sudo tee /etc/systemd/system/k3s.service.env << 'EOF'"
        echo -e "        HTTP_PROXY=<proxy_url>"
        echo -e "        HTTPS_PROXY=<proxy_url>"
        echo -e "        NO_PROXY=127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,\\"
        echo -e "          .svc,.svc.cluster.local,localhost"
        echo -e "        EOF"
        echo -e "        sudo systemctl daemon-reload && sudo systemctl restart k3s${NC}"
        echo ""
        echo -e "  ${BOLD}  2. Helm values (so pods get proxy env vars):${NC}"
        echo -e "        ${DIM}# In your site values.yaml, add to each component:${NC}"
        echo -e "        ${DIM}control-agent:${NC}"
        echo -e "        ${DIM}  customEnv:${NC}"
        echo -e "        ${DIM}    - name: HTTP_PROXY${NC}"
        echo -e "        ${DIM}      value: \"<proxy_url>\"${NC}"
        echo -e "        ${DIM}    - name: HTTPS_PROXY${NC}"
        echo -e "        ${DIM}      value: \"<proxy_url>\"${NC}"
        echo -e "        ${DIM}    - name: NO_PROXY${NC}"
        echo -e "        ${DIM}      value: \"10.0.0.0/8,172.16.0.0/12,.svc,.svc.cluster.local\"${NC}"
        echo ""
        echo -e "  ${BOLD}  3. Quick fix — patch running deployments now:${NC}"
        echo ""

        if confirm "Patch proxy env vars into pods now?"; then
            local proxy_url
            read -rp "  Enter proxy URL (e.g. http://proxy.corp:8080): " proxy_url || _dpd_eof_exit
            [[ -n "$proxy_url" ]] && _apply_proxy_patch "$proxy_url"
        fi

        echo ""
        echo -e "    ${YELLOW}•${NC} Required outbound access for hybrid sites:"
        echo -e "        ${DIM}contents.observo.ai:443${NC}   (CDN — install artifacts)"
        echo -e "        ${DIM}p01-auth.observo.ai:443${NC}   (auth — control-agent tokens)"
        echo -e "        ${DIM}p01-api.observo.ai:443${NC}    (API  — config, pipelines)"
        echo -e "        ${DIM}checkip.amazonaws.com:80${NC}  (IP detection for TLS certs)"
        echo -e "        ${DIM}*.dkr.ecr.us-east-1.amazonaws.com:443${NC} (container images)"
        echo ""
    fi

    pause
}

# ============================================================
#  Masked init container panics
# ============================================================
scan_init_panics() {
    log_info "Checking for masked init container failures"
    echo ""

    local found=false
    local pods
    pods=$(kc get pods -n "$NAMESPACE" --no-headers 2>/dev/null | awk '{print $1}')

    while IFS= read -r pod; do
        [[ -z "$pod" ]] && continue
        local inits
        inits=$(kc get pod "$pod" -n "$NAMESPACE" \
            -o jsonpath='{range .status.initContainerStatuses[*]}{.name}{" "}{.state.terminated.exitCode}{"\n"}{end}' 2>/dev/null || true)

        while IFS= read -r line; do
            [[ -z "$line" ]] && continue
            local iname iexit
            iname=$(echo "$line" | awk '{print $1}')
            iexit=$(echo "$line" | awk '{print $2}')

            if [[ "$iexit" == "0" ]]; then
                local ilogs
                ilogs=$(kc logs "$pod" -n "$NAMESPACE" -c "$iname" --tail=20 2>&1 || true)
                if echo "$ilogs" | grep -q "panic:"; then
                    log_err "$pod/$iname — panic masked by pipe (exited 0)"
                    DETECTED_ISSUES+=("masked-panic: $pod/$iname panicked but reported exit 0")
                    found=true
                fi
            fi
        done <<< "$inits"
    done <<< "$pods"

    $found || log_ok "No masked init failures"
}

# ============================================================
#  Fix dispatcher
# ============================================================
run_all_fixes() {
    echo ""
    log_info "Running fixes..."
    echo ""

    local fixed=0
    local tls_fixed=false
    local conn_fixed=false
    local docker_init_blocked=false
    local wef_bundle=false
    for issue in "${DETECTED_ISSUES[@]:-}"; do
        [[ "$issue" == docker-init:* ]] && docker_init_blocked=true
        [[ "$issue" == wef-not-ready:* ]] && wef_bundle=true
    done

    for issue in "${DETECTED_ISSUES[@]}"; do
        case "$issue" in
            tls-ca-trust:*|malformed-token:*|masked-panic:*)
                if ! $tls_fixed; then
                    fix_tls_ca_trust && { ((fixed++)) || true; tls_fixed=true; }
                fi
                ;;
        esac
    done

    for issue in "${DETECTED_ISSUES[@]}"; do
        case "$issue" in
            oom:*)
                if [[ "$SITE_TYPE" == "docker" ]]; then
                    docker_fix_oom && { ((fixed++)) || true; }
                else
                    local pod_container
                    pod_container=$(echo "$issue" | sed 's/oom: //' | cut -d' ' -f1)
                    log_warn "OOMKilled: $pod_container — increase memory limits in Helm values"
                fi
                ;;
            connectivity:*)
                if [[ "$SITE_TYPE" == "docker" ]] && ! $conn_fixed; then
                    docker_fix_connectivity && { ((fixed++)) || true; conn_fixed=true; }
                fi
                ;;
            wef-checkpoint-store:*)
                # wef-not-ready's Make-ready includes the checkpoint store;
                # doing it here too would cost a second recreate.
                if [[ "$SITE_TYPE" == "docker" ]] && ! $wef_bundle; then
                    docker_fix_wef_checkpoint_store && { ((fixed++)) || true; }
                fi
                ;;
            wef-not-ready:*)
                if [[ "$SITE_TYPE" == "docker" ]]; then
                    docker_wef_make_ready inline && { ((fixed++)) || true; }
                fi
                ;;
            docker-svc-down:*)
                if $docker_init_blocked; then
                    : # services are blocked by control-plane-init; fixing init + restart is the remedy
                else
                    local svc
                    svc=$(echo "$issue" | sed 's#docker-svc-down: [^/]*/##' | cut -d' ' -f1)
                    docker_fix_restart_service "$svc" && { ((fixed++)) || true; }
                fi
                ;;
            docker-init:*)
                log_warn "control-plane-init has not completed — the 5 services stay down until it does."
                echo "    This is almost always a connectivity/TLS problem reaching the control plane."
                echo "    Fix the connectivity/TLS issue above, then restart the container to re-run init."
                ;;
            docker-restarting:*|docker-exited:*)
                log_warn "$issue"
                if confirm "Restart container $DOCKER_CONTAINER now?"; then
                    dk restart "$DOCKER_CONTAINER" && { log_fix "Restarted $DOCKER_CONTAINER"; ((fixed++)) || true; }
                fi
                ;;
            docker-token-missing:*)
                log_warn "$issue"
                echo "    The site token is written by control-plane-init after it authenticates."
                echo "    Resolve the auth/connectivity failure, then restart the container."
                ;;
            docker-volume-missing:*)
                log_warn "$issue"
                echo "    Ensure the data volume is mounted, e.g.:  -v observo-data:/var/observo/data"
                ;;
            docker-disk-pressure:*)
                log_warn "$issue"
                echo "    Free space on the Docker storage filesystem:"
                df -h /var/lib/docker 2>/dev/null | sed 's/^/      /'
                echo "    Consider: docker system prune, or expand the disk."
                ;;
            pvc-pending:*)
                log_warn "PVC pending — check StorageClass and provisioner"
                kc get sc 2>/dev/null | sed 's/^/    /'
                ;;
            rbac:*)
                log_warn "RBAC issue detected — check ServiceAccount and ClusterRoleBindings"
                local pod_name
                pod_name=$(echo "$issue" | sed 's/rbac: //' | cut -d/ -f1)
                local sa
                sa=$(kc get pod "$pod_name" -n "$NAMESPACE" -o jsonpath='{.spec.serviceAccountName}' 2>/dev/null || true)
                [[ -n "$sa" ]] && echo "    ServiceAccount: $sa"
                ;;
            image-pull:*)
                local pod_name
                pod_name=$(echo "$issue" | sed 's/image-pull: //' | cut -d' ' -f1)
                log_warn "Image pull failed for $pod_name — check image registry credentials"
                local secret
                secret=$(kc get pod "$pod_name" -n "$NAMESPACE" -o jsonpath='{.spec.imagePullSecrets[*].name}' 2>/dev/null || true)
                if [[ -n "$secret" ]]; then
                    echo "    Image pull secret: $secret"
                    kc get secret "$secret" -n "$NAMESPACE" &>/dev/null \
                        && echo "    Secret exists" \
                        || echo "    Secret MISSING"
                else
                    echo "    No imagePullSecrets configured"
                fi
                ;;
            node-pressure:*)
                log_warn "$issue"
                echo "    Check disk usage: df -h"
                echo "    Check memory: free -m"
                ;;
            crashloop:*|error-state:*)
                local pod_name dep_name issue_label
                if [[ "$issue" == crashloop:* ]]; then
                    pod_name=$(echo "$issue" | sed 's/crashloop: //' | cut -d' ' -f1)
                    issue_label="CrashLoopBackOff"
                else
                    pod_name=$(echo "$issue" | sed 's/error-state: //' | cut -d' ' -f1)
                    issue_label="Error state"
                fi
                # Derive parent deployment name from pod's ownerReferences
                dep_name=$(kc get pod "$pod_name" -n "$NAMESPACE" \
                    -o jsonpath='{.metadata.ownerReferences[0].name}' 2>/dev/null | sed 's/-[a-f0-9]\{8,10\}$//')
                log_warn "$issue_label: $pod_name (deployment: ${dep_name:-unknown})"

                # -- Diagnostics --
                echo ""
                local term_reason
                term_reason=$(kc get pod "$pod_name" -n "$NAMESPACE" \
                    -o jsonpath='{range .status.containerStatuses[*]}{.name}{": "}{.lastState.terminated.reason}{" (exit "}{.lastState.terminated.exitCode}{")\n"}{end}' 2>/dev/null || true)
                if [[ -n "$term_reason" ]]; then
                    echo "    Last termination:"
                    echo "$term_reason" | while IFS= read -r tr; do
                        [[ -n "$tr" ]] && echo "      $tr"
                    done
                fi
                echo ""
                echo "    Recent logs (last 20 lines — previous crash):"
                local crash_logs
                crash_logs=$(kc logs "$pod_name" -n "$NAMESPACE" --all-containers --previous --tail=80 2>&1 || true)
                if [[ -z "$crash_logs" || "$crash_logs" == *"previous terminated container"* ]]; then
                    crash_logs=$(kc logs "$pod_name" -n "$NAMESPACE" --all-containers --tail=80 2>&1 || true)
                fi
                echo "$crash_logs" | tail -20 | sed 's/^/      /'
                echo ""
                echo "    Recent events:"
                kc get events -n "$NAMESPACE" --field-selector "involvedObject.name=$pod_name" \
                    --sort-by='.lastTimestamp' 2>/dev/null | tail -5 | sed 's/^/      /'

                # -- Root cause analysis --
                local root_cause="unknown"

                local oom_check
                oom_check=$(kc get pod "$pod_name" -n "$NAMESPACE" \
                    -o jsonpath='{range .status.containerStatuses[*]}{.lastState.terminated.reason}{"\n"}{end}' 2>/dev/null || true)
                if echo "$oom_check" | grep -q "OOMKilled"; then
                    root_cause="oom"
                elif _dp_has_outbound_failure "$crash_logs"; then
                    root_cause="connectivity"
                elif echo "$crash_logs" | grep -q "certificate signed by unknown authority"; then
                    root_cause="tls"
                fi

                echo ""
                # -- Route to targeted fix --
                case "$root_cause" in
                    oom)
                        fix_oom "$pod_name" "$dep_name" && ((fixed++)) || true
                        ;;
                    connectivity)
                        fix_connectivity "$pod_name" "$dep_name" && ((fixed++)) || true
                        ;;
                    tls)
                        fix_tls_ca_trust && ((fixed++)) || true
                        ;;
                    *)
                        log_warn "No specific root cause identified in logs"
                        if confirm "Delete pod $pod_name to trigger a fresh restart?"; then
                            kc delete pod "$pod_name" -n "$NAMESPACE" && { log_fix "Deleted $pod_name"; ((fixed++)) || true; }
                        fi
                        ;;
                esac
                ;;
            not-ready:*)
                local pod_name
                pod_name=$(echo "$issue" | sed 's/not-ready: //' | cut -d' ' -f1)
                log_warn "Not ready: $pod_name"
                echo ""
                echo "    Recent logs (last 20 lines):"
                kc logs "$pod_name" -n "$NAMESPACE" --tail=20 --all-containers 2>&1 | sed 's/^/      /'
                echo ""
                echo "    Recent events:"
                kc get events -n "$NAMESPACE" --field-selector "involvedObject.name=$pod_name" \
                    --sort-by='.lastTimestamp' 2>/dev/null | tail -5 | sed 's/^/      /'
                echo ""
                local probes
                probes=$(kc get pod "$pod_name" -n "$NAMESPACE" \
                    -o jsonpath='{range .spec.containers[*]}{"  "}{.name}{": readinessProbe="}{.readinessProbe.httpGet.path}{" period="}{.readinessProbe.periodSeconds}{"s\n"}{end}' 2>/dev/null || true)
                if [[ -n "$probes" ]]; then
                    echo "    Readiness probes:"
                    echo "$probes" | sed 's/^/      /'
                fi
                echo ""
                if confirm "Delete pod $pod_name to trigger a fresh restart?"; then
                    kc delete pod "$pod_name" -n "$NAMESPACE" && { log_fix "Deleted $pod_name"; ((fixed++)) || true; }
                fi
                ;;
            pending:*)
                local pod_name
                pod_name=$(echo "$issue" | sed 's/pending: //' | cut -d' ' -f1)
                log_warn "Pending: $pod_name"
                echo ""
                echo "    Pod events:"
                kc get events -n "$NAMESPACE" --field-selector "involvedObject.name=$pod_name" \
                    --sort-by='.lastTimestamp' 2>/dev/null | tail -8 | sed 's/^/      /'
                echo ""
                echo "    Node allocatable resources:"
                kc get nodes -o custom-columns="NAME:.metadata.name,CPU:.status.allocatable.cpu,MEM:.status.allocatable.memory" \
                    --no-headers 2>/dev/null | sed 's/^/      /'
                echo ""
                local node_sel
                node_sel=$(kc get pod "$pod_name" -n "$NAMESPACE" \
                    -o jsonpath='{.spec.nodeSelector}' 2>/dev/null || true)
                local affinity
                affinity=$(kc get pod "$pod_name" -n "$NAMESPACE" \
                    -o jsonpath='{.spec.affinity}' 2>/dev/null || true)
                if [[ -n "$node_sel" && "$node_sel" != "{}" ]]; then
                    echo "    Node selector: $node_sel"
                fi
                if [[ -n "$affinity" && "$affinity" != "{}" ]]; then
                    echo "    Affinity rules configured (check with: kubectl describe pod $pod_name -n $NAMESPACE)"
                fi
                local requests
                requests=$(kc get pod "$pod_name" -n "$NAMESPACE" \
                    -o jsonpath='{range .spec.containers[*]}{"  "}{.name}{": cpu="}{.resources.requests.cpu}{" mem="}{.resources.requests.memory}{"\n"}{end}' 2>/dev/null || true)
                if [[ -n "$requests" ]]; then
                    echo "    Pod resource requests:"
                    echo "$requests" | sed 's/^/      /'
                fi
                ;;
        esac
    done

    echo ""
    [[ $fixed -gt 0 ]] && log_fix "Applied $fixed automatic fix(es)" || log_warn "Some issues need manual intervention (see above)"
}

fix_tls_ca_trust() {
    [[ "$SITE_TYPE" == "docker" ]] && { docker_fix_tls_ca_trust; return $?; }
    if [[ -z "$HOST_CA_PATH" ]]; then
        log_err "No host CA bundle — cannot fix"
        return 1
    fi

    local vols
    vols=$(kc get deployment control-agent -n "$NAMESPACE" -o jsonpath='{.spec.template.spec.volumes[*].name}' 2>/dev/null || true)
    if echo "$vols" | grep -q "host-ca-certs"; then
        log_ok "CA bundle patch already applied"
        if confirm "Force restart control-agent anyway?"; then
            kc rollout restart deployment/control-agent -n "$NAMESPACE"
            kc rollout status deployment/control-agent -n "$NAMESPACE" --timeout=120s 2>/dev/null || true
        fi
        return 0
    fi

    log_fix "Patching control-agent with host CA bundle ($HOST_CA_PATH)..."

    local patch='[
        {"op":"add","path":"/spec/template/spec/volumes/-","value":{"name":"host-ca-certs","hostPath":{"path":"'"$HOST_CA_PATH"'","type":"File"}}},
        {"op":"add","path":"/spec/template/spec/initContainers/0/volumeMounts/-","value":{"name":"host-ca-certs","mountPath":"/host-certs/ca-certificates.crt","readOnly":true}},
        {"op":"add","path":"/spec/template/spec/initContainers/0/env/-","value":{"name":"SSL_CERT_FILE","value":"/host-certs/ca-certificates.crt"}},
        {"op":"add","path":"/spec/template/spec/containers/0/volumeMounts/-","value":{"name":"host-ca-certs","mountPath":"/host-certs/ca-certificates.crt","readOnly":true}},
        {"op":"add","path":"/spec/template/spec/containers/0/env/-","value":{"name":"SSL_CERT_FILE","value":"/host-certs/ca-certificates.crt"}}
    ]'

    if kc patch deployment control-agent -n "$NAMESPACE" --type='json' -p="$patch"; then
        log_fix "Patch applied — waiting for rollout..."
        kc rollout status deployment/control-agent -n "$NAMESPACE" --timeout=120s 2>/dev/null || true
        return 0
    else
        log_err "Patch failed"
        return 1
    fi
}

# ============================================================
#  Shared proxy patch helper
# ============================================================
_apply_proxy_patch() {
    local proxy_url="$1"
    local no_proxy_val="127.0.0.0/8,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,.svc,.svc.cluster.local,localhost"
    for dep in control-agent data-plane observo-collector pattern-extractor; do
        if kc get deployment "$dep" -n "$NAMESPACE" &>/dev/null; then
            local container_name
            container_name=$(kc get deployment "$dep" -n "$NAMESPACE" \
                -o jsonpath='{.spec.template.spec.containers[0].name}' 2>/dev/null)
            local env_patch
            env_patch=$(cat <<PEOF
{"spec":{"template":{"spec":{"containers":[{"name":"${container_name}","env":[{"name":"HTTP_PROXY","value":"${proxy_url}"},{"name":"HTTPS_PROXY","value":"${proxy_url}"},{"name":"NO_PROXY","value":"${no_proxy_val}"}]}]}}}}
PEOF
)
            if kc patch deployment "$dep" -n "$NAMESPACE" --type=strategic -p="$env_patch" 2>/dev/null; then
                log_fix "Patched $dep with proxy env vars"
            else
                log_err "Failed to patch $dep"
            fi
        fi
    done
    echo ""
    log_info "Waiting for rollouts..."
    for dep in control-agent data-plane observo-collector pattern-extractor; do
        kc rollout status deployment/"$dep" -n "$NAMESPACE" --timeout=120s 2>/dev/null || true
    done
    log_fix "All deployments restarted with proxy config"
    return 0
}

# ============================================================
#  OOM fix — bump memory limits
# ============================================================
fix_oom() {
    local pod="$1" dep="$2"
    local current_limit
    current_limit=$(kc get deployment "$dep" -n "$NAMESPACE" \
        -o jsonpath='{.spec.template.spec.containers[0].resources.limits.memory}' 2>/dev/null || echo "")

    log_err "Root cause: OOMKilled (current limit: ${current_limit:-none})"

    if [[ -z "$current_limit" ]]; then
        log_warn "No memory limit set — container was killed by node-level pressure"
        log_warn "Set an explicit memory limit in Helm values for: $dep"
        return 1
    fi

    local numeric unit new_limit
    numeric=$(echo "$current_limit" | grep -oE '[0-9]+')
    unit=$(echo "$current_limit" | grep -oE '[A-Za-z]+')

    case "$unit" in
        Gi) new_limit="$((numeric * 3 / 2))Gi" ;;
        Mi) new_limit="$((numeric * 3 / 2))Mi" ;;
        *)  log_warn "Cannot parse memory unit: $current_limit"; return 1 ;;
    esac

    echo "    Current: $current_limit  →  Proposed: $new_limit"
    if confirm "Bump memory limit on deployment/$dep to $new_limit?"; then
        local container_name
        container_name=$(kc get deployment "$dep" -n "$NAMESPACE" \
            -o jsonpath='{.spec.template.spec.containers[0].name}' 2>/dev/null)
        if kc set resources deployment/"$dep" -n "$NAMESPACE" \
            -c "$container_name" --limits="memory=$new_limit"; then
            log_fix "Memory limit bumped to $new_limit — rollout in progress"
            kc rollout status deployment/"$dep" -n "$NAMESPACE" --timeout=120s 2>/dev/null || true
            return 0
        fi
    fi
    return 1
}

# ============================================================
#  Connectivity fix — detect and inject proxy
# ============================================================
fix_connectivity() {
    local pod="$1" dep="$2"
    log_err "Root cause: outbound connection failures"

    # Check if pod already has proxy env vars
    local has_proxy
    has_proxy=$(kc get deployment "$dep" -n "$NAMESPACE" \
        -o jsonpath='{.spec.template.spec.containers[0].env[*].name}' 2>/dev/null || true)
    if echo "$has_proxy" | grep -q "HTTPS_PROXY"; then
        log_warn "Proxy env vars already set — may be wrong URL or proxy is down"
        if confirm "Delete pod $pod to retry with current proxy config?"; then
            kc delete pod "$pod" -n "$NAMESPACE" && log_fix "Deleted $pod"
            return 0
        fi
        return 1
    fi

    # Auto-detect K3s proxy config
    local k3s_proxy=""
    if [[ -f /etc/systemd/system/k3s.service.env ]]; then
        k3s_proxy=$(grep -i "HTTPS_PROXY" /etc/systemd/system/k3s.service.env 2>/dev/null | head -1 | cut -d= -f2- || true)
    fi

    echo ""
    echo "    Pods have no proxy env vars but need to reach:"
    echo "      p01-auth.observo.ai:443   (authentication)"
    echo "      p01-api.observo.ai:443    (configuration)"

    if [[ -n "$k3s_proxy" ]]; then
        echo ""
        log_info "Found K3s proxy config: $k3s_proxy"
        if confirm "Patch all deployments with proxy $k3s_proxy?"; then
            _apply_proxy_patch "$k3s_proxy" && return 0
        fi
    else
        if confirm "Patch proxy env vars into pods now?"; then
            local proxy_url
            read -rp "  Enter proxy URL (e.g. http://proxy.corp:8080): " proxy_url || _dpd_eof_exit
            [[ -n "$proxy_url" ]] && _apply_proxy_patch "$proxy_url" && return 0
        fi
    fi
    return 1
}

# ============================================================
# ████  Docker standalone site backend  ████████████████████
# ============================================================
# A Docker site is ONE container (image *observo-standalone-site*)
# running all Data Pipeline services under an s6 supervisor:
#   control-plane-init (oneshot, must succeed first), then
#   dataplane, control-agent, collector, pattern-extractor, monitor.
# Endpoints come from container env (AUTH_DOMAIN_URL etc), not hardcoded.

docker_setup_new_site() {
    banner "New Site Setup"
    echo
    log_info "No Data Pipeline container is running. Let's set one up."
    echo
    echo "  Step 1 — Get your site credentials from SentinelOne:"
    echo
    echo "    1. Log in to SentinelOne"
    echo "    2. Navigate to: Account → Data Pipelines → Pipeline Manager"
    echo "    3. Select: Sites → Add Site → Self Hosted"
    echo "    4. Choose your scope"
    echo "    5. The console will generate a .env file — download it"
    echo

    local user_home; user_home="$(_dpd_home)"
    local env_file="$user_home/ai-data-pipelines.env"

    echo "  Copy that file to:"
    echo -e "    ${CYAN}${env_file}${NC}"
    echo

    if [[ -f "$env_file" ]]; then
        log_ok "Found $env_file"
    elif confirm "Can't get the file onto this host, or not sure it's in the right place? Paste its contents in directly instead"; then
        _dpd_paste_env "$env_file" || return 1
    else
        echo "  Waiting for ${env_file}...  (Ctrl-C to abort)"
        echo -n "  Checking"
        while [[ ! -f "$env_file" ]]; do
            echo -n "."; sleep 3
        done
        echo
        log_ok "Found $env_file"
    fi
    chmod 600 "$env_file"
    echo

    # Parse credentials from comment header — the .env file embeds docker login details
    # in a comment line like:   docker login -u AWS -p 'eyJw...' 822434346939.dkr.ecr.us-east-1.amazonaws.com
    local login_line registry token
    login_line=$(grep -m1 'docker login' "$env_file") || {
        log_err "Could not find 'docker login' line in $env_file"; return 1
    }
    registry=$(awk '{print $NF}' <<< "$login_line") || {
        log_err "Could not parse ECR registry from $env_file"; return 1
    }
    token=$(sed "s/.*-p '\\([^']*\\)'.*/\\1/" <<< "$login_line") || {
        log_err "Could not parse ECR token from $env_file"; return 1
    }

    # Parse image URI from comment header (looks like: 822434346939.dkr.ecr.us-east-1.amazonaws.com/observo-standalone-site:2.26.3)
    local image
    image=$(grep -oE '[0-9]+\.dkr\.ecr\.[a-z0-9-]+\.amazonaws\.com/[a-zA-Z0-9/_-]+:[0-9.]+' "$env_file" | head -1) || {
        log_err "Could not find ECR image URI in $env_file"; return 1
    }
    echo

    # Step 2: Docker login
    echo "  Step 2 — Authenticating with container registry..."
    if docker login -u AWS --password-stdin "$registry" <<< "$token" >/dev/null 2>&1; then
        log_ok "Registry login successful"
    else
        log_err "Docker login failed — verify $env_file is correct"
        return 1
    fi
    echo

    # WEF/WEC mode: build the site WEF-ready from the first start (port,
    # checkpoint store, cert mount, optional FIPS-off) instead of creating it
    # bare and recreating it later via Make-ready. The console source usually
    # doesn't exist yet at this point, so nothing here depends on it.
    local port_specs=() wef_mounts=() wef_port="" wef_cert_dir=""
    if $WEF_MODE; then
        echo "  WEF/WEC — preparing this site for Windows Event Forwarding"
        echo
        while true; do
            read -rp "    WEF listener port [${DP_WEF_PORT_DEFAULT}]: " wef_port || _dpd_eof_exit
            wef_port="${wef_port:-$DP_WEF_PORT_DEFAULT}"
            [[ "$wef_port" =~ ^[0-9]+$ && "$wef_port" -ge 1 && "$wef_port" -le 65535 ]] && break
            log_warn "Enter a port number (1-65535)"
        done
        port_specs+=("${wef_port}:${wef_port}/tcp")
        log_ok "Added: ${wef_port}:${wef_port}/tcp (use the same port in the console source's listen address)"

        wef_cert_dir="$DP_WEF_CERT_DIR_DEFAULT"
        _dp_wef_fix_cert_perms "$wef_cert_dir"
        wef_mounts+=("${wef_cert_dir}:${wef_cert_dir}:ro")
        log_ok "Certificate folder: ${wef_cert_dir} (mounted read-only at the same path)"

        local cp_file; cp_file="$(_dp_wef_checkpoint_file)"
        _dp_wef_write_checkpoint_store "$cp_file"
        wef_mounts+=("${cp_file}:/etc/dataplane/dataplane-globals.yaml:ro")
        log_ok "Checkpoint store: ${cp_file}"

        echo
        echo -e "    ${RED}${BOLD}FIPS warning:${NC} WEF can't start with FIPS-mode crypto on (image 2.46.0, PKCS12KDF)."
        echo "    Turning it off applies to the WHOLE site. Don't do this in a FedRAMP/DoD or other FIPS-required environment."
        if confirm "Disable FIPS-validated crypto for this site?"; then
            _dp_env_set_openssl_conf "$env_file" "/etc/ssl/openssl.cnf.default"
            log_ok "Set OPENSSL_CONF=/etc/ssl/openssl.cnf.default in $env_file"
        else
            log_warn "FIPS left on — the WEF source will fail to start until it's turned off (Tools 15 → 2)."
        fi
        echo
    fi

    # Step 3: Ask about ports (optional)
    echo "  Step 3 — Configure source listener ports (optional)"
    if confirm "Add${wef_port:+ more} source listener ports now?"; then
        while true; do
            echo
            echo "    Port mapping presets:"
            echo "      1) Syslog TCP (514:10514)"
            echo "      2) Syslog TLS (514:10514/tls)"
            echo "      3) Syslog UDP (514:10514/udp)"
            echo "      4) HEC push (8088:8088)"
            echo "      5) Kafka (9092:9092)"
            echo "      6) Custom"
            echo "      0) Skip ports"
            echo
            local port_choice
            read -rp "    Choose [0-6]: " port_choice || _dpd_eof_exit
            [[ "$port_choice" == "0" ]] && break

            local port_spec
            case "$port_choice" in
                1) port_spec="514:10514" ;;
                2) port_spec="514:10514" ;;  # TLS handled by container config
                3) port_spec="514:10514/udp" ;;
                4) port_spec="8088:8088" ;;
                5) port_spec="9092:9092" ;;
                6)
                    read -rp "    Enter port mapping (host:container[/proto]): " port_spec || _dpd_eof_exit
                    [[ -z "$port_spec" ]] && continue
                    ;;
                *) log_warn "Invalid choice"; continue ;;
            esac

            port_specs+=("$port_spec")
            log_ok "Added: $port_spec"
        done
    fi
    echo

    # Step 4: Docker Compose or plain `docker run`? Ask before starting
    # anything — deciding after the container is already running (the old
    # behavior) left a docker-run container and an unused compose file
    # both claiming the same container name, so `docker compose up -d`
    # would then collide with it.
    echo "  Step 4 — How do you want to manage this site?"
    local use_compose=false
    if confirm "Use Docker Compose (recommended — easier to manage/update)?"; then
        use_compose=true
    fi
    echo

    # Step 5: Start the container
    echo "  Step 5 — Starting the Data Pipeline container..."
    if $use_compose; then
        local compose_file="$user_home/docker-compose-observo.yml"
        cat > "$compose_file" <<COMPOSE
services:
  observo-standalone-site:
    image: $image
    container_name: observo-standalone-site
    env_file: $env_file
    tmpfs:
      - /etc/secrets:uid=1000,gid=1000,mode=0700
    volumes:
      - observo-data:/var/observo/data
COMPOSE
        local m
        for m in "${wef_mounts[@]+"${wef_mounts[@]}"}"; do
            echo "      - \"$m\"" >> "$compose_file"
        done
        if [[ ${#port_specs[@]} -gt 0 ]]; then
            echo "    ports:" >> "$compose_file"
            for spec in "${port_specs[@]}"; do
                echo "      - \"$spec\"" >> "$compose_file"
            done
        fi
        cat >> "$compose_file" <<COMPOSE
    restart: unless-stopped

volumes:
  observo-data:
COMPOSE
        log_ok "Created: $compose_file"

        if ! docker compose version >/dev/null 2>&1; then
            log_err "docker compose (v2 plugin) not found — install it, then run: docker compose -f $compose_file up -d"
            return 1
        fi
        if docker compose -f "$compose_file" up -d >/dev/null 2>&1; then
            log_ok "Container started via Docker Compose: observo-standalone-site"
            echo -e "          Manage with: ${CYAN}docker compose -f $compose_file [up -d|down|logs|restart]${NC}"
        else
            log_err "docker compose up failed. Check: docker compose -f $compose_file logs"
            return 1
        fi
    else
        local docker_flags=()
        if [[ ${#port_specs[@]} -gt 0 ]]; then
            for spec in "${port_specs[@]}"; do
                docker_flags+=("-p" "$spec")
            done
        fi
        local m
        for m in "${wef_mounts[@]+"${wef_mounts[@]}"}"; do
            docker_flags+=("-v" "$m")
        done
        if docker run -d \
            --name observo-standalone-site \
            --env-file "$env_file" \
            --tmpfs /etc/secrets:uid=1000,gid=1000,mode=0700 \
            -v observo-data:/var/observo/data \
            "${docker_flags[@]+"${docker_flags[@]}"}" \
            "$image" >/dev/null 2>&1; then
            log_ok "Container started: observo-standalone-site"
        else
            log_err "Failed to start container. Check: docker logs observo-standalone-site"
            return 1
        fi
    fi
    echo

    if $WEF_MODE; then
        _dp_wef_print_next_steps "$wef_port" "$wef_cert_dir"
        DP_NEW_SITE_WEF=true
        pause
    fi

    DOCKER_CONTAINER="observo-standalone-site"
    return 0
}

# --- small helpers ---
_in_list() { local needle="$1"; shift; local x; for x in "$@"; do [[ "$x" == "$needle" ]] && return 0; done; return 1; }

add_issue() {  # append unless an identical entry already exists
    local new="$1" e
    for e in "${DETECTED_ISSUES[@]:-}"; do [[ "$e" == "$new" ]] && return 0; done
    DETECTED_ISSUES+=("$new")
}

human_bytes() {
    local b="${1:-0}"
    [[ -z "$b" || "$b" == "0" ]] && { echo "unlimited"; return; }
    awk -v b="$b" 'BEGIN{ split("B KB MB GB TB",u," "); i=1; while(b>=1024 && i<5){b/=1024;i++} printf "%.1f%s", b, u[i] }'
}

url_to_hostport() {
    local url="$1" scheme rest host port
    scheme="${url%%://*}"
    rest="${url#*://}"
    host="${rest%%/*}"
    if [[ "$host" == *:* ]]; then
        port="${host##*:}"; host="${host%%:*}"
    elif [[ "$scheme" == "https" ]]; then port=443; else port=80; fi
    echo "${host}:${port}"
}

# ============================================================
#  Docker install guide (OS discovery + guided engine install)
# ============================================================
# Reached from docker_preflight when the docker binary is missing.
# On Linux we detect the distro family and (after confirmation) run the
# official install steps; on Mac/Windows/WSL we point at Docker Desktop.
# Setting DPD_INSTALL_TEST=1 runs the package-install steps only and skips
# the systemctl / usermod tail so the functions are testable in a plain
# (non-systemd, unprivileged) container.

_dpd_sudo() { [[ ${EUID:-$(id -u)} -eq 0 ]] && echo "" || echo "sudo"; }

# The invoking (non-root) user's home dir, even when this script is run via
# sudo — where user-facing files like ai-data-pipelines.env actually live.
# $HOME alone resolves to /root under sudo, not the real login user's home.
_dpd_home() {
    local target_user="${SUDO_USER:-}" h
    if [[ ${EUID:-$(id -u)} -eq 0 && -n "$target_user" && "$target_user" != "root" ]]; then
        h="$(eval echo "~$target_user" 2>/dev/null)"
        [[ -n "$h" && "$h" != "~$target_user" && -d "$h" ]] && { echo "$h"; return; }
    fi
    echo "$HOME"
}

# chown a path back to the real invoking user when running under sudo, so a
# file Doctor writes into that user's home isn't left root-owned. No-op
# outside sudo. Matches the home-resolution rule in _dpd_home above.
_dpd_chown_back() {
    [[ ${EUID:-$(id -u)} -eq 0 && -n "${SUDO_USER:-}" && "$SUDO_USER" != "root" ]] || return 0
    # user:group, not just user — otherwise the file keeps root's group.
    chown "$SUDO_USER:$(id -gn "$SUDO_USER" 2>/dev/null)" "$@" 2>/dev/null
}

# A small global profile (not per-site) remembering whether this host
# manages WEF/WEC-forwarding sites, so the startup question is only asked
# once. Sets WEF_MODE; returns 1 if there's no saved answer yet.
_dpd_profile_file() { echo "$(_dpd_home)/.data-pipeline-doctor/profile"; }

_dpd_load_wef_mode() {
    local pf line
    pf="$(_dpd_profile_file)"
    [[ -f "$pf" ]] || return 1
    local found=false
    while IFS= read -r line; do
        case "$line" in
            wef=true)  WEF_MODE=true;  found=true ;;
            wef=false) WEF_MODE=false; found=true ;;
        esac
    done < "$pf"
    $found
}

_dpd_ask_wef_mode() {
    echo ""
    echo -e "  ${BOLD}Windows Event Forwarding (WEF/WEC)${NC}"
    echo "    Answer yes if Windows hosts will forward their event logs to this site."
    echo "    Doctor then sets the site up for it (port, certificate folder, checkpoint"
    echo "    store, FIPS) and checks it on every run."
    echo -e "  ${DIM}Not sure? Answer no — you can add WEF any time later from Tools 15 →${NC}"
    echo -e "  ${DIM}Make this site WEF-ready, without reinstalling.${NC}"
    echo ""
    local ans
    read -rp "  Will this site receive Windows events over WEF/WEC? [y/N] " ans || ans=""
    local pf dir
    pf="$(_dpd_profile_file)"; dir="$(dirname "$pf")"
    mkdir -p "$dir" 2>/dev/null
    if [[ "$ans" =~ ^[Yy] ]]; then WEF_MODE=true; else WEF_MODE=false; fi
    echo "wef=${WEF_MODE}" > "$pf" 2>/dev/null
    _dpd_chown_back "$pf" "$dir"
    if $WEF_MODE; then
        log_ok "WEF/WEC mode on — this site will be checked for WEF readiness once its container is found."
    else
        log_info "WEF/WEC mode off — Tools 15 is still available if you need it later."
    fi
    echo -e "  ${DIM}Saved to ${pf} (edit or delete it to change the answer).${NC}"
}

# Runs right after docker_preflight when WEF/WEC mode is on, so a "yes" at
# startup leads straight to the fix instead of waiting to be found under
# Tools 15. Read-only unless the user accepts the Make-ready offer.
_dpd_wef_startup_check() {
    $WEF_MODE || return 0
    # Just built WEF-ready by docker_setup_new_site, which already printed the
    # next steps; its pipeline (and WEF source) won't have arrived yet.
    $DP_NEW_SITE_WEF && return 0
    [[ "$(dinspect '{{.State.Running}}')" == "true" ]] || return 0
    _dp_wef_check
    echo ""
    if ! $DP_WEF_FOUND; then
        log_info "WEF/WEC: no Windows Event Forwarding source in this site's pipeline yet."
        echo -e "  ${DIM}Add one in the console, then use Tools 15 → Make this site WEF-ready.${NC}"
        pause
        return 0
    fi
    if [[ $DP_WEF_ISSUES -eq 0 ]] && ! $DP_WEF_FIPS_ON; then
        log_ok "WEF/WEC: this site is WEF-ready."
        return 0
    fi
    echo -e "  ${BOLD}WEF/WEC readiness — $DOCKER_CONTAINER${NC}"
    echo ""
    _dp_wef_print_report
    if confirm_yes "This site isn't WEF-ready yet. Make it WEF-ready now?"; then
        docker_wef_make_ready
    else
        log_info "Skipped — run it later from Tools 15 → 2."
        pause
    fi
}

# Prompt for the .env contents directly instead of waiting on a file copy —
# sidesteps every "wrong home dir / wrong filename / NFS cache / sudo vs
# root" flavor of "the file isn't where I expect" report.
_dpd_paste_env() {
    local target="$1" line
    echo
    echo "  Paste the full contents of the downloaded .env file below."
    echo "  When done, press Enter then Ctrl-D (or type a line with just EOF)."
    echo
    : > "$target"
    while IFS= read -r line; do
        [[ "$line" == "EOF" ]] && break
        printf '%s\n' "$line" >> "$target"
    done
    if [[ ! -s "$target" ]]; then
        log_err "No content received — aborting."
        rm -f "$target"
        return 1
    fi
    chmod 600 "$target"
    log_ok "Saved pasted .env contents to $target"
}

# Detect the host OS into DPD_OS_FAMILY / DPD_OS_ID / DPD_OS_VER.
_dpd_detect_os() {
    DPD_OS_FAMILY=""; DPD_OS_ID=""; DPD_OS_VER=""
    case "$(uname -s)" in
        Darwin)                DPD_OS_FAMILY="mac"; return ;;
        MINGW*|MSYS*|CYGWIN*)  DPD_OS_FAMILY="windows"; return ;;
    esac
    if grep -qiE 'microsoft|wsl' /proc/version 2>/dev/null; then
        DPD_OS_FAMILY="wsl"; return
    fi
    if [[ -r /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DPD_OS_ID="${ID:-}"; DPD_OS_VER="${VERSION_ID:-}"
        case "${ID:-}" in
            amzn)                         DPD_OS_FAMILY="amazon" ;;
            ubuntu|debian)                DPD_OS_FAMILY="debian" ;;
            rhel|centos|rocky|almalinux)  DPD_OS_FAMILY="rhel" ;;
            fedora)                       DPD_OS_FAMILY="fedora" ;;
            *)
                case " ${ID_LIKE:-} " in
                    *debian*)   DPD_OS_FAMILY="debian" ;;
                    *fedora*)   DPD_OS_FAMILY="fedora" ;;
                    *rhel*|*centos*)  DPD_OS_FAMILY="rhel" ;;
                    *)          DPD_OS_FAMILY="unknown" ;;
                esac ;;
        esac
    else
        DPD_OS_FAMILY="unknown"
    fi
}

# Echo a command, then run it (unless DPD_INSTALL_TEST set the caller to skip).
_dpd_run() {
    echo -e "    ${DIM}\$ $*${NC}"
    "$@"
}

dpd_install_debian() {
    local SUDO repo_url codename arch
    SUDO="$(_dpd_sudo)"
    [[ "$DPD_OS_ID" == "debian" ]] && repo_url="https://download.docker.com/linux/debian" \
                                   || repo_url="https://download.docker.com/linux/ubuntu"
    echo "  Installing Docker Engine from Docker's official apt repository..."
    echo
    _dpd_run $SUDO apt-get update -y || return 1
    _dpd_run $SUDO apt-get install -y ca-certificates curl || return 1
    _dpd_run $SUDO install -m 0755 -d /etc/apt/keyrings || return 1
    _dpd_run $SUDO curl -fsSL "$repo_url/gpg" -o /etc/apt/keyrings/docker.asc || return 1
    _dpd_run $SUDO chmod a+r /etc/apt/keyrings/docker.asc || return 1
    arch="$(dpkg --print-architecture)"
    codename="$( . /etc/os-release && echo "${VERSION_CODENAME:-}" )"
    echo "deb [arch=$arch signed-by=/etc/apt/keyrings/docker.asc] $repo_url $codename stable" \
        | $SUDO tee /etc/apt/sources.list.d/docker.list >/dev/null || return 1
    _dpd_run $SUDO apt-get update -y || return 1
    _dpd_run $SUDO apt-get install -y docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin || return 1
    _dpd_post_install
}

dpd_install_rhel() {
    local SUDO
    SUDO="$(_dpd_sudo)"
    echo "  Installing Docker Engine from Docker's official dnf repository..."
    echo
    _dpd_run $SUDO dnf -y install dnf-plugins-core || return 1
    # dnf5 (config-manager addrepo) vs dnf4 (config-manager --add-repo)
    if $SUDO dnf config-manager --help 2>&1 | grep -q -- '--add-repo'; then
        _dpd_run $SUDO dnf config-manager --add-repo \
            https://download.docker.com/linux/centos/docker-ce.repo || return 1
    else
        _dpd_run $SUDO dnf config-manager addrepo --from-repofile \
            https://download.docker.com/linux/centos/docker-ce.repo || return 1
    fi
    _dpd_run $SUDO dnf install -y docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin || return 1
    _dpd_post_install
}

dpd_install_fedora() {
    local SUDO
    SUDO="$(_dpd_sudo)"
    echo "  Installing Docker Engine from Docker's official dnf repository..."
    echo
    _dpd_run $SUDO dnf -y install dnf-plugins-core || return 1
    # dnf5 (config-manager addrepo) vs dnf4 (config-manager --add-repo)
    if $SUDO dnf config-manager --help 2>&1 | grep -q -- '--add-repo'; then
        _dpd_run $SUDO dnf config-manager --add-repo \
            https://download.docker.com/linux/fedora/docker-ce.repo || return 1
    else
        _dpd_run $SUDO dnf config-manager addrepo --from-repofile \
            https://download.docker.com/linux/fedora/docker-ce.repo || return 1
    fi
    _dpd_run $SUDO dnf install -y docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin || return 1
    _dpd_post_install
}

dpd_install_amazon() {
    local SUDO
    SUDO="$(_dpd_sudo)"
    echo "  Installing Docker from the Amazon Linux repositories..."
    echo
    if [[ "$DPD_OS_VER" == 2* && "$DPD_OS_VER" != "2023" ]]; then
        # Amazon Linux 2 — docker ships via amazon-linux-extras
        if command -v amazon-linux-extras >/dev/null 2>&1; then
            _dpd_run $SUDO amazon-linux-extras install -y docker || return 1
        else
            _dpd_run $SUDO yum install -y docker || return 1
        fi
    else
        # Amazon Linux 2023 (and newer) — dnf
        _dpd_run $SUDO dnf install -y docker || return 1
    fi
    _dpd_post_install
}

# Enable + start the daemon and add the user to the docker group.
# Skipped under DPD_INSTALL_TEST (no systemd / unprivileged container).
_dpd_post_install() {
    if [[ -n "${DPD_INSTALL_TEST:-}" ]]; then
        log_info "Test mode: skipping 'systemctl enable --now docker' and group setup."
        return 0
    fi
    local SUDO; SUDO="$(_dpd_sudo)"
    echo
    _dpd_run $SUDO systemctl enable --now docker || \
        log_warn "Could not start docker via systemctl — start it manually."
    local target_user="${SUDO_USER:-$USER}"
    if [[ -n "$target_user" && "$target_user" != "root" ]]; then
        _dpd_run $SUDO usermod -aG docker "$target_user" || true
        log_warn "Added '$target_user' to the 'docker' group — log out/in for it to take effect."
    fi
    log_ok "Docker Engine installed."
}

docker_install_guide() {
    banner
    _dpd_detect_os
    log_info "Detected OS: ${DPD_OS_ID:-$(uname -s)} ${DPD_OS_VER:-} (family: ${DPD_OS_FAMILY:-unknown})"
    echo
    case "$DPD_OS_FAMILY" in
        mac)
            echo "  Docker on macOS ships as Docker Desktop. Install it from:"
            echo -e "    ${CYAN}https://docs.docker.com/desktop/setup/install/mac-install/${NC}"
            echo
            if command -v open >/dev/null 2>&1 && confirm "Open the download page now?"; then
                open "https://docs.docker.com/desktop/setup/install/mac-install/" >/dev/null 2>&1 || true
            fi
            echo "  After installing & starting Docker Desktop, re-run this tool."
            return 1 ;;
        windows|wsl)
            echo "  Docker on Windows ships as Docker Desktop (with WSL 2 integration). Install it from:"
            echo -e "    ${CYAN}https://docs.docker.com/desktop/setup/install/windows-install/${NC}"
            echo
            echo "  After installing & starting Docker Desktop, re-run this tool."
            return 1 ;;
        debian) confirm "Install Docker Engine now (apt)?" && dpd_install_debian ;;
        rhel)   confirm "Install Docker Engine now (dnf)?" && dpd_install_rhel ;;
        fedora) confirm "Install Docker Engine now (dnf)?" && dpd_install_fedora ;;
        amazon) confirm "Install Docker Engine now?"       && dpd_install_amazon ;;
        *)
            log_err "Could not auto-detect a supported OS for automatic install."
            echo "  See Docker's install docs: ${CYAN}https://docs.docker.com/engine/install/${NC}"
            return 1 ;;
    esac
}

# ============================================================
#  Docker preflight & endpoint discovery
# ============================================================
docker_preflight() {
    if ! command -v docker >/dev/null 2>&1; then
        log_warn "Docker is not installed on this host."
        docker_install_guide || exit 1
        if ! command -v docker >/dev/null 2>&1; then
            log_err "Docker still not found. Re-run this tool after installing Docker."
            exit 1
        fi
    fi
    if ! docker info >/dev/null 2>&1; then
        log_warn "Docker is installed but the daemon isn't reachable."
        if [[ "$(uname -s)" == "Linux" ]] && confirm "Try to start the Docker daemon now?"; then
            $(_dpd_sudo) systemctl enable --now docker >/dev/null 2>&1 || true
        fi
        if ! docker info >/dev/null 2>&1; then
            echo "  Is Docker running? You may need to run as root or join the 'docker' group:"
            echo "    sudo usermod -aG docker \$USER   # then log out/in"
            echo "  Or re-run this tool with sudo."
            exit 1
        fi
    fi

    if [[ -z "$DOCKER_CONTAINER" ]]; then
        local matches arr=()
        matches=$(docker ps --format '{{.Names}}\t{{.Image}}' | grep "$DOCKER_IMAGE_MATCH" | awk '{print $1}')
        while IFS= read -r m; do [[ -n "$m" ]] && arr+=("$m"); done <<< "$matches"

        if [[ ${#arr[@]} -eq 0 ]]; then
            docker_setup_new_site || exit 1
        elif [[ ${#arr[@]} -eq 1 ]]; then
            DOCKER_CONTAINER="${arr[0]}"
        else
            local ch; ch=$(pick_one "Multiple Data Pipeline containers found — pick one:" "${arr[@]}")
            DOCKER_CONTAINER="${arr[$((ch-1))]}"
        fi
    fi

    if ! docker inspect "$DOCKER_CONTAINER" >/dev/null 2>&1; then
        log_err "Container '$DOCKER_CONTAINER' not found. Exiting."; exit 1
    fi
    [[ "$(dinspect '{{.State.Running}}')" != "true" ]] && \
        log_warn "Container '$DOCKER_CONTAINER' is not running — some checks will be limited"

    # Scans work without root (docker group), but every fix that rewrites the
    # Compose file fails if Doctor created it under sudo. Say so up front.
    if [[ ${EUID:-$(id -u)} -ne 0 ]] && _dp_compose_info && [[ ! -w "$DP_COMPOSE_FILE" ]]; then
        log_warn "Not running as root — $DP_COMPOSE_FILE isn't writable by $(id -un), so fixes that recreate the container will fail."
        echo -e "  ${DIM}Scans still work. For fixes, re-run with:  sudo $0${NC}"
    fi

    detect_host_ca
    docker_load_endpoints
    svc_list >/dev/null 2>&1 || true
}

docker_load_endpoints() {
    OBSERVO_SITE_ID="$(dk_env OBSERVO_SITE_ID)"
    SITE_TOKEN_FILE_PATH="$(dk_env SITE_TOKEN_FILE_PATH)"
    GATEWAY_TLS_SECURED="$(dk_env GATEWAY_TLS_SECURED)"
    API_GATEWAY_ENDPOINT_VAL="$(dk_env API_GATEWAY_ENDPOINT)"
    DOCKER_ENDPOINTS=()
    local env_dump urls dests u hp
    env_dump=$(dinspect '{{range .Config.Env}}{{println .}}{{end}}')

    # 1) Endpoints expressed as full URLs (e.g. AUTH_DOMAIN_URL=https://...).
    urls=$(echo "$env_dump" | grep -oiE 'https?://[A-Za-z0-9._:-]+' | sort -u)
    while IFS= read -r u; do
        [[ -z "$u" ]] && continue
        hp=$(url_to_hostport "$u")
        _in_list "$hp" "${DOCKER_ENDPOINTS[@]:-}" || DOCKER_ENDPOINTS+=("$hp")
    done <<< "$urls"

    # 2) Bare host:port egress targets — the data/metrics/api destinations the site
    #    must reach (LOGS_DESTINATION, METRICS_DESTINATION, API_GATEWAY_ENDPOINT, ...).
    #    These have no scheme, so the URL pass above misses them. A blocked
    #    LOGS_DESTINATION is the #1 "data not flowing to AI SIEM" cause.
    dests=$(echo "$env_dump" \
        | grep -iE '^[A-Za-z0-9_]*(DESTINATION|ENDPOINT|GATEWAY)[A-Za-z0-9_]*=' \
        | cut -d= -f2- \
        | grep -oiE '[A-Za-z0-9][A-Za-z0-9.-]+\.[A-Za-z][A-Za-z0-9.-]*(:[0-9]+)?' | sort -u)
    while IFS= read -r u; do
        [[ -z "$u" ]] && continue
        [[ "$u" == *:* ]] || u="${u}:443"     # default to TLS port
        _in_list "$u" "${DOCKER_ENDPOINTS[@]:-}" || DOCKER_ENDPOINTS+=("$u")
    done <<< "$dests"
}

# ============================================================
#  Docker scanners (parallel to K8s scan_*; share issue tags)
# ============================================================
docker_scan_container() {
    log_info "Container health — $DOCKER_CONTAINER"
    echo ""
    local status running oom restarts policy health image mem
    status=$(dinspect '{{.State.Status}}')
    running=$(dinspect '{{.State.Running}}')
    oom=$(dinspect '{{.State.OOMKilled}}')
    restarts=$(dinspect '{{.RestartCount}}')
    policy=$(dinspect '{{.HostConfig.RestartPolicy.Name}}')
    health=$(dinspect '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}')
    image=$(dinspect '{{.Config.Image}}')
    mem=$(dinspect '{{.HostConfig.Memory}}')

    echo -e "  ${DIM}Image:${NC} $image"
    if [[ "$running" == "true" ]]; then
        log_ok "Container running (status: $status, restarts: $restarts)"
    elif [[ "$status" == "restarting" ]]; then
        log_err "Container is restarting (restarts: $restarts)"
        add_issue "docker-restarting: $DOCKER_CONTAINER is restarting (restarts: $restarts)"
    else
        log_err "Container not running (status: $status)"
        add_issue "docker-exited: $DOCKER_CONTAINER is $status"
    fi

    if [[ "$oom" == "true" ]]; then
        log_err "Container was OOMKilled (mem limit: $(human_bytes "$mem"))"
        add_issue "oom: $DOCKER_CONTAINER was OOMKilled (limit: $(human_bytes "$mem"))"
    fi
    [[ "$health" != "none" && "$health" != "healthy" ]] && log_warn "Healthcheck status: $health"
    [[ "$policy" == "no" || -z "$policy" ]] && \
        log_warn "Restart policy: ${policy:-none} (container won't auto-restart on failure)"
}

docker_scan_services() {
    log_info "Service health (s6) — $DOCKER_CONTAINER"
    echo ""
    local svcs
    svcs=$(svc_list)
    if [[ -z "$svcs" ]]; then
        log_warn "Could not list s6 services (s6 tools unavailable or container down)"
        return
    fi
    local any_down=false svc st
    while IFS= read -r svc; do
        [[ -z "$svc" ]] && continue
        st=$(svc_status_raw "$svc")
        if [[ -z "$st" ]]; then
            log_warn "$svc — status unknown"
        elif [[ "$st" == up* ]]; then
            log_ok "$svc — $st"
        else
            log_err "$svc — $st"
            any_down=true
            add_issue "docker-svc-down: $DOCKER_CONTAINER/$svc is down ($st)"
        fi
    done <<< "$svcs"
    $any_down && log_warn "Services down often mean control-plane-init has not completed — see option 1/init."
}

docker_scan_init() {
    log_info "control-plane-init status"
    echo ""
    local ilogs
    ilogs=$(dexec sh -c 'cat /var/log/control-plane-init/current 2>/dev/null' 2>/dev/null || true)
    [[ -z "$ilogs" ]] && ilogs=$(dk logs "$DOCKER_CONTAINER" --tail 300 2>&1 || true)

    if echo "$ilogs" | grep -qiE "attempt [0-9]+ failed|all [0-9]+ attempts failed"; then
        log_err "control-plane-init is failing (retry loop) — services stay down until it succeeds"
        if echo "$ilogs" | grep -qiE "EOF|connection refused|dial tcp.*timeout|no such host|network is unreachable|connection timed out|i/o timeout"; then
            log_err "  Root cause: cannot reach the control-plane endpoint (connectivity / TLS reset)"
            add_issue "connectivity: $DOCKER_CONTAINER/control-plane-init cannot reach control plane"
        elif echo "$ilogs" | grep -q "certificate signed by unknown authority"; then
            log_err "  Root cause: TLS certificate not trusted"
            add_issue "tls-ca-trust: $DOCKER_CONTAINER/control-plane-init cannot verify control plane TLS"
        elif echo "$ilogs" | grep -qiE "token is malformed|invalid number of segments|unauthorized|forbidden"; then
            log_err "  Root cause: authentication rejected"
            add_issue "malformed-token: $DOCKER_CONTAINER/control-plane-init auth rejected"
        fi
        add_issue "docker-init: control-plane-init has not completed (services blocked)"
        echo ""
        echo "    Recent control-plane-init log:"
        echo "$ilogs" | grep -iE "panic:|error|attempt|EOF|token" | tail -8 | sed 's/^/      /'
    elif echo "$ilogs" | grep -q "panic:"; then
        log_err "control-plane-init panicked"
        add_issue "docker-init: control-plane-init panicked"
        echo "$ilogs" | grep -iE "panic:|error" | tail -5 | sed 's/^/      /'
    else
        log_ok "No control-plane-init failures detected"
    fi
}

docker_scan_service_logs() {
    log_info "Scanning logs for known error patterns"
    echo ""
    local logs found=false
    logs=$(dk logs "$DOCKER_CONTAINER" --tail 300 2>&1 || true)

    if echo "$logs" | grep -q "certificate signed by unknown authority"; then
        log_err "TLS CA trust failure in logs"
        add_issue "tls-ca-trust: $DOCKER_CONTAINER cannot verify TLS to control plane"; found=true
    fi
    if echo "$logs" | grep -q "token is malformed\|invalid number of segments"; then
        log_err "Auth token malformed"
        add_issue "malformed-token: $DOCKER_CONTAINER bad auth token"; found=true
    fi
    if _dp_has_outbound_failure "$logs"; then
        log_err "Outbound connection failures in logs"
        add_issue "connectivity: $DOCKER_CONTAINER has outbound connection failures"; found=true
    fi
    if echo "$logs" | grep -q "No checkpoint store configured"; then
        log_err "A Windows Event Forwarding source has no checkpoint store configured"
        add_issue "wef-checkpoint-store: $DOCKER_CONTAINER WEF source needs a checkpoint store"; found=true
    fi
    if echo "$logs" | grep -qi "forbidden\|unauthorized"; then
        log_warn "Possible auth/permission errors in logs"; found=true
    fi
    $found || log_ok "No known error patterns in recent logs"
}

docker_scan_tls() {
    log_info "TLS & certificate checks (Docker site)"
    echo ""
    if [[ -n "$HOST_CA_PATH" ]]; then
        local count
        count=$(grep -c "BEGIN CERTIFICATE" "$HOST_CA_PATH" 2>/dev/null || echo 0)
        log_ok "Host CA bundle: $HOST_CA_PATH ($count certs)"
    else
        log_err "No host CA bundle found"
        add_issue "no-host-ca: Host has no CA certificate bundle"
    fi

    [[ ${#DOCKER_ENDPOINTS[@]} -eq 0 ]] && log_warn "No endpoints derived from container env"
    local hp host port result issuer container_ok
    for hp in "${DOCKER_ENDPOINTS[@]:-}"; do
        [[ -z "$hp" ]] && continue
        host="${hp%%:*}"; port="${hp##*:}"
        [[ "$port" == "80" ]] && { log_info "Skipping non-TLS endpoint $hp"; continue; }
        result=$(openssl s_client -connect "$hp" -servername "$host" </dev/null 2>&1)
        if echo "$result" | grep -q "verify return:1"; then
            issuer=$(echo "$result" | grep "issuer=" | head -1 | sed 's/.*CN *= *//')
            log_ok "TLS $hp — issued by ${issuer:-unknown}"
        else
            # The host may simply lack this endpoint's name/network path (a
            # lab-only hostname, a container-only network, etc.) while the
            # site itself — which runs entirely inside the container — is
            # fine. Check from inside the container before treating this as
            # a real issue, same reasoning as the DNS check below.
            container_ok=false
            dexec sh -c "openssl s_client -connect '$hp' -servername '$host' </dev/null 2>&1" 2>/dev/null \
                | grep -q "verify return:1" && container_ok=true
            if $container_ok; then
                log_warn "TLS $hp — verification failed from the host, but the container verifies it fine. Likely a host-only DNS/network gap, not a site problem."
            else
                log_err "TLS $hp — verification failed from host and from inside the container"
                add_issue "tls-host: Cannot verify $host"
            fi
        fi
    done

    if [[ -n "$SITE_TOKEN_FILE_PATH" ]]; then
        if dexec test -f "$SITE_TOKEN_FILE_PATH" 2>/dev/null; then
            log_ok "Site token present: $SITE_TOKEN_FILE_PATH"
        else
            log_err "Site token missing: $SITE_TOKEN_FILE_PATH (control-plane-init has not authenticated)"
            add_issue "docker-token-missing: site token $SITE_TOKEN_FILE_PATH not present"
        fi
    fi
}

docker_scan_dns() {
    log_info "DNS resolution checks (Docker site)"
    echo ""
    if [[ ${#DOCKER_ENDPOINTS[@]} -eq 0 ]]; then
        log_warn "No endpoints to resolve"; return
    fi
    local seen=() hp host container_ok
    for hp in "${DOCKER_ENDPOINTS[@]}"; do
        host="${hp%%:*}"
        _in_list "$host" "${seen[@]:-}" && continue
        seen+=("$host")

        # Check the container first: it's what actually runs the site. The
        # host may use a different resolver/network path entirely (a
        # lab-only hostname, a container-only network) and simply not have
        # this name — that's not a site problem if the container resolves it.
        if dexec getent hosts "$host" >/dev/null 2>&1; then
            container_ok=true
            log_ok "Container resolves: $host"
        else
            container_ok=false
            log_warn "Container cannot resolve: $host"
            add_issue "dns: container cannot resolve $host"
        fi

        if nslookup "$host" &>/dev/null || dig +short "$host" 2>/dev/null | grep -q .; then
            log_ok "Host resolves: $host"
        elif $container_ok; then
            log_warn "Host cannot resolve $host, but the container resolves it fine. Likely a host-only DNS gap, not a site problem."
        else
            log_err "Host cannot resolve: $host"
            add_issue "dns: Cannot resolve $host from host"
        fi
    done
}

docker_scan_storage() {
    log_info "Volume & disk checks (Docker site)"
    echo ""
    local mounts
    mounts=$(dinspect '{{range .Mounts}}{{.Type}} {{.Name}} {{.Source}} {{.Destination}}{{println}}{{end}}')
    if [[ -z "$mounts" ]]; then
        log_warn "Container has no volume mounts (data is not persisted)"
    else
        local m mname mdst
        while IFS= read -r m; do
            [[ -z "$m" ]] && continue
            mname=$(echo "$m" | awk '{print $2}')
            mdst=$(echo "$m" | awk '{print $NF}')
            log_ok "Mount: ${mname:-volume} -> $mdst"
        done <<< "$mounts"
    fi

    # Persistent data/queue dir varies by build: /var/observo/data or /var/lib/dp-site.
    local data_dir=""
    for d in /var/observo/data /var/lib/dp-site; do
        if dexec test -d "$d" 2>/dev/null; then data_dir="$d"; break; fi
    done
    if [[ -z "$data_dir" ]]; then
        log_warn "No persistent data dir found (/var/observo/data or /var/lib/dp-site)"
        add_issue "docker-volume-missing: no persistent data dir in $DOCKER_CONTAINER"
    elif dexec test -w "$data_dir" 2>/dev/null; then
        log_ok "Data dir writable: $data_dir"
    else
        log_warn "Data dir not writable: $data_dir"
        add_issue "docker-volume-missing: $data_dir not writable in $DOCKER_CONTAINER"
    fi

    local pct
    pct=$(df -P /var/lib/docker 2>/dev/null | awk 'NR==2{gsub("%","",$5); print $5}')
    if [[ -n "$pct" ]]; then
        if [[ "$pct" -ge 90 ]]; then
            log_err "Docker storage ${pct}% full"
            add_issue "docker-disk-pressure: docker storage ${pct}% full"
        else
            log_ok "Docker storage ${pct}% used"
        fi
    fi
}

docker_scan_resources() {
    log_info "Resource usage (Docker site)"
    echo ""
    local mem nanocpu stats
    mem=$(dinspect '{{.HostConfig.Memory}}')
    nanocpu=$(dinspect '{{.HostConfig.NanoCpus}}')
    echo "    Memory limit: $(human_bytes "$mem")"
    if [[ -n "$nanocpu" && "$nanocpu" != "0" ]]; then
        echo "    CPU limit:    $(awk -v n="$nanocpu" 'BEGIN{printf "%.2f", n/1000000000}') cores"
    else
        echo "    CPU limit:    unlimited"
    fi
    echo ""
    stats=$(docker stats --no-stream --format '{{.CPUPerc}}|{{.MemUsage}}|{{.MemPerc}}' "$DOCKER_CONTAINER" 2>/dev/null || true)
    if [[ -n "$stats" ]]; then
        echo "    Live usage:   CPU $(echo "$stats" | cut -d'|' -f1)  Mem $(echo "$stats" | cut -d'|' -f2) ($(echo "$stats" | cut -d'|' -f3))"
    fi
    if [[ "$(dinspect '{{.State.OOMKilled}}')" == "true" ]]; then
        log_err "Container was OOMKilled"
        add_issue "oom: $DOCKER_CONTAINER was OOMKilled (limit: $(human_bytes "$mem"))"
    fi
}

# ============================================================
#  Docker fixes (advise + restart; container env/mounts can't
#  be live-patched, so TLS/proxy fixes recreate-or-restart)
# ============================================================
docker_fix_connectivity() {
    log_err "Root cause: container cannot reach the control plane"
    echo ""
    echo "    Endpoints the site must reach:"
    local hp
    for hp in "${DOCKER_ENDPOINTS[@]:-}"; do [[ -n "$hp" ]] && echo "      $hp"; done

    local has_proxy
    has_proxy=$(dinspect '{{range .Config.Env}}{{println .}}{{end}}' | grep -iE '^HTTPS?_PROXY=' || true)
    echo ""
    if [[ -n "$has_proxy" ]]; then
        log_warn "Container already has proxy env vars:"
        echo "$has_proxy" | sed 's/^/      /'
        echo "    The proxy may be wrong or unreachable. Verify it can reach the endpoints above."
    else
        log_info "Container has NO proxy env vars. If this host needs a proxy for egress,"
        echo "    recreate the container with proxy settings, e.g.:"
        echo ""
        echo "      docker run ... \\"
        echo "        -e HTTPS_PROXY=http://proxy.corp:8080 \\"
        echo "        -e HTTP_PROXY=http://proxy.corp:8080 \\"
        echo "        -e NO_PROXY=localhost,127.0.0.1 \\"
        echo "        <observo-standalone-site image>"
        echo ""
        echo "    (A running container's env cannot be changed in place — it must be recreated.)"
    fi
    echo ""
    if confirm "Restart $DOCKER_CONTAINER now to retry control-plane-init?"; then
        dk restart "$DOCKER_CONTAINER" && { log_fix "Restarted $DOCKER_CONTAINER — watch logs for init success"; return 0; }
    fi
    return 1
}

docker_fix_tls_ca_trust() {
    log_err "Root cause: TLS certificate to the control plane is not trusted"
    [[ -z "$HOST_CA_PATH" ]] && log_warn "No host CA bundle found on this machine to mount."
    echo ""
    echo "    A running container cannot gain a new mount/env in place. To trust your CA,"
    echo "    recreate the container with the host CA bundle mounted, e.g.:"
    echo ""
    echo "      docker run ... \\"
    echo "        -v ${HOST_CA_PATH:-/etc/ssl/certs/ca-certificates.crt}:/etc/ssl/certs/ca-certificates.crt:ro \\"
    echo "        -e SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \\"
    echo "        <observo-standalone-site image>"
    echo ""
    if confirm "Restart $DOCKER_CONTAINER now to retry (if the bundle is already present)?"; then
        dk restart "$DOCKER_CONTAINER" && { log_fix "Restarted $DOCKER_CONTAINER"; return 0; }
    fi
    return 1
}

docker_fix_oom() {
    local mem new
    mem=$(dinspect '{{.HostConfig.Memory}}')
    if [[ -z "$mem" || "$mem" == "0" ]]; then
        log_warn "No memory limit set — container was killed by host-level memory pressure."
        echo "    Set a limit on recreate (e.g. --memory 12g) or free host memory."
        return 1
    fi
    new=$(( mem * 3 / 2 ))
    echo "    Current: $(human_bytes "$mem")  →  Proposed: $(human_bytes "$new")"
    if confirm "Bump container memory limit to $(human_bytes "$new") via 'docker update'?"; then
        local compose_file=""
        _dp_compose_info && compose_file="$DP_COMPOSE_FILE"

        if docker update --memory "$new" --memory-swap "$new" "$DOCKER_CONTAINER" 2>/dev/null; then
            log_fix "Memory limit updated to $(human_bytes "$new")"
            if [[ -n "$compose_file" ]]; then
                _dp_compose_set_mem_limit "$compose_file" "$new" "$new"
                log_info "Also updated ${compose_file} so this survives a future recreate."
            fi
            return 0
        fi
        if docker update --memory "$new" "$DOCKER_CONTAINER" 2>/dev/null; then
            log_fix "Memory limit updated to $(human_bytes "$new") (swap unchanged)"
            if [[ -n "$compose_file" ]]; then
                _dp_compose_set_mem_limit "$compose_file" "$new" ""
                log_info "Also updated ${compose_file} so this survives a future recreate."
            fi
            return 0
        fi
        log_err "docker update failed — recreate the container with: --memory $(human_bytes "$new")"
    fi
    return 1
}

# ============================================================
#  WEF/WEC integration — shared read-only helpers
# ============================================================
# Block-scoped read of a WEF source's settings from inside the container's
# own resolved /etc/dataplane/config.yaml, confirmed against a real file on
# a live site (2026-10-30). Keyed on `type: wef` as the block signal, not on
# proximity to `collector_address:` — source keys are alphabetical, so
# address: and collector_address: can be separated by an arbitrary-sized
# auth: block (an earlier line-proximity version of this broke exactly this
# way on the real file). Also reads the confirmed real cert key names
# (auth.ca_file / auth.crt_file / auth.key_file) instead of a generic
# path-shaped regex, so it can no longer sweep in cert paths belonging to a
# different, non-WEF source. Assumes the real file's confirmed indent:
# 2-space source-name line, 4-space keys under it, 6-space under auth:.
# Reports the first WEF-typed source if more than one exists. Sets
# DP_WEF_FOUND, DP_WEF_LISTEN, DP_WEF_CALLBACK, DP_WEF_CERT_PATHS (array).
_dp_wef_read_config() {
    DP_WEF_FOUND=false
    DP_WEF_LISTEN=""
    DP_WEF_CALLBACK=""
    DP_WEF_CERT_PATHS=()

    local cfg
    cfg=$(dexec sh -c "cat /etc/dataplane/config.yaml /etc/collector/config.yaml 2>/dev/null" 2>/dev/null)
    [[ -z "$cfg" ]] && return 1

    local parsed
    parsed=$(echo "$cfg" | awk '
        function flush() {
            if (iswef) print "WEF_FOUND=1\nWEF_LISTEN=" addr "\nWEF_CALLBACK=" cb "\nWEF_CERTS=" certs
            iswef=0; addr=""; cb=""; certs=""
        }
        /^sources:/ { insrc=1; next }
        /^[^ ]/ { if (insrc) flush(); insrc=0 }
        insrc && /^  [^ ]/ { flush(); next }
        insrc && /^    type:[ ]*wef[ ]*$/ { iswef=1 }
        insrc && /^    address:/ { sub(/^    address:[ ]*/,""); addr=$0 }
        insrc && /^    collector_address:/ { sub(/^    collector_address:[ ]*/,""); cb=$0 }
        insrc && /^      (ca|crt|key)_file:/ { sub(/^      [a-z]+_file:[ ]*/,""); certs=certs" "$0 }
        END { if (insrc) flush() }
    ')
    [[ -z "$parsed" ]] && return 1

    local line certstr c
    while IFS= read -r line; do
        case "$line" in
            WEF_FOUND=*)    DP_WEF_FOUND=true ;;
            WEF_LISTEN=*)   DP_WEF_LISTEN="${line#WEF_LISTEN=}" ;;
            WEF_CALLBACK=*) DP_WEF_CALLBACK="${line#WEF_CALLBACK=}" ;;
            WEF_CERTS=*)
                certstr="${line#WEF_CERTS=}"
                for c in $certstr; do DP_WEF_CERT_PATHS+=("$c"); done
                ;;
        esac
    done <<< "$(echo "$parsed" | head -4)"   # first WEF source only, if more than one

    $DP_WEF_FOUND
}

# Populates DP_WEF_REPORT (array of "LEVEL|message", LEVEL one of
# OK/WARN/FAIL), DP_WEF_ISSUES (FAIL count), DP_WEF_WARNINGS (WARN count).
# Read-only — safe to call often, including just to render the live menu
# count. Requires $DOCKER_CONTAINER to already be resolved.
_dp_wef_check() {
    DP_WEF_REPORT=()
    DP_WEF_ISSUES=0
    DP_WEF_WARNINGS=0
    DP_WEF_FIPS_ON=false   # a WARN, not a FAIL (it's a policy choice), but Make-ready still fixes it

    _dp_wef_read_config
    if $DP_WEF_FOUND; then
        DP_WEF_REPORT+=("OK|WEF source found — listen ${DP_WEF_LISTEN:-unknown}, callback ${DP_WEF_CALLBACK:-unknown}")
    else
        DP_WEF_REPORT+=("FAIL|No WEF source found in the dataplane config")
        ((DP_WEF_ISSUES++))
        return 0   # nothing else below is meaningful without a WEF source
    fi

    # Port published on the host
    local cport="${DP_WEF_LISTEN##*:}" hp hport cport2 published=false
    if [[ "$cport" =~ ^[0-9]+$ ]]; then
        while IFS='|' read -r hp hport cport2; do
            [[ -z "$cport2" ]] && continue
            [[ "${cport2%%/*}" == "$cport" ]] && published=true
        done < <(dinspect '{{range $p, $b := .HostConfig.PortBindings}}{{range $b}}{{.HostIp}}|{{.HostPort}}|{{$p}}{{println}}{{end}}{{end}}')
        if $published; then
            DP_WEF_REPORT+=("OK|Container port ${cport} is published on the host")
        else
            DP_WEF_REPORT+=("FAIL|Container port ${cport} is not published on the host (see Source ports)")
            ((DP_WEF_ISSUES++))
        fi
    else
        DP_WEF_REPORT+=("WARN|Could not determine the WEF listen port from the config")
        ((DP_WEF_WARNINGS++))
    fi

    # Checkpoint store mounted
    if dinspect '{{range .Mounts}}{{.Destination}}{{println}}{{end}}' | grep -qF "/etc/dataplane/dataplane-globals.yaml"; then
        DP_WEF_REPORT+=("OK|Checkpoint store config is mounted")
    else
        DP_WEF_REPORT+=("FAIL|No checkpoint store config mounted")
        ((DP_WEF_ISSUES++))
    fi

    # Cert paths mounted and readable by uid 1000 (the container's user)
    if [[ ${#DP_WEF_CERT_PATHS[@]} -eq 0 ]]; then
        DP_WEF_REPORT+=("WARN|Could not identify certificate file paths from the dataplane config")
        ((DP_WEF_WARNINGS++))
    else
        local p
        for p in "${DP_WEF_CERT_PATHS[@]}"; do
            if dexec test -r "$p" 2>/dev/null; then
                DP_WEF_REPORT+=("OK|Readable inside the container: $p")
            else
                DP_WEF_REPORT+=("FAIL|Not readable inside the container (check the mount and uid 1000 ownership): $p")
                ((DP_WEF_ISSUES++))
            fi
        done
    fi

    # Crypto mode — WEF cannot build its TLS identity with FIPS on (image 2.46.0)
    local opensslconf
    opensslconf=$(dinspect '{{range .Config.Env}}{{println .}}{{end}}' | grep '^OPENSSL_CONF=' | cut -d= -f2-)
    if [[ "$opensslconf" == *openssl.cnf.default ]]; then
        DP_WEF_REPORT+=("OK|FIPS mode disabled for WEF (OPENSSL_CONF=${opensslconf})")
    else
        DP_WEF_REPORT+=("WARN|FIPS mode is likely on — WEF fails to start on image 2.46.0 with FIPS enabled (PKCS12KDF). See 'Make this site WEF-ready'.")
        ((DP_WEF_WARNINGS++))
        DP_WEF_FIPS_ON=true
    fi

    # Last WEF runtime error + forwarders seen (informational)
    local logs lasterr principals
    logs=$(dk logs "$DOCKER_CONTAINER" --tail 300 2>&1 || true)
    lasterr=$(echo "$logs" | grep -iE "checkpoint store configured|PKCS12KDF|collector_address is unset" | tail -1)
    if [[ -n "$lasterr" ]]; then
        DP_WEF_REPORT+=("WARN|Last WEF error in recent logs: ${lasterr#*Z }")
        ((DP_WEF_WARNINGS++))
    else
        DP_WEF_REPORT+=("OK|No WEF error patterns in recent logs")
    fi

    principals=$(echo "$logs" | grep -oE 'principal: [^)]+' | sed 's/principal: //' | sort -u)
    if [[ -n "$principals" ]]; then
        DP_WEF_REPORT+=("OK|Forwarders seen recently: $(echo "$principals" | paste -sd, -)")
    else
        DP_WEF_REPORT+=("WARN|No forwarders seen in recent logs yet")
        ((DP_WEF_WARNINGS++))
    fi
}

# A Windows Event Forwarding source stops at startup with "No checkpoint
# store configured" on a Docker standalone site — the dataplane's checkpoint
# settings aren't loaded from the Add Source form. Writes a small YAML file
# and mounts it at /etc/dataplane/dataplane-globals.yaml (unsupported
# workaround; confirm with SentinelOne for the supported fix on your
# version). Requires a recreate — a mount can't be added to a running
# container — so this follows the same Compose-aware recreate-with-backup
# shape as the other recreate-based fixes.
docker_fix_wef_checkpoint_store() {
    local mount_dst="/etc/dataplane/dataplane-globals.yaml"

    if dinspect '{{range .Mounts}}{{.Destination}}{{println}}{{end}}' | grep -qF "$mount_dst"; then
        log_ok "A dataplane-globals.yaml is already mounted at $mount_dst"
        echo "    If the WEF source is still failing, check its contents on the host."
        return 1
    fi

    log_err "Root cause: a Windows Event Forwarding source has no checkpoint store configured"
    echo "    This is a known product gap, not a misconfiguration — the Add Source form has"
    echo "    no checkpoint field. The workaround below is unsupported; confirm with"
    echo "    SentinelOne for your version before relying on it in production."
    echo ""

    local hostfile="$(_dpd_home)/.data-pipeline-doctor/dataplane-globals.yaml"
    echo "    Will write $hostfile:"
    echo -e "      ${DIM}data_dir: /var/observo/data/dataplane${NC}"
    echo -e "      ${DIM}checkpoint:${NC}"
    echo -e "      ${DIM}  store_path: /var/observo/data/dataplane/checkpoints.db3${NC}"
    echo "    ...and mount it read-only at ${mount_dst} (requires a recreate)."
    echo ""

    if ! confirm "Write the checkpoint config and recreate $DOCKER_CONTAINER with it mounted?"; then
        return 1
    fi

    mkdir -p "$(dirname "$hostfile")" 2>/dev/null
    cat > "$hostfile" <<'EOF'
# Lab workaround: checkpoint store for the dataplane instance (WEF source needs one).
# Mirrors /etc/collector-globals/collector-globals.yaml, with a separate db file.
data_dir: /var/observo/data/dataplane
checkpoint:
  store_path: /var/observo/data/dataplane/checkpoints.db3
EOF
    # The container reads this as uid 1000. A host-written file can come out
    # unreadable to it depending on the host user's uid (confirmed live: the
    # same class of failure hit cert files mounted the same way, on a host
    # where the invoking user wasn't uid 1000). Nothing here is a secret, so
    # make it world-readable rather than trying to chown to a uid that may
    # not even exist as a real user on this host.
    chmod 644 "$hostfile" 2>/dev/null
    # Under sudo, root wrote this into the real user's home (_dpd_home) —
    # give it back to them so it's not a root-owned file sitting in their
    # own home directory.
    _dpd_chown_back "$hostfile" "$(dirname "$hostfile")"

    local compose_file=""
    _dp_compose_info && compose_file="$DP_COMPOSE_FILE"

    if [[ -n "$compose_file" ]]; then
        local compose_backup="${compose_file}.bak.$(date +%Y%m%d%H%M%S)"
        if ! cp "$compose_file" "$compose_backup"; then
            log_err "Could not back up ${compose_file} — aborting."
            return 1
        fi
        _dp_compose_add_mount "$compose_file" "$hostfile" "$mount_dst" "ro"
        if docker compose -f "$compose_file" up -d >/dev/null 2>&1; then
            log_fix "Mounted $hostfile at ${mount_dst} and recreated $DOCKER_CONTAINER."
            log_info "Also updated ${compose_file} (backup: ${compose_backup}) so this survives a future recreate."
            return 0
        fi
        log_err "docker compose up failed — restoring the previous ${compose_file}"
        cp "$compose_backup" "$compose_file"
        docker compose -f "$compose_file" up -d >/dev/null 2>&1
        return 1
    fi

    DP_EXTRA_MOUNTS=("${hostfile}:${mount_dst}:ro")
    _dp_build_run_cmd
    local backup="${DOCKER_CONTAINER}_pre$(date +%s)"
    if ! docker stop "$DOCKER_CONTAINER" >/dev/null 2>&1; then
        log_err "Failed to stop container"; return 1
    fi
    if ! docker rename "$DOCKER_CONTAINER" "$backup" >/dev/null 2>&1; then
        log_err "Failed to rename; container is stopped — start it again with: docker start $DOCKER_CONTAINER"
        return 1
    fi
    if "${DP_RUN_CMD[@]}" >/dev/null 2>&1; then
        log_fix "Recreated $DOCKER_CONTAINER with $hostfile mounted at ${mount_dst}. Backup: $backup"
        echo -e "  ${DIM}Verify, then remove the backup: docker rm $backup${NC}"
        return 0
    fi
    log_err "Recreate failed — rolling back to the previous container"
    docker rm -f "$DOCKER_CONTAINER" >/dev/null 2>&1
    docker rename "$backup" "$DOCKER_CONTAINER" >/dev/null 2>&1
    docker start "$DOCKER_CONTAINER" >/dev/null 2>&1 && log_info "Rolled back; original container is running again."
    return 1
}

docker_fix_restart_service() {
    local svc="$1" ch
    log_warn "Service down: $svc"
    echo "    1) Restart just this service (s6-svc)   2) Restart whole container   3) Skip"
    read -rp "  Choose [1-3]: " ch || _dpd_eof_exit
    case "$ch" in
        1)  if dexec s6-svc -r "/run/service/$svc" 2>/dev/null || dexec s6-svc -du "/run/service/$svc" 2>/dev/null; then
                log_fix "Requested restart of service $svc"; return 0
            fi
            log_err "Could not restart $svc via s6 — try restarting the container"; return 1 ;;
        2)  dk restart "$DOCKER_CONTAINER" && { log_fix "Restarted $DOCKER_CONTAINER"; return 0; }; return 1 ;;
        *)  return 1 ;;
    esac
}

# ============================================================
#  Docker full scan, menus & routing
# ============================================================
docker_full_scan() {
    banner
    echo -e "  ${BOLD}Running full diagnostic scan (Docker site)...${NC}"
    echo ""
    DETECTED_ISSUES=()

    docker_scan_container;     hr
    docker_scan_services;      hr
    docker_scan_init;          hr
    docker_scan_service_logs;  hr
    docker_scan_tls;           hr
    docker_scan_dns;           hr
    docker_scan_storage;       hr
    docker_scan_resources;     hr
    if $WEF_MODE; then
        # Any readiness gap is raised as one wef-not-ready issue, fixed by
        # "Make this site WEF-ready" — one recreate covering the checkpoint
        # store, certs and FIPS. It supersedes wef-checkpoint-store (raised by
        # docker_scan_service_logs above), so the fix pass doesn't fix one of
        # three and leave WEF still broken.
        echo -e "  ${BOLD}WEF/WEC readiness${NC}"
        echo ""
        _dp_wef_check
        _dp_wef_print_report
        if $DP_WEF_FOUND && { [[ $DP_WEF_ISSUES -gt 0 ]] || $DP_WEF_FIPS_ON; }; then
            add_issue "wef-not-ready: $DOCKER_CONTAINER is not WEF-ready (${DP_WEF_ISSUES} blocking issue(s)$($DP_WEF_FIPS_ON && echo ', FIPS on'))"
        fi
        hr
    fi

    echo ""
    if [[ ${#DETECTED_ISSUES[@]} -eq 0 ]]; then
        log_ok "No issues detected — site looks healthy"
    else
        echo -e "  ${RED}${BOLD}Issues found: ${#DETECTED_ISSUES[@]}${NC}"
        echo ""
        for i in "${!DETECTED_ISSUES[@]}"; do
            echo -e "    ${RED}$((i+1)).${NC} ${DETECTED_ISSUES[$i]}"
        done
        echo ""
        confirm "Attempt to fix these issues?" && run_all_fixes
    fi
    pause
}

docker_run_scan() {  # $1=scan fn, $2=title
    banner
    echo -e "  ${BOLD}$2${NC}"
    echo ""
    DETECTED_ISSUES=()
    "$1"
    if [[ ${#DETECTED_ISSUES[@]} -gt 0 ]]; then
        echo ""; hr
        echo -e "  ${RED}Issues found: ${#DETECTED_ISSUES[@]}${NC}"
        local issue
        for issue in "${DETECTED_ISSUES[@]}"; do echo -e "    ${RED}•${NC} $issue"; done
        echo ""
        confirm "Attempt to fix detected issues?" && run_all_fixes
    fi
    pause
}

docker_menu_resources() {
    banner
    echo -e "  ${BOLD}Container & Resource Health${NC}"
    echo ""
    DETECTED_ISSUES=()
    docker_scan_container
    hr
    docker_scan_resources
    if [[ ${#DETECTED_ISSUES[@]} -gt 0 ]]; then
        echo ""
        local issue
        for issue in "${DETECTED_ISSUES[@]}"; do echo -e "    ${RED}•${NC} $issue"; done
        confirm "Attempt to fix?" && run_all_fixes
    fi
    pause
}

# ============================================================
#  Docker tools — logs, debugger, restart, tap, proxy
# ============================================================
docker_pick_service_log() {
    local svcs arr=() s ch
    svcs=$(svc_list)
    while IFS= read -r s; do [[ -n "$s" ]] && arr+=("$s"); done <<< "$svcs"
    if [[ ${#arr[@]} -eq 0 ]]; then log_warn "No services found"; pause; return; fi
    ch=$(pick_one "Pick a service:" "${arr[@]}")
    [[ "$ch" =~ ^[0-9]+$ ]] && (( ch>=1 && ch<=${#arr[@]} )) || return
    local svc="${arr[$((ch-1))]}" out
    out=$(dexec sh -c "cat /var/log/$svc/current 2>/dev/null" 2>/dev/null)
    if [[ -n "$out" ]]; then
        echo "$out" | less -R
    else
        log_warn "No dedicated log file for $svc — showing filtered combined logs"
        echo ""
        dk logs "$DOCKER_CONTAINER" 2>&1 | grep -i "$svc" | less -R
    fi
}

docker_menu_logs() {
    while true; do
        banner
        echo -e "  ${BOLD}Logs — $DOCKER_CONTAINER${NC}"
        echo ""
        echo -e "    ${CYAN}1)${NC}  Combined container logs (last 200)"
        echo -e "    ${CYAN}2)${NC}  Follow combined logs (Ctrl+C to stop)"
        echo -e "    ${CYAN}3)${NC}  Per-service log"
        echo -e "    ${CYAN}4)${NC}  control-plane-init log"
        echo ""
        echo -e "    ${CYAN}0)${NC}  Back"
        echo ""
        local ch; read -rp "  Choose [0-4]: " ch || _dpd_eof_exit
        case "$ch" in
            1)  dk logs "$DOCKER_CONTAINER" --tail 200 2>&1 | less -R ;;
            2)  echo -e "  ${DIM}── Ctrl+C to stop ──${NC}"; echo ""; dk logs -f --tail 50 "$DOCKER_CONTAINER" 2>&1 || true; pause ;;
            3)  docker_pick_service_log ;;
            4)  { dexec sh -c 'cat /var/log/control-plane-init/current 2>/dev/null' 2>/dev/null \
                    || dk logs "$DOCKER_CONTAINER" 2>&1 | grep -iE 'CPI|control-plane|panic|attempt'; } | less -R ;;
            0)  return ;;
            *)  ;;
        esac
    done
}

docker_menu_restart() {
    banner
    echo -e "  ${BOLD}Restart — $DOCKER_CONTAINER${NC}"
    echo ""
    echo -e "    ${CYAN}1)${NC}  Restart a single service (s6)"
    echo -e "    ${CYAN}2)${NC}  Restart the whole container"
    echo ""
    echo -e "    ${CYAN}0)${NC}  Back"
    echo ""
    local ch; read -rp "  Choose [0-2]: " ch || _dpd_eof_exit
    case "$ch" in
        1)  local svcs arr=() s c svc
            svcs=$(svc_list)
            while IFS= read -r s; do [[ -n "$s" ]] && arr+=("$s"); done <<< "$svcs"
            if [[ ${#arr[@]} -eq 0 ]]; then log_warn "No services found"; pause; return; fi
            c=$(pick_one "Restart which service?" "${arr[@]}")
            [[ "$c" =~ ^[0-9]+$ ]] && (( c>=1 && c<=${#arr[@]} )) || { pause; return; }
            svc="${arr[$((c-1))]}"
            if dexec s6-svc -r "/run/service/$svc" 2>/dev/null || dexec s6-svc -du "/run/service/$svc" 2>/dev/null; then
                log_fix "Restarted service $svc"
            else
                log_err "Could not restart $svc via s6"
            fi
            pause ;;
        2)  if confirm "Restart container $DOCKER_CONTAINER?"; then
                dk restart "$DOCKER_CONTAINER" && log_fix "Restarted $DOCKER_CONTAINER"
            fi
            pause ;;
        0)  return ;;
        *)  ;;
    esac
}

docker_service_debug_menu() {
    while true; do
        banner
        echo -e "  ${BOLD}Service Debugger — $DOCKER_CONTAINER${NC}"
        echo ""
        echo -e "    ${CYAN}1)${NC}  s6 status (all services)"
        echo -e "    ${CYAN}2)${NC}  Show container env"
        echo -e "    ${CYAN}3)${NC}  Open a shell in the container"
        echo -e "    ${CYAN}4)${NC}  View a service log"
        echo -e "    ${CYAN}5)${NC}  Restart a service / container"
        echo ""
        echo -e "    ${CYAN}0)${NC}  Back"
        echo ""
        local ch s; read -rp "  Choose [0-5]: " ch || _dpd_eof_exit
        case "$ch" in
            1)  echo ""; while IFS= read -r s; do
                    [[ -z "$s" ]] && continue
                    printf "    %-22s " "$s"; svc_status_raw "$s" || echo "unknown"
                done <<< "$(svc_list)"; pause ;;
            2)  dinspect '{{range .Config.Env}}{{println .}}{{end}}' | sort | less -R ;;
            3)  log_info "Opening shell (type 'exit' to return)..."; echo ""; dexec_it sh -c 'bash 2>/dev/null || sh' || true ;;
            4)  docker_pick_service_log ;;
            5)  docker_menu_restart ;;
            0)  return ;;
            *)  ;;
        esac
    done
}

# Extract component IDs (with type) from a section of the dataplane YAML.
# $1 = section name (sources|transforms|sinks); config is read on stdin.
# Pure awk — no python/pyyaml dependency. Emits "<id> (<type>)" per line.
_dp_components() {
    awk -v want="$1" '
        /^[A-Za-z_][A-Za-z0-9_]*:/ { in_sect = ($0 ~ ("^" want ":")) ? 1 : 0; next }
        in_sect && /^  "?[A-Za-z0-9_]+"?:[[:space:]]*$/ {
            id=$0; sub(/^  /,"",id); sub(/:.*/,"",id); gsub(/"/,"",id); cur=id; order[++n]=id
        }
        in_sect && /^    type:/ {
            t=$0; sub(/^[[:space:]]*type:[[:space:]]*/,"",t); gsub(/["'"'"']/,"",t); typ[cur]=t
        }
        END { for (i=1;i<=n;i++){ k=order[i]; print k" "(typ[k]?typ[k]:"unknown") } }
    '
}

# Human name for an entity id, from PIPELINE_NAME_MAP ("entityid|Name"). Empty if unknown.
# bash 3.2-safe: linear scan, no associative arrays.
_name_for_entity() {
    local entity="$1" e
    for e in "${PIPELINE_NAME_MAP[@]:-}"; do
        [[ -n "$e" && "$e" == "$entity|"* ]] && { printf '%s' "${e#*|}"; return 0; }
    done
    return 1
}

# Load entity-id -> human-name mapping (optional). Lets you see the UI names.
#   Source 1: $DP_NAMES_FILE, else ~/.data-pipeline-doctor/names.<siteid>.csv
#             Format, one per line:  <entity-id>,<Human Name>     (# comments ok)
#   Source 2 (TODO): auto-fetch from the manager gateway
#             ($API_GATEWAY_ENDPOINT_VAL) with the site token. The data plane only
#             stores numeric IDs; names live in the control plane. Wiring this needs
#             the manager API contract (gRPC protobufs), so it's left as an extension point.
docker_load_component_names() {
    PIPELINE_NAME_MAP=()
    local f="${DP_NAMES_FILE:-$HOME/.data-pipeline-doctor/names.${OBSERVO_SITE_ID}.csv}"
    [[ -f "$f" ]] || return 0
    local line idpart namepart
    while IFS= read -r line; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        idpart="${line%%,*}"; namepart="${line#*,}"
        idpart="$(echo "$idpart" | tr -d '[:space:]')"
        [[ -n "$idpart" && -n "$namepart" && "$idpart" != "$namepart" ]] && PIPELINE_NAME_MAP+=("${idpart}|${namepart}")
    done < "$f"
    [[ ${#PIPELINE_NAME_MAP[@]} -gt 0 ]] && log_info "Loaded ${#PIPELINE_NAME_MAP[@]} component name(s) from $f"
}

# Map a raw connector type to a human label (per the GA connector vocabulary).
# Unknown/internal types pass through unchanged.
_friendly_type() {
    case "$1" in
        splunk_hec)  echo "Splunk HEC" ;;
        s3|aws_s3)   echo "Amazon S3" ;;
        syslog)      echo "Syslog" ;;
        kafka)       echo "Kafka" ;;
        hec)         echo "HEC push" ;;
        demo_logs)   echo "Demo logs" ;;
        blackhole)   echo "Blackhole (discard)" ;;
        internal_logs|internal_metrics) echo "Internal telemetry" ;;
        *)           echo "$1" ;;
    esac
}

# Render one component line: friendly name (if known) + friendly type + dimmed id.
# Args: <number> <kind-label> <color> <id> <type>
_dp_print_item() {
    local num="$1" klabel="$2" color="$3" id="$4" type="$5" entity name ftype disp
    entity="${id%%_*}"
    name="$(_name_for_entity "$entity" || true)"
    ftype="$(_friendly_type "$type")"
    if [[ -n "$name" ]]; then
        disp="${name}  ${DIM}(${ftype})${NC}"
    else
        disp="${ftype}  ${DIM}(${id})${NC}"
    fi
    echo -e "    ${CYAN}$num)${NC} ${color}${klabel}${NC} ${disp}"
}

# Parse the sinks section, emitting "<id>\t<type>\t<uri>" per sink.
_dp_sinks() {
    awk '
        /^sinks:/{f=1;next} f&&/^[A-Za-z_]/{f=0}
        f&&/^  "?[A-Za-z0-9_]+"?:[[:space:]]*$/ { id=$0; sub(/^  /,"",id); sub(/:.*/,"",id); gsub(/"/,"",id); cur=id; order[++n]=id }
        f&&/^    type:/ { t=$0; sub(/^[[:space:]]*type:[[:space:]]*/,"",t); gsub(/["'"'"']/,"",t); typ[cur]=t }
        f&&/^    uri:/  { u=$0; sub(/^[[:space:]]*uri:[[:space:]]*/,"",u);  gsub(/["'"'"']/,"",u);  uri[cur]=u }
        END { for(i=1;i<=n;i++){k=order[i]; print k"\t"(typ[k]?typ[k]:"unknown")"\t"(uri[k]?uri[k]:"") } }
    '
}

# An internal sink = control-plane telemetry or a discard; not a real egress.
_is_internal_sink() {
    local type="$1" uri="$2"
    case "$type" in blackhole|internal_logs|internal_metrics) return 0 ;; esac
    case "$uri" in *"/control-agent/"*|*"/v1/samples"*|*"/stream-data-analytics"*) return 0 ;; esac
    return 1
}

docker_menu_dataplane_tap() {
    banner
    echo -e "  ${BOLD}Tail Sources & Destinations${NC}"
    echo -e "  ${DIM}Powered by dataplane tap (inside $DOCKER_CONTAINER)${NC}"
    echo ""

    local cfg="" p
    for p in /etc/dataplane/config.yaml /etc/dataplane/data_plane_config.yaml; do
        cfg=$(dexec sh -c "cat $p 2>/dev/null" 2>/dev/null)
        [[ -n "$cfg" ]] && break
    done
    if [[ -z "$cfg" ]]; then
        log_err "Could not read dataplane config from container"
        pause; return
    fi

    docker_load_component_names

    # The dataplane API (GraphQL) is what 'tap' connects to. It binds to a
    # site-specific address (e.g. 127.0.0.4:8686), so read it from the config.
    local api_addr api_url
    api_addr=$(echo "$cfg" | awk '/^api:/{f=1;next} f&&/^[A-Za-z_]/{f=0} f&&/address:/{print $2; exit}')
    [[ -z "$api_addr" ]] && api_addr="127.0.0.1:8686"
    api_url="http://${api_addr}/graphql"

    # Parse components. Sources/transforms are "<id> <type>"; sinks are "<id>\t<type>\t<uri>".
    local sources=() transforms=() egress=() internal=() line sid stype suri
    while IFS= read -r line; do [[ -n "$line" ]] && sources+=("$line"); done    < <(echo "$cfg" | _dp_components sources)
    while IFS= read -r line; do [[ -n "$line" ]] && transforms+=("$line"); done < <(echo "$cfg" | _dp_components transforms)
    while IFS=$'\t' read -r sid stype suri; do
        [[ -z "$sid" ]] && continue
        if _is_internal_sink "$stype" "$suri"; then internal+=("${sid}|${stype}|${suri}")
        else egress+=("${sid}|${stype}|${suri}"); fi
    done < <(echo "$cfg" | _dp_sinks)

    if [[ ${#sources[@]} -eq 0 && ${#transforms[@]} -eq 0 && ${#egress[@]} -eq 0 && ${#internal[@]} -eq 0 ]]; then
        log_warn "No components found in dataplane config"
        echo ""; echo -e "  ${DIM}Raw config (first 30 lines):${NC}"
        echo "$cfg" | head -30 | sed 's/^/    /'
        pause; return
    fi

    # One-time editable names skeleton (UI names live in the control plane, not here).
    if [[ ${#PIPELINE_NAME_MAP[@]} -eq 0 ]]; then
        local names_file="${DP_NAMES_FILE:-$HOME/.data-pipeline-doctor/names.${OBSERVO_SITE_ID}.csv}"
        local skel="${names_file}.template"
        if [[ ! -f "$names_file" && ! -f "$skel" ]]; then
            mkdir -p "$(dirname "$skel")" 2>/dev/null
            {
                echo "# Data Pipeline component names for site ${OBSERVO_SITE_ID}"
                echo "# Fill in the names you see in the UI, then rename this file to:"
                echo "#   $(basename "$names_file")"
                echo "# Format: <entity-id>,<Human Name>"
                printf '%s\n' "${sources[@]}" "${transforms[@]}" \
                    | awk '{ e=$1; sub(/_.*/,"",e); if(!(e in seen)){seen[e]=1; print e",  # type: "$2} }'
            } > "$skel" 2>/dev/null
        fi
    fi

    # Render loop with a toggle to expand internal sinks + transforms.
    local expanded=false choice
    while true; do
        banner
        echo -e "  ${BOLD}Tail Sources & Destinations${NC}"
        echo -e "  ${DIM}dataplane tap inside $DOCKER_CONTAINER — site ${OBSERVO_SITE_ID}${NC}"
        echo ""

        # Rebuild selection arrays for the current view.
        local all_kinds=() item_ids=() i id type uri ent nm ftype
        if [[ ${#sources[@]} -gt 0 ]]; then
            echo -e "  ${BOLD}Sources:${NC}"
            for i in "${!sources[@]}"; do
                id="${sources[$i]%% *}"; type="${sources[$i]#* }"
                all_kinds+=("source"); item_ids+=("$id")
                _dp_print_item "${#all_kinds[@]}" "[source]" "$GREEN" "$id" "$type"
            done
            echo ""
        fi

        echo -e "  ${BOLD}Egress${NC} ${DIM}(data leaving this stage)${NC}:"
        if [[ ${#egress[@]} -gt 0 ]]; then
            for i in "${!egress[@]}"; do
                id="${egress[$i]%%|*}"; type="$(echo "${egress[$i]}" | cut -d'|' -f2)"; uri="$(echo "${egress[$i]}" | cut -d'|' -f3-)"
                all_kinds+=("sink"); item_ids+=("$id")
                ent="${id%%_*}"; nm="$(_name_for_entity "$ent" || true)"; ftype="$(_friendly_type "$type")"
                if [[ -n "$nm" ]]; then
                    echo -e "    ${CYAN}${#all_kinds[@]})${NC} ${YELLOW}[egress]${NC} ${nm} ${DIM}(${ftype} → ${uri:-?})${NC}"
                else
                    echo -e "    ${CYAN}${#all_kinds[@]})${NC} ${YELLOW}[egress]${NC} ${ftype} ${DIM}→ ${uri:-?}  [${id}]${NC}"
                fi
            done
        else
            echo -e "    ${DIM}none on the data plane — egress is resolved via the control plane${NC}"
        fi
        echo ""
        echo -e "  ${DIM}Note: your *named* destination (Splunk/S3/etc.) is configured in the${NC}"
        echo -e "  ${DIM}Data Pipeline UI; the data plane only shows where bytes physically go.${NC}"
        echo ""

        if $expanded; then
            if [[ ${#internal[@]} -gt 0 ]]; then
                echo -e "  ${BOLD}Internal sinks${NC} ${DIM}(telemetry / discard)${NC}:"
                for i in "${!internal[@]}"; do
                    id="${internal[$i]%%|*}"; type="$(echo "${internal[$i]}" | cut -d'|' -f2)"; uri="$(echo "${internal[$i]}" | cut -d'|' -f3-)"
                    all_kinds+=("sink"); item_ids+=("$id")
                    echo -e "    ${CYAN}${#all_kinds[@]})${NC} ${DIM}[internal] ${type} → ${uri:-(none)}  [${id}]${NC}"
                done
                echo ""
            fi
            if [[ ${#transforms[@]} -gt 0 ]]; then
                echo -e "  ${BOLD}Transforms${NC}:"
                for i in "${!transforms[@]}"; do
                    id="${transforms[$i]%% *}"; type="${transforms[$i]#* }"
                    all_kinds+=("transform"); item_ids+=("$id")
                    _dp_print_item "${#all_kinds[@]}" "[transform]" "$CYAN" "$id" "$type"
                done
                echo ""
            fi
        else
            echo -e "  ${DIM}+ ${#internal[@]} internal sink(s), ${#transforms[@]} transform(s) hidden — enter 's' to show${NC}"
            echo ""
        fi

        hr; echo ""
        echo -e "    ${CYAN}s)${NC} $($expanded && echo 'Hide' || echo 'Show') internal sinks & transforms     ${CYAN}0)${NC} Back"
        echo ""
        read -rp "  Select component to tap [0-${#all_kinds[@]}]: " choice || _dpd_eof_exit
        [[ "$choice" == "0" || -z "$choice" ]] && return
        if [[ "$choice" == "s" || "$choice" == "S" ]]; then
            $expanded && expanded=false || expanded=true
            continue
        fi
        if ! [[ "$choice" =~ ^[0-9]+$ ]] || (( choice < 1 || choice > ${#all_kinds[@]} )); then
            log_warn "Invalid selection"; sleep 1; continue
        fi
        break
    done

    local tap_id="${item_ids[$((choice-1))]}" kind="${all_kinds[$((choice-1))]}"
    local friendly; friendly="$(_name_for_entity "${tap_id%%_*}" || true)"
    [[ -n "$friendly" ]] && friendly="${friendly} (${tap_id})" || friendly="${tap_id}"

    # 'dataplane tap' observes a component's OUTPUTS. Sinks have no outputs, so
    # tap their INPUTS instead (--inputs-of). Sources/transforms tap directly.
    local tap_args
    if [[ "$kind" == "sink" ]]; then
        tap_args="--inputs-of '$tap_id'"
        echo ""; log_info "Tailing input events into ${BOLD}${friendly}${NC}... ${DIM}(Ctrl+C to stop)${NC}"
    else
        tap_args="'$tap_id'"
        echo ""; log_info "Tailing output events from ${BOLD}${friendly}${NC}... ${DIM}(Ctrl+C to stop)${NC}"
    fi
    echo -e "  ${DIM}API: ${api_url}${NC}"
    echo ""
    # Source the FIPS OpenSSL profile (the service does this in its run script —
    # without it the tap binary panics with "library has no ciphers").
    dexec_it sh -c ". /etc/profile.d/openssl-fips.sh 2>/dev/null; /usr/bin/dataplane tap -u '$api_url' $tap_args 2>&1" || {
        echo ""; log_warn "Tap exited. The component may currently be idle (no events), or the dataplane API isn't ready."
    }
    pause
}

docker_menu_proxy_connectivity() {
    banner
    echo -e "  ${BOLD}Proxy & Connectivity Check (Docker site)${NC}"
    echo ""
    local total_pass=0 total_fail=0

    echo -e "  ${BOLD}1. Host proxy environment${NC}"
    echo ""
    local proxy_detected=false active_proxy="" var val
    for var in HTTP_PROXY http_proxy HTTPS_PROXY https_proxy ALL_PROXY all_proxy; do
        val="${!var:-}"
        [[ -n "$val" ]] && { log_info "$var = $val"; proxy_detected=true; [[ -z "$active_proxy" ]] && active_proxy="$val"; }
    done
    $proxy_detected || log_ok "No proxy environment variables set on host"
    echo ""

    echo -e "  ${BOLD}2. Container proxy environment${NC}"
    echo ""
    local cproxy
    cproxy=$(dinspect '{{range .Config.Env}}{{println .}}{{end}}' | grep -iE '^(HTTPS?|ALL|NO)_PROXY=' || true)
    if [[ -n "$cproxy" ]]; then echo "$cproxy" | sed 's/^/    /'; else log_info "Container has no proxy env vars set"; fi
    echo ""

    if [[ ${#DOCKER_ENDPOINTS[@]} -eq 0 ]]; then
        log_warn "No endpoints derived from container env"; pause; return
    fi

    echo -e "  ${BOLD}3. DNS resolution (host)${NC}"
    echo ""
    local hp host seen=()
    for hp in "${DOCKER_ENDPOINTS[@]}"; do
        host="${hp%%:*}"; _in_list "$host" "${seen[@]:-}" && continue; seen+=("$host")
        if nslookup "$host" &>/dev/null || dig +short "$host" 2>/dev/null | grep -q .; then
            log_ok "Resolves: $host"; ((total_pass++)) || true
        else
            log_err "Cannot resolve: $host"; ((total_fail++)) || true
        fi
    done
    echo ""

    echo -e "  ${BOLD}4. Endpoint connectivity (from host)${NC}"
    echo ""
    local port scheme
    for hp in "${DOCKER_ENDPOINTS[@]}"; do
        host="${hp%%:*}"; port="${hp##*:}"; scheme=https
        [[ "$port" == "80" ]] && scheme=http
        if test_endpoint "${scheme}://${host}" "$host" "$active_proxy"; then ((total_pass++)) || true; else ((total_fail++)) || true; fi
    done
    echo ""

    echo -e "  ${BOLD}5. Endpoint connectivity (from inside container)${NC}"
    echo ""
    local code
    for hp in "${DOCKER_ENDPOINTS[@]}"; do
        host="${hp%%:*}"; port="${hp##*:}"; scheme=https
        [[ "$port" == "80" ]] && scheme=http
        code=$(dexec sh -c "command -v curl >/dev/null 2>&1 && curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 --max-time 10 '${scheme}://${host}'" 2>/dev/null || true)
        if [[ -z "$code" ]]; then
            log_warn "container -> $host — could not test (curl unavailable in container?)"
        elif [[ "$code" == "000" ]]; then
            log_err "container -> $host — connection failed"; ((total_fail++)) || true
        else
            log_ok "container -> $host — HTTP $code"; ((total_pass++)) || true
        fi
    done
    echo ""

    echo -e "  ${BOLD}6. TLS verification (host)${NC}"
    echo ""
    seen=()
    for hp in "${DOCKER_ENDPOINTS[@]}"; do
        host="${hp%%:*}"; port="${hp##*:}"
        [[ "$port" == "80" ]] && continue
        _in_list "$host" "${seen[@]:-}" && continue; seen+=("$host")
        if test_endpoint_tls "$host" "$port"; then ((total_pass++)) || true; else ((total_fail++)) || true; fi
    done
    echo ""
    hr
    echo -e "  ${BOLD}Summary:${NC} ${GREEN}${total_pass} passed${NC}, ${RED}${total_fail} failed${NC}"
    pause
}

# ============================================================
#  Source ports — open host ports for new sources
# ============================================================
# Annotate a "hostport -> containerport/proto" mapping with a likely source type.
_dp_port_role() {
    local cport="$1" hport="$2"
    case "$cport" in
        6514/tcp) echo "Syslog TLS" ;;
        10514/udp|514/udp) echo "Syslog UDP" ;;
        514/tcp|1514/tcp) echo "Syslog TCP" ;;
        8088/tcp) echo "HEC push" ;;
        9092/tcp) echo "Kafka" ;;
        *) echo "—" ;;
    esac
}

# OS-specific firewall allow hints (guidance only; never executed).
_dp_firewall_hints() {
    local port="$1" proto="$2"
    echo -e "  ${DIM}Host firewall (run the one for your OS):${NC}"
    echo "    ufw:       sudo ufw allow ${port}/${proto}"
    echo "    firewalld: sudo firewall-cmd --add-port=${port}/${proto} --permanent && sudo firewall-cmd --reload"
    echo "    iptables:  sudo iptables -A INPUT -p ${proto} --dport ${port} -j ACCEPT"
}

# Informational only: report whether the container is already set up to receive
# traffic on a container port. NEVER blocks — publishing the host port and
# configuring the source in the UI can happen in either order.
_dp_listener_status() {
    local cport="$1" proto="$2" hexport listening cfg
    hexport=$(printf '%04X' "$cport" 2>/dev/null)
    # Runtime: is a socket listening/bound on this port inside the container?
    if [[ -n "$hexport" ]]; then
        listening=$(dexec sh -c "cat /proc/net/${proto} /proc/net/${proto}6 2>/dev/null" 2>/dev/null \
            | awk -v port="$hexport" -v proto="$proto" 'NR>1 { split($2,a,":");
                  if (toupper(a[2])==port) { if (proto=="tcp" && $4=="0A"){print "y";exit} if (proto=="udp"){print "y";exit} } }')
    fi
    # Config: is a source declared to listen on this port? (e.g. address: 0.0.0.0:8088)
    cfg=$(dexec sh -c "cat /etc/dataplane/config.yaml /etc/collector/config.yaml 2>/dev/null" 2>/dev/null \
        | grep -E '^[[:space:]]*address:' | grep -cE ":${cport}([^0-9]|\$)" 2>/dev/null)

    if [[ -n "$listening" ]]; then
        log_ok "A service is already listening on container port ${cport}/${proto} — publishing it will connect traffic through."
    elif [[ "${cfg:-0}" -gt 0 ]]; then
        log_ok "A source is configured for container port ${cport} in the dataplane config (listener should be up)."
    else
        log_info "Nothing is listening on container port ${cport}/${proto} yet — that's expected if you haven't"
        echo -e "    ${DIM}configured the source in the UI. Order doesn't matter: open the port here and configure${NC}"
        echo -e "    ${DIM}the source (set its listen address to :${cport}) in either order — data flows once both are done.${NC}"
    fi
}

# Detect whether $DOCKER_CONTAINER was created by Docker Compose, and if so,
# which compose file it came from. Reads Compose's own labels rather than
# assuming a path (~/docker-compose-observo.yml) — the file may have been
# renamed, moved, or never existed under that name. Sets DP_COMPOSE_FILE on
# success; returns 1 if not Compose-managed or the file is no longer there.
_dp_compose_info() {
    local cfgfiles
    cfgfiles=$(dinspect '{{index .Config.Labels "com.docker.compose.project.config_files"}}')
    [[ -z "$cfgfiles" || "$cfgfiles" == "<no value>" ]] && return 1
    DP_COMPOSE_FILE="${cfgfiles%%,*}"   # config_files can be comma-separated; take the first
    [[ -f "$DP_COMPOSE_FILE" ]] || return 1
    return 0
}

# Add a "-p"-style port mapping to a Compose file's service, so a future
# `docker compose up -d` doesn't silently drop ports added via this menu.
# Creates the `ports:` key if it's missing; idempotent (skips if the exact
# mapping is already present). Assumes the single-service layout this tool
# generates (2-space service indent, 4-space key indent under it).
_dp_compose_add_port() {
    local file="$1" newmap="$2"
    if grep -qF "\"${newmap}\"" "$file"; then
        return 0   # already present
    fi
    if grep -qE '^[[:space:]]*ports:[[:space:]]*$' "$file"; then
        awk -v newmap="$newmap" '
            { print }
            /^[[:space:]]*ports:[[:space:]]*$/ { print "      - \"" newmap "\"" }
        ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
    else
        awk -v newmap="$newmap" '
            { print }
            /^[[:space:]]*container_name:/ && !done {
                print "    ports:"
                print "      - \"" newmap "\""
                done=1
            }
        ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
    fi
}

# Set (or add) a Compose file's mem_limit / memswap_limit keys, mirroring a
# live `docker update --memory` bump. Without this, the file keeps saying
# "unlimited" and a future `docker compose up -d` — for any reason, not just
# another OOM fix — silently reverts the bump on recreate. memswap may be
# empty to only touch mem_limit (matches the docker update fallback path
# that only bumps --memory, not --memory-swap).
_dp_compose_set_mem_limit() {
    local file="$1" mem="$2" memswap="$3"

    if grep -qE '^[[:space:]]*mem_limit:' "$file"; then
        awk -v mem="$mem" '
            /^[[:space:]]*mem_limit:/ { sub(/mem_limit:.*/, "mem_limit: " mem) }
            { print }
        ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
    else
        awk -v mem="$mem" '
            { print }
            /^[[:space:]]*container_name:/ && !done {
                print "    mem_limit: " mem
                done=1
            }
        ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
    fi

    [[ -z "$memswap" ]] && return 0

    if grep -qE '^[[:space:]]*memswap_limit:' "$file"; then
        awk -v ms="$memswap" '
            /^[[:space:]]*memswap_limit:/ { sub(/memswap_limit:.*/, "memswap_limit: " ms) }
            { print }
        ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
    else
        awk -v ms="$memswap" '
            { print }
            /^[[:space:]]*mem_limit:/ && !done {
                print "    memswap_limit: " ms
                done=1
            }
        ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
    fi
}

# Add a host-path volume mount to a Compose file's service, so a future
# `docker compose up -d` doesn't silently drop it. Creates the service's
# `volumes:` key if it's missing; idempotent (skips if the exact spec is
# already present). mode is appended if non-empty (e.g. "ro"). Assumes the
# single-service layout this tool generates (2-space service indent,
# 4-space key indent under it) — the same assumption _dp_compose_add_port
# makes. Unlike `ports:`, `volumes:` is also a legal TOP-LEVEL Compose key
# (named-volume declarations), so the match below requires the exact
# 4-space service-key indent rather than the looser `[[:space:]]*` other
# compose-sync helpers use — a generic match would also fire on the
# top-level `volumes:` block and corrupt it.
_dp_compose_add_mount() {
    local file="$1" host_path="$2" container_path="$3" mode="${4:-}"
    local spec="${host_path}:${container_path}"
    [[ -n "$mode" ]] && spec="${spec}:${mode}"

    if grep -qF "${spec}" "$file"; then
        return 0   # already present
    fi
    if grep -qE '^    volumes:[[:space:]]*$' "$file"; then
        awk -v spec="$spec" '
            { print }
            /^    volumes:[[:space:]]*$/ && !done { print "      - \"" spec "\""; done=1 }
        ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
    else
        awk -v spec="$spec" '
            { print }
            /^[[:space:]]*container_name:/ && !done {
                print "    volumes:"
                print "      - \"" spec "\""
                done=1
            }
        ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
    fi
}

# Add or update a KEY=value entry in a Compose file's service `environment:`
# list (list form, matching this tool's own style for ports:/volumes:).
# Unlike volumes:, environment: has no top-level meaning in the Compose
# spec, so (like ports:/mem_limit:) a generic indentation match is safe
# here. Creates the key if missing; replaces the whole line in place if the
# key is already set (only recognizes the exact quoted form this tool
# itself writes — a hand-edited line in a different style won't match and
# a second entry will be appended instead, which Compose resolves by last
# value winning).
_dp_compose_set_env() {
    local file="$1" key="$2" value="$3"
    if grep -qE "^[[:space:]]*- \"${key}=" "$file"; then
        awk -v key="$key" -v value="$value" '
            $0 ~ ("^[[:space:]]*- \"" key "=") { print "      - \"" key "=" value "\""; next }
            { print }
        ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
        return
    fi
    if grep -qE '^[[:space:]]*environment:[[:space:]]*$' "$file"; then
        awk -v key="$key" -v value="$value" '
            { print }
            /^[[:space:]]*environment:[[:space:]]*$/ && !done { print "      - \"" key "=" value "\""; done=1 }
        ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
    else
        awk -v key="$key" -v value="$value" '
            { print }
            /^[[:space:]]*container_name:/ && !done {
                print "    environment:"
                print "      - \"" key "=" value "\""
                done=1
            }
        ' "$file" > "${file}.tmp" && mv "${file}.tmp" "$file"
    fi
}

# Reconstruct the `docker run` argv for the current container, adding extra -p
# mappings ($@). Sets globals DP_RUN_CMD (array) and DP_ENV_FILE. Env is written
# to a 0600 --env-file (HOSTNAME dropped so Docker assigns a fresh one) — secrets
# are never placed inline on the command line.
_dp_build_run_cmd() {
    local envfile="$HOME/.data-pipeline-doctor/${DOCKER_CONTAINER}.env"
    mkdir -p "$(dirname "$envfile")" 2>/dev/null
    dinspect '{{range .Config.Env}}{{println .}}{{end}}' | grep -vE '^HOSTNAME=' > "$envfile" 2>/dev/null
    local ee
    for ee in "${DP_EXTRA_ENV[@]}"; do echo "$ee" >> "$envfile"; done
    DP_EXTRA_ENV=()   # consume so an env override never leaks into an unrelated later call
    chmod 600 "$envfile" 2>/dev/null
    DP_ENV_FILE="$envfile"

    local image restart mem nanocpu cpus
    image=$(dinspect '{{.Config.Image}}')
    restart=$(dinspect '{{.HostConfig.RestartPolicy.Name}}')
    mem=$(dinspect '{{.HostConfig.Memory}}')
    nanocpu=$(dinspect '{{.HostConfig.NanoCpus}}')

    DP_RUN_CMD=(docker run -d --name "$DOCKER_CONTAINER")
    [[ -n "$restart" && "$restart" != "no" ]] && DP_RUN_CMD+=(--restart "$restart")
    [[ -n "$mem" && "$mem" != "0" ]] && DP_RUN_CMD+=(--memory "$mem")
    if [[ -n "$nanocpu" && "$nanocpu" != "0" ]]; then
        cpus=$(awk -v n="$nanocpu" 'BEGIN{printf "%.2f", n/1000000000}')
        DP_RUN_CMD+=(--cpus "$cpus")
    fi
    DP_RUN_CMD+=(--env-file "$envfile")

    local vtype vname vsrc vdst vrw spec
    while IFS='|' read -r vtype vname vsrc vdst vrw; do
        [[ -z "$vdst" ]] && continue
        if [[ "$vtype" == "volume" ]]; then spec="${vname}:${vdst}"; else spec="${vsrc}:${vdst}"; fi
        [[ "$vrw" == "false" ]] && spec="${spec}:ro"
        DP_RUN_CMD+=(-v "$spec")
    done < <(dinspect '{{range .Mounts}}{{.Type}}|{{.Name}}|{{.Source}}|{{.Destination}}|{{.RW}}{{println}}{{end}}')

    local hip hport cport
    while IFS='|' read -r hip hport cport; do
        [[ -z "$cport" ]] && continue
        if [[ -n "$hip" ]]; then DP_RUN_CMD+=(-p "${hip}:${hport}:${cport}"); else DP_RUN_CMD+=(-p "${hport}:${cport}"); fi
    done < <(dinspect '{{range $p, $b := .HostConfig.PortBindings}}{{range $b}}{{.HostIp}}|{{.HostPort}}|{{$p}}{{println}}{{end}}{{end}}')

    local np
    for np in "$@"; do DP_RUN_CMD+=(-p "$np"); done

    local nm
    for nm in "${DP_EXTRA_MOUNTS[@]}"; do DP_RUN_CMD+=(-v "$nm"); done
    DP_EXTRA_MOUNTS=()   # consume so a mount never leaks into an unrelated later call

    DP_RUN_CMD+=("$image")
}

docker_menu_source_ports() {
    banner
    echo -e "  ${BOLD}Source Ports — $DOCKER_CONTAINER${NC}"
    echo ""

    echo -e "  ${BOLD}Currently published:${NC}"
    local any=false hip hport cport role
    while IFS='|' read -r hip hport cport; do
        [[ -z "$cport" ]] && continue
        any=true
        role="$(_dp_port_role "$cport" "$hport")"
        printf "    host ${CYAN}%-7s${NC} → container %-11s ${DIM}%s${NC}\n" "$hport" "$cport" "$role"
    done < <(dinspect '{{range $p, $b := .HostConfig.PortBindings}}{{range $b}}{{.HostIp}}|{{.HostPort}}|{{$p}}{{println}}{{end}}{{end}}')
    $any || echo -e "    ${DIM}(none published)${NC}"
    echo ""

    # Choose a preset (prefills proto + suggested port) or custom.
    local choice
    choice=$(pick_one "Add a port for which source type?" \
        "Syslog TCP" "Syslog TLS" "Syslog UDP" "HEC push" "Kafka" "Custom" "Back")
    local proto sugg
    case "$choice" in
        1) proto=tcp; sugg=1514 ;;
        2) proto=tcp; sugg=6514 ;;
        3) proto=udp; sugg=514 ;;
        4) proto=tcp; sugg=8088 ;;
        5) proto=tcp; sugg=9092 ;;
        6) proto=""; sugg="" ;;
        *) return ;;
    esac
    if [[ -z "$proto" ]]; then
        read -rp "  Protocol [tcp/udp] (default tcp): " proto || _dpd_eof_exit; proto="${proto:-tcp}"
    fi
    # One prompt, docker-style. Accepts:  HOST  |  HOST:CONTAINER  |  with optional /tcp|/udp
    # If only HOST is given, the container port defaults to the same number.
    local input hport cport
    echo -e "  ${DIM}Enter the mapping as host[:container] — e.g. ${NC}10001${DIM} or ${NC}10001:10001${DIM} (container port"
    echo -e "  must match the source's listen port; defaults to the host port).${NC}"
    read -rp "  Port mapping${sugg:+ (default $sugg)}: " input || _dpd_eof_exit; input="${input:-$sugg}"
    input="${input// /}"                                  # tolerate stray spaces
    if [[ "$input" == */* ]]; then proto="${input##*/}"; input="${input%%/*}"; fi   # optional /proto override
    if [[ "$input" == *:* ]]; then hport="${input%%:*}"; cport="${input##*:}"; else hport="$input"; cport="$input"; fi
    if ! [[ "$hport" =~ ^[0-9]+$ && "$cport" =~ ^[0-9]+$ ]]; then
        log_err "Invalid mapping '$input' — use host or host:container (e.g. 10001 or 10001:10001)"; pause; return
    fi
    if ! [[ "$proto" =~ ^(tcp|udp)$ ]]; then
        log_err "Invalid protocol '$proto' — use tcp or udp"; pause; return
    fi

    local newmap="${hport}:${cport}/${proto}"
    echo ""
    log_info "New mapping: -p ${newmap}"
    _dp_listener_status "$cport" "$proto"
    echo ""
    _dp_firewall_hints "$hport" "$proto"
    echo ""
    echo -e "  ${YELLOW}Docker can't add a port to a running container — it must be recreated.${NC}"
    echo ""

    local act
    local compose_file=""
    if _dp_compose_info; then
        compose_file="$DP_COMPOSE_FILE"
        log_info "This site is managed by Docker Compose (${compose_file})."
        echo -e "  ${DIM}The port will be added there too, so a future 'docker compose up -d' doesn't drop it.${NC}"
        echo ""
    fi

    act=$(pick_one "How do you want to proceed?" \
        "Show the recreate command (I'll run it myself)" \
        "Recreate the container now (confirm first)" \
        "Back")
    case "$act" in
        1)
            if [[ -n "$compose_file" ]]; then
                echo ""
                echo -e "  ${BOLD}Recreate command:${NC}"
                echo ""
                echo "    cp ${compose_file} ${compose_file}.bak   # backup first"
                echo "    # then add under the service's 'ports:' list (create it if missing):"
                echo "    #   - \"${newmap}\""
                echo "    docker compose -f ${compose_file} up -d"
                echo ""
                echo -e "  ${DIM}Rollback if needed: cp ${compose_file}.bak ${compose_file} && docker compose -f ${compose_file} up -d${NC}"
            else
                _dp_build_run_cmd "$newmap"
                echo ""
                echo -e "  ${DIM}Env written to ${DP_ENV_FILE} (chmod 600 — contains secrets).${NC}"
                echo -e "  ${BOLD}Recreate command:${NC}"
                echo ""
                echo "    docker stop $DOCKER_CONTAINER && docker rename $DOCKER_CONTAINER ${DOCKER_CONTAINER}_old && \\"
                printf '    '; printf '%q ' "${DP_RUN_CMD[@]}"; echo
                echo ""
                echo -e "  ${DIM}Rollback if needed: docker rm -f $DOCKER_CONTAINER; docker rename ${DOCKER_CONTAINER}_old $DOCKER_CONTAINER; docker start $DOCKER_CONTAINER${NC}"
            fi
            pause ;;
        2)
            if [[ -n "$compose_file" ]]; then
                echo ""
                echo -e "  ${YELLOW}This will update ${compose_file} and recreate ${DOCKER_CONTAINER} via Compose (~brief downtime).${NC}"
                if ! confirm "Add -p ${newmap} to ${compose_file} and run 'docker compose up -d' now?"; then pause; return; fi
                if ! cp "$compose_file" "${compose_file}.bak"; then
                    log_err "Could not back up ${compose_file} — aborting."; pause; return
                fi
                _dp_compose_add_port "$compose_file" "$newmap"
                if docker compose -f "$compose_file" up -d >/dev/null 2>&1; then
                    log_fix "Updated ${compose_file} and recreated $DOCKER_CONTAINER with -p ${newmap}."
                    echo -e "  ${DIM}Previous file saved as ${compose_file}.bak${NC}"
                else
                    log_err "docker compose up failed — restoring the previous ${compose_file}"
                    cp "${compose_file}.bak" "$compose_file"
                    docker compose -f "$compose_file" up -d >/dev/null 2>&1
                fi
            else
                _dp_build_run_cmd "$newmap"
                echo ""
                echo -e "  ${YELLOW}This will stop and recreate ${DOCKER_CONTAINER} (~brief downtime).${NC}"
                echo -e "  ${DIM}The current container is renamed (not deleted) so you can roll back.${NC}"
                if ! confirm "Recreate $DOCKER_CONTAINER now with -p ${newmap}?"; then pause; return; fi
                local backup="${DOCKER_CONTAINER}_pre$(date +%s)"
                if ! docker stop "$DOCKER_CONTAINER" >/dev/null 2>&1; then log_err "Failed to stop container"; pause; return; fi
                if ! docker rename "$DOCKER_CONTAINER" "$backup" >/dev/null 2>&1; then log_err "Failed to rename; container is stopped — start it again with: docker start $DOCKER_CONTAINER"; pause; return; fi
                if "${DP_RUN_CMD[@]}" >/dev/null 2>&1; then
                    log_fix "Recreated $DOCKER_CONTAINER with -p ${newmap}. Backup: $backup"
                    echo -e "  ${DIM}Verify, then remove the backup: docker rm $backup${NC}"
                else
                    log_err "Recreate failed — rolling back to the previous container"
                    docker rm -f "$DOCKER_CONTAINER" >/dev/null 2>&1
                    docker rename "$backup" "$DOCKER_CONTAINER" >/dev/null 2>&1
                    docker start "$DOCKER_CONTAINER" >/dev/null 2>&1 && log_info "Rolled back; original container is running again."
                fi
            fi
            pause ;;
        *) return ;;
    esac
}

_dp_wef_print_report() {
    local line level msg
    for line in "${DP_WEF_REPORT[@]:-}"; do
        [[ -z "$line" ]] && continue
        level="${line%%|*}"; msg="${line#*|}"
        case "$level" in
            OK)   log_ok "$msg" ;;
            WARN) log_warn "$msg" ;;
            FAIL) log_err "$msg" ;;
            *)    echo "    $msg" ;;
        esac
    done
}

docker_wef_menu_readiness() {
    banner
    echo -e "  ${BOLD}WEF/WEC Readiness Check — $DOCKER_CONTAINER${NC}"
    echo -e "  ${DIM}Read-only — nothing here changes anything.${NC}"
    echo ""
    _dp_wef_check
    _dp_wef_print_report
    echo ""
    if [[ $DP_WEF_ISSUES -eq 0 ]]; then
        log_ok "No blocking issues found${DP_WEF_WARNINGS:+ (${DP_WEF_WARNINGS} warning(s))}."
    else
        echo -e "  ${RED}${BOLD}${DP_WEF_ISSUES} blocking issue(s) found.${NC}"
        echo "    Use '2) Make this site WEF-ready' to fix what can be fixed automatically."
    fi
    pause
}

# Bundles everything WEF needs into ONE recreate: checkpoint store, cert
# mount at the paths the console source actually expects, and disabling
# FIPS crypto if it's on (confirmed live: WEF cannot build its TLS identity
# with FIPS enabled on image 2.46.0). Each piece reuses the same
# Compose-sync / raw-run-recreate pattern as the other fixes. The cert
# source directory on the host isn't guessable — Doctor asks for it rather
# than assuming a path.
# Path the vendor WEF guide uses for the server cert, key and CA. Absent from
# the 2.46.0 image, so mounting here can't shadow anything the site ships.
DP_WEF_CERT_DIR_DEFAULT="/etc/s1/wef"
DP_WEF_PORT_DEFAULT=5986

# Host-side checkpoint store for the WEF source, mounted at
# /etc/dataplane/dataplane-globals.yaml. Shared by new-site setup and Make-ready.
_dp_wef_checkpoint_file() { echo "$(_dpd_home)/.data-pipeline-doctor/dataplane-globals.yaml"; }

_dp_wef_write_checkpoint_store() {
    local hostfile="$1"
    mkdir -p "$(dirname "$hostfile")" 2>/dev/null
    cat > "$hostfile" <<'EOF'
# Lab workaround: checkpoint store for the dataplane instance (WEF source needs one).
# Mirrors /etc/collector-globals/collector-globals.yaml, with a separate db file.
data_dir: /var/observo/data/dataplane
checkpoint:
  store_path: /var/observo/data/dataplane/checkpoints.db3
EOF
    chmod 644 "$hostfile" 2>/dev/null
    _dpd_chown_back "$hostfile" "$(dirname "$hostfile")"
}

# The container runs as uid 1000: it owns the cert files, certs stay
# world-readable (they're public), and every private key is 600 — not just
# the first one found. Creates the directory if it doesn't exist yet.
_dp_wef_fix_cert_perms() {
    local dir="$1" s
    s=$(_dpd_sudo)
    $s mkdir -p "$dir" 2>/dev/null
    $s find "$dir" -type d -exec chmod 755 {} + 2>/dev/null
    $s find "$dir" -type f -exec chmod 644 {} + 2>/dev/null
    $s find "$dir" -type f \( -iname '*.key' -o -iname '*key*.pem' -o -iname '*.p12' -o -iname '*.pfx' \) \
        -exec chmod 600 {} + 2>/dev/null
    $s chown -R 1000:1000 "$dir" 2>/dev/null
}

# Set OPENSSL_CONF in a site env file (replace the line, or append it).
_dp_env_set_openssl_conf() {
    local env_file="$1" value="$2"
    if grep -qE '^OPENSSL_CONF=' "$env_file"; then
        sed -i.dpdtmp "s#^OPENSSL_CONF=.*#OPENSSL_CONF=${value}#" "$env_file" && rm -f "${env_file}.dpdtmp"
    else
        echo "OPENSSL_CONF=${value}" >> "$env_file"
    fi
}

# Shown at the end of new-site setup in WEF/WEC mode: the steps Doctor
# can't do for the customer (their certs, the console source).
_dp_wef_print_next_steps() {
    local port="$1" cert_dir="$2" fqdn f missing=()
    fqdn="$(hostname -f 2>/dev/null || hostname)"
    for f in ca.crt server.crt server.key; do
        $(_dpd_sudo) test -f "$cert_dir/$f" 2>/dev/null || missing+=("$f")
    done
    echo -e "  ${BOLD}WEF/WEC — next steps${NC}"
    echo ""
    if [[ ${#missing[@]} -gt 0 ]]; then
        echo "    1. Copy the server certificate, key, and CA into ${cert_dir}:"
        echo "         ${missing[*]}"
        echo "       Then re-run Doctor (or Tools 15 → 2) to set ownership for the container."
    else
        echo "    1. Certificates found in ${cert_dir} — ownership set for the container."
    fi
    echo "    2. In the console, add a Windows Event Forwarding source to this site:"
    echo "         Listen address:     0.0.0.0:${port}"
    echo "         Collector address:  ${fqdn}:${port}   (the name Windows forwarders resolve)"
    echo "         CA / cert / key:    ${cert_dir}/ca.crt, ${cert_dir}/server.crt, ${cert_dir}/server.key"
    echo "    3. Point the Windows subscription manager at:"
    echo "         Server=https://${fqdn}:${port}/wsman/SubscriptionManager/WEC,Refresh=60,IssuerCA=<CA thumbprint>"
    echo "    4. Check it with Tools 15 → 1 (readiness check) once the source is deployed."
    echo ""
}

# The env_file a Compose service reads (first one), or nothing. Used so the
# FIPS switch is written where operators look for it, not only as a Compose
# override that silently disagrees with the env file.
_dp_compose_env_file() {
    local file="$1" ef
    ef=$(awk '/^[[:space:]]*env_file:[[:space:]]*[^[:space:]]/ { sub(/^[[:space:]]*env_file:[[:space:]]*/, ""); gsub(/["'\'']/, ""); print; exit }' "$file")
    [[ -z "$ef" ]] && return 0
    [[ "$ef" == /* ]] || ef="$(dirname "$file")/$ef"   # Compose resolves relative paths from the file's dir
    echo "$ef"
}

# $1 = "inline" when called from the full scan's fix pass: no banner (it would
# clear the scan output) and no pauses (the scan pauses once at the end).
# Returns 0 only when the site was changed.
docker_wef_make_ready() {
    local inline=false
    [[ "${1:-}" == "inline" ]] && inline=true
    if $inline; then
        log_info "Make this site WEF-ready — $DOCKER_CONTAINER"
    else
        banner
        echo -e "  ${BOLD}Make this site WEF-ready — $DOCKER_CONTAINER${NC}"
    fi
    echo ""
    _dp_wef_check

    if ! $DP_WEF_FOUND; then
        log_err "No WEF source found in the dataplane config — add the Windows Event Forwarding source in the console first."
        $inline || pause; return 1
    fi

    local need_checkpoint=false need_certs=false need_fips=false
    dinspect '{{range .Mounts}}{{.Destination}}{{println}}{{end}}' | grep -qF "/etc/dataplane/dataplane-globals.yaml" \
        || need_checkpoint=true

    if [[ ${#DP_WEF_CERT_PATHS[@]} -eq 0 ]]; then
        need_certs=true
    else
        local p
        for p in "${DP_WEF_CERT_PATHS[@]}"; do
            dexec test -r "$p" 2>/dev/null || need_certs=true
        done
    fi

    $DP_WEF_FIPS_ON && need_fips=true

    if ! $need_checkpoint && ! $need_certs && ! $need_fips; then
        log_ok "Already WEF-ready — nothing to do."
        $inline || pause; return 1
    fi

    # Every change below ends in rewriting the Compose/env files (root-owned
    # when Doctor set the site up under sudo) or recreating the container.
    # Fail here with the fix, not half-way through after writing files.
    local compose_file="" env_file=""
    _dp_compose_info && compose_file="$DP_COMPOSE_FILE"
    if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
        local blocked=""
        [[ -n "$compose_file" && ! -w "$compose_file" ]] && blocked="$compose_file"
        [[ -z "$blocked" && -n "$compose_file" && ! -w "$(dirname "$compose_file")" ]] && blocked="$(dirname "$compose_file")"
        if [[ -n "$blocked" ]]; then
            log_err "Not running as root, and $blocked isn't writable by $(id -un)."
            echo -e "  ${DIM}Re-run Doctor with sudo:  sudo $0${NC}"
            $inline || pause; return 1
        fi
    fi

    echo "  Plan:"
    $need_checkpoint && echo "    - Write and mount a checkpoint store (dataplane-globals.yaml)"
    if $need_certs; then
        echo "    - Mount certificate files at the path(s) the source expects:"
        if [[ ${#DP_WEF_CERT_PATHS[@]} -gt 0 ]]; then
            local p; for p in "${DP_WEF_CERT_PATHS[@]}"; do echo "        $p"; done
        else
            echo "        (could not read the expected paths from the config — you'll confirm the host side, but"
            echo "         the container-side destination will need to be entered too)"
        fi
    fi
    $need_fips && echo "    - Disable FIPS-mode crypto for this site (OPENSSL_CONF=/etc/ssl/openssl.cnf.default) — WEF cannot start with FIPS on"
    echo ""

    local cert_src_dir="" cert_dst_dir=""
    if $need_certs; then
        # Container side: wherever the console source points, else the guide's path.
        if [[ ${#DP_WEF_CERT_PATHS[@]} -gt 0 ]]; then
            cert_dst_dir="$(dirname "${DP_WEF_CERT_PATHS[0]}")"
        fi
        # Host side defaults to the same path when it exists, so host and
        # container match like in the guide; otherwise the guide's path.
        local src_default="$DP_WEF_CERT_DIR_DEFAULT"
        [[ -n "$cert_dst_dir" && -d "$cert_dst_dir" ]] && src_default="$cert_dst_dir"
        echo -e "  ${YELLOW}Where are the server certificate, key, and CA file on THIS host right now?${NC}"
        echo "    (the folder containing them — Enter for ${src_default})"
        read -rp "  Host cert directory [${src_default}]: " cert_src_dir || _dpd_eof_exit
        cert_src_dir="${cert_src_dir:-$src_default}"
        if [[ ! -d "$cert_src_dir" ]]; then
            log_err "$cert_src_dir is not a directory — copy the certs there first, or enter where they are. Aborting."
            $inline || pause; return 1
        fi
        if [[ -z "$cert_dst_dir" ]]; then
            read -rp "  Container-side path the source expects these files at [${DP_WEF_CERT_DIR_DEFAULT}]: " cert_dst_dir || _dpd_eof_exit
            cert_dst_dir="${cert_dst_dir:-$DP_WEF_CERT_DIR_DEFAULT}"
        fi
    fi

    if $need_fips; then
        echo ""
        echo -e "  ${RED}${BOLD}FIPS warning:${NC} this disables FIPS-validated crypto for the WHOLE site, not just WEF."
        echo "    Do not do this in a FedRAMP/DoD or other FIPS-required environment."
        if ! confirm "Disable FIPS-validated crypto for this entire site?"; then
            need_fips=false
            log_warn "Skipping the FIPS change — WEF will likely still fail to start until this is addressed."
        fi
    fi

    if ! $need_checkpoint && ! $need_certs && ! $need_fips; then
        log_info "Nothing left to apply."
        $inline || pause; return 1
    fi

    echo ""
    if ! confirm "Apply the plan above and recreate $DOCKER_CONTAINER now (one recreate, existing container backed up)?"; then
        $inline || pause; return 1
    fi

    local hostfile
    hostfile="$(_dp_wef_checkpoint_file)"
    $need_checkpoint && _dp_wef_write_checkpoint_store "$hostfile"
    $need_certs && _dp_wef_fix_cert_perms "$cert_src_dir"

    if [[ -n "$compose_file" ]]; then
        local stamp compose_backup env_backup=""
        stamp="$(date +%Y%m%d%H%M%S)"
        compose_backup="${compose_file}.bak.${stamp}"
        if ! cp -p "$compose_file" "$compose_backup"; then
            log_err "Could not back up ${compose_file} — aborting."
            $inline || pause; return 1
        fi
        $need_checkpoint && _dp_compose_add_mount "$compose_file" "$hostfile" "/etc/dataplane/dataplane-globals.yaml" "ro"
        $need_certs && _dp_compose_add_mount "$compose_file" "$cert_src_dir" "$cert_dst_dir" "ro"
        if $need_fips; then
            _dp_compose_set_env "$compose_file" "OPENSSL_CONF" "/etc/ssl/openssl.cnf.default"
            # Keep the env file in step with the Compose override, so nobody
            # reads OPENSSL_CONF=...fips there and thinks FIPS is still on.
            env_file="$(_dp_compose_env_file "$compose_file")"
            if [[ -n "$env_file" && -f "$env_file" ]] && grep -qE '^OPENSSL_CONF=' "$env_file"; then
                env_backup="${env_file}.bak.${stamp}"
                if cp -p "$env_file" "$env_backup"; then
                    _dp_env_set_openssl_conf "$env_file" "/etc/ssl/openssl.cnf.default"
                else
                    env_backup=""
                    log_warn "Could not back up ${env_file} — left it unchanged (the Compose override still applies)."
                fi
            fi
        fi

        if docker compose -f "$compose_file" up -d >/dev/null 2>&1; then
            log_fix "Recreated $DOCKER_CONTAINER with the WEF changes applied."
            log_info "Previous compose file saved as ${compose_backup}"
            [[ -n "$env_backup" ]] && log_info "Previous env file saved as ${env_backup}"
        else
            log_err "docker compose up failed — restoring the previous ${compose_file}"
            cp -p "$compose_backup" "$compose_file"
            [[ -n "$env_backup" ]] && cp -p "$env_backup" "$env_file"
            docker compose -f "$compose_file" up -d >/dev/null 2>&1
            $inline || pause; return 1
        fi
    else
        DP_EXTRA_MOUNTS=()
        $need_checkpoint && DP_EXTRA_MOUNTS+=("${hostfile}:/etc/dataplane/dataplane-globals.yaml:ro")
        $need_certs && DP_EXTRA_MOUNTS+=("${cert_src_dir}:${cert_dst_dir}:ro")
        DP_EXTRA_ENV=()
        $need_fips && DP_EXTRA_ENV+=("OPENSSL_CONF=/etc/ssl/openssl.cnf.default")
        _dp_build_run_cmd

        local backup="${DOCKER_CONTAINER}_pre$(date +%s)"
        if ! docker stop "$DOCKER_CONTAINER" >/dev/null 2>&1; then
            log_err "Failed to stop container"; $inline || pause; return 1
        fi
        if ! docker rename "$DOCKER_CONTAINER" "$backup" >/dev/null 2>&1; then
            log_err "Failed to rename; container is stopped — start it again with: docker start $DOCKER_CONTAINER"
            $inline || pause; return 1
        fi
        if "${DP_RUN_CMD[@]}" >/dev/null 2>&1; then
            log_fix "Recreated $DOCKER_CONTAINER with the WEF changes applied. Backup: $backup"
        else
            log_err "Recreate failed — rolling back to the previous container"
            docker rm -f "$DOCKER_CONTAINER" >/dev/null 2>&1
            docker rename "$backup" "$DOCKER_CONTAINER" >/dev/null 2>&1
            docker start "$DOCKER_CONTAINER" >/dev/null 2>&1 && log_info "Rolled back; original container is running again."
            $inline || pause; return 1
        fi
    fi

    echo ""
    log_info "Re-running the readiness check..."
    sleep 2
    echo ""
    _dp_wef_check
    _dp_wef_print_report
    $inline || pause
    return 0
}

docker_menu_wef() {
    while true; do
        banner
        echo -e "  ${BOLD}WEF/WEC Integration — $DOCKER_CONTAINER${NC}"
        echo ""
        if ! $WEF_MODE; then
            echo -e "  ${DIM}WEF/WEC mode is off for this host. You can still use this menu;${NC}"
            echo -e "  ${DIM}turn it on by answering yes next time Doctor starts up.${NC}"
            echo ""
        fi
        echo -e "    ${CYAN} 1)${NC} Readiness check (read-only)"
        echo -e "    ${CYAN} 2)${NC} Make this site WEF-ready (one recreate)"
        echo ""
        echo -e "    ${CYAN} 0)${NC} Back"
        echo ""
        local choice
        read -rp "  Choose [0-2]: " choice || return
        case "$choice" in
            1) docker_wef_menu_readiness ;;
            2) docker_wef_make_ready ;;
            0|*) return ;;
        esac
    done
}

# Pick a syslog-capable published port for the current container.
# Sets DP_SYSLOG_PORT and DP_SYSLOG_PROTO on success; returns 1 on cancel / none found.
# Auto-selects when only one candidate, otherwise offers a menu.
_dp_pick_syslog_port() {
    # Collect syslog-capable published ports (skip HEC push and Kafka which have dedicated ports).
    local entries=() hports=() protos=() hip hport cport role label
    while IFS='|' read -r hip hport cport; do
        [[ -z "$cport" ]] && continue
        role="$(_dp_port_role "$cport" "$hport")"
        case "$role" in
            "HEC push"|"Kafka") continue ;;
        esac
        if [[ "$role" == Syslog* ]]; then
            label="host ${hport} → container ${cport}  (${role})"
        else
            label="host ${hport} → container ${cport}  (custom)"
        fi
        entries+=("$label")
        hports+=("$hport")
        protos+=("${cport##*/}")
    done < <(dinspect '{{range $p, $b := .HostConfig.PortBindings}}{{range $b}}{{.HostIp}}|{{.HostPort}}|{{$p}}{{println}}{{end}}{{end}}')

    if [[ ${#entries[@]} -eq 0 ]]; then
        log_warn "No syslog-capable published ports found."
        echo -e "  ${DIM}Use option 12 — Source ports to publish one first.${NC}"
        pause; return 1
    fi

    if [[ ${#entries[@]} -eq 1 ]]; then
        DP_SYSLOG_PORT="${hports[0]}"; DP_SYSLOG_PROTO="${protos[0]}"
        log_info "Using the only available port: host ${DP_SYSLOG_PORT} (${DP_SYSLOG_PROTO})"
        echo ""
        return 0
    fi

    local port_count="${#entries[@]}" port_choice
    entries+=("Back")
    port_choice=$(pick_one "Which port to send to?" "${entries[@]}")
    if [[ ! "$port_choice" =~ ^[0-9]+$ || "$port_choice" -gt "$port_count" || "$port_choice" -lt 1 ]]; then
        return 1
    fi
    DP_SYSLOG_PORT="${hports[$(( port_choice - 1 ))]}"
    DP_SYSLOG_PROTO="${protos[$(( port_choice - 1 ))]}"
    return 0
}

docker_menu_syslog_test() {
    banner
    echo -e "  ${BOLD}Syslog Tester — $DOCKER_CONTAINER${NC}"
    echo ""

    _dp_pick_syslog_port || return
    local port="$DP_SYSLOG_PORT" proto="$DP_SYSLOG_PROTO"

    # Pick event category.
    local cat_choice cat
    cat_choice=$(pick_one "Which event type?" \
        "Firewall (fw)" \
        "Authentication (auth)" \
        "DNS (dns)" \
        "Web (web)" \
        "Generic" \
        "Back")
    case "$cat_choice" in
        1) cat="fw" ;;
        2) cat="auth" ;;
        3) cat="dns" ;;
        4) cat="web" ;;
        5) cat="generic" ;;
        *) return ;;
    esac

    # Generate UUID, build and send the event.
    local UUID event body_preview
    UUID="$(_dp_gen_uuid)"
    event="$(_dp_syslog_event "$cat" "$UUID")"
    body_preview="${event##*|}"

    echo ""
    log_info "Sending to localhost:${port}/${proto}"
    echo -e "  ${DIM}${body_preview}${NC}"
    echo ""

    if _dp_send_syslog "$event" "$port" "$proto"; then
        log_ok "Test event sent."
        echo -e "  ${DIM}Watch it arrive: Docker menu option 10 — Tail sources & destinations.${NC}"
        echo ""
        echo "Use the following in SDL Event ALL Search to locate the test event: message contains '${UUID}'"
        echo ""
    else
        log_err "Failed to send test event — check that the port is published and a listener is up."
    fi
    pause
}

# Continuous generator: send a fresh syslog event every N seconds until Ctrl-C.
# A log preview / dataplane tap is a LIVE sampler — it only shows lines that flow
# through the component during its ~30s capture window. A steady trickle keeps the
# source non-idle so previews always have data to sample, instead of racing one-shot sends.
docker_menu_syslog_stream() {
    banner
    echo -e "  ${BOLD}Syslog Stream (continuous) — $DOCKER_CONTAINER${NC}"
    echo ""

    _dp_pick_syslog_port || return
    local port="$DP_SYSLOG_PORT" proto="$DP_SYSLOG_PROTO"

    # Pick event category.
    local cat_choice cat
    cat_choice=$(pick_one "Which event type?" \
        "Firewall (fw)" \
        "Authentication (auth)" \
        "DNS (dns)" \
        "Web (web)" \
        "Generic" \
        "Back")
    case "$cat_choice" in
        1) cat="fw" ;;
        2) cat="auth" ;;
        3) cat="dns" ;;
        4) cat="web" ;;
        5) cat="generic" ;;
        *) return ;;
    esac

    # Interval between events (default 1s).
    local rate
    read -rp "  Seconds between events [1]: " rate || _dpd_eof_exit
    [[ -z "$rate" ]] && rate=1
    if [[ ! "$rate" =~ ^[0-9]+$ ]] || [[ "$rate" -lt 1 ]]; then
        log_warn "Invalid interval — using 1 second."
        rate=1
    fi

    # One UUID for the whole stream run, so every event in this batch shares a
    # single test-id — search 'message contains <UUID>' to find them all at once.
    local UUID
    UUID="$(_dp_gen_uuid)"

    echo ""
    log_info "Streaming ${cat} events to localhost:${port}/${proto} every ${rate}s."
    echo -e "  ${DIM}Open a log preview / Tail (option 10) in the Observo UI now — press Ctrl-C to stop.${NC}"
    echo -e "  ${DIM}Find this batch in SDL Event ALL Search: message contains '${UUID}'${NC}"
    echo ""

    # Trap SIGINT locally so Ctrl-C stops the loop and returns to the menu
    # (instead of killing the whole script); restored on exit.
    local sent=0 fails=0 stop=0 event
    trap 'stop=1' INT
    while [[ "$stop" -eq 0 ]]; do
        event="$(_dp_syslog_event "$cat" "$UUID")"
        if _dp_send_syslog "$event" "$port" "$proto" >/dev/null 2>&1; then
            sent=$(( sent + 1 ))
        else
            fails=$(( fails + 1 ))
        fi
        printf "\r  ${DIM}sent %d   failed %d${NC}   " "$sent" "$fails"
        [[ "$stop" -eq 1 ]] && break
        sleep "$rate"
    done
    trap - INT

    echo ""
    echo ""
    if [[ "$sent" -gt 0 ]]; then
        if [[ "$fails" -gt 0 ]]; then
            log_ok "Stream stopped — ${sent} event(s) sent, ${fails} failed."
        else
            log_ok "Stream stopped — ${sent} event(s) sent."
        fi
    else
        log_err "Stream stopped — no events sent (${fails} failed). Check the port is published and a listener is up."
    fi
    pause
}

docker_main_menu() {
    while true; do
        banner
        echo -e "  ${DIM}Container:${NC} $DOCKER_CONTAINER"
        echo -e "  ${DIM}Image:${NC}     $(dinspect '{{.Config.Image}}')"
        echo -e "  ${DIM}Site ID:${NC}   ${OBSERVO_SITE_ID:-unknown}"
        echo ""
        echo -e "  ${BOLD}Diagnostics${NC}"
        hr
        printf "    ${CYAN}%2s)${NC} %-30s ${CYAN}%2s)${NC} %s\n" 1 "Full diagnostic scan" 2 "Service health (s6)"
        printf "    ${CYAN}%2s)${NC} %-30s ${CYAN}%2s)${NC} %s\n" 3 "Container & resources" 4 "TLS & certificates"
        printf "    ${CYAN}%2s)${NC} %-30s ${CYAN}%2s)${NC} %s\n" 5 "DNS resolution" 6 "Volume & disk"
        echo ""
        echo -e "  ${BOLD}Tools${NC}"
        hr
        printf "    ${CYAN}%2s)${NC} %-30s ${CYAN}%2s)${NC} %s\n" 7 "Logs (combined/service)" 8 "Service debugger"
        printf "    ${CYAN}%2s)${NC} %-30s ${CYAN}%2s)${NC} %s\n" 9 "Restart service/container" 10 "Tail sources & destinations"
        printf "    ${CYAN}%2s)${NC} %-30s ${CYAN}%2s)${NC} %s\n" 11 "Proxy & connectivity" 12 "Source ports"
        printf "    ${CYAN}%2s)${NC} %-30s ${CYAN}%2s)${NC} %s\n" 13 "Syslog tester" 14 "Syslog stream (continuous)"
        local wef_label="WEF/WEC integration"
        if $WEF_MODE; then
            _dp_wef_check
            [[ $DP_WEF_ISSUES -gt 0 ]] && wef_label="WEF/WEC integration (${DP_WEF_ISSUES} issue$([[ $DP_WEF_ISSUES -eq 1 ]] || echo s))"
        fi
        printf "    ${CYAN}%2s)${NC} %s\n" 15 "$wef_label"
        echo ""
        hr
        echo ""
        echo -e "    ${CYAN} 0)${NC} Exit"
        echo ""
        local choice
        read -rp "  Choose [0-15]: " choice || { echo ""; log_info "Goodbye."; exit 0; }
        case "$choice" in
            1)  docker_full_scan ;;
            2)  docker_run_scan docker_scan_services "Service Health (s6)" ;;
            3)  docker_menu_resources ;;
            4)  docker_run_scan docker_scan_tls "TLS & Certificates" ;;
            5)  docker_run_scan docker_scan_dns "DNS Resolution" ;;
            6)  docker_run_scan docker_scan_storage "Volume & Disk" ;;
            7)  docker_menu_logs ;;
            8)  docker_service_debug_menu ;;
            9)  docker_menu_restart ;;
            10) docker_menu_dataplane_tap ;;
            11) docker_menu_proxy_connectivity ;;
            12) docker_menu_source_ports ;;
            13) docker_menu_syslog_test ;;
            14) docker_menu_syslog_stream ;;
            15) docker_menu_wef ;;
            0)  echo ""; log_info "Goodbye."; exit 0 ;;
            *)  ;;
        esac
    done
}

# ============================================================
#  Entry point
# ============================================================
# Guarded so the script can be sourced as a library (e.g. by the test
# harness in tests/) without launching the interactive menu.
if [[ "${BASH_SOURCE[0]:-$0}" == "${0}" ]]; then
    parse_args "$@"
    preflight
    if [[ "$SITE_TYPE" == "docker" ]]; then
        docker_main_menu
    else
        main_menu
    fi
fi
