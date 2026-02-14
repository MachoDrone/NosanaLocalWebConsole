#!/usr/bin/env bash
# Usage: bash <(wget -qO- https://raw.githubusercontent.com/MachoDrone/NosanaLocalWebConsole/refs/heads/main/NosanaLocalWebConsole.sh)
echo "v0.01.1"
sleep 3
# =============================================================================
# Nosana WebUI — Netdata Launcher
#
# Deploys Netdata in Docker with full host monitoring + NVIDIA GPU support.
# By default requires login (nginx reverse proxy with basic auth).
# Uses your OS username — you provide your existing password.
#
# Persistent config in ~/.nosana-webui/ survives container restarts/purges.
#
# Usage:
#   bash <(wget -qO- https://raw.githubusercontent.com/.../NosanaLocalWebConsole.sh)
#   ... --nologin           # no login, open access
#   ... --port PORT         # public port (default: 19999)
#   ... --stop              # stop and remove containers
#   ... --status            # show status
#   ... --reset-password    # change stored password
#
# Tested: Ubuntu 20.04 – 24.04 (Desktop, Server, Minimal, Core)
# Requires: Docker (already present on Nosana hosts)
# =============================================================================
set -euo pipefail

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
NETDATA_CONTAINER="nosana-netdata"
PROXY_CONTAINER="nosana-proxy"
CONFIG_DIR="${HOME}/.nosana-webui"
NETDATA_IMAGE="netdata/netdata:stable"
NGINX_IMAGE="nginx:alpine"
DEFAULT_PORT=19999
NETDATA_INTERNAL_PORT=19998
HTPASSWD_FILE="${CONFIG_DIR}/.htpasswd"
PASSWORD_FILE="${CONFIG_DIR}/.password"
NGINX_CONF="${CONFIG_DIR}/nginx.conf"

# Terminal colors
if [ -t 1 ]; then
    R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' B='\033[0;34m'
    C='\033[0;36m' BOLD='\033[1m' NC='\033[0m'
else
    R='' G='' Y='' B='' C='' BOLD='' NC=''
fi

info()  { echo -e "${G}[OK]${NC}    $*"; }
warn()  { echo -e "${Y}[WARN]${NC}  $*"; }
err()   { echo -e "${R}[ERR]${NC}   $*"; }
step()  { echo -e "${C}[....]${NC}  $*"; }

# -----------------------------------------------------------------------------
# Checks
# -----------------------------------------------------------------------------
check_docker() {
    if ! command -v docker &>/dev/null; then
        err "Docker not found."
        echo "  Nosana hosts should already have Docker installed."
        echo "  https://learn.nosana.com/hosts/grid-ubuntu"
        exit 1
    fi
    if ! docker info &>/dev/null 2>&1; then
        err "Docker installed but not running or lacking permission."
        echo "  Try: sudo systemctl start docker"
        echo "  Or:  sudo usermod -aG docker \$USER  (then re-login)"
        exit 1
    fi
}

check_gpu() {
    command -v nvidia-smi &>/dev/null && nvidia-smi &>/dev/null 2>&1
}

check_nvidia_runtime() {
    docker info 2>/dev/null | grep -qi "nvidia" || \
    command -v nvidia-container-toolkit &>/dev/null || \
    [ -f /usr/bin/nvidia-container-runtime ]
}

# -----------------------------------------------------------------------------
# Cleanup stale state from previous runs
# -----------------------------------------------------------------------------
cleanup_stale() {
    # Stop and remove any existing containers
    for c in "${PROXY_CONTAINER}" "${NETDATA_CONTAINER}"; do
        if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${c}$"; then
            step "Removing old container: ${c}"
            docker stop "${c}" 2>/dev/null || true
            docker rm "${c}" 2>/dev/null || true
        fi
    done

    # Also remove the old single-container name if it exists (from Grok's version)
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^nosana-webui$"; then
        step "Removing old nosana-webui container..."
        docker stop "nosana-webui" 2>/dev/null || true
        docker rm "nosana-webui" 2>/dev/null || true
    fi

    # Remove stale Netdata config volume that may have wrong bind settings
    # Data volumes (lib, cache) are kept — only config is reset for clean bind
    if docker volume ls -q 2>/dev/null | grep -q "^netdata-config$"; then
        step "Removing stale netdata-config volume (fresh config on next start)..."
        docker volume rm netdata-config 2>/dev/null || true
    fi
}

# -----------------------------------------------------------------------------
# Persistent config directory
# -----------------------------------------------------------------------------
setup_config() {
    mkdir -p "${CONFIG_DIR}/custom-tabs"

    if [ ! -f "${CONFIG_DIR}/config.json" ]; then
        cat > "${CONFIG_DIR}/config.json" << 'EOF'
{
    "version": "1.0.0",
    "custom_buttons": [
        { "label": "GPU Status",         "command": "nvidia-smi" },
        { "label": "GPU Processes",       "command": "nvidia-smi pmon -c 1" },
        { "label": "Docker Containers",   "command": "docker ps --format 'table {{.Names}}\\t{{.Status}}\\t{{.Ports}}'" },
        { "label": "Nosana Node Logs",    "command": "docker logs --tail 50 nosana-node 2>/dev/null || echo 'Nosana node container not found'" },
        { "label": "Disk Usage",          "command": "df -h" },
        { "label": "Memory",              "command": "free -h" },
        { "label": "Top Processes",        "command": "ps aux --sort=-%mem | head -20" }
    ]
}
EOF
        info "Created config at ${CONFIG_DIR}/config.json"
    fi
}

# -----------------------------------------------------------------------------
# Authentication — uses your OS username, you type your existing password
# -----------------------------------------------------------------------------
setup_password() {
    if [ -f "${HTPASSWD_FILE}" ] && [ -f "${PASSWORD_FILE}" ]; then
        local existing_user
        existing_user=$(head -1 "${HTPASSWD_FILE}" | cut -d: -f1)
        echo ""
        echo -e "  ${BOLD}Existing credentials found:${NC}"
        echo -e "    User: ${G}${existing_user}${NC}"
        echo -e "    Pass: (stored in ${PASSWORD_FILE})"
        echo -e "    Use --reset-password to change."
        echo ""
        return 0
    fi

    create_password
}

create_password() {
    echo ""
    echo -e "${BOLD}  Set up WebUI login${NC}"
    echo ""

    # Default to current OS username
    local default_user
    default_user=$(whoami)
    read -rp "  Username [${default_user}]: " input_user
    local auth_user="${input_user:-${default_user}}"

    # Ask for their existing OS password
    echo ""
    echo "  Enter the password you use to log into this Ubuntu machine."
    echo "  (Stored locally in ${CONFIG_DIR} — not sent anywhere.)"
    echo ""

    local auth_pass=""
    while true; do
        read -rsp "  Password: " auth_pass
        echo ""
        if [ -z "${auth_pass}" ]; then
            warn "Password cannot be empty."
            continue
        fi
        local confirm_pass=""
        read -rsp "  Confirm:  " confirm_pass
        echo ""
        if [ "${auth_pass}" != "${confirm_pass}" ]; then
            err "Passwords don't match. Try again."
            echo ""
            continue
        fi
        break
    done

    # Generate htpasswd (openssl present on all Ubuntu variants)
    local hashed
    hashed=$(openssl passwd -apr1 "${auth_pass}")
    echo "${auth_user}:${hashed}" > "${HTPASSWD_FILE}"
    echo -n "${auth_pass}" > "${PASSWORD_FILE}"
    chmod 600 "${HTPASSWD_FILE}" "${PASSWORD_FILE}"

    echo ""
    info "Credentials saved for user: ${auth_user}"
    echo ""
}

# -----------------------------------------------------------------------------
# Nginx config generation
# -----------------------------------------------------------------------------
generate_nginx_conf() {
    local mode="$1"  # "secure" or "open"
    local netdata_port="${NETDATA_INTERNAL_PORT}"
    local listen_port="${DEFAULT_PORT}"

    # In nologin/open mode, Netdata listens on the public port directly
    # but we still proxy through nginx for consistency and future custom tabs
    if [ "${mode}" = "open" ]; then
        netdata_port="${DEFAULT_PORT}"
    fi

    cat > "${NGINX_CONF}" << NGINXEOF
worker_processes 1;
error_log /var/log/nginx/error.log warn;
pid /tmp/nginx.pid;

events { worker_connections 128; }

http {
    upstream netdata {
        server 127.0.0.1:${netdata_port};
        keepalive 64;
    }

    server {
        listen ${listen_port};
NGINXEOF

    if [ "${mode}" = "secure" ]; then
        cat >> "${NGINX_CONF}" << 'NGINXEOF'

        # Basic auth — nothing visible until you log in
        auth_basic "Nosana WebUI";
        auth_basic_user_file /etc/nginx/.htpasswd;
NGINXEOF
    fi

    cat >> "${NGINX_CONF}" << 'NGINXEOF'

        location / {
            proxy_pass http://netdata;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # WebSocket support (Netdata live charts)
            proxy_http_version 1.1;
            proxy_set_header Upgrade $http_upgrade;
            proxy_set_header Connection "upgrade";

            proxy_connect_timeout 60s;
            proxy_read_timeout 300s;
            proxy_send_timeout 300s;
        }
    }
}
NGINXEOF
}

# -----------------------------------------------------------------------------
# Firewall
# -----------------------------------------------------------------------------
open_firewall() {
    local public_port="$1"
    if command -v ufw >/dev/null 2>&1; then
        if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
            step "UFW: opening ${public_port}, blocking ${NETDATA_INTERNAL_PORT}..."
            sudo ufw allow "${public_port}"/tcp comment "Nosana WebUI" >/dev/null 2>&1 || true
            sudo ufw deny "${NETDATA_INTERNAL_PORT}"/tcp comment "Nosana internal" >/dev/null 2>&1 || true
            sudo ufw reload >/dev/null 2>&1 || true
            info "UFW: ${public_port} open, ${NETDATA_INTERNAL_PORT} blocked."
        fi
    fi
}

# -----------------------------------------------------------------------------
# Stop / Status
# -----------------------------------------------------------------------------
do_stop() {
    step "Stopping Nosana WebUI containers..."
    for c in "${PROXY_CONTAINER}" "${NETDATA_CONTAINER}" "nosana-webui"; do
        if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${c}$"; then
            docker stop "${c}" 2>/dev/null || true
            docker rm "${c}" 2>/dev/null || true
            info "Removed ${c}"
        fi
    done
    echo ""
    info "Config preserved at ${CONFIG_DIR}"
    info "Re-run this script to relaunch."
}

do_status() {
    echo -e "${BOLD}Nosana WebUI Status${NC}"
    echo "──────────────────────────────────────"
    if docker info &>/dev/null 2>&1; then
        echo -e "  Docker:    ${G}running${NC}"
    else
        echo -e "  Docker:    ${R}not running${NC}"
    fi
    if check_gpu; then
        local gpu_name
        gpu_name=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1)
        echo -e "  GPU:       ${G}${gpu_name}${NC}"
    else
        echo -e "  GPU:       ${Y}not detected${NC}"
    fi
    for c in "${NETDATA_CONTAINER}" "${PROXY_CONTAINER}"; do
        local label="${c#nosana-}"
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${c}$"; then
            echo -e "  ${label}:  ${G}running${NC}"
        elif docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${c}$"; then
            echo -e "  ${label}:  ${Y}stopped${NC}"
        else
            echo -e "  ${label}:  not deployed"
        fi
    done
    local ip
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo ""
    echo -e "  URL:       http://${ip:-localhost}:${DEFAULT_PORT}"
    echo -e "  Config:    ${CONFIG_DIR}"
    echo ""
}

# -----------------------------------------------------------------------------
# Launch Netdata
# -----------------------------------------------------------------------------
launch_netdata() {
    local bind_addr="$1"
    local bind_port="$2"

    step "Pulling latest Netdata image..."
    docker pull "${NETDATA_IMAGE}"

    step "Launching Netdata (bound to ${bind_addr}:${bind_port})..."

    local -a cmd=(
        docker run -d
        --name "${NETDATA_CONTAINER}"
        --hostname "nosana-$(hostname)"
        --restart unless-stopped
        --pid=host
        --network=host
        --cap-add SYS_PTRACE
        --cap-add SYS_ADMIN
        --security-opt apparmor=unconfined

        # Host filesystem (read-only)
        -v /proc:/host/proc:ro
        -v /sys:/host/sys:ro
        -v /etc/os-release:/host/etc/os-release:ro
        -v /etc/passwd:/host/etc/passwd:ro
        -v /etc/group:/host/etc/group:ro
        -v /var/log:/host/var/log:ro
        -v /etc/localtime:/etc/localtime:ro

        # Docker socket — see other containers
        -v /var/run/docker.sock:/var/run/docker.sock:ro

        # Persistent storage
        -v netdata-config:/etc/netdata
        -v netdata-lib:/var/lib/netdata
        -v netdata-cache:/var/cache/netdata

        # Nosana WebUI shared config
        -v "${CONFIG_DIR}:/nosana-webui:rw"
    )

    # GPU support
    if check_nvidia_runtime; then
        info "NVIDIA runtime detected — enabling --gpus all"
        cmd+=(--gpus all)
    elif check_gpu; then
        warn "GPU found but nvidia-container-toolkit missing — direct device mount."
        for dev in /dev/nvidia0 /dev/nvidiactl /dev/nvidia-uvm /dev/nvidia-uvm-tools; do
            [ -e "$dev" ] && cmd+=(--device "${dev}:${dev}")
        done
        local smi_path
        smi_path=$(command -v nvidia-smi 2>/dev/null || true)
        if [ -n "$smi_path" ]; then
            cmd+=(-v "${smi_path}:${smi_path}:ro")
        fi
    else
        warn "No NVIDIA GPU detected."
    fi

    # Image name
    cmd+=("${NETDATA_IMAGE}")

    # CRITICAL: Force bind address via -W command-line flag.
    # This overrides ANY config file, including stale settings in volumes.
    # This is the fix for the auth bypass bug — without this, Netdata
    # ignores our config file overrides and binds to 0.0.0.0:19999.
    cmd+=(-W "set web bind to = ${bind_addr}:${bind_port}")

    if "${cmd[@]}"; then
        info "Netdata started."
    else
        err "Netdata failed. Check: docker logs ${NETDATA_CONTAINER}"
        exit 1
    fi

    # Wait for Netdata to be ready
    step "Waiting for Netdata to initialize..."
    local retries=15
    while [ $retries -gt 0 ]; do
        if curl -sf "http://${bind_addr}:${bind_port}/api/v1/info" >/dev/null 2>&1; then
            info "Netdata responding on ${bind_addr}:${bind_port}"
            return 0
        fi
        retries=$((retries - 1))
        sleep 2
    done
    warn "Netdata not responding after 30s — may still be starting."
    warn "Check: docker logs ${NETDATA_CONTAINER}"
}

# -----------------------------------------------------------------------------
# Launch nginx proxy
# -----------------------------------------------------------------------------
launch_proxy() {
    step "Pulling nginx image..."
    docker pull "${NGINX_IMAGE}"

    step "Launching proxy on port ${DEFAULT_PORT}..."

    local -a cmd=(
        docker run -d
        --name "${PROXY_CONTAINER}"
        --restart unless-stopped
        --network=host
        -v "${NGINX_CONF}:/etc/nginx/nginx.conf:ro"
    )

    if [ -f "${HTPASSWD_FILE}" ]; then
        cmd+=(-v "${HTPASSWD_FILE}:/etc/nginx/.htpasswd:ro")
    fi

    cmd+=("${NGINX_IMAGE}")

    if "${cmd[@]}"; then
        info "Proxy started."
    else
        err "Proxy failed. Check: docker logs ${PROXY_CONTAINER}"
        exit 1
    fi

    # Verify
    step "Verifying proxy..."
    local retries=10
    while [ $retries -gt 0 ]; do
        local code
        code=$(curl -sf -o /dev/null -w "%{http_code}" "http://127.0.0.1:${DEFAULT_PORT}/" 2>/dev/null || echo "000")
        if [ "${code}" = "401" ] || [ "${code}" = "200" ]; then
            if [ "${code}" = "401" ]; then
                info "Proxy verified — returns 401 (login required). Auth is working."
            else
                info "Proxy verified — returns 200 (open access)."
            fi
            return 0
        fi
        retries=$((retries - 1))
        sleep 1
    done
    warn "Proxy not responding. Check: docker logs ${PROXY_CONTAINER}"
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
    local port="${DEFAULT_PORT}"
    local action="launch"
    local nologin=false

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --port)            port="$2"; DEFAULT_PORT="$2"; shift 2 ;;
            --nologin)         nologin=true; shift ;;
            --stop)            action="stop"; shift ;;
            --status)          action="status"; shift ;;
            --reset-password)  action="reset-pw"; shift ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo ""
                echo "  --nologin          No login required (open access)"
                echo "  --port PORT        Public port (default: ${DEFAULT_PORT})"
                echo "  --stop             Stop and remove containers"
                echo "  --status           Show status"
                echo "  --reset-password   Change stored password"
                exit 0
                ;;
            *) err "Unknown option: $1"; exit 1 ;;
        esac
    done

    case "${action}" in
        stop)     do_stop; exit 0 ;;
        status)   do_status; exit 0 ;;
        reset-pw)
            setup_config
            create_password
            if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${PROXY_CONTAINER}$"; then
                docker restart "${PROXY_CONTAINER}" >/dev/null
                info "Proxy restarted with new credentials."
            fi
            exit 0
            ;;
    esac

    # ── Launch ──
    echo ""
    echo -e "${BOLD}${B}  Nosana WebUI — Netdata Launcher${NC}"
    echo ""

    check_docker
    setup_config
    cleanup_stale

    if [ "${nologin}" = true ]; then
        # ── NOLOGIN MODE ──
        info "Mode: anonymous (no login required)"
        echo ""

        # Netdata on internal port, nginx proxies openly on public port
        launch_netdata "127.0.0.1" "${NETDATA_INTERNAL_PORT}"
        generate_nginx_conf "open"
        launch_proxy
    else
        # ── SECURE MODE ──
        info "Mode: login required"

        setup_password

        # Netdata on localhost only, nginx adds auth on public port
        launch_netdata "127.0.0.1" "${NETDATA_INTERNAL_PORT}"
        generate_nginx_conf "secure"
        launch_proxy

        # Block direct access to Netdata's internal port
        open_firewall "${port}"
    fi

    # ── Summary ──
    local ip
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')

    echo ""
    echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
    echo -e "  ${G}${BOLD}Nosana WebUI is running!${NC}"
    echo ""
    echo -e "  ${BOLD}Local:${NC}    ${C}http://localhost:${port}${NC}"
    if [ -n "${ip:-}" ]; then
        echo -e "  ${BOLD}Network:${NC}  ${C}http://${ip}:${port}${NC}"
    fi
    echo ""

    if [ "${nologin}" = true ]; then
        echo -e "  ${BOLD}Mode:${NC}     Anonymous (open access)"
    else
        local cred_user
        cred_user=$(head -1 "${HTPASSWD_FILE}" | cut -d: -f1)
        echo -e "  ${BOLD}Mode:${NC}     Login required"
        echo -e "  ${BOLD}User:${NC}     ${G}${cred_user}${NC}"
        echo -e "  ${BOLD}Pass:${NC}     (your OS password — stored in ${PASSWORD_FILE})"
    fi

    echo ""
    echo -e "  ${BOLD}Config:${NC}   ${CONFIG_DIR}/"
    echo -e "  ${BOLD}Stop:${NC}     $0 --stop"
    echo -e "  ${BOLD}Status:${NC}   $0 --status"
    echo -e "  ${BOLD}Update:${NC}   Re-run this script (pulls latest images)"
    echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
    echo ""
}

main "$@"
