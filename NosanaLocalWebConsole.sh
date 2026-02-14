#!/usr/bin/env bash
# Usage: bash <(wget -qO- https://raw.githubusercontent.com/MachoDrone/NosanaLocalWebConsole/refs/heads/main/NosanaLocalWebConsole.sh)
echo "v0.01.4"
sleep 3
# =============================================================================
# Nosana WebUI — Netdata Launcher
#
# Deploys Netdata in Docker with full host monitoring + NVIDIA GPU support.
# Default: login required (nginx basic auth). Use --nologin for open access.
#
# Auth: your OS username + password you set at first run.
# Config in ~/.nosana-webui/ survives container restarts/purges.
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
AUTH_VERSION_FILE="${CONFIG_DIR}/.auth_version"
NGINX_CONF="${CONFIG_DIR}/nginx.conf"
AUTH_VERSION="2"

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
# Cleanup stale state
# -----------------------------------------------------------------------------
cleanup_stale() {
    for c in "${PROXY_CONTAINER}" "${NETDATA_CONTAINER}" "nosana-webui"; do
        if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${c}$"; then
            step "Removing old container: ${c}"
            docker stop "${c}" 2>/dev/null || true
            docker rm "${c}" 2>/dev/null || true
        fi
    done
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
# Authentication
# -----------------------------------------------------------------------------
credentials_are_current() {
    [ -f "${HTPASSWD_FILE}" ] && \
    [ -f "${PASSWORD_FILE}" ] && \
    [ -f "${AUTH_VERSION_FILE}" ] && \
    [ "$(cat "${AUTH_VERSION_FILE}" 2>/dev/null)" = "${AUTH_VERSION}" ]
}

setup_password() {
    if credentials_are_current; then
        local existing_user
        existing_user=$(head -1 "${HTPASSWD_FILE}" | cut -d: -f1)
        echo ""
        echo -e "  ${BOLD}Existing credentials:${NC}"
        echo -e "    User: ${G}${existing_user}${NC}"
        echo -e "    Pass: (stored in ${PASSWORD_FILE})"
        echo -e "    Use --reset-password to change."
        echo ""
        return 0
    fi

    if [ -f "${HTPASSWD_FILE}" ] || [ -f "${PASSWORD_FILE}" ]; then
        warn "Old credentials from a previous version detected — resetting."
        rm -f "${HTPASSWD_FILE}" "${PASSWORD_FILE}" "${AUTH_VERSION_FILE}"
    fi

    create_password
}

create_password() {
    echo ""
    echo -e "${BOLD}  Set up WebUI login${NC}"
    echo ""

    local default_user
    default_user=$(whoami)
    read -rp "  Username [${default_user}]: " input_user
    local auth_user="${input_user:-${default_user}}"

    echo ""
    echo "  Enter the password you want for the WebUI."
    echo "  (Tip: use your Ubuntu login password so you don't forget it.)"
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

    local hashed
    hashed=$(openssl passwd -apr1 "${auth_pass}")
    echo "${auth_user}:${hashed}" > "${HTPASSWD_FILE}"
    echo -n "${auth_pass}" > "${PASSWORD_FILE}"
    echo -n "${AUTH_VERSION}" > "${AUTH_VERSION_FILE}"
    chmod 644 "${HTPASSWD_FILE}"
    chmod 600 "${PASSWORD_FILE}" "${AUTH_VERSION_FILE}"

    echo ""
    info "Credentials saved for user: ${auth_user}"
    echo ""
}

# -----------------------------------------------------------------------------
# Nginx config — based on Netdata official documentation
# https://learn.netdata.cloud/docs/netdata-agent/configuration/securing-agents/running-the-agent-behind-a-reverse-proxy/nginx
# -----------------------------------------------------------------------------
generate_nginx_conf() {
    cat > "${NGINX_CONF}" << NGINXEOF
worker_processes 1;
error_log /var/log/nginx/error.log warn;
pid /tmp/nginx.pid;

events { worker_connections 256; }

http {
    # Upstream definition — matches Netdata official nginx docs
    upstream netdata {
        server 127.0.0.1:${NETDATA_INTERNAL_PORT};
        keepalive 1024;
    }

    server {
        listen ${DEFAULT_PORT};

        # Basic auth — nothing visible until you log in
        auth_basic "Nosana WebUI";
        auth_basic_user_file /etc/nginx/.htpasswd;

        location / {
            # Headers per Netdata official nginx proxy documentation
            proxy_set_header X-Forwarded-Host \$host;
            proxy_set_header X-Forwarded-Server \$host;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_pass http://netdata;
            proxy_http_version 1.1;
            proxy_pass_request_headers on;
            proxy_set_header Connection "keep-alive";
            proxy_store off;

            # Netdata compresses responses by default.
            # Let it pass through to the browser as-is.
            gzip on;
            gzip_proxied any;
            gzip_types *;
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
            step "UFW: allowing ${public_port}, blocking ${NETDATA_INTERNAL_PORT}..."
            sudo ufw allow "${public_port}"/tcp comment "Nosana WebUI" >/dev/null 2>&1 || true
            sudo ufw deny "${NETDATA_INTERNAL_PORT}"/tcp comment "Nosana internal" >/dev/null 2>&1 || true
            sudo ufw reload >/dev/null 2>&1 || true
            info "UFW configured."
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
    local port_mapping="$1"

    step "Pulling latest Netdata image..."
    docker pull "${NETDATA_IMAGE}"

    step "Launching Netdata..."

    local -a cmd=(
        docker run -d
        --name "${NETDATA_CONTAINER}"
        --hostname "nosana-$(hostname)"
        --restart unless-stopped
        --pid=host
        --cap-add SYS_PTRACE
        --cap-add SYS_ADMIN
        --security-opt apparmor=unconfined

        # Port mapping controls access (Docker-enforced, not config-dependent)
        -p "${port_mapping}"

        # Host filesystem (read-only) for real host monitoring
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

    cmd+=("${NETDATA_IMAGE}")

    if "${cmd[@]}"; then
        info "Netdata container started."
    else
        err "Netdata failed. Check: docker logs ${NETDATA_CONTAINER}"
        exit 1
    fi

    # Wait for Netdata to be ready
    step "Waiting for Netdata to initialize..."
    local check_port
    if [[ "${port_mapping}" == 127.0.0.1:* ]]; then
        check_port="${NETDATA_INTERNAL_PORT}"
    else
        check_port="${DEFAULT_PORT}"
    fi

    local retries=20
    while [ $retries -gt 0 ]; do
        if curl -sf "http://127.0.0.1:${check_port}/api/v1/info" >/dev/null 2>&1; then
            info "Netdata responding on port ${check_port}"
            return 0
        fi
        retries=$((retries - 1))
        sleep 2
    done

    warn "Netdata not responding after 40s."
    local status
    status=$(docker inspect -f '{{.State.Status}}' "${NETDATA_CONTAINER}" 2>/dev/null || echo "unknown")
    echo "  Container status: ${status}"
    if [ "${status}" = "running" ]; then
        echo "  Last 10 log lines:"
        docker logs --tail 10 "${NETDATA_CONTAINER}" 2>&1 | sed 's/^/    /'
    fi
    echo ""
    warn "Continuing — Netdata may need more time on first start."
}

# -----------------------------------------------------------------------------
# Launch nginx auth proxy
# -----------------------------------------------------------------------------
launch_proxy() {
    step "Pulling nginx image..."
    docker pull "${NGINX_IMAGE}"

    step "Launching auth proxy on port ${DEFAULT_PORT}..."

    # Nginx uses --network=host so it can reach Netdata on 127.0.0.1
    local -a cmd=(
        docker run -d
        --name "${PROXY_CONTAINER}"
        --restart unless-stopped
        --network=host
        -v "${NGINX_CONF}:/etc/nginx/nginx.conf:ro"
        -v "${HTPASSWD_FILE}:/etc/nginx/.htpasswd:ro"
    )

    cmd+=("${NGINX_IMAGE}")

    if "${cmd[@]}"; then
        info "Proxy started."
    else
        err "Proxy failed. Check: docker logs ${PROXY_CONTAINER}"
        exit 1
    fi

    # Verify
    step "Verifying auth proxy..."
    sleep 2
    local retries=10
    while [ $retries -gt 0 ]; do
        local code
        code=$(curl -sf -o /dev/null -w "%{http_code}" "http://127.0.0.1:${DEFAULT_PORT}/" 2>/dev/null || echo "000")
        if [ "${code}" = "401" ]; then
            info "Auth working — browser will prompt for username/password."
            return 0
        elif [ "${code}" = "200" ] || [ "${code}" = "302" ]; then
            # This shouldn't happen in secure mode, but Netdata may redirect
            info "Proxy responding (HTTP ${code})."
            return 0
        fi
        retries=$((retries - 1))
        sleep 1
    done

    # Even if verification times out, check if nginx is actually running
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${PROXY_CONTAINER}$"; then
        info "Proxy container is running. It may need a moment to fully start."
        echo "  Check manually: curl -I http://127.0.0.1:${DEFAULT_PORT}/"
    else
        warn "Proxy container is not running. Check: docker logs ${PROXY_CONTAINER}"
    fi
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
            rm -f "${HTPASSWD_FILE}" "${PASSWORD_FILE}" "${AUTH_VERSION_FILE}"
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
        # ══════════════════════════════════════
        # NOLOGIN MODE — Netdata open on network
        # ══════════════════════════════════════
        info "Mode: anonymous (no login required)"
        echo ""

        # Netdata directly on all interfaces, no proxy
        launch_netdata "0.0.0.0:${port}:19999"
    else
        # ══════════════════════════════════════
        # SECURE MODE — Netdata behind auth proxy
        # ══════════════════════════════════════
        info "Mode: login required"

        setup_password

        # Netdata on localhost only (Docker port mapping enforces this)
        launch_netdata "127.0.0.1:${NETDATA_INTERNAL_PORT}:19999"

        # Nginx with basic auth, using Netdata's official proxy config
        generate_nginx_conf
        launch_proxy

        # Firewall
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
        echo -e "  ${BOLD}Pass:${NC}     (your password — stored in ${PASSWORD_FILE})"
    fi

    echo ""
    echo -e "  ${BOLD}Config:${NC}   ${CONFIG_DIR}/"
    echo -e "  ${BOLD}Stop:${NC}     $0 --stop"
    echo -e "  ${BOLD}Status:${NC}   $0 --status"
    echo -e "  ${BOLD}Update:${NC}   Re-run this script (pulls latest images)"
    echo ""
    echo -e "  ${Y}Note:${NC} Clear your browser cache or use private browsing"
    echo -e "  if you see stale errors from previous attempts."
    echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
    echo ""
}

main "$@"
