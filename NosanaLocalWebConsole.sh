#!/usr/bin/env bash
# Usage: bash <(wget -qO- https://raw.githubusercontent.com/MachoDrone/NosanaLocalWebConsole/refs/heads/main/NosanaLocalWebConsole.sh)
echo "v0.01.00"
sleep 2
# =============================================================================
# Nosana WebUI — Netdata Launcher
#
# Deploys Netdata in Docker with full host monitoring + NVIDIA GPU support.
# By default, access requires login (nginx reverse proxy with basic auth).
# Use --nologin for anonymous open access.
#
# Persistent config in ~/.nosana-webui/ survives container restarts/purges.
#
# Usage:
#   bash <(wget -qO- https://raw.githubusercontent.com/.../NosanaLocalWebConsole.sh)
#   ... --nologin           # no login required, open access
#   ... --port PORT         # change public port (default: 19999)
#   ... --stop              # stop and remove containers
#   ... --status            # show status
#   ... --reset-password    # set a new password
#
# Tested on: Ubuntu 20.04 – 24.04 (Desktop, Server, Minimal, Core)
# Requires:  Docker (already present on Nosana hosts)
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
NETDATA_INTERNAL_PORT=19998  # Netdata listens here, only on localhost
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
# Persistent config directory
# -----------------------------------------------------------------------------
setup_config() {
    mkdir -p "${CONFIG_DIR}/custom-tabs"
    mkdir -p "${CONFIG_DIR}/overrides"

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
# Authentication setup
# -----------------------------------------------------------------------------
setup_password() {
    # If credentials already exist, reuse them
    if [ -f "${HTPASSWD_FILE}" ] && [ -f "${PASSWORD_FILE}" ]; then
        local existing_pass
        existing_pass=$(cat "${PASSWORD_FILE}")
        local existing_user
        existing_user=$(head -1 "${HTPASSWD_FILE}" | cut -d: -f1)
        echo ""
        echo -e "  ${BOLD}Existing credentials found:${NC}"
        echo -e "    User: ${G}${existing_user}${NC}"
        echo -e "    Pass: ${G}${existing_pass}${NC}"
        echo -e "    (Use --reset-password to change)"
        echo ""
        return 0
    fi

    create_password
}

create_password() {
    echo ""
    echo -e "${BOLD}  Set up WebUI login credentials${NC}"
    echo ""

    # Get username — default to current OS username
    local default_user
    default_user=$(whoami)
    read -rp "  Username [${default_user}]: " input_user
    local auth_user="${input_user:-${default_user}}"

    # Get password — prompt interactively or generate
    local auth_pass=""
    echo ""
    echo "  Choose password option:"
    echo "    1) Type a password"
    echo "    2) Auto-generate a secure password"
    echo ""
    read -rp "  Choice [1/2]: " pass_choice

    case "${pass_choice}" in
        2)
            auth_pass=$(openssl rand -hex 12 2>/dev/null || head -c 24 /dev/urandom | base64 | tr -dc 'a-zA-Z0-9' | head -c 24)
            echo ""
            echo -e "  Generated password: ${G}${auth_pass}${NC}"
            ;;
        *)
            echo ""
            while [ -z "${auth_pass}" ]; do
                read -rsp "  Enter password: " auth_pass
                echo ""
                if [ -z "${auth_pass}" ]; then
                    warn "Password cannot be empty."
                fi
            done
            # Confirm
            local confirm_pass=""
            read -rsp "  Confirm password: " confirm_pass
            echo ""
            if [ "${auth_pass}" != "${confirm_pass}" ]; then
                err "Passwords don't match. Try again."
                create_password
                return
            fi
            ;;
    esac

    # Generate htpasswd using openssl (available on all Ubuntu variants)
    # Format: user:$apr1$salt$hash
    local hashed
    hashed=$(openssl passwd -apr1 "${auth_pass}")
    echo "${auth_user}:${hashed}" > "${HTPASSWD_FILE}"
    echo -n "${auth_pass}" > "${PASSWORD_FILE}"
    chmod 600 "${HTPASSWD_FILE}" "${PASSWORD_FILE}"

    echo ""
    echo -e "  ${BOLD}Credentials saved:${NC}"
    echo -e "    User: ${G}${auth_user}${NC}"
    echo -e "    Pass: ${G}${auth_pass}${NC}"
    echo -e "    Stored in: ${PASSWORD_FILE}"
    echo ""
    info "Credentials configured."
}

# -----------------------------------------------------------------------------
# Nginx config generation
# -----------------------------------------------------------------------------
generate_nginx_conf_secure() {
    local upstream_port="$1"
    cat > "${NGINX_CONF}" << NGINXEOF
worker_processes 1;
events { worker_connections 128; }

http {
    # Upstream: Netdata on localhost
    upstream netdata {
        server 127.0.0.1:${upstream_port};
        keepalive 64;
    }

    server {
        listen 19999;

        # Basic auth — nothing visible until authenticated
        auth_basic "Nosana WebUI";
        auth_basic_user_file /etc/nginx/.htpasswd;

        location / {
            proxy_pass http://netdata;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;

            # WebSocket support (Netdata uses these for live charts)
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection "upgrade";

            # Timeouts for long-polling / streaming
            proxy_connect_timeout 60s;
            proxy_read_timeout 300s;
            proxy_send_timeout 300s;
        }
    }
}
NGINXEOF
}

generate_nginx_conf_open() {
    local upstream_port="$1"
    cat > "${NGINX_CONF}" << NGINXEOF
worker_processes 1;
events { worker_connections 128; }

http {
    upstream netdata {
        server 127.0.0.1:${upstream_port};
        keepalive 64;
    }

    server {
        listen 19999;

        # No auth — open access
        location / {
            proxy_pass http://netdata;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
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
# Firewall helper
# -----------------------------------------------------------------------------
open_firewall() {
    local port="$1"
    if command -v ufw >/dev/null 2>&1; then
        if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
            step "UFW active — opening port ${port}/tcp..."
            sudo ufw allow "${port}"/tcp comment "Nosana WebUI" >/dev/null 2>&1 && \
                info "Port ${port} opened in UFW." || \
                warn "Could not open UFW port. Run manually: sudo ufw allow ${port}/tcp"
        fi
    fi
}

# -----------------------------------------------------------------------------
# Stop / Status
# -----------------------------------------------------------------------------
do_stop() {
    step "Stopping Nosana WebUI containers..."
    for c in "${PROXY_CONTAINER}" "${NETDATA_CONTAINER}"; do
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

    # Docker
    if docker info &>/dev/null 2>&1; then
        echo -e "  Docker:    ${G}running${NC}"
    else
        echo -e "  Docker:    ${R}not running${NC}"
    fi

    # GPU
    if check_gpu; then
        local gpu_name
        gpu_name=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1)
        echo -e "  GPU:       ${G}${gpu_name}${NC}"
    else
        echo -e "  GPU:       ${Y}not detected${NC}"
    fi

    # Netdata container
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${NETDATA_CONTAINER}$"; then
        echo -e "  Netdata:   ${G}running${NC}"
    elif docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${NETDATA_CONTAINER}$"; then
        echo -e "  Netdata:   ${Y}stopped${NC}"
    else
        echo -e "  Netdata:   ${R}not deployed${NC}"
    fi

    # Proxy container
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${PROXY_CONTAINER}$"; then
        echo -e "  Proxy:     ${G}running${NC} (auth enabled)"
    elif docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${PROXY_CONTAINER}$"; then
        echo -e "  Proxy:     ${Y}stopped${NC}"
    else
        echo -e "  Proxy:     not deployed (nologin mode or not started)"
    fi

    # Access URL
    local port="${DEFAULT_PORT}"
    local ip
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
    echo ""
    echo -e "  URL:       http://${ip:-localhost}:${port}"
    echo -e "  Config:    ${CONFIG_DIR}"
    echo ""
}

# -----------------------------------------------------------------------------
# Launch Netdata
# -----------------------------------------------------------------------------
launch_netdata() {
    local listen_addr="$1"  # 127.0.0.1 (behind proxy) or 0.0.0.0 (open)
    local listen_port="$2"

    # Remove old instance
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${NETDATA_CONTAINER}$"; then
        docker stop "${NETDATA_CONTAINER}" 2>/dev/null || true
        docker rm "${NETDATA_CONTAINER}" 2>/dev/null || true
    fi

    step "Pulling latest Netdata image..."
    docker pull "${NETDATA_IMAGE}"

    # Write Netdata bind config so it listens where we tell it
    mkdir -p "${CONFIG_DIR}/overrides"
    cat > "${CONFIG_DIR}/overrides/nosana-bind.conf" << EOF
[web]
    bind to = ${listen_addr}:${listen_port}
EOF

    step "Launching Netdata (listening on ${listen_addr}:${listen_port})..."

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

        # Host filesystem (read-only) for real host monitoring
        -v /proc:/host/proc:ro
        -v /sys:/host/sys:ro
        -v /etc/os-release:/host/etc/os-release:ro
        -v /etc/passwd:/host/etc/passwd:ro
        -v /etc/group:/host/etc/group:ro
        -v /var/log:/host/var/log:ro
        -v /etc/localtime:/etc/localtime:ro

        # Docker socket — lets Netdata see other containers
        -v /var/run/docker.sock:/var/run/docker.sock:ro

        # Persistent Netdata storage
        -v netdata-config:/etc/netdata
        -v netdata-lib:/var/lib/netdata
        -v netdata-cache:/var/cache/netdata

        # Our config overrides (bind address, etc)
        -v "${CONFIG_DIR}/overrides:/etc/netdata/netdata.conf.d:ro"

        # Nosana WebUI shared config
        -v "${CONFIG_DIR}:/nosana-webui:rw"
    )

    # GPU support
    if check_nvidia_runtime; then
        info "NVIDIA container runtime detected — enabling --gpus all"
        cmd+=(--gpus all)
    elif check_gpu; then
        warn "GPU found but nvidia-container-toolkit not installed."
        warn "Attempting direct device mount as fallback."
        for dev in /dev/nvidia0 /dev/nvidiactl /dev/nvidia-uvm /dev/nvidia-uvm-tools; do
            [ -e "$dev" ] && cmd+=(--device "${dev}:${dev}")
        done
        local smi_path
        smi_path=$(command -v nvidia-smi 2>/dev/null || true)
        if [ -n "$smi_path" ]; then
            cmd+=(-v "${smi_path}:${smi_path}:ro")
        fi
    else
        warn "No NVIDIA GPU detected. GPU monitoring unavailable."
    fi

    cmd+=("${NETDATA_IMAGE}")

    if "${cmd[@]}"; then
        info "Netdata container started."
    else
        err "Failed to start Netdata. Check: docker logs ${NETDATA_CONTAINER}"
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# Launch nginx auth proxy
# -----------------------------------------------------------------------------
launch_proxy() {
    local public_port="$1"

    # Remove old instance
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${PROXY_CONTAINER}$"; then
        docker stop "${PROXY_CONTAINER}" 2>/dev/null || true
        docker rm "${PROXY_CONTAINER}" 2>/dev/null || true
    fi

    step "Pulling nginx image..."
    docker pull "${NGINX_IMAGE}"

    step "Launching auth proxy on port ${public_port}..."

    local -a cmd=(
        docker run -d
        --name "${PROXY_CONTAINER}"
        --restart unless-stopped
        --network=host

        # Nginx config and htpasswd
        -v "${NGINX_CONF}:/etc/nginx/nginx.conf:ro"
        -v "${HTPASSWD_FILE}:/etc/nginx/.htpasswd:ro"
    )

    cmd+=("${NGINX_IMAGE}")

    if "${cmd[@]}"; then
        info "Auth proxy started."
    else
        err "Failed to start proxy. Check: docker logs ${PROXY_CONTAINER}"
        exit 1
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
            --port)            port="$2"; shift 2 ;;
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
                echo "  --reset-password   Change login credentials"
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
            # Restart proxy if running to pick up new credentials
            if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${PROXY_CONTAINER}$"; then
                docker restart "${PROXY_CONTAINER}"
                info "Proxy restarted with new credentials."
            fi
            exit 0
            ;;
    esac

    # ── Launch flow ──
    echo ""
    echo -e "${BOLD}${B}  Nosana WebUI — Netdata Launcher${NC}"
    echo ""

    check_docker
    setup_config

    if [ "${nologin}" = true ]; then
        # ── NOLOGIN MODE ──
        # Netdata listens directly on all interfaces, no proxy needed
        info "Mode: anonymous (no login required)"
        echo ""

        launch_netdata "0.0.0.0" "${port}"

        # Stop proxy if it was previously running
        if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${PROXY_CONTAINER}$"; then
            docker stop "${PROXY_CONTAINER}" 2>/dev/null || true
            docker rm "${PROXY_CONTAINER}" 2>/dev/null || true
            info "Removed auth proxy (not needed in nologin mode)."
        fi
    else
        # ── SECURE MODE ──
        # Netdata listens on localhost only, nginx proxy handles auth
        info "Mode: login required"

        setup_password

        # Netdata on localhost only (not reachable from network directly)
        launch_netdata "127.0.0.1" "${NETDATA_INTERNAL_PORT}"

        # Generate nginx config pointing to Netdata's internal port
        generate_nginx_conf_secure "${NETDATA_INTERNAL_PORT}"

        # Launch nginx proxy on the public port
        launch_proxy "${port}"
    fi

    # ── Firewall ──
    open_firewall "${port}"

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
        local cred_pass
        cred_pass=$(cat "${PASSWORD_FILE}")
        echo -e "  ${BOLD}Mode:${NC}     Login required"
        echo -e "  ${BOLD}User:${NC}     ${G}${cred_user}${NC}"
        echo -e "  ${BOLD}Pass:${NC}     ${G}${cred_pass}${NC}"
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
