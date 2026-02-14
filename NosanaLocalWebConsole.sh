#!/usr/bin/env bash
# Usage: bash <(wget -qO- https://raw.githubusercontent.com/MachoDrone/NosanaLocalWebConsole/refs/heads/main/NosanaLocalWebConsole.sh)
echo "v0.00.02" #increment with each edit
sleep 2

# =============================================================================
# Nosana WebUI — Netdata Launcher
#
# Deploys Netdata in Docker with full host monitoring + NVIDIA GPU support.
# Persistent config survives container restarts and purges.
#
# Usage (always use this):
#   bash <(wget -qO- https://raw.githubusercontent.com/MachoDrone/NosanaLocalWebConsole/refs/heads/main/NosanaLocalWebConsole.sh)
#
# Tested on: Ubuntu 20.04 – 24.04 (Desktop, Server, Minimal, Core)
# Requires: Docker (already present on Nosana hosts)
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
CONTAINER_NAME="nosana-webui"
CONFIG_DIR="${HOME}/.nosana-webui"
NETDATA_IMAGE="netdata/netdata:stable"
DEFAULT_PORT=19999

# Terminal colors
if [ -t 1 ]; then
    R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' B='\033[0;34m'
    C='\033[0;36m' BOLD='\033[1m' NC='\033[0m'
else
    R='' G='' Y='' B='' C='' BOLD='' NC=''
fi
info() { echo -e "${G}[OK]${NC}    $*"; }
warn() { echo -e "${Y}[WARN]${NC}  $*"; }
err()  { echo -e "${R}[ERR]${NC}   $*"; }
step() { echo -e "${C}[....]${NC}  $*"; }

# -----------------------------------------------------------------------------
# Checks
# -----------------------------------------------------------------------------
check_docker() {
    if ! command -v docker &>/dev/null; then
        err "Docker not found."
        echo "  Nosana hosts should already have Docker installed."
        echo "  If this is a fresh machine, set up Nosana first:"
        echo "  https://learn.nosana.com/hosts/grid-ubuntu"
        exit 1
    fi
    if ! docker info &>/dev/null 2>&1; then
        err "Docker is installed but not running, or current user lacks permission."
        echo "  Try: sudo systemctl start docker"
        echo "  Or:  sudo usermod -aG docker \$USER (then log out and back in)"
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
# Persistent config + Netdata bind override
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
        { "label": "Memory",             "command": "free -h" },
        { "label": "Top Processes",       "command": "ps aux --sort=-%mem | head -20" }
    ]
}
EOF
        info "Created config at ${CONFIG_DIR}/config.json"
    fi

    # Force Netdata to listen on all interfaces (fixes the localhost-only bind issue)
    if [ ! -f "${CONFIG_DIR}/overrides/bind.conf" ]; then
        cat > "${CONFIG_DIR}/overrides/bind.conf" << 'EOF'
[web]
    bind to = 0.0.0.0
    bind to = [::]
EOF
        info "Created Netdata all-interfaces bind override"
    fi
}

# -----------------------------------------------------------------------------
# Firewall helper (auto-opens if UFW is active)
# -----------------------------------------------------------------------------
open_firewall() {
    local port="$1"
    if command -v ufw >/dev/null 2>&1; then
        if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
            step "UFW active — opening port ${port}/tcp..."
            sudo ufw allow "${port}"/tcp comment "Nosana WebUI (Netdata)" >/dev/null && \
            sudo ufw reload >/dev/null && \
            info "Port ${port} opened in UFW." || \
            warn "UFW allow failed — run manually if needed: sudo ufw allow ${port}/tcp"
        else
            info "UFW installed but inactive — skipping (no firewall blocking)."
        fi
    else
        warn "No UFW detected. If network access fails, open port ${port} manually."
    fi
}

# -----------------------------------------------------------------------------
# Stop / Status
# -----------------------------------------------------------------------------
do_stop() { ... }  # unchanged from your original
do_status() { ... }  # unchanged from your original

# -----------------------------------------------------------------------------
# Launch
# -----------------------------------------------------------------------------
do_launch() {
    local port="$1"

    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER_NAME}$"; then
        step "Removing previous instance..."
        docker stop "${CONTAINER_NAME}" 2>/dev/null || true
        docker rm "${CONTAINER_NAME}" 2>/dev/null || true
    fi

    step "Pulling latest Netdata image..."
    docker pull "${NETDATA_IMAGE}"

    step "Launching Netdata on port ${port}..."

    local -a cmd=(
        docker run -d
        --name "${CONTAINER_NAME}"
        --hostname "nosana-$(hostname)"
        --restart unless-stopped
        --pid=host
        --network=host
        --cap-add SYS_PTRACE
        --cap-add SYS_ADMIN
        --security-opt apparmor=unconfined
        -v /proc:/host/proc:ro
        -v /sys:/host/sys:ro
        -v /etc/os-release:/host/etc/os-release:ro
        -v /etc/passwd:/host/etc/passwd:ro
        -v /etc/group:/host/etc/group:ro
        -v /var/log:/host/var/log:ro
        -v /etc/localtime:/etc/localtime:ro
        -v /var/run/docker.sock:/var/run/docker.sock:ro
        -v netdata-config:/etc/netdata
        -v netdata-lib:/var/lib/netdata
        -v netdata-cache:/var/cache/netdata
        -v "${CONFIG_DIR}:/nosana-webui:rw"
        # Netdata bind override (so it listens on your LAN IP, not just localhost)
        -v "${CONFIG_DIR}/overrides:/etc/netdata/netdata.conf.d:ro"
    )

    # GPU support (unchanged)
    if check_nvidia_runtime; then
        info "NVIDIA container runtime detected — enabling --gpus all"
        cmd+=(--gpus all)
    elif check_gpu; then
        warn "GPU found but nvidia-container-toolkit missing."
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
        echo ""
        echo -e "${BOLD}════════════════════════════════════════════════════${NC}"
        echo -e "  ${G}${BOLD}Netdata is running!${NC}"
        echo ""
        echo -e "  ${BOLD}Local:${NC}     http://localhost:${port}"
        echo -e "  ${BOLD}Network:${NC}   http://$(hostname -I | awk '{print $1}'):${port}"
        echo ""
        open_firewall "${port}"
        echo -e "  ${BOLD}Config:${NC}    ${CONFIG_DIR}/"
        echo -e "  ${BOLD}Stop:${NC}      $0 --stop"
        echo -e "  ${BOLD}Status:${NC}    $0 --status"
        echo -e "  ${BOLD}Update:${NC}    Re-run this one-liner"
        echo -e "${BOLD}════════════════════════════════════════════════════${NC}"
        echo ""
    else
        err "Failed to start container. Check: docker logs ${CONTAINER_NAME}"
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# Main (unchanged)
# -----------------------------------------------------------------------------
main() {
    local port="${DEFAULT_PORT}"
    local action="launch"
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --port) port="$2"; shift 2 ;;
            --stop) action="stop"; shift ;;
            --status) action="status"; shift ;;
            --help|-h)
                echo "Usage: $0 [--port PORT] [--stop] [--status] [--help]"
                exit 0
                ;;
            *) err "Unknown option: $1"; exit 1 ;;
        esac
    done

    case "${action}" in
        stop) do_stop; exit 0 ;;
        status) do_status; exit 0 ;;
    esac

    echo ""
    echo -e "${BOLD}${B}  Nosana WebUI — Netdata Launcher${NC}"
    echo ""

    check_docker
    setup_config
    do_launch "${port}"
}

main "$@"
