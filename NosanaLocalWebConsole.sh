#!/usr/bin/env bash
# attempt use: bash <(wget -qO- https://raw.githubusercontent.com/MachoDrone/NosanaLocalWebConsole/refs/heads/main/NosanaLocalWebConsole.sh)
echo "v0.00.01" #increment with each edit
sleep 3 #slight pause to focus on updates while testing
# =============================================================================
# Nosana WebUI — Netdata Launcher
#
# Deploys Netdata in Docker with full host monitoring + NVIDIA GPU support.
# Persistent config survives container restarts and purges.
#
# Usage:
#   wget -qO- https://raw.githubusercontent.com/YOUR_ORG/nosana-webui/main/start.sh | bash
#   curl -sSL https://raw.githubusercontent.com/YOUR_ORG/nosana-webui/main/start.sh | bash
#   ./start.sh [--port 19999] [--stop] [--status] [--help]
#
# Tested on: Ubuntu 20.04 – 24.04 (Desktop, Server, Minimal, Core)
# Requires:  Docker (already present on Nosana hosts)
# =============================================================================

set -euo pipefail

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
CONTAINER_NAME="nosana-webui"
CONFIG_DIR="${HOME}/.nosana-webui"
NETDATA_IMAGE="netdata/netdata:stable"
DEFAULT_PORT=19999

# Terminal colors (graceful fallback for non-interactive shells)
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
        echo "  If this is a fresh machine, set up Nosana first:"
        echo "  https://learn.nosana.com/hosts/grid-ubuntu"
        exit 1
    fi
    if ! docker info &>/dev/null 2>&1; then
        err "Docker is installed but not running, or current user lacks permission."
        echo "  Try: sudo systemctl start docker"
        echo "  Or:  sudo usermod -aG docker \$USER  (then log out and back in)"
        exit 1
    fi
}

check_gpu() {
    # Returns 0 if nvidia-smi works on the host
    command -v nvidia-smi &>/dev/null && nvidia-smi &>/dev/null 2>&1
}

check_nvidia_runtime() {
    # Returns 0 if Docker can use --gpus
    docker info 2>/dev/null | grep -qi "nvidia" || \
    command -v nvidia-container-toolkit &>/dev/null || \
    [ -f /usr/bin/nvidia-container-runtime ]
}

# -----------------------------------------------------------------------------
# Persistent config directory (survives container death)
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
}

# -----------------------------------------------------------------------------
# Stop / Status
# -----------------------------------------------------------------------------
do_stop() {
    step "Stopping ${CONTAINER_NAME}..."
    docker stop "${CONTAINER_NAME}" 2>/dev/null && info "Stopped." || true
    docker rm "${CONTAINER_NAME}" 2>/dev/null && info "Removed." || true
    echo ""
    info "Config preserved at ${CONFIG_DIR}"
    info "Re-run this script to relaunch."
}

do_status() {
    echo -e "${BOLD}Nosana WebUI Status${NC}"
    echo "──────────────────────────────────────"

    # Runtime
    if docker info &>/dev/null 2>&1; then
        echo -e "  Docker:     ${G}running${NC}"
    else
        echo -e "  Docker:     ${R}not running${NC}"
    fi

    # GPU
    if check_gpu; then
        local gpu_name
        gpu_name=$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1)
        echo -e "  GPU:        ${G}${gpu_name}${NC}"
    else
        echo -e "  GPU:        ${Y}not detected${NC}"
    fi

    # Container
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER_NAME}$"; then
        local port
        port=$(docker port "${CONTAINER_NAME}" 19999/tcp 2>/dev/null | head -1 || echo "unknown")
        echo -e "  Netdata:    ${G}running${NC} → http://localhost:${port%%/*}"
        echo -e "  Container:  $(docker ps --filter name=${CONTAINER_NAME} --format '{{.Status}}')"
    elif docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER_NAME}$"; then
        echo -e "  Netdata:    ${Y}stopped${NC}"
    else
        echo -e "  Netdata:    ${R}not deployed${NC}"
    fi

    # Config
    echo -e "  Config:     ${CONFIG_DIR}"
    echo ""
}

# -----------------------------------------------------------------------------
# Launch
# -----------------------------------------------------------------------------
do_launch() {
    local port="$1"

    # Remove old instance if exists
    if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${CONTAINER_NAME}$"; then
        step "Removing previous instance..."
        docker stop "${CONTAINER_NAME}" 2>/dev/null || true
        docker rm "${CONTAINER_NAME}" 2>/dev/null || true
    fi

    step "Pulling latest Netdata image..."
    docker pull "${NETDATA_IMAGE}"

    step "Launching Netdata on port ${port}..."

    # Assemble the command as an array for clarity
    local -a cmd=(
        docker run -d
        --name "${CONTAINER_NAME}"
        --hostname "nosana-$(hostname)"
        --restart unless-stopped

        # ── Host visibility (this is what makes Netdata see real host stats) ──
        --pid=host                                  # See host processes
        --network=host                              # Use host network stack
        --cap-add SYS_PTRACE                        # Read /proc details
        --cap-add SYS_ADMIN                         # cgroup access
        --security-opt apparmor=unconfined           # Required on Ubuntu

        # ── Mount host filesystems read-only ──
        -v /proc:/host/proc:ro
        -v /sys:/host/sys:ro
        -v /etc/os-release:/host/etc/os-release:ro
        -v /etc/passwd:/host/etc/passwd:ro
        -v /etc/group:/host/etc/group:ro
        -v /var/log:/host/var/log:ro
        -v /etc/localtime:/etc/localtime:ro

        # ── Docker socket so Netdata can see other containers ──
        -v /var/run/docker.sock:/var/run/docker.sock:ro

        # ── Persistent Netdata storage (survives restarts) ──
        -v netdata-config:/etc/netdata
        -v netdata-lib:/var/lib/netdata
        -v netdata-cache:/var/cache/netdata

        # ── Nosana WebUI shared config (survives container purge) ──
        -v "${CONFIG_DIR}:/nosana-webui:rw"
    )

    # ── GPU support ──
    if check_nvidia_runtime; then
        info "NVIDIA container runtime detected — enabling --gpus all"
        cmd+=(--gpus all)
    elif check_gpu; then
        warn "GPU found but nvidia-container-toolkit missing."
        warn "Netdata will monitor host GPU via /proc but some features may be limited."
        # Mount nvidia devices directly as fallback
        for dev in /dev/nvidia0 /dev/nvidiactl /dev/nvidia-uvm /dev/nvidia-uvm-tools; do
            [ -e "$dev" ] && cmd+=(--device "${dev}:${dev}")
        done
        # Mount nvidia-smi if it exists (some setups have it at different paths)
        local smi_path
        smi_path=$(command -v nvidia-smi 2>/dev/null || true)
        if [ -n "$smi_path" ]; then
            cmd+=(-v "${smi_path}:${smi_path}:ro")
        fi
    else
        warn "No NVIDIA GPU detected. GPU monitoring will be unavailable."
    fi

    # ── Image ──
    cmd+=("${NETDATA_IMAGE}")

    # ── Go ──
    if "${cmd[@]}"; then
        echo ""
        echo -e "${BOLD}════════════════════════════════════════════════════${NC}"
        echo -e "  ${G}${BOLD}Netdata is running!${NC}"
        echo ""
        echo -e "  ${BOLD}Open in your browser:${NC}"
        echo -e "  ${C}→ http://localhost:${port}${NC}"
        echo ""
        echo -e "  ${BOLD}Config:${NC}  ${CONFIG_DIR}/"
        echo -e "  ${BOLD}Stop:${NC}    $0 --stop"
        echo -e "  ${BOLD}Status:${NC}  $0 --status"
        echo -e "  ${BOLD}Update:${NC}  Re-run this script"
        echo -e "${BOLD}════════════════════════════════════════════════════${NC}"
        echo ""
    else
        err "Failed to start container."
        err "Check: docker logs ${CONTAINER_NAME}"
        exit 1
    fi
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
    local port="${DEFAULT_PORT}"
    local action="launch"

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --port)     port="$2"; shift 2 ;;
            --stop)     action="stop"; shift ;;
            --status)   action="status"; shift ;;
            --help|-h)
                echo "Usage: $0 [--port PORT] [--stop] [--status] [--help]"
                echo ""
                echo "  --port PORT   Web UI port (default: 19999)"
                echo "  --stop        Stop and remove the container"
                echo "  --status      Show current status"
                exit 0
                ;;
            *) err "Unknown option: $1"; exit 1 ;;
        esac
    done

    case "${action}" in
        stop)   do_stop; exit 0 ;;
        status) do_status; exit 0 ;;
    esac

    # ── Launch flow ──
    echo ""
    echo -e "${BOLD}${B}  Nosana WebUI — Netdata Launcher${NC}"
    echo ""

    check_docker
    setup_config
    do_launch "${port}"
}

main "$@"
