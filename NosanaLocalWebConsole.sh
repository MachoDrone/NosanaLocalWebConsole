#!/usr/bin/env bash
# Usage: bash <(wget -qO- https://raw.githubusercontent.com/MachoDrone/NosanaLocalWebConsole/refs/heads/main/NosanaLocalWebConsole.sh)
NOSWEB_VERSION="0.02.24"
echo "v${NOSWEB_VERSION}"
sleep 3
# =============================================================================
# NOSweb — GPU Host Monitoring Stack
#
# Deploys five containers per host. Nothing installed on the host.
#   NOSweb-netdata      System metrics (CPU, RAM, disk, network, Docker)
#   NOSweb-dcgm         NVIDIA GPU detailed metrics (temp, power, clocks, etc.)
#   NOSweb-prometheus    Time-series database — scrapes all metrics
#   NOSweb-grafana       Dashboards — the main UI you'll use
#   NOSweb-proxy         Nginx auth gateway — single entry point
#
# QUICK START (one command, works on any Nosana host):
#   bash <(wget -qO- https://raw.githubusercontent.com/.../NosanaLocalWebConsole.sh)
#
# OPTIONS:
#   --group "my-farm"     Assign this host to a named group (default: "Unassigned").
#                         Only hosts in the same group see each other.
#                         Saved after first run — no need to repeat on reboot.
#   --home fleet|gpu|host Set landing dashboard (default: fleet). Saved.
#   --nologin             No password required (open access).
#   --port PORT           Public port (default: 19999).
#   --stop                Stop and remove all NOSweb containers.
#   --status              Show status of all containers.
#   --reset               Full reset: delete volumes, clear cache, relaunch.
#   --reset-password      Change stored login credentials.
#
# GROUPS:
#   Groups let operators separate hosts into independent sets.
#   Two operators on the same LAN with different group names will never
#   see each other's hosts. If you don't care about groups, do nothing —
#   the default group is "Unassigned" and all hosts see each other.
#
# NETWORKING — HOW HOSTS FIND EACH OTHER (Phase 2+):
#   Hosts on the same local network (LAN) find each other automatically.
#   No setup needed — just run the script on each host.
#
#   If you have hosts on DIFFERENT networks (different locations, data
#   centers, subnets, or behind different routers), they cannot discover
#   each other automatically because network broadcasts don't cross
#   router boundaries. In that case, point the remote host at any one
#   host it CAN reach:
#
#     --peer 192.168.0.114
#
#   That single connection is enough. The remote host learns about all
#   other hosts through the peer, and the peer tells everyone about the
#   new host. You only need ONE --peer flag, not a list of all hosts.
#
#   Example: You have 10 hosts at home and 2 at a data center.
#     - The 10 home hosts find each other automatically (same LAN).
#     - The 2 data center hosts find each other automatically (same LAN).
#     - Run ONE data center host with: --peer <any-home-host-IP>
#     - Now all 12 hosts can see each other.
#
# AFTER A DOCKER PRUNE:
#   If someone runs "docker system prune --all" or "docker volume prune",
#   just re-run this script. All settings live in ~/.nosana-webui/ on the
#   host filesystem, not in Docker. You will lose chart history but
#   everything else (login, group, dashboards) comes back as it was.
#
# =============================================================================
set -euo pipefail

# -----------------------------------------------------------------------------
# Config
# -----------------------------------------------------------------------------
CONFIG_DIR="${HOME}/.nosana-webui"
DOCKER_NETWORK="NOSweb-net"

# Container names
C_NETDATA="NOSweb-netdata"
C_DCGM="NOSweb-dcgm"
C_PROMETHEUS="NOSweb-prometheus"
C_GRAFANA="NOSweb-grafana"
C_PROXY="NOSweb-proxy"

# Legacy names to clean up
LEGACY_CONTAINERS="nosana-netdata nosana-proxy nosana-webui"

# Images
IMG_NETDATA="netdata/netdata:stable"
IMG_DCGM="nvidia/dcgm-exporter:latest"
IMG_PROMETHEUS="prom/prometheus:latest"
IMG_GRAFANA="grafana/grafana:latest"
IMG_NGINX="nginx:alpine"

# Internal ports (on Docker network, not exposed to host)
PORT_NETDATA=19999
PORT_DCGM=9400
PORT_PROMETHEUS=9090
PORT_GRAFANA=3000

# Public port (nginx proxy)
DEFAULT_PORT=19999

# Persistent paths (survive docker prune)
HTPASSWD_FILE="${CONFIG_DIR}/.htpasswd"
PASSWORD_FILE="${CONFIG_DIR}/.password"
AUTH_VERSION_FILE="${CONFIG_DIR}/.auth_version"
GROUP_FILE="${CONFIG_DIR}/.group"
NGINX_CONF="${CONFIG_DIR}/nginx.conf"
PROM_DIR="${CONFIG_DIR}/prometheus"
PROM_CONF="${PROM_DIR}/prometheus.yml"
PROM_TARGETS="${PROM_DIR}/targets"
GRAFANA_DIR="${CONFIG_DIR}/grafana"
GRAFANA_PROV="${GRAFANA_DIR}/provisioning"
GRAFANA_DASH="${GRAFANA_DIR}/dashboards"
DCGM_COUNTERS="${CONFIG_DIR}/dcgm-counters.csv"

# Discovery (HTTP gossip — no UDP needed)
PEERS_FILE="${CONFIG_DIR}/peers.dat"
SEED_PEERS_FILE="${CONFIG_DIR}/.seed_peers"
FLEET_TARGETS="${PROM_TARGETS}/fleet.json"
DISCOVERY_SCRIPT="${CONFIG_DIR}/discovery.sh"
PROXY_ENTRYPOINT="${CONFIG_DIR}/proxy-entrypoint.sh"
INFO_METRICS="${CONFIG_DIR}/info_metrics"
WALLET_FILE="${CONFIG_DIR}/.wallet"
GPU_WALLETS_FILE="${CONFIG_DIR}/gpu_wallets"
SCANNER_PID_FILE="${CONFIG_DIR}/.wallet_scanner.pid"
HOME_DASH_FILE="${CONFIG_DIR}/.home_dashboard"

AUTH_VERSION="2"
DEFAULT_GROUP="Unassigned"

# Runtime flag
NOLOGIN=false

# Terminal colors
if [ -t 1 ]; then
    R='\033[0;31m' G='\033[0;32m' Y='\033[1;33m' B='\033[0;34m'
    C_CLR='\033[0;36m' BOLD='\033[1m' NC='\033[0m'
else
    R='' G='' Y='' B='' C_CLR='' BOLD='' NC=''
fi

info()  { echo -e "${G}[OK]${NC}    $*"; }
warn()  { echo -e "${Y}[WARN]${NC}  $*"; }
err()   { echo -e "${R}[ERR]${NC}   $*"; }
step()  { echo -e "${C_CLR}[....]${NC}  $*"; }

# -----------------------------------------------------------------------------
# Checks
# -----------------------------------------------------------------------------
check_docker() {
    if ! command -v docker &>/dev/null; then
        err "Docker not found. Nosana hosts should have Docker installed."
        exit 1
    fi
    if ! docker info &>/dev/null 2>&1; then
        err "Docker not running or permission denied."
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

get_hostname() { hostname 2>/dev/null || echo "unknown"; }
get_ip() { hostname -I 2>/dev/null | awk '{print $1}'; }

# -----------------------------------------------------------------------------
# Cleanup
# -----------------------------------------------------------------------------
cleanup_containers() {
    local all_containers="${C_PROXY} ${C_GRAFANA} ${C_PROMETHEUS} ${C_DCGM} ${C_NETDATA} ${LEGACY_CONTAINERS}"
    for c in ${all_containers}; do
        if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${c}$"; then
            step "Removing container: ${c}"
            docker stop "${c}" 2>/dev/null || true
            docker rm "${c}" 2>/dev/null || true
        fi
    done
}

cleanup_legacy_volumes() {
    for v in netdata-config; do
        if docker volume ls -q 2>/dev/null | grep -q "^${v}$"; then
            step "Removing legacy volume: ${v}"
            docker volume rm "${v}" 2>/dev/null || true
        fi
    done
}

# -----------------------------------------------------------------------------
# Docker network
# -----------------------------------------------------------------------------
ensure_network() {
    if ! docker network inspect "${DOCKER_NETWORK}" &>/dev/null; then
        step "Creating Docker network: ${DOCKER_NETWORK}"
        docker network create "${DOCKER_NETWORK}" >/dev/null
    fi
    info "Docker network ready."
}

# -----------------------------------------------------------------------------
# Config directory
# -----------------------------------------------------------------------------
setup_config() {
    mkdir -p "${CONFIG_DIR}" "${PROM_DIR}" "${PROM_TARGETS}" \
             "${GRAFANA_PROV}/datasources" "${GRAFANA_PROV}/dashboards" \
             "${GRAFANA_DASH}"
}

# -----------------------------------------------------------------------------
# Group
# -----------------------------------------------------------------------------
setup_group() {
    local group_arg="$1"
    if [ -n "${group_arg}" ]; then
        echo -n "${group_arg}" > "${GROUP_FILE}"
        info "Group: ${group_arg}"
    elif [ ! -f "${GROUP_FILE}" ]; then
        echo -n "${DEFAULT_GROUP}" > "${GROUP_FILE}"
        info "Group: ${DEFAULT_GROUP} (use --group to change)"
    else
        info "Group: $(cat "${GROUP_FILE}")"
    fi
}

# -----------------------------------------------------------------------------
# Peers (cross-subnet discovery seeds)
# -----------------------------------------------------------------------------
setup_peers() {
    local -a new_peers=("$@")
    # Merge new --peer args into seed file
    if [ ${#new_peers[@]} -gt 0 ]; then
        touch "${SEED_PEERS_FILE}"
        for p in "${new_peers[@]}"; do
            [ -z "${p}" ] && continue
            if ! grep -qx "${p}" "${SEED_PEERS_FILE}" 2>/dev/null; then
                echo "${p}" >> "${SEED_PEERS_FILE}"
                info "Peer added: ${p}"
            fi
        done
    fi
    # Initialize empty files if they don't exist
    touch "${SEED_PEERS_FILE}" "${PEERS_FILE}"
    [ -f "${FLEET_TARGETS}" ] || echo '[]' > "${FLEET_TARGETS}"
    local count=0
    [ -s "${SEED_PEERS_FILE}" ] && count=$(grep -c . "${SEED_PEERS_FILE}" 2>/dev/null) || true
    if [ "${count:-0}" -gt 0 ] 2>/dev/null; then
        info "Seed peers: ${count} (stored in ${SEED_PEERS_FILE})"
    fi
}

# -----------------------------------------------------------------------------
# Wallet detection (public address only — private key never stored/logged)
# -----------------------------------------------------------------------------
scan_gpu_wallets() {
    # Discover wallet-to-GPU mapping from Nosana containers
    # Supports Type A (direct Docker) and Type B (podman-in-docker)
    local tmp_file
    tmp_file=$(mktemp "${GPU_WALLETS_FILE}.XXXXXX" 2>/dev/null || echo "${GPU_WALLETS_FILE}.tmp")

    # Type A: nosana-cli running directly in Docker
    local cid wallet gpu
    while read -r cid; do
        [ -z "$cid" ] && continue
        wallet=$(docker logs "$cid" 2>&1 | head -22 | grep -m1 "Wallet:" | awk '{print $NF}' || true)
        gpu=$(docker inspect "$cid" --format '{{join .Config.Cmd " "}}' 2>/dev/null | grep -o '\-\-gpu [0-9]*' | awk '{print $2}' || true)
        [ -z "$gpu" ] && gpu="0"
        [ -n "$wallet" ] && echo "${gpu}|${wallet}"
    done < <(docker ps -a --filter ancestor=nosana/nosana-cli:latest -q 2>/dev/null) > "$tmp_file"

    # Type B: nosana node inside podman-in-docker
    local podman_cid
    podman_cid=$(docker ps -q --filter name=podman 2>/dev/null | head -1 || true)
    if [ -n "$podman_cid" ]; then
        local pcid pname pimage
        while IFS=$'\t' read -r pcid pname pimage; do
            [ -z "$pcid" ] && continue
            if echo "${pname}${pimage}" | grep -qi "nosana"; then
                wallet=$(docker exec podman podman logs "$pcid" 2>&1 | head -22 | grep -m1 "Wallet:" | awk '{print $NF}' || true)
                [ -z "$wallet" ] && continue
                gpu=$(docker exec podman podman inspect "$pcid" --format '{{join .Config.Cmd " "}}' 2>/dev/null | grep -o '\-\-gpu [0-9]*' | awk '{print $2}' || true)
                [ -z "$gpu" ] && gpu="0"
                echo "${gpu}|${wallet}" >> "$tmp_file"
            fi
        done < <(docker exec podman podman ps -a --format '{{.ID}}\t{{.Names}}\t{{.Image}}' 2>/dev/null || true)
    fi

    # Dedup, sort by GPU index, update file only if we found wallets
    local new_file="${GPU_WALLETS_FILE}.new"
    sort -t'|' -k1 -n "$tmp_file" | uniq > "$new_file"
    if [ -s "$new_file" ]; then
        mv "$new_file" "${GPU_WALLETS_FILE}"
        # Backward compat: write first wallet to .wallet
        local first_wallet
        first_wallet=$(head -1 "${GPU_WALLETS_FILE}" | cut -d'|' -f2)
        [ -n "$first_wallet" ] && echo -n "$first_wallet" > "${WALLET_FILE}"
    else
        rm -f "$new_file"
    fi
    rm -f "$tmp_file"
}

setup_wallet() {
    scan_gpu_wallets || true
    if [ -s "${GPU_WALLETS_FILE}" ]; then
        local count
        count=$(wc -l < "${GPU_WALLETS_FILE}")
        info "GPU wallets discovered: ${count}"
        while IFS='|' read -r gpu wallet; do
            info "  GPU ${gpu}: ${wallet:0:8}..."
        done < "${GPU_WALLETS_FILE}"
    else
        warn "No Nosana containers found — wallet discovery skipped."
        # Fall back to old key-file detection for backward compat
        local wallet="" key_file="${HOME}/.nosana/nosana_key.json"
        if command -v solana &>/dev/null && [ -f "${key_file}" ]; then
            wallet=$(solana address -k "${key_file}" 2>/dev/null || true)
        fi
        if [ -z "${wallet}" ] && [ -f "${key_file}" ] && command -v python3 &>/dev/null; then
            wallet=$(python3 -c "
import json,sys
A='123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
try:
    kp=json.load(open('${key_file}'))
    pk=bytes(kp[32:64])
    n=int.from_bytes(pk,'big')
    r=''
    while n>0:n,m=divmod(n,58);r=A[m]+r
    for b in pk:
        if b==0:r='1'+r
        else:break
    print(r)
except:sys.exit(1)
" 2>/dev/null || true)
        fi
        if [ -n "$wallet" ]; then
            echo "0|${wallet}" > "${GPU_WALLETS_FILE}"
            echo -n "${wallet}" > "${WALLET_FILE}"
            info "Wallet (from key file): ${wallet:0:8}..."
        else
            echo -n "unknown" > "${WALLET_FILE}"
            warn "Wallet: not detected (no Nosana key or containers found)"
        fi
    fi
}

start_wallet_scanner() {
    # Background daemon: rescans containers every 60s, updates gpu_wallets + info_metrics
    if [ -f "$SCANNER_PID_FILE" ]; then
        kill "$(cat "$SCANNER_PID_FILE")" 2>/dev/null || true
    fi
    (
        set +eu
        while true; do
            sleep 60
            scan_gpu_wallets || true
            generate_info_metrics || true
        done
    ) &
    echo $! > "$SCANNER_PID_FILE"
    disown 2>/dev/null || true
    info "Wallet scanner started (PID: $!, every 60s)."
}

# -----------------------------------------------------------------------------
# Authentication
# -----------------------------------------------------------------------------
credentials_are_current() {
    [ -f "${HTPASSWD_FILE}" ] && [ -f "${PASSWORD_FILE}" ] && \
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
    [ -f "${HTPASSWD_FILE}" ] || [ -f "${PASSWORD_FILE}" ] && {
        warn "Old credentials detected — resetting."
        rm -f "${HTPASSWD_FILE}" "${PASSWORD_FILE}" "${AUTH_VERSION_FILE}"
    }
    create_password
}

create_password() {
    echo ""
    echo -e "${BOLD}  Set up WebUI login${NC}"
    echo "  (You may use your Ubuntu login credentials so you don't forget them.)"
    echo ""
    read -rp "  Username: " input_user
    local auth_user="${input_user}"
    [ -z "${auth_user}" ] && { err "Username cannot be empty."; create_password; return; }
    echo ""
    echo "  Enter the password you want for the WebUI."
    echo ""
    local auth_pass=""
    while true; do
        read -rsp "  Password: " auth_pass; echo ""
        [ -z "${auth_pass}" ] && { warn "Cannot be empty."; continue; }
        local confirm_pass=""
        read -rsp "  Confirm:  " confirm_pass; echo ""
        [ "${auth_pass}" != "${confirm_pass}" ] && { err "Passwords don't match."; echo ""; continue; }
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
# Generate DCGM custom counters CSV
# The default counters are too limited. This adds fan speed, P-State,
# throttle reasons, PCIe link info, and violation counters.
# -----------------------------------------------------------------------------
generate_dcgm_counters() {
    cat > "${DCGM_COUNTERS}" << 'DCGMEOF'
DCGM_FI_DEV_SM_CLOCK, gauge, SM clock frequency (in MHz).
DCGM_FI_DEV_MEM_CLOCK, gauge, Memory clock frequency (in MHz).
DCGM_FI_DEV_GPU_TEMP, gauge, GPU temperature (in C).
DCGM_FI_DEV_MEMORY_TEMP, gauge, Memory temperature (in C).
DCGM_FI_DEV_POWER_USAGE, gauge, Power draw (in W).
DCGM_FI_DEV_TOTAL_ENERGY_CONSUMPTION, counter, Total energy consumption since boot (in mJ).
DCGM_FI_DEV_GPU_UTIL, gauge, GPU utilization (in pct).
DCGM_FI_DEV_MEM_COPY_UTIL, gauge, Memory utilization (in pct).
DCGM_FI_DEV_ENC_UTIL, gauge, Encoder utilization (in pct).
DCGM_FI_DEV_DEC_UTIL, gauge, Decoder utilization (in pct).
DCGM_FI_DEV_FB_FREE, gauge, Framebuffer memory free (in MiB).
DCGM_FI_DEV_FB_USED, gauge, Framebuffer memory used (in MiB).
DCGM_FI_DEV_FAN_SPEED, gauge, Fan speed for the device in percent 0-100.
DCGM_FI_DEV_SLOWDOWN_TEMP, gauge, Slowdown temperature threshold (in C).
DCGM_FI_DEV_POWER_MGMT_LIMIT, gauge, Power management limit (in W).
DCGM_FI_DEV_PSTATE, gauge, Performance state (P-State) 0-15.
DCGM_FI_DEV_CLOCK_THROTTLE_REASONS, gauge, Current clock throttle reasons (bitmask).
DCGM_FI_DEV_POWER_VIOLATION, counter, Power throttling duration (in us).
DCGM_FI_DEV_THERMAL_VIOLATION, counter, Thermal throttling duration (in us).
DCGM_FI_DEV_PCIE_TX_THROUGHPUT, counter, Total PCIe TX bytes.
DCGM_FI_DEV_PCIE_RX_THROUGHPUT, counter, Total PCIe RX bytes.
DCGM_FI_DEV_PCIE_LINK_GEN, gauge, PCIe current link generation.
DCGM_FI_DEV_PCIE_LINK_WIDTH, gauge, PCIe current link width.
DCGM_FI_DEV_PCIE_REPLAY_COUNTER, counter, PCIe replay counter.
DCGM_FI_DEV_XID_ERRORS, gauge, XID errors.
DCGM_FI_DEV_CORRECTABLE_REMAPPED_ROWS, counter, Correctable remapped rows.
DCGM_FI_DEV_UNCORRECTABLE_REMAPPED_ROWS, counter, Uncorrectable remapped rows.
DCGM_FI_DEV_ROW_REMAP_FAILURE, gauge, Row remap failure.
DCGM_FI_DEV_NVLINK_BANDWIDTH_TOTAL, counter, NVLink total bandwidth.
DCGM_FI_DEV_VGPU_LICENSE_STATUS, gauge, vGPU license status.
DCGMEOF

    info "DCGM custom counters generated ($(grep -c '^DCGM' "${DCGM_COUNTERS}") fields)."
}

# -----------------------------------------------------------------------------
# Generate host info metrics (static file served by nginx for Prometheus)
# Exposes wallet address as a Prometheus label — no private key involved.
# -----------------------------------------------------------------------------
generate_info_metrics() {
    local tmp
    tmp=$(mktemp "${INFO_METRICS}.XXXXXX" 2>/dev/null || echo "${INFO_METRICS}.tmp")

    cat > "$tmp" << 'INFOHDR'
# HELP nosweb_host_info NOSweb host identity information
# TYPE nosweb_host_info gauge
INFOHDR

    if [ -s "${GPU_WALLETS_FILE}" ]; then
        local gpu wallet
        while IFS='|' read -r gpu wallet; do
            [ -z "$gpu" ] || [ -z "$wallet" ] && continue
            echo "nosweb_host_info{gpu=\"${gpu}\",wallet=\"${wallet}\"} 1" >> "$tmp"
        done < "${GPU_WALLETS_FILE}"
    else
        # Fallback: single wallet from .wallet file
        local wallet
        wallet=$(cat "${WALLET_FILE}" 2>/dev/null || echo "unknown")
        echo "nosweb_host_info{gpu=\"0\",wallet=\"${wallet}\"} 1" >> "$tmp"
    fi

    chmod 644 "$tmp"
    mv "$tmp" "${INFO_METRICS}"
}

# -----------------------------------------------------------------------------
# Generate Prometheus config
# -----------------------------------------------------------------------------
generate_prometheus_config() {
    local my_hostname
    my_hostname=$(get_hostname)

    cat > "${PROM_CONF}" << PROMEOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'prometheus'
    static_configs:
      - targets: ['localhost:9090']
        labels:
          host: '${my_hostname}'

  - job_name: 'grafana'
    static_configs:
      - targets: ['${C_GRAFANA}:3000']
        labels:
          host: '${my_hostname}'

  - job_name: 'netdata'
    metrics_path: '/api/v1/allmetrics'
    params:
      format: ['prometheus']
    honor_labels: true
    file_sd_configs:
      - files: ['/etc/prometheus/targets/netdata.json']
        refresh_interval: 30s

  - job_name: 'dcgm'
    file_sd_configs:
      - files: ['/etc/prometheus/targets/dcgm.json']
        refresh_interval: 30s

  - job_name: 'netdata-fleet'
    metrics_path: '/metrics/netdata'
    honor_labels: true
    file_sd_configs:
      - files: ['/etc/prometheus/targets/fleet.json']
        refresh_interval: 30s

  - job_name: 'dcgm-fleet'
    metrics_path: '/metrics/dcgm'
    file_sd_configs:
      - files: ['/etc/prometheus/targets/fleet.json']
        refresh_interval: 30s

  - job_name: 'nosweb-info'
    metrics_path: '/metrics/info'
    scrape_interval: 60s
    static_configs:
      - targets: ['${C_PROXY}:80']
        labels:
          host: '${my_hostname}'

  - job_name: 'info-fleet'
    metrics_path: '/metrics/info'
    scrape_interval: 60s
    file_sd_configs:
      - files: ['/etc/prometheus/targets/fleet.json']
        refresh_interval: 30s

  - job_name: 'balance'
    metrics_path: '/metrics/balance'
    honor_labels: true
    scrape_interval: 60s
    static_configs:
      - targets: ['${C_PROXY}:80']
PROMEOF

    # Phase 1: local targets (container names on Docker network)
    cat > "${PROM_TARGETS}/netdata.json" << TEOF
[{"targets": ["${C_NETDATA}:${PORT_NETDATA}"], "labels": {"host": "${my_hostname}"}}]
TEOF

    cat > "${PROM_TARGETS}/dcgm.json" << TEOF
[{"targets": ["${C_DCGM}:${PORT_DCGM}"], "labels": {"host": "${my_hostname}"}}]
TEOF

    info "Prometheus config generated."
}

# -----------------------------------------------------------------------------
# Generate Grafana provisioning
# -----------------------------------------------------------------------------
generate_grafana_provisioning() {
    cat > "${GRAFANA_PROV}/datasources/prometheus.yml" << 'DSEOF'
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://NOSweb-prometheus:9090
    isDefault: true
    uid: prometheus
    editable: true
DSEOF

    cat > "${GRAFANA_PROV}/dashboards/dashboards.yml" << 'DPEOF'
apiVersion: 1
providers:
  - name: 'NOSweb'
    orgId: 1
    folder: ''
    type: file
    disableDeletion: false
    editable: true
    updateIntervalSeconds: 30
    options:
      path: /var/lib/grafana/dashboards
      foldersFromFilesStructure: false
DPEOF

    info "Grafana provisioning generated."
}

# -----------------------------------------------------------------------------
# Generate Grafana dashboards
# -----------------------------------------------------------------------------
generate_gpu_dashboard() {
    cat > "${GRAFANA_DASH}/gpu-overview.json" << 'GPUEOF'
{
  "uid": "gpu-overview",
  "title": "GPU Overview",
  "description": "NVIDIA GPU metrics from DCGM Exporter",
  "tags": ["gpu", "nvidia", "dcgm"],
  "timezone": "browser",
  "schemaVersion": 39,
  "version": 6,
  "refresh": "10s",
  "time": {"from": "now-1h", "to": "now"},
  "panels": [
    {
      "id": 1, "type": "gauge", "title": "GPU Utilization",
      "gridPos": {"h": 6, "w": 6, "x": 0, "y": 0},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [{"refId": "A", "expr": "max by (gpu)(DCGM_FI_DEV_GPU_UTIL)", "legendFormat": "GPU {{gpu}}"}],
      "fieldConfig": {"defaults": {"unit": "percent", "decimals": 0, "min": 0, "max": 100,
        "thresholds": {"mode": "absolute", "steps": [
          {"value": null, "color": "green"}, {"value": 70, "color": "yellow"}, {"value": 90, "color": "red"}
        ]}}}
    },
    {
      "id": 2, "type": "gauge", "title": "Memory Used",
      "gridPos": {"h": 6, "w": 6, "x": 6, "y": 0},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [{"refId": "A", "expr": "max by (gpu)(DCGM_FI_DEV_FB_USED) / (max by (gpu)(DCGM_FI_DEV_FB_USED) + max by (gpu)(DCGM_FI_DEV_FB_FREE)) * 100", "legendFormat": "GPU {{gpu}}"}],
      "fieldConfig": {"defaults": {"unit": "percent", "decimals": 0, "min": 0, "max": 100,
        "thresholds": {"mode": "absolute", "steps": [
          {"value": null, "color": "green"}, {"value": 70, "color": "yellow"}, {"value": 90, "color": "red"}
        ]}}}
    },
    {
      "id": 3, "type": "gauge", "title": "Temperature",
      "gridPos": {"h": 6, "w": 6, "x": 12, "y": 0},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [{"refId": "A", "expr": "max by (gpu)(DCGM_FI_DEV_GPU_TEMP)", "legendFormat": "GPU {{gpu}}"}],
      "fieldConfig": {"defaults": {"unit": "celsius", "decimals": 0, "min": 0, "max": 100,
        "thresholds": {"mode": "absolute", "steps": [
          {"value": null, "color": "green"}, {"value": 70, "color": "yellow"}, {"value": 85, "color": "red"}
        ]}}}
    },
    {
      "id": 4, "type": "gauge", "title": "Power (% of Limit)",
      "gridPos": {"h": 6, "w": 6, "x": 18, "y": 0},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [{"refId": "A", "expr": "max by (gpu)(DCGM_FI_DEV_POWER_USAGE) / max by (gpu)(DCGM_FI_DEV_POWER_MGMT_LIMIT) * 100", "legendFormat": "GPU {{gpu}}"}],
      "fieldConfig": {"defaults": {"unit": "percent", "decimals": 0, "min": 0, "max": 100,
        "thresholds": {"mode": "absolute", "steps": [
          {"value": null, "color": "green"}, {"value": 70, "color": "yellow"}, {"value": 90, "color": "red"}
        ]}}}
    },
    {
      "id": 11, "type": "gauge", "title": "Fan Speed",
      "gridPos": {"h": 6, "w": 5, "x": 0, "y": 6},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [{"refId": "A", "expr": "max by (gpu)(DCGM_FI_DEV_FAN_SPEED)", "legendFormat": "GPU {{gpu}}"}],
      "fieldConfig": {"defaults": {"unit": "percent", "decimals": 0, "min": 0, "max": 100,
        "thresholds": {"mode": "absolute", "steps": [
          {"value": null, "color": "green"}, {"value": 60, "color": "yellow"}, {"value": 85, "color": "red"}
        ]}}}
    },
    {
      "id": 13, "type": "stat", "title": "Throttle",
      "description": "Power=SW power cap or HW brake. Heat=thermal slowdown. Idle=sleeping, OK=active no throttle, Throttle!=active+limited. Fleet table shows Pwr Limit(orange) vs Heat(red) detail.",
      "gridPos": {"h": 6, "w": 7, "x": 5, "y": 6},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [
        {"refId": "A", "expr": "clamp_max(clamp_max(floor(max by (gpu)(DCGM_FI_DEV_CLOCK_THROTTLE_REASONS) / 4) % 2, 1) + clamp_max(floor(max by (gpu)(DCGM_FI_DEV_CLOCK_THROTTLE_REASONS) / 128) % 2, 1), 1) * 2 + (max by (gpu)(DCGM_FI_DEV_PSTATE) < bool 8)", "legendFormat": "GPU {{gpu}} Power"},
        {"refId": "B", "expr": "clamp_max(clamp_max(floor(max by (gpu)(DCGM_FI_DEV_CLOCK_THROTTLE_REASONS) / 8) % 2, 1) + clamp_max(floor(max by (gpu)(DCGM_FI_DEV_CLOCK_THROTTLE_REASONS) / 32) % 2, 1) + clamp_max(floor(max by (gpu)(DCGM_FI_DEV_CLOCK_THROTTLE_REASONS) / 64) % 2, 1), 1) * 2 + (max by (gpu)(DCGM_FI_DEV_PSTATE) < bool 8)", "legendFormat": "GPU {{gpu}} Heat"}
      ],
      "fieldConfig": {"defaults": {
        "decimals": 0, "noValue": "N/A",
        "mappings": [
          {"type": "value", "options": {"0": {"text": "Idle", "color": "#808080"}}},
          {"type": "value", "options": {"1": {"text": "OK", "color": "green"}}},
          {"type": "value", "options": {"2": {"text": "Throttle!", "color": "red"}}},
          {"type": "value", "options": {"3": {"text": "Throttle!", "color": "red"}}}
        ],
        "thresholds": {"mode": "absolute", "steps": [{"value": null, "color": "#808080"}]}}},
      "options": {"graphMode": "none", "colorMode": "value", "textMode": "auto", "orientation": "horizontal",
        "reduceOptions": {"calcs": ["lastNotNull"]},
        "text": {"titleSize": 11, "valueSize": 14}}
    },
    {
      "id": 14, "type": "stat", "title": "PCIe (peak 24h)",
      "description": "Peak negotiated PCIe gen+width in 24h. Grey=idle(ASPM), dark-green=active, green=optimal(Gen4x16+).",
      "gridPos": {"h": 6, "w": 5, "x": 12, "y": 6},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [
        {"refId": "A", "expr": "max by (gpu)(max_over_time(DCGM_FI_DEV_PCIE_LINK_GEN[24h])) * 100 + max by (gpu)(max_over_time(DCGM_FI_DEV_PCIE_LINK_WIDTH[24h]))", "legendFormat": "GPU {{gpu}}"}
      ],
      "fieldConfig": {"defaults": {"decimals": 0, "noValue": "N/A",
        "mappings": [{"type": "value", "options": {
          "101": {"text": "waiting"}, "102": {"text": "waiting"}, "104": {"text": "waiting"}, "108": {"text": "waiting"}, "116": {"text": "waiting"},
          "201": {"text": "2.0x1"}, "204": {"text": "2.0x4"}, "208": {"text": "2.0x8"}, "216": {"text": "2.0x16"},
          "301": {"text": "3.0x1"}, "304": {"text": "3.0x4"}, "308": {"text": "3.0x8"}, "316": {"text": "3.0x16"},
          "401": {"text": "4.0x1"}, "404": {"text": "4.0x4"}, "408": {"text": "4.0x8"}, "416": {"text": "4.0x16"},
          "501": {"text": "5.0x1"}, "504": {"text": "5.0x4"}, "508": {"text": "5.0x8"}, "516": {"text": "5.0x16"}
        }}],
        "thresholds": {"mode": "absolute", "steps": [
          {"value": null, "color": "#555555"},
          {"value": 200, "color": "dark-green"},
          {"value": 416, "color": "green"}
        ]}}},
      "options": {"graphMode": "none", "colorMode": "value", "textMode": "auto", "orientation": "horizontal",
        "reduceOptions": {"calcs": ["lastNotNull"]},
        "text": {"titleSize": 11, "valueSize": 14}}
    },
    {
      "id": 19, "type": "stat", "title": "NOSweb Stack",
      "description": "Monitoring overhead: RAM from Prometheus+Grafana process metrics. Full stack est. ~350-500MB total (includes Netdata, DCGM, nginx).",
      "gridPos": {"h": 6, "w": 7, "x": 17, "y": 6},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [
        {"refId": "A", "expr": "sum(process_resident_memory_bytes{job=~\"prometheus|grafana\"}) / 1024 / 1024", "legendFormat": "Prom+Graf MB"},
        {"refId": "B", "expr": "sum(rate(process_cpu_seconds_total{job=~\"prometheus|grafana\"}[2m])) * 100", "legendFormat": "CPU %"}
      ],
      "fieldConfig": {"defaults": {"decimals": 0,
        "thresholds": {"mode": "absolute", "steps": [
          {"value": null, "color": "green"}, {"value": 300, "color": "yellow"}, {"value": 600, "color": "red"}
        ]}},
        "overrides": [
          {"matcher": {"id": "byName", "options": "Prom+Graf MB"}, "properties": [{"id": "unit", "value": "decmbytes"}]},
          {"matcher": {"id": "byName", "options": "CPU %"}, "properties": [{"id": "unit", "value": "percent"}, {"id": "decimals", "value": 1}]}
        ]},
      "options": {"graphMode": "area", "colorMode": "value", "textMode": "auto",
        "reduceOptions": {"calcs": ["lastNotNull"]}}
    },
    {
      "id": 5, "type": "timeseries", "title": "GPU Utilization Over Time",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 12},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [{"refId": "A", "expr": "max by (gpu)(DCGM_FI_DEV_GPU_UTIL)", "legendFormat": "GPU {{gpu}}"}],
      "fieldConfig": {"defaults": {"unit": "percent", "decimals": 0, "max": 100, "color": {"mode": "palette-classic"},
        "custom": {"lineWidth": 2, "fillOpacity": 15, "spanNulls": true}}}
    },
    {
      "id": 6, "type": "timeseries", "title": "GPU Memory Over Time (MiB)",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 12},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [
        {"refId": "A", "expr": "max by (gpu)(DCGM_FI_DEV_FB_USED)", "legendFormat": "GPU {{gpu}} Used"},
        {"refId": "B", "expr": "max by (gpu)(DCGM_FI_DEV_FB_FREE)", "legendFormat": "GPU {{gpu}} Free"}
      ],
      "fieldConfig": {"defaults": {"unit": "decmbytes", "decimals": 0, "color": {"mode": "palette-classic"},
        "custom": {"lineWidth": 2, "fillOpacity": 15, "spanNulls": true}}}
    },
    {
      "id": 7, "type": "timeseries", "title": "Temperature Over Time",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 20},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [
        {"refId": "A", "expr": "max by (gpu)(DCGM_FI_DEV_GPU_TEMP)", "legendFormat": "GPU {{gpu}} Core"},
        {"refId": "B", "expr": "max by (gpu)(DCGM_FI_DEV_MEMORY_TEMP)", "legendFormat": "GPU {{gpu}} Mem"}
      ],
      "fieldConfig": {"defaults": {"unit": "celsius", "decimals": 0, "color": {"mode": "palette-classic"},
        "custom": {"lineWidth": 2, "fillOpacity": 10, "spanNulls": true,
          "thresholdsStyle": {"mode": "line"}},
        "thresholds": {"mode": "absolute", "steps": [
          {"value": null, "color": "green"}, {"value": 80, "color": "red"}
        ]}}}
    },
    {
      "id": 8, "type": "timeseries", "title": "Power Draw Over Time",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 20},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [
        {"refId": "A", "expr": "max by (gpu)(DCGM_FI_DEV_POWER_USAGE)", "legendFormat": "GPU {{gpu}} Draw"},
        {"refId": "B", "expr": "max by (gpu)(DCGM_FI_DEV_POWER_MGMT_LIMIT)", "legendFormat": "GPU {{gpu}} Limit"}
      ],
      "fieldConfig": {"defaults": {"unit": "watt", "decimals": 0, "color": {"mode": "palette-classic"},
        "custom": {"lineWidth": 2, "fillOpacity": 15, "spanNulls": true}},
        "overrides": [{"matcher": {"id": "byRegexp", "options": "Limit"}, "properties": [
          {"id": "custom.lineStyle", "value": {"fill": "dash", "dash": [10, 10]}},
          {"id": "custom.fillOpacity", "value": 0}
        ]}]}
    },
    {
      "id": 9, "type": "timeseries", "title": "Clock Speeds & P-State",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 28},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [
        {"refId": "A", "expr": "max by (gpu)(DCGM_FI_DEV_SM_CLOCK)", "legendFormat": "GPU {{gpu}} SM (MHz)"},
        {"refId": "B", "expr": "max by (gpu)(DCGM_FI_DEV_MEM_CLOCK)", "legendFormat": "GPU {{gpu}} Mem (MHz)"},
        {"refId": "C", "expr": "max by (gpu)(DCGM_FI_DEV_PSTATE)", "legendFormat": "GPU {{gpu}} P-State"}
      ],
      "fieldConfig": {"defaults": {"decimals": 0, "color": {"mode": "palette-classic"},
        "custom": {"lineWidth": 2, "fillOpacity": 10, "spanNulls": true, "axisPlacement": "auto"}},
        "overrides": [{"matcher": {"id": "byRegexp", "options": "P-State"}, "properties": [
          {"id": "custom.axisPlacement", "value": "right"},
          {"id": "custom.fillOpacity", "value": 0},
          {"id": "custom.lineStyle", "value": {"fill": "dash", "dash": [5, 5]}},
          {"id": "min", "value": 0},
          {"id": "max", "value": 15}
        ]}]}
    },
    {
      "id": 15, "type": "timeseries", "title": "Throttle Events",
      "description": "SW=power cap HW=thermal. Value 1 = actively throttling.",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 28},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [
        {"refId": "A", "expr": "clamp_max(floor(max by (gpu)(DCGM_FI_DEV_CLOCK_THROTTLE_REASONS) / 4) % 2, 1)", "legendFormat": "GPU {{gpu}} SW (power)"},
        {"refId": "B", "expr": "clamp_max(floor(max by (gpu)(DCGM_FI_DEV_CLOCK_THROTTLE_REASONS) / 8) % 2, 1)", "legendFormat": "GPU {{gpu}} HW (thermal)"}
      ],
      "fieldConfig": {"defaults": {"decimals": 0, "min": 0, "max": 1, "color": {"mode": "palette-classic"},
        "custom": {"lineWidth": 2, "fillOpacity": 50, "spanNulls": true, "drawStyle": "bars"}}}
    },
    {
      "id": 16, "type": "timeseries", "title": "Fan Speed Over Time",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 36},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [{"refId": "A", "expr": "max by (gpu)(DCGM_FI_DEV_FAN_SPEED)", "legendFormat": "GPU {{gpu}}"}],
      "fieldConfig": {"defaults": {"unit": "percent", "decimals": 0, "min": 0, "max": 100, "color": {"mode": "palette-classic"},
        "custom": {"lineWidth": 2, "fillOpacity": 15, "spanNulls": true}}}
    },
    {
      "id": 18, "type": "timeseries", "title": "PCIe Link Speed Over Time",
      "description": "PCIe gen and lane width. Drops at idle (ASPM).",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 36},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [
        {"refId": "A", "expr": "max by (gpu)(DCGM_FI_DEV_PCIE_LINK_GEN)", "legendFormat": "GPU {{gpu}} Gen"},
        {"refId": "B", "expr": "max by (gpu)(DCGM_FI_DEV_PCIE_LINK_WIDTH)", "legendFormat": "GPU {{gpu}} Width"}
      ],
      "fieldConfig": {"defaults": {"decimals": 0, "color": {"mode": "palette-classic"},
        "custom": {"lineWidth": 2, "fillOpacity": 10, "spanNulls": true}},
        "overrides": [{"matcher": {"id": "byRegexp", "options": "Width"}, "properties": [
          {"id": "custom.axisPlacement", "value": "right"}
        ]}]}
    }
  ]
}
GPUEOF
}

generate_host_dashboard() {
    cat > "${GRAFANA_DASH}/host-overview.json" << 'HOSTEOF'
{
  "uid": "host-overview",
  "title": "Host Overview",
  "description": "System metrics from Netdata via Prometheus",
  "tags": ["host", "system", "netdata"],
  "timezone": "browser",
  "schemaVersion": 39,
  "version": 1,
  "refresh": "10s",
  "time": {"from": "now-1h", "to": "now"},
  "panels": [
    {
      "id": 1, "type": "timeseries", "title": "CPU Usage",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [
        {"refId": "A", "expr": "netdata_system_cpu_percentage_average{dimension=~\"user|system|softirq|irq\"}", "legendFormat": "{{dimension}}"}
      ],
      "fieldConfig": {"defaults": {"unit": "percent", "color": {"mode": "palette-classic"},
        "custom": {"lineWidth": 1, "fillOpacity": 30, "stacking": {"mode": "normal"}, "spanNulls": true}}}
    },
    {
      "id": 2, "type": "timeseries", "title": "RAM Usage (MiB)",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [
        {"refId": "A", "expr": "netdata_system_ram_MiB_average{dimension=\"used\"}", "legendFormat": "Used"},
        {"refId": "B", "expr": "netdata_system_ram_MiB_average{dimension=\"cached\"}", "legendFormat": "Cached"},
        {"refId": "C", "expr": "netdata_system_ram_MiB_average{dimension=\"buffers\"}", "legendFormat": "Buffers"}
      ],
      "fieldConfig": {"defaults": {"unit": "decmbytes", "decimals": 0, "color": {"mode": "palette-classic"},
        "custom": {"lineWidth": 1, "fillOpacity": 30, "stacking": {"mode": "normal"}, "spanNulls": true}}}
    },
    {
      "id": 3, "type": "timeseries", "title": "Network Traffic",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 8},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [
        {"refId": "A", "expr": "netdata_system_net_kilobits_persec_average{dimension=\"received\"}", "legendFormat": "Received"},
        {"refId": "B", "expr": "netdata_system_net_kilobits_persec_average{dimension=\"sent\"}", "legendFormat": "Sent"}
      ],
      "fieldConfig": {"defaults": {"unit": "Kbits", "decimals": 0, "color": {"mode": "palette-classic"},
        "custom": {"lineWidth": 2, "fillOpacity": 15, "spanNulls": true}}}
    },
    {
      "id": 4, "type": "timeseries", "title": "Disk I/O",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [
        {"refId": "A", "expr": "netdata_system_io_KiB_persec_average{dimension=\"in\"}", "legendFormat": "Read"},
        {"refId": "B", "expr": "netdata_system_io_KiB_persec_average{dimension=\"out\"}", "legendFormat": "Write"}
      ],
      "fieldConfig": {"defaults": {"unit": "KiBs", "decimals": 0, "color": {"mode": "palette-classic"},
        "custom": {"lineWidth": 2, "fillOpacity": 15, "spanNulls": true}}}
    }
  ]
}
HOSTEOF
}

generate_fleet_dashboard() {
    cat > "${GRAFANA_DASH}/fleet-overview.json" << 'FLEETEOF'
{
  "uid": "fleet-overview",
  "title": "Fleet Overview",
  "description": "All GPUs across all hosts — compact status view",
  "tags": ["fleet", "gpu", "overview"],
  "timezone": "browser",
  "schemaVersion": 39,
  "version": 1,
  "refresh": "10s",
  "time": {"from": "now-15m", "to": "now"},
  "panels": [
    {
      "id": 1, "type": "table", "title": "GPU Fleet Status",
      "description": "One row per GPU across fleet. Perf=P-state (P0=max, P8=idle).\\n\\nThrottle (15m lookback):\\n  ok = no throttle\\n  Pwr Limit (orange) = normal, GPU hitting configured power cap\\n  Heat Throttle! (red) = thermal slowdown, check airflow/dust/spacing\\n  HW Pwr Brake! (red) = PSU/cable issue, needs immediate attention\\n  Combined states shown when multiple throttles active\\n\\nSOL/STK/NOS update every 5m via Solana RPC. Footer shows fleet totals.",
      "gridPos": {"h": 14, "w": 24, "x": 0, "y": 0},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [
        {"refId": "A", "expr": "max by (host, gpu)(DCGM_FI_DEV_GPU_UTIL)", "format": "table", "instant": true},
        {"refId": "B", "expr": "max by (host, gpu)(DCGM_FI_DEV_GPU_TEMP)", "format": "table", "instant": true},
        {"refId": "C", "expr": "max by (host, gpu)(DCGM_FI_DEV_POWER_USAGE) / max by (host, gpu)(DCGM_FI_DEV_POWER_MGMT_LIMIT) * 100", "format": "table", "instant": true},
        {"refId": "D", "expr": "max by (host, gpu)(DCGM_FI_DEV_FAN_SPEED)", "format": "table", "instant": true},
        {"refId": "E", "expr": "clamp_max(floor(max by (host, gpu)(max_over_time(DCGM_FI_DEV_CLOCK_THROTTLE_REASONS[15m])) / 4) % 2, 1) + clamp_max(floor(max by (host, gpu)(max_over_time(DCGM_FI_DEV_CLOCK_THROTTLE_REASONS[15m])) / 128) % 2, 1) * 4 + clamp_max(clamp_max(floor(max by (host, gpu)(max_over_time(DCGM_FI_DEV_CLOCK_THROTTLE_REASONS[15m])) / 8) % 2, 1) + clamp_max(floor(max by (host, gpu)(max_over_time(DCGM_FI_DEV_CLOCK_THROTTLE_REASONS[15m])) / 32) % 2, 1) + clamp_max(floor(max by (host, gpu)(max_over_time(DCGM_FI_DEV_CLOCK_THROTTLE_REASONS[15m])) / 64) % 2, 1), 1) * 2", "format": "table", "instant": true},
        {"refId": "F", "expr": "label_replace(max by (host, gpu, modelName)(DCGM_FI_DEV_GPU_TEMP * 0 + 1), \"model\", \"$1\", \"modelName\", \"(?:NVIDIA )?(?:GeForce )?(.+)\")", "format": "table", "instant": true},
        {"refId": "G", "expr": "label_replace(max by (host, gpu, wallet)(nosweb_host_info), \"wallet_short\", \"$1...\", \"wallet\", \"^(.{5}).*\")", "format": "table", "instant": true},
        {"refId": "H", "expr": "max by (host, gpu)(max_over_time(DCGM_FI_DEV_PCIE_LINK_GEN[24h])) * 100 + max by (host, gpu)(max_over_time(DCGM_FI_DEV_PCIE_LINK_WIDTH[24h]))", "format": "table", "instant": true},
        {"refId": "I", "expr": "max by (host)(netdata_disk_space_GiB_average{family=\"/\",dimension=\"used\"}) / (max by (host)(netdata_disk_space_GiB_average{family=\"/\",dimension=\"used\"}) + max by (host)(netdata_disk_space_GiB_average{family=\"/\",dimension=\"avail\"})) * 100", "format": "table", "instant": true},
        {"refId": "J", "expr": "max by (host, gpu)(nosweb_sol_balance)", "format": "table", "instant": true},
        {"refId": "K", "expr": "max by (host, gpu)(nosweb_nos_staked)", "format": "table", "instant": true},
        {"refId": "L", "expr": "max by (host, gpu)(nosweb_nos_balance)", "format": "table", "instant": true},
        {"refId": "M", "expr": "max by (host, gpu)(DCGM_FI_DEV_PSTATE)", "format": "table", "instant": true}
      ],
      "transformations": [
        {"id": "merge", "options": {}},
        {"id": "organize", "options": {
          "excludeByName": {"Time": true, "Time 1": true, "Time 2": true, "Time 3": true, "Time 4": true, "Time 5": true, "Time 6": true, "Time 7": true, "Time 8": true, "Time 9": true, "Time 10": true, "Time 11": true, "Time 12": true, "Time 13": true, "modelName": true, "Value #F": true, "Value #G": true},
          "indexByName": {"wallet_short": 0, "wallet": 1, "host": 2, "gpu": 3, "model": 4, "Value #H": 5, "Value #M": 6, "Value #A": 7, "Value #B": 8, "Value #C": 9, "Value #D": 10, "Value #E": 11, "Value #I": 12, "Value #J": 13, "Value #K": 14, "Value #L": 15},
          "renameByName": {
            "wallet_short": "Explorer",
            "wallet": "wallet",
            "host": "PC",
            "gpu": "GPUid",
            "model": "Model",
            "Value #H": "Bus",
            "Value #M": "Perf",
            "Value #A": "GPU Utilization",
            "Value #B": "Temperature",
            "Value #C": "GPU Power",
            "Value #D": "Fan Speed",
            "Value #E": "Throttle",
            "Value #I": "Storage / Root",
            "Value #J": "SOL",
            "Value #K": "STK",
            "Value #L": "NOS"
          }
        }}
      ],
      "fieldConfig": {
        "defaults": {
          "custom": {"align": "center", "inspect": false, "filterable": true}
        },
        "overrides": [
          {
            "matcher": {"id": "byName", "options": "Explorer"},
            "properties": [
              {"id": "custom.width", "value": 65},
              {"id": "custom.align", "value": "left"},
              {"id": "color", "value": {"mode": "fixed", "fixedColor": "#6EA8FE"}},
              {"id": "custom.cellOptions", "value": {"type": "color-text"}},
              {"id": "links", "value": [{"title": "Nosana Explorer", "url": "https://explore.nosana.com/hosts/${__data.fields.wallet}", "targetBlank": true}]}
            ]
          },
          {
            "matcher": {"id": "byName", "options": "wallet"},
            "properties": [{"id": "custom.hidden", "value": true}]
          },
          {
            "matcher": {"id": "byName", "options": "PC"},
            "properties": [
              {"id": "custom.width", "value": 55},
              {"id": "custom.align", "value": "left"}
            ]
          },
          {
            "matcher": {"id": "byName", "options": "GPUid"},
            "properties": [{"id": "custom.width", "value": 45}]
          },
          {
            "matcher": {"id": "byName", "options": "Model"},
            "properties": [
              {"id": "custom.width", "value": 90},
              {"id": "custom.align", "value": "left"}
            ]
          },
          {
            "matcher": {"id": "byName", "options": "Bus"},
            "properties": [
              {"id": "custom.width", "value": 65},
              {"id": "custom.cellOptions", "value": {"type": "color-text"}},
              {"id": "mappings", "value": [{"type": "value", "options": {
                "101": {"text": "waiting"}, "102": {"text": "waiting"}, "104": {"text": "waiting"}, "108": {"text": "waiting"}, "116": {"text": "waiting"},
                "201": {"text": "2.0x1"}, "202": {"text": "2.0x2"}, "204": {"text": "2.0x4"}, "208": {"text": "2.0x8"}, "216": {"text": "2.0x16"},
                "301": {"text": "3.0x1"}, "302": {"text": "3.0x2"}, "304": {"text": "3.0x4"}, "308": {"text": "3.0x8"}, "316": {"text": "3.0x16"},
                "401": {"text": "4.0x1"}, "402": {"text": "4.0x2"}, "404": {"text": "4.0x4"}, "408": {"text": "4.0x8"}, "416": {"text": "4.0x16"},
                "501": {"text": "5.0x1"}, "502": {"text": "5.0x2"}, "504": {"text": "5.0x4"}, "508": {"text": "5.0x8"}, "516": {"text": "5.0x16"}
              }}]},
              {"id": "thresholds", "value": {"mode": "absolute", "steps": [
                {"value": null, "color": "#555555"},
                {"value": 200, "color": "dark-green"},
                {"value": 416, "color": "green"}
              ]}}
            ]
          },
          {
            "matcher": {"id": "byName", "options": "Perf"},
            "properties": [
              {"id": "custom.width", "value": 40},
              {"id": "custom.cellOptions", "value": {"type": "color-text"}},
              {"id": "mappings", "value": [{"type": "value", "options": {
                "0": {"text": "P0", "color": "green"},
                "1": {"text": "P1", "color": "green"},
                "2": {"text": "P2", "color": "dark-green"},
                "3": {"text": "P3", "color": "dark-green"},
                "4": {"text": "P4", "color": "dark-green"},
                "5": {"text": "P5", "color": "#888888"},
                "6": {"text": "P6", "color": "#888888"},
                "7": {"text": "P7", "color": "#888888"},
                "8": {"text": "P8", "color": "#555555"},
                "9": {"text": "P9", "color": "#555555"},
                "10": {"text": "P10", "color": "#555555"},
                "11": {"text": "P11", "color": "#555555"},
                "12": {"text": "P12", "color": "#555555"}
              }}]}
            ]
          },
          {
            "matcher": {"id": "byName", "options": "GPU Utilization"},
            "properties": [
              {"id": "unit", "value": "percent"}, {"id": "decimals", "value": 0},
              {"id": "min", "value": 0}, {"id": "max", "value": 100},
              {"id": "custom.cellOptions", "value": {"type": "gauge", "mode": "basic"}},
              {"id": "thresholds", "value": {"mode": "absolute", "steps": [
                {"value": null, "color": "dark-green"}, {"value": 70, "color": "yellow"}, {"value": 90, "color": "red"}
              ]}},
              {"id": "custom.width", "value": 100}
            ]
          },
          {
            "matcher": {"id": "byName", "options": "Temperature"},
            "properties": [
              {"id": "unit", "value": "celsius"}, {"id": "decimals", "value": 0},
              {"id": "min", "value": 0}, {"id": "max", "value": 100},
              {"id": "custom.cellOptions", "value": {"type": "gauge", "mode": "basic"}},
              {"id": "thresholds", "value": {"mode": "absolute", "steps": [
                {"value": null, "color": "dark-green"}, {"value": 78, "color": "orange"}, {"value": 83, "color": "red"}
              ]}},
              {"id": "custom.width", "value": 80}
            ]
          },
          {
            "matcher": {"id": "byName", "options": "GPU Power"},
            "properties": [
              {"id": "unit", "value": "percent"}, {"id": "decimals", "value": 0},
              {"id": "min", "value": 0}, {"id": "max", "value": 100},
              {"id": "custom.cellOptions", "value": {"type": "gauge", "mode": "basic"}},
              {"id": "thresholds", "value": {"mode": "absolute", "steps": [
                {"value": null, "color": "dark-green"}, {"value": 80, "color": "orange"}, {"value": 95, "color": "red"}
              ]}},
              {"id": "custom.width", "value": 80}
            ]
          },
          {
            "matcher": {"id": "byName", "options": "Fan Speed"},
            "properties": [
              {"id": "unit", "value": "percent"}, {"id": "decimals", "value": 0},
              {"id": "min", "value": 0}, {"id": "max", "value": 100},
              {"id": "custom.cellOptions", "value": {"type": "gauge", "mode": "basic"}},
              {"id": "thresholds", "value": {"mode": "absolute", "steps": [
                {"value": null, "color": "dark-green"}, {"value": 60, "color": "orange"}, {"value": 80, "color": "red"}
              ]}},
              {"id": "custom.width", "value": 70}
            ]
          },
          {
            "matcher": {"id": "byName", "options": "Throttle"},
            "properties": [
              {"id": "mappings", "value": [
                {"type": "value", "options": {
                  "0": {"text": "ok", "color": "#555555"},
                  "1": {"text": "Pwr Limit", "color": "#555555"},
                  "2": {"text": "Heat Throttle!", "color": "red"},
                  "3": {"text": "Heat+Pwr!", "color": "red"},
                  "4": {"text": "HW Pwr Brake!", "color": "red"},
                  "5": {"text": "Brake+Pwr!", "color": "red"},
                  "6": {"text": "Brake+Heat!", "color": "red"},
                  "7": {"text": "Brake+Heat+Pwr!", "color": "red"}
                }}
              ]},
              {"id": "custom.cellOptions", "value": {"type": "color-text"}},
              {"id": "custom.width", "value": 100}
            ]
          },
          {
            "matcher": {"id": "byName", "options": "Storage / Root"},
            "properties": [
              {"id": "unit", "value": "percent"}, {"id": "decimals", "value": 0},
              {"id": "min", "value": 0}, {"id": "max", "value": 100},
              {"id": "custom.cellOptions", "value": {"type": "gauge", "mode": "basic"}},
              {"id": "thresholds", "value": {"mode": "absolute", "steps": [
                {"value": null, "color": "dark-green"}, {"value": 70, "color": "yellow"}, {"value": 90, "color": "red"}
              ]}},
              {"id": "custom.width", "value": 70}
            ]
          },
          {
            "matcher": {"id": "byName", "options": "SOL"},
            "properties": [
              {"id": "decimals", "value": 4},
              {"id": "custom.cellOptions", "value": {"type": "color-text"}},
              {"id": "mappings", "value": [
                {"type": "value", "options": {"0": {"text": "waiting", "color": "#555555"}}}
              ]},
              {"id": "thresholds", "value": {"mode": "absolute", "steps": [
                {"value": null, "color": "#555555"},
                {"value": 0.0001, "color": "red"},
                {"value": 0.0065, "color": "orange"},
                {"value": 0.01, "color": "green"}
              ]}},
              {"id": "custom.width", "value": 70}
            ]
          },
          {
            "matcher": {"id": "byName", "options": "STK"},
            "properties": [
              {"id": "decimals", "value": 0},
              {"id": "custom.cellOptions", "value": {"type": "color-text"}},
              {"id": "mappings", "value": [
                {"type": "value", "options": {"0": {"text": "waiting", "color": "#555555"}}}
              ]},
              {"id": "color", "value": {"mode": "fixed", "fixedColor": "dark-green"}},
              {"id": "custom.width", "value": 55}
            ]
          },
          {
            "matcher": {"id": "byName", "options": "NOS"},
            "properties": [
              {"id": "decimals", "value": 3},
              {"id": "custom.cellOptions", "value": {"type": "color-text"}},
              {"id": "mappings", "value": [
                {"type": "value", "options": {"0": {"text": "waiting", "color": "#555555"}}}
              ]},
              {"id": "color", "value": {"mode": "fixed", "fixedColor": "dark-green"}},
              {"id": "custom.width", "value": 75}
            ]
          }
        ]
      },
      "options": {
        "showHeader": true,
        "cellHeight": "sm",
        "footer": {"show": true, "reducer": ["sum"], "fields": ["SOL", "STK", "NOS"], "countRows": true},
        "sortBy": [{"displayName": "PC", "desc": false}]
      }
    }
  ]
}
FLEETEOF
}

generate_dashboards() {
    generate_gpu_dashboard
    generate_host_dashboard
    generate_fleet_dashboard
    # Inject version into dashboard titles (heredocs are single-quoted, can't expand vars)
    sed -i "s/\"title\": \"GPU Overview\"/\"title\": \"GPU Overview | NOSweb v${NOSWEB_VERSION}\"/" "${GRAFANA_DASH}/gpu-overview.json"
    sed -i "s/\"title\": \"Host Overview\"/\"title\": \"Host Overview | NOSweb v${NOSWEB_VERSION}\"/" "${GRAFANA_DASH}/host-overview.json"
    sed -i "s/\"title\": \"NOSweb Stack\"/\"title\": \"NOSweb Stack v${NOSWEB_VERSION}\"/" "${GRAFANA_DASH}/gpu-overview.json"
    sed -i "s/\"title\": \"Fleet Overview\"/\"title\": \"Fleet Overview | NOSweb v${NOSWEB_VERSION}\"/" "${GRAFANA_DASH}/fleet-overview.json"
    info "Grafana dashboards generated."
}

# -----------------------------------------------------------------------------
# Generate Discovery script (runs inside proxy container)
# HTTP gossip — polls peers via /discovery endpoint on port 19999.
# Scans local /24 subnet for LAN auto-discovery. No UDP, no socat.
# Peers are never removed — tagged offline after 3 minutes of silence.
# Only online peers written to Prometheus fleet.json targets.
# -----------------------------------------------------------------------------
generate_discovery_script() {
    cat > "${DISCOVERY_SCRIPT}" << 'DISCEOF'
#!/bin/sh
# NOSweb Fleet Discovery — HTTP gossip with per-GPU wallet support
# Each host scans containers for wallet-to-GPU mapping.
# Balances fetched per wallet from Solana RPC, shared via gossip.

PEERS_FILE="/data/peers.dat"
TARGETS_FILE="/data/targets/fleet.json"
SEED_FILE="/data/seed_peers"
GPU_WALLETS="/data/gpu_wallets"
GPU_BALANCES="/tmp/gpu_balances"
MY_IP="${NOSWEB_IP}"
MY_HOST="${NOSWEB_HOSTNAME}"
MY_GROUP="${NOSWEB_GROUP}"
MY_PORT="${NOSWEB_PORT:-19999}"
INTERVAL=30
OFFLINE_AFTER=180
SCAN_DIR="/tmp/discovery_scan"
BALANCE_FILE="/data/targets/balance.prom"
BALANCE_INTERVAL=300
SOLANA_RPC="https://api.mainnet-beta.solana.com"
NOS_MINT="nosXBVoaCTtYdLvKY6Csb4AC8JCdQKKAaWYtx2ZMoo7"
NOS_STAKE_PROGRAM="nosScmHY2uR24Zh751PmGj9ww9QRNHewh9H59AfrTJE"

log() { echo "[discovery] $*"; }

touch "$PEERS_FILE"
mkdir -p "$(dirname "$TARGETS_FILE")" "$SCAN_DIR"

# ── Initialize GPU balances file (gpu|wallet|sol|nos|stk per line) ──
init_gpu_balances() {
    if [ -f "$GPU_WALLETS" ] && [ -s "$GPU_WALLETS" ]; then
        local gpu wallet
        > "$GPU_BALANCES"
        while IFS='|' read -r gpu wallet; do
            [ -z "$gpu" ] || [ -z "$wallet" ] && continue
            echo "${gpu}|${wallet}|0|0|0" >> "$GPU_BALANCES"
        done < "$GPU_WALLETS"
    else
        echo "0|unknown|0|0|0" > "$GPU_BALANCES"
    fi
}
init_gpu_balances

# ── Build gpus string for discovery JSON: 0|wallet|sol|nos|stk,1|wallet|... ──
build_gpus_string() {
    local first=1 result=""
    if [ -f "$GPU_BALANCES" ]; then
        while IFS='|' read -r gpu wallet sol nos stk; do
            [ -z "$gpu" ] && continue
            [ "$first" -eq 0 ] && result="${result},"
            result="${result}${gpu}|${wallet}|${sol}|${nos}|${stk}"
            first=0
        done < "$GPU_BALANCES"
    fi
    echo "$result"
}

# ── Write discovery.json ──
write_discovery() {
    local gpus_str first_wallet first_sol first_nos first_stk
    gpus_str=$(build_gpus_string)
    # Backward compat: first wallet's data in top-level fields
    first_wallet=$(head -1 "$GPU_BALANCES" 2>/dev/null | cut -d'|' -f2)
    first_sol=$(head -1 "$GPU_BALANCES" 2>/dev/null | cut -d'|' -f3)
    first_nos=$(head -1 "$GPU_BALANCES" 2>/dev/null | cut -d'|' -f4)
    first_stk=$(head -1 "$GPU_BALANCES" 2>/dev/null | cut -d'|' -f5)
    [ -z "$first_wallet" ] && first_wallet="unknown"
    [ -z "$first_sol" ] && first_sol="0"
    [ -z "$first_nos" ] && first_nos="0"
    [ -z "$first_stk" ] && first_stk="0"
    cat > /data/discovery.json << IDJSON
{"host":"${MY_HOST}","ip":"${MY_IP}","group":"${MY_GROUP}","port":${MY_PORT},"version":"${NOSWEB_VERSION:-unknown}","wallet":"${first_wallet}","sol":${first_sol},"nos":${first_nos},"stk":${first_stk},"gpus":"${gpus_str}"}
IDJSON
}

write_discovery

# ── Write per-GPU balance metrics for Prometheus ──
write_balance_metrics() {
    local tmp
    tmp=$(mktemp -p "$(dirname "$BALANCE_FILE")")
    cat > "$tmp" << 'BALHEADER'
# HELP nosweb_sol_balance SOL balance per GPU wallet
# TYPE nosweb_sol_balance gauge
# HELP nosweb_nos_balance NOS token balance per GPU wallet
# TYPE nosweb_nos_balance gauge
# HELP nosweb_nos_staked Staked NOS balance per GPU wallet
# TYPE nosweb_nos_staked gauge
BALHEADER

    # Own balances (per GPU)
    if [ -f "$GPU_BALANCES" ]; then
        local gpu wallet sol nos stk
        while IFS='|' read -r gpu wallet sol nos stk; do
            [ -z "$gpu" ] && continue
            [ "$wallet" = "unknown" ] && continue
            printf 'nosweb_sol_balance{host="%s",gpu="%s"} %s\n' "$MY_HOST" "$gpu" "${sol:-0}" >> "$tmp"
            printf 'nosweb_nos_balance{host="%s",gpu="%s"} %s\n' "$MY_HOST" "$gpu" "${nos:-0}" >> "$tmp"
            printf 'nosweb_nos_staked{host="%s",gpu="%s"} %s\n' "$MY_HOST" "$gpu" "${stk:-0}" >> "$tmp"
        done < "$GPU_BALANCES"
    fi

    # Peer balances from peers.dat
    local now ip host group port last_seen status gpus_data age
    now=$(date +%s)
    while IFS='|' read -r ip host group port last_seen status gpus_data; do
        [ -z "$ip" ] && continue
        [ "$ip" = "$MY_IP" ] && continue
        age=$((now - last_seen))
        [ "$age" -gt "$OFFLINE_AFTER" ] && continue
        [ -z "$gpus_data" ] && continue
        # Parse gpus_data: 0|wallet|sol|nos|stk,1|wallet|sol|nos|stk,...
        echo "$gpus_data" | tr ',' '\n' | while IFS='|' read -r pgpu pwallet psol pnos pstk; do
            [ -z "$pgpu" ] && continue
            [ "$pwallet" = "unknown" ] && continue
            printf 'nosweb_sol_balance{host="%s",gpu="%s"} %s\n' "$host" "$pgpu" "${psol:-0}" >> "$tmp"
            printf 'nosweb_nos_balance{host="%s",gpu="%s"} %s\n' "$host" "$pgpu" "${pnos:-0}" >> "$tmp"
            printf 'nosweb_nos_staked{host="%s",gpu="%s"} %s\n' "$host" "$pgpu" "${pstk:-0}" >> "$tmp"
        done
    done < "$PEERS_FILE"

    chmod 644 "$tmp"
    mv "$tmp" "$BALANCE_FILE"
}

write_balance_metrics

# ── Derive /24 subnet base from own IP ──
subnet_base() {
    echo "$MY_IP" | sed 's/\.[0-9]*$//'
}

# ── Write Prometheus file_sd JSON from peers.dat ──
write_targets() {
    local now tmp first ip host group port last_seen status age
    now=$(date +%s)
    tmp=$(mktemp -p "$(dirname "$TARGETS_FILE")")
    first=1
    printf '[' > "$tmp"
    while IFS='|' read -r ip host group port last_seen status _; do
        [ -z "$ip" ] && continue
        [ "$ip" = "$MY_IP" ] && continue
        age=$((now - last_seen))
        if [ "$age" -gt "$OFFLINE_AFTER" ]; then
            status="offline"
        else
            status="online"
        fi
        if [ "$status" = "online" ]; then
            [ "$first" -eq 0 ] && printf ',' >> "$tmp"
            first=0
            printf '{"targets":["%s:%s"],"labels":{"host":"%s"}}' "$ip" "$port" "$host" >> "$tmp"
        fi
    done < "$PEERS_FILE"
    printf ']' >> "$tmp"
    chmod 644 "$tmp"
    mv "$tmp" "$TARGETS_FILE"
}

# ── Process a /discovery JSON response ──
process_response() {
    local ip="$1" body="$2"
    local rhost rip rgroup rport rgpus
    rhost=$(echo "$body" | sed -n 's/.*"host"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    rip=$(echo "$body" | sed -n 's/.*"ip"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    rgroup=$(echo "$body" | sed -n 's/.*"group"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    rport=$(echo "$body" | sed -n 's/.*"port"[[:space:]]*:[[:space:]]*\([0-9]*\).*/\1/p')
    [ -z "$rhost" ] && return
    [ -z "$rip" ] && rip="$ip"
    [ -z "$rport" ] && rport="$MY_PORT"
    [ "$rip" = "$MY_IP" ] && return
    [ "$rgroup" != "$MY_GROUP" ] && return

    # Try new gpus field first, fall back to legacy wallet/sol/nos/stk
    rgpus=$(echo "$body" | sed -n 's/.*"gpus"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
    if [ -z "$rgpus" ]; then
        # Legacy: single wallet
        local rwallet rsol rnos rstk
        rwallet=$(echo "$body" | sed -n 's/.*"wallet"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
        rsol=$(echo "$body" | grep -o '"sol":[0-9.e+-]*' | head -1 | grep -o '[0-9.e+-]*$')
        rnos=$(echo "$body" | grep -o '"nos":[0-9.e+-]*' | head -1 | grep -o '[0-9.e+-]*$')
        rstk=$(echo "$body" | grep -o '"stk":[0-9.e+-]*' | head -1 | grep -o '[0-9.e+-]*$')
        [ -z "$rwallet" ] && rwallet="unknown"
        [ -z "$rsol" ] && rsol="0"
        [ -z "$rnos" ] && rnos="0"
        [ -z "$rstk" ] && rstk="0"
        rgpus="0|${rwallet}|${rsol}|${rnos}|${rstk}"
    fi

    # Upsert peer: ip|host|group|port|ts|status|gpus_data
    local now tmp
    now=$(date +%s)
    tmp=$(mktemp -p /data)
    grep -v "^${rip}|" "$PEERS_FILE" > "$tmp" 2>/dev/null || true
    echo "${rip}|${rhost}|${rgroup}|${rport}|${now}|online|${rgpus}" >> "$tmp"
    cat "$tmp" > "$PEERS_FILE" && rm -f "$tmp"
    log "peer: ${rhost} (${rip}) gpus=${rgpus}"
}

# ── Probe a single IP via HTTP ──
probe_ip() {
    local ip="$1" port="${2:-$MY_PORT}"
    local outfile="${SCAN_DIR}/${ip}"
    wget -q -T 1 -O "$outfile" "http://${ip}:${port}/discovery" 2>/dev/null || rm -f "$outfile"
}

# ── Gossip round ──
gossip_round() {
    rm -f "${SCAN_DIR}"/*

    # Re-read gpu_wallets in case scanner updated it
    if [ -f "$GPU_WALLETS" ] && [ -s "$GPU_WALLETS" ]; then
        local new_count old_count
        new_count=$(wc -l < "$GPU_WALLETS")
        old_count=$(wc -l < "$GPU_BALANCES" 2>/dev/null || echo 0)
        if [ "$new_count" != "$old_count" ]; then
            init_gpu_balances
            log "gpu_wallets changed (${old_count} -> ${new_count}), reinitializing"
        fi
    fi

    local base
    base=$(subnet_base)

    local i=1
    while [ "$i" -le 254 ]; do
        probe_ip "${base}.${i}" &
        i=$((i + 1))
    done

    if [ -f "$SEED_FILE" ]; then
        while IFS= read -r peer; do
            [ -z "$peer" ] && continue
            probe_ip "$peer" &
        done < "$SEED_FILE"
    fi

    while IFS='|' read -r ip _ _ port _ _ _; do
        [ -z "$ip" ] && continue
        [ "$ip" = "$MY_IP" ] && continue
        probe_ip "$ip" "$port" &
    done < "$PEERS_FILE"

    wait

    local changed=0
    for f in "${SCAN_DIR}"/*; do
        [ -f "$f" ] || continue
        local ip body
        ip=$(basename "$f")
        body=$(cat "$f")
        [ -z "$body" ] && continue
        echo "$body" | grep -q '"host"' || continue
        process_response "$ip" "$body"
        changed=1
    done

    write_targets
    write_balance_metrics
    [ "$changed" -eq 1 ] && log "targets updated"
}

# ── Fetch balance for a single wallet ──
fetch_wallet_balance() {
    local wallet="$1"
    local sol="0" nos="0" stk="0"
    local resp raw lamports retry

    # SOL
    for retry in 1 2; do
        resp=$(wget -q -T 8 -O - \
            --header='Content-Type: application/json' \
            --post-data='{"jsonrpc":"2.0","id":1,"method":"getBalance","params":["'"$wallet"'"]}' \
            "$SOLANA_RPC" 2>/dev/null) && break || sleep 2
    done
    if [ -n "$resp" ]; then
        lamports=$(echo "$resp" | grep -o '"value":[0-9]*' | head -1 | grep -o '[0-9]*$')
        [ -n "$lamports" ] && [ "$lamports" -gt 0 ] 2>/dev/null && \
            sol=$(awk "BEGIN{printf \"%.10f\", $lamports/1000000000}")
    fi

    # NOS
    for retry in 1 2; do
        resp=$(wget -q -T 8 -O - \
            --header='Content-Type: application/json' \
            --post-data='{"jsonrpc":"2.0","id":1,"method":"getTokenAccountsByOwner","params":["'"$wallet"'",{"mint":"'"$NOS_MINT"'"},{"encoding":"jsonParsed"}]}' \
            "$SOLANA_RPC" 2>/dev/null) && break || sleep 2
    done
    if [ -n "$resp" ]; then
        raw=$(echo "$resp" | grep -o '"uiAmount":[0-9.e+-]*' | head -1 | grep -o '[0-9.e+-]*$')
        if [ -n "$raw" ] && [ "$raw" != "0" ]; then
            nos=$(awk "BEGIN{printf \"%.6f\", $raw + 0}")
        fi
        if [ "$nos" = "0" ]; then
            raw=$(echo "$resp" | grep -o '"amount":"[0-9]*"' | head -1 | grep -o '[0-9]*')
            [ -n "$raw" ] && [ "$raw" != "0" ] && \
                nos=$(awk "BEGIN{printf \"%.6f\", $raw/1000000}")
        fi
    fi

    # STK
    for retry in 1 2; do
        resp=$(wget -q -T 10 -O - \
            --header='Content-Type: application/json' \
            --post-data='{"jsonrpc":"2.0","id":1,"method":"getProgramAccounts","params":["'"$NOS_STAKE_PROGRAM"'",{"encoding":"jsonParsed","filters":[{"memcmp":{"offset":8,"bytes":"'"$wallet"'","encoding":"base58"}}]}]}' \
            "$SOLANA_RPC" 2>/dev/null) && break || sleep 2
    done
    if [ -n "$resp" ]; then
        local stk_raw
        stk_raw=$(echo "$resp" | grep -o '"amount":"[0-9]*"' | head -1 | grep -o '[0-9]*')
        [ -n "$stk_raw" ] && [ "$stk_raw" != "0" ] && \
            stk=$(awk "BEGIN{printf \"%.6f\", $stk_raw/1000000}")
    fi

    echo "${sol}|${nos}|${stk}"
}

# ── Fetch balances for ALL GPU wallets ──
fetch_balances() {
    [ ! -f "$GPU_BALANCES" ] && return 1

    local stagger
    stagger=$((${MY_IP##*.} % 26))
    sleep "$stagger"

    local gpu wallet sol nos stk result tmp_bal
    tmp_bal=$(mktemp -p /tmp)

    while IFS='|' read -r gpu wallet _sol _nos _stk; do
        [ -z "$gpu" ] || [ -z "$wallet" ] || [ "$wallet" = "unknown" ] && continue
        result=$(fetch_wallet_balance "$wallet")
        sol=$(echo "$result" | cut -d'|' -f1)
        nos=$(echo "$result" | cut -d'|' -f2)
        stk=$(echo "$result" | cut -d'|' -f3)
        echo "${gpu}|${wallet}|${sol}|${nos}|${stk}" >> "$tmp_bal"
        log "balance: GPU${gpu} (${wallet:0:8}...) SOL=${sol} NOS=${nos} STK=${stk}"
        # Small delay between wallets to avoid RPC rate limits
        sleep 2
    done < "$GPU_BALANCES"

    [ -s "$tmp_bal" ] && mv "$tmp_bal" "$GPU_BALANCES" || rm -f "$tmp_bal"

    write_discovery
    write_balance_metrics
}

# ── Main loop ──
log "starting: host=${MY_HOST} ip=${MY_IP} group=${MY_GROUP} port=${MY_PORT}"
log "mode: per-GPU wallet discovery + gossip balance sharing"
if [ -f "$GPU_WALLETS" ]; then
    log "gpu_wallets: $(wc -l < "$GPU_WALLETS") entries"
fi
write_targets

last_balance=0
while true; do
    gossip_round
    now=$(date +%s)
    if [ $((now - last_balance)) -ge "$BALANCE_INTERVAL" ]; then
        fetch_balances && last_balance=$now || true
    fi
    sleep "$INTERVAL"
done
DISCEOF

    chmod +x "${DISCOVERY_SCRIPT}"
    info "Discovery script generated."
}

# -----------------------------------------------------------------------------
# Generate Proxy entrypoint (starts nginx + discovery sidecar)
# No extra packages needed — wget is built into Alpine nginx.
# -----------------------------------------------------------------------------
generate_proxy_entrypoint() {
    cat > "${PROXY_ENTRYPOINT}" << 'ENTRYEOF'
#!/bin/sh
# NOSweb Proxy Entrypoint — nginx + fleet discovery in one container

# Start nginx using the official entrypoint (background)
/docker-entrypoint.sh nginx -g 'daemon off;' &
NGINX_PID=$!

# Give nginx a moment to start
sleep 2

# Start discovery sidecar
if [ -f /data/discovery.sh ]; then
    /data/discovery.sh &
    DISC_PID=$!
    echo "[entrypoint] nginx(${NGINX_PID}) + discovery(${DISC_PID}) running"
else
    echo "[entrypoint] WARNING: discovery.sh not found, running nginx only"
fi

# Wait — if either exits, container stops
wait $NGINX_PID
ENTRYEOF

    chmod +x "${PROXY_ENTRYPOINT}"
    info "Proxy entrypoint generated."
}

# -----------------------------------------------------------------------------
# Generate Nginx config
# Key fix: WebSocket upgrade must be conditional (map block in http context).
# Without this, Grafana's live features break with "Something went wrong".
# Routes:  / → Grafana    /netdata/ → Netdata    /prometheus/ → Prometheus
# -----------------------------------------------------------------------------
generate_nginx_conf() {
    local auth_block=""
    if [ "${NOLOGIN}" = false ] && [ -f "${HTPASSWD_FILE}" ]; then
        auth_block='
        auth_basic "NOSweb";
        auth_basic_user_file /etc/nginx/.htpasswd;'
    fi

    cat > "${NGINX_CONF}" << NGINXEOF
worker_processes 1;
error_log /var/log/nginx/error.log warn;
pid /tmp/nginx.pid;

events { worker_connections 256; }

http {
    # Conditional WebSocket upgrade — required for Grafana live features.
    # Without this map, setting Connection to "upgrade" unconditionally
    # breaks normal HTTP requests and causes "Something went wrong".
    map \$http_upgrade \$connection_upgrade {
        default upgrade;
        '' close;
    }

    upstream netdata_backend {
        server ${C_NETDATA}:${PORT_NETDATA};
        keepalive 1024;
    }

    upstream grafana_backend {
        server ${C_GRAFANA}:${PORT_GRAFANA};
        keepalive 64;
    }

    server {
        listen 80;
${auth_block}

        # Unauthenticated metrics endpoints for fleet Prometheus scraping
        location = /metrics/netdata {
            auth_basic off;
            proxy_pass http://netdata_backend/api/v1/allmetrics?format=prometheus;
            proxy_set_header Host \$host;
        }
        location = /metrics/dcgm {
            auth_basic off;
            proxy_pass http://${C_DCGM}:${PORT_DCGM}/metrics;
            proxy_set_header Host \$host;
        }
        location = /metrics/info {
            auth_basic off;
            default_type text/plain;
            alias /data/info_metrics;
        }
        location = /metrics/balance {
            auth_basic off;
            default_type text/plain;
            alias /data/targets/balance.prom;
        }

        # Fleet discovery endpoint — serves host identity JSON (no auth)
        location = /discovery {
            auth_basic off;
            default_type application/json;
            alias /data/discovery.json;
        }

        # Default: Grafana dashboards
        location / {
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto \$scheme;
            proxy_pass http://grafana_backend;
            proxy_http_version 1.1;
            proxy_set_header Upgrade \$http_upgrade;
            proxy_set_header Connection \$connection_upgrade;

            # Hide Grafana's "Sign in" button (nginx handles auth, not Grafana)
            proxy_set_header Accept-Encoding "";
            sub_filter_once off;
            sub_filter '</head>' '<style>a[href="/login"],button[aria-label="Sign in"]{display:none!important}</style></head>';
        }

        # Netdata at /netdata/ (official subfolder proxy config)
        location = /netdata {
            return 301 /netdata/;
        }

        location ~ /netdata/(?<ndpath>.*) {
            proxy_redirect off;
            proxy_set_header Host \$host;
            proxy_set_header X-Forwarded-Host \$host;
            proxy_set_header X-Forwarded-Server \$host;
            proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
            proxy_http_version 1.1;
            proxy_pass_request_headers on;
            proxy_set_header Connection "keep-alive";
            proxy_store off;
            proxy_pass http://netdata_backend/\$ndpath\$is_args\$args;
            gzip on;
            gzip_proxied any;
            gzip_types text/plain text/css application/json application/javascript text/xml;
        }

        # Prometheus at /prometheus/
        location /prometheus/ {
            proxy_pass http://${C_PROMETHEUS}:${PORT_PROMETHEUS}/;
            proxy_set_header Host \$host;
            proxy_set_header X-Real-IP \$remote_addr;
        }
    }
}
NGINXEOF

    info "Nginx config generated."
}

# -----------------------------------------------------------------------------
# Firewall
# -----------------------------------------------------------------------------
open_firewall() {
    local public_port="$1"
    if command -v ufw >/dev/null 2>&1; then
        if sudo ufw status 2>/dev/null | grep -q "Status: active"; then
            step "UFW: allowing port ${public_port}/tcp..."
            sudo ufw allow "${public_port}"/tcp comment "NOSweb" >/dev/null 2>&1 || true
            sudo ufw reload >/dev/null 2>&1 || true
            info "UFW configured."
        fi
    fi
}

# -----------------------------------------------------------------------------
# Wait for HTTP endpoint
# -----------------------------------------------------------------------------
wait_for_http() {
    local url="$1" label="$2" max_wait="${3:-30}"
    local elapsed=0
    step "Waiting for ${label}..."
    while [ ${elapsed} -lt ${max_wait} ]; do
        if curl -s -o /dev/null -w '' "${url}" 2>/dev/null; then
            info "${label} is ready."
            return 0
        fi
        sleep 2; elapsed=$((elapsed + 2))
    done
    warn "${label} not responding after ${max_wait}s — may still be starting."
    return 1
}

container_ip() {
    docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$1" 2>/dev/null
}

# -----------------------------------------------------------------------------
# Launch containers
# -----------------------------------------------------------------------------
launch_netdata() {
    step "Pulling Netdata..."
    docker pull "${IMG_NETDATA}"

    step "Launching Netdata..."
    local -a cmd=(
        docker run -d
        --name "${C_NETDATA}"
        --hostname "nosana-$(get_hostname)"
        --restart unless-stopped
        --network "${DOCKER_NETWORK}"
        --pid=host
        --cap-add SYS_PTRACE
        --cap-add SYS_ADMIN
        --security-opt apparmor=unconfined
        -e NETDATA_DISABLE_CLOUD=1
        -v /proc:/host/proc:ro
        -v /sys:/host/sys:ro
        -v /etc/os-release:/host/etc/os-release:ro
        -v /etc/passwd:/host/etc/passwd:ro
        -v /etc/group:/host/etc/group:ro
        -v /var/log:/host/var/log:ro
        -v /etc/localtime:/etc/localtime:ro
        -v /var/run/docker.sock:/var/run/docker.sock:ro
        -v /sys/fs/cgroup:/host/sys/fs/cgroup:ro
        -v netdata-lib:/var/lib/netdata
        -v netdata-cache:/var/cache/netdata
    )

    if check_nvidia_runtime; then
        info "NVIDIA runtime detected"
        cmd+=(--gpus all)
    elif check_gpu; then
        warn "GPU found but nvidia-container-toolkit missing — direct device mount."
        for dev in /dev/nvidia0 /dev/nvidiactl /dev/nvidia-uvm /dev/nvidia-uvm-tools; do
            [ -e "$dev" ] && cmd+=(--device "${dev}:${dev}")
        done
        local smi_path
        smi_path=$(command -v nvidia-smi 2>/dev/null || true)
        [ -n "$smi_path" ] && cmd+=(-v "${smi_path}:${smi_path}:ro")
    fi

    cmd+=("${IMG_NETDATA}")
    "${cmd[@]}" && info "Netdata started." || { err "Netdata failed."; return 1; }

    local ip; ip=$(container_ip "${C_NETDATA}")
    [ -n "$ip" ] && wait_for_http "http://${ip}:${PORT_NETDATA}/api/v1/info" "Netdata" 40 || true
}

launch_dcgm() {
    if ! check_nvidia_runtime; then
        warn "NVIDIA runtime not found — skipping DCGM exporter."
        echo '[]' > "${PROM_TARGETS}/dcgm.json"
        return 0
    fi

    step "Pulling DCGM exporter..."
    if ! docker pull "${IMG_DCGM}" 2>/dev/null; then
        warn "Could not pull DCGM image — skipping."
        echo '[]' > "${PROM_TARGETS}/dcgm.json"
        return 0
    fi

    # Try with custom counters first
    step "Launching DCGM exporter..."
    docker run -d \
        --name "${C_DCGM}" \
        --restart no \
        --network "${DOCKER_NETWORK}" \
        --gpus all \
        --cap-add SYS_ADMIN \
        -v "${DCGM_COUNTERS}:/etc/dcgm-exporter/default-counters.csv:ro" \
        "${IMG_DCGM}" 2>/dev/null || true

    sleep 6
    local dcgm_ip
    dcgm_ip=$(container_ip "${C_DCGM}" 2>/dev/null)
    if [ -n "${dcgm_ip}" ] && curl -sf "http://${dcgm_ip}:9400/metrics" >/dev/null 2>&1; then
        info "DCGM exporter started (custom counters: 30 fields)."
        docker update --restart unless-stopped "${C_DCGM}" >/dev/null 2>&1
    else
        # Custom counters failed — retry with defaults
        warn "Custom counters failed. Retrying with DCGM defaults..."
        docker rm -f "${C_DCGM}" 2>/dev/null || true
        docker run -d \
            --name "${C_DCGM}" \
            --restart unless-stopped \
            --network "${DOCKER_NETWORK}" \
            --gpus all \
            --cap-add SYS_ADMIN \
            "${IMG_DCGM}" 2>/dev/null || true
        sleep 6
        dcgm_ip=$(container_ip "${C_DCGM}" 2>/dev/null)
        if [ -n "${dcgm_ip}" ] && curl -sf "http://${dcgm_ip}:9400/metrics" >/dev/null 2>&1; then
            info "DCGM exporter started (default counters)."
        else
            warn "DCGM exporter crashed — GPU may not support DCGM."
            echo '[]' > "${PROM_TARGETS}/dcgm.json"
            docker rm -f "${C_DCGM}" 2>/dev/null || true
            return 0
        fi
    fi
}

launch_prometheus() {
    step "Pulling Prometheus..."
    docker pull "${IMG_PROMETHEUS}"

    step "Launching Prometheus..."
    docker run -d \
        --name "${C_PROMETHEUS}" \
        --restart unless-stopped \
        --network "${DOCKER_NETWORK}" \
        -v "${PROM_CONF}:/etc/prometheus/prometheus.yml:ro" \
        -v "${PROM_TARGETS}:/etc/prometheus/targets:ro" \
        -v NOSweb-prometheus-data:/prometheus \
        "${IMG_PROMETHEUS}" \
        --config.file=/etc/prometheus/prometheus.yml \
        --storage.tsdb.retention.time=15d \
        --web.enable-lifecycle \
    && info "Prometheus started." || { err "Prometheus failed."; return 1; }

    local ip; ip=$(container_ip "${C_PROMETHEUS}")
    [ -n "$ip" ] && wait_for_http "http://${ip}:${PORT_PROMETHEUS}/-/ready" "Prometheus" 30 || true
}

launch_grafana() {
    step "Pulling Grafana..."
    docker pull "${IMG_GRAFANA}"

    # Home dashboard: stored preference or default to fleet-overview
    local home_dash
    home_dash=$(cat "${HOME_DASH_FILE}" 2>/dev/null || echo "fleet-overview")
    [ ! -f "${HOME_DASH_FILE}" ] && echo -n "${home_dash}" > "${HOME_DASH_FILE}"

    step "Launching Grafana..."
    docker run -d \
        --name "${C_GRAFANA}" \
        --restart unless-stopped \
        --network "${DOCKER_NETWORK}" \
        -v "${GRAFANA_PROV}:/etc/grafana/provisioning:ro" \
        -v "${GRAFANA_DASH}:/var/lib/grafana/dashboards:ro" \
        -v NOSweb-grafana-data:/var/lib/grafana \
        -e GF_AUTH_ANONYMOUS_ENABLED=true \
        -e GF_AUTH_ANONYMOUS_ORG_ROLE=Admin \
        -e GF_AUTH_DISABLE_LOGIN_FORM=true \
        -e GF_AUTH_BASIC_ENABLED=false \
        -e GF_AUTH_DISABLE_SIGNOUT_MENU=true \
        -e GF_AUTH_SIGV4_AUTH_ENABLED=false \
        -e GF_USERS_ALLOW_SIGN_UP=false \
        -e GF_SECURITY_ALLOW_EMBEDDING=true \
        -e GF_SECURITY_DISABLE_GRAVATAR=true \
        -e "GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH=/var/lib/grafana/dashboards/${home_dash}.json" \
        -e GF_USERS_DEFAULT_THEME=dark \
        -e GF_HIDE_VERSION=true \
        -e "GF_SERVER_ROOT_URL=http://localhost:${DEFAULT_PORT}/" \
        "${IMG_GRAFANA}" \
    && info "Grafana started (home: ${home_dash})." || { err "Grafana failed."; return 1; }

    local ip; ip=$(container_ip "${C_GRAFANA}")
    [ -n "$ip" ] && wait_for_http "http://${ip}:${PORT_GRAFANA}/api/health" "Grafana" 30 || true
}

launch_proxy() {
    step "Pulling Nginx..."
    docker pull "${IMG_NGINX}"

    local my_ip my_hostname my_group
    my_ip=$(get_ip)
    my_hostname=$(get_hostname)
    my_group=$(cat "${GROUP_FILE}" 2>/dev/null || echo "${DEFAULT_GROUP}")

    step "Launching proxy on port ${DEFAULT_PORT}..."
    local -a cmd=(
        docker run -d
        --name "${C_PROXY}"
        --restart unless-stopped
        --network "${DOCKER_NETWORK}"
        --entrypoint /data/entrypoint.sh
        -p "${DEFAULT_PORT}:80"
        -v "${NGINX_CONF}:/etc/nginx/nginx.conf:ro"
        -v "${PROXY_ENTRYPOINT}:/data/entrypoint.sh:ro"
        -v "${DISCOVERY_SCRIPT}:/data/discovery.sh:ro"
        -v "${INFO_METRICS}:/data/info_metrics:ro"
        -v "${GPU_WALLETS_FILE}:/data/gpu_wallets:ro"
        -v "${PEERS_FILE}:/data/peers.dat"
        -v "${SEED_PEERS_FILE}:/data/seed_peers:ro"
        -v "${PROM_TARGETS}:/data/targets"
        -e "NOSWEB_IP=${my_ip}"
        -e "NOSWEB_HOSTNAME=${my_hostname}"
        -e "NOSWEB_GROUP=${my_group}"
        -e "NOSWEB_PORT=${DEFAULT_PORT}"
        -e "NOSWEB_VERSION=${NOSWEB_VERSION}"
    )

    [ "${NOLOGIN}" = false ] && [ -f "${HTPASSWD_FILE}" ] && \
        cmd+=(-v "${HTPASSWD_FILE}:/etc/nginx/.htpasswd:ro")

    cmd+=("${IMG_NGINX}")
    "${cmd[@]}" && info "Proxy started." || { err "Proxy failed."; return 1; }

    # Verify proxy is responding (don't use -f flag — 401 is expected and valid)
    sleep 4
    local code
    code=$(curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:${DEFAULT_PORT}/" 2>/dev/null || true)

    if [ "${NOLOGIN}" = false ]; then
        if [ "${code}" = "401" ]; then
            info "Auth working — login required."
        elif [ "${code}" = "302" ] || [ "${code}" = "200" ]; then
            info "Proxy responding (HTTP ${code})."
        else
            warn "Proxy returned HTTP ${code}. Check: docker logs ${C_PROXY}"
        fi
    else
        if [ "${code}" = "200" ] || [ "${code}" = "302" ]; then
            info "Proxy responding."
        else
            warn "Proxy returned HTTP ${code}. Check: docker logs ${C_PROXY}"
        fi
    fi

    # Verify discovery sidecar
    sleep 2
    if docker logs "${C_PROXY}" 2>&1 | grep -q "\[discovery\] starting"; then
        info "Fleet discovery active (HTTP gossip via /discovery)."
    else
        warn "Discovery sidecar may not have started. Check: docker logs ${C_PROXY}"
    fi
}

# -----------------------------------------------------------------------------
# Stop / Status
# -----------------------------------------------------------------------------
do_stop() {
    step "Stopping NOSweb..."
    for c in "${C_PROXY}" "${C_GRAFANA}" "${C_PROMETHEUS}" "${C_DCGM}" "${C_NETDATA}" ${LEGACY_CONTAINERS}; do
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
    echo ""
    echo -e "${BOLD}NOSweb Status${NC}"
    echo "──────────────────────────────────────"
    if docker info &>/dev/null 2>&1; then
        echo -e "  Docker:      ${G}running${NC}"
    else
        echo -e "  Docker:      ${R}not running${NC}"
    fi
    if check_gpu; then
        echo -e "  GPU:         ${G}$(nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -1)${NC}"
    else
        echo -e "  GPU:         ${Y}not detected${NC}"
    fi
    [ -f "${GROUP_FILE}" ] && echo -e "  Group:       $(cat "${GROUP_FILE}")"
    echo ""
    for c in "${C_NETDATA}" "${C_DCGM}" "${C_PROMETHEUS}" "${C_GRAFANA}" "${C_PROXY}"; do
        local short="${c#NOSweb-}"
        local pad=$(( 14 - ${#short} ))
        if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${c}$"; then
            echo -e "  ${short}:$(printf '%*s' $pad '') ${G}running${NC}"
        elif docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^${c}$"; then
            echo -e "  ${short}:$(printf '%*s' $pad '') ${Y}stopped${NC}"
        else
            echo -e "  ${short}:$(printf '%*s' $pad '') ${R}not deployed${NC}"
        fi
    done
    local ip; ip=$(get_ip)
    echo ""
    echo -e "  Dashboard:   ${C_CLR}http://${ip:-localhost}:${DEFAULT_PORT}/${NC}"
    echo -e "  Config:      ${CONFIG_DIR}"
    echo ""
}

# -----------------------------------------------------------------------------
# Main
# -----------------------------------------------------------------------------
main() {
    local port="${DEFAULT_PORT}"
    local action="launch"
    local group_arg=""
    local home_arg=""
    local -a peer_args=()

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --port)            port="$2"; DEFAULT_PORT="$2"; shift 2 ;;
            --nologin)         NOLOGIN=true; shift ;;
            --group)           group_arg="$2"; shift 2 ;;
            --peer)            peer_args+=("$2"); shift 2 ;;
            --home)            home_arg="$2"; shift 2 ;;
            --stop)            action="stop"; shift ;;
            --status)          action="status"; shift ;;
            --reset-password)  action="reset-pw"; shift ;;
            --reset)           action="reset"; shift ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo "  --group NAME       Group name (default: Unassigned)"
                echo "  --peer IP          Cross-subnet peer (repeatable)"
                echo "  --home DASHBOARD   Home dashboard: fleet, gpu, host (default: fleet)"
                echo "  --nologin          No login required"
                echo "  --port PORT        Public port (default: ${DEFAULT_PORT})"
                echo "  --stop             Stop all containers"
                echo "  --status           Show status"
                echo "  --reset            Full reset (delete volumes, relaunch)"
                echo "  --reset-password   Change password"
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
            docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${C_PROXY}$" && \
                docker restart "${C_PROXY}" >/dev/null && info "Proxy restarted."
            exit 0
            ;;
        reset)
            step "Full reset: removing containers and data volumes..."
            cleanup_containers
            for v in NOSweb-prometheus-data NOSweb-grafana-data netdata-lib netdata-cache; do
                docker volume rm "${v}" 2>/dev/null && info "Removed volume: ${v}" || true
            done
            info "Reset complete. Relaunching..."
            echo ""
            action="launch"
            ;;
    esac

    # ── Launch ──
    echo ""
    echo -e "${BOLD}${B}  NOSweb — GPU Host Monitoring Stack${NC}"
    echo ""

    check_docker
    setup_config
    setup_group "${group_arg}"
    setup_peers "${peer_args[@]}"
    setup_wallet
    touch "${GPU_WALLETS_FILE}"
    # Home dashboard preference
    if [ -n "${home_arg}" ]; then
        case "${home_arg}" in
            fleet) echo -n "fleet-overview" > "${HOME_DASH_FILE}" ;;
            gpu)   echo -n "gpu-overview" > "${HOME_DASH_FILE}" ;;
            host)  echo -n "host-overview" > "${HOME_DASH_FILE}" ;;
            *)     warn "Unknown --home value: ${home_arg}. Use: fleet, gpu, host" ;;
        esac
    fi
    cleanup_containers
    cleanup_legacy_volumes
    ensure_network

    if [ "${NOLOGIN}" = true ]; then
        info "Mode: open access (no login)"
    else
        info "Mode: login required"
        setup_password
    fi

    echo ""
    generate_dcgm_counters
    generate_info_metrics
    generate_prometheus_config
    generate_grafana_provisioning
    generate_dashboards
    generate_nginx_conf
    generate_discovery_script
    generate_proxy_entrypoint
    echo ""

    launch_netdata;   echo ""
    launch_dcgm;      echo ""
    launch_prometheus; echo ""
    launch_grafana;    echo ""
    launch_proxy

    start_wallet_scanner

    open_firewall "${port}"

    # ── Summary ──
    local ip; ip=$(get_ip)
    echo ""
    echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
    echo -e "  ${G}${BOLD}NOSweb is running!${NC}"
    echo ""
    echo -e "  ${BOLD}Dashboard:${NC}   ${C_CLR}http://${ip:-localhost}:${port}/${NC}"
    echo ""
    if [ "${NOLOGIN}" = true ]; then
        echo -e "  ${BOLD}Mode:${NC}        Open access (no login)"
    else
        local cred_user
        cred_user=$(head -1 "${HTPASSWD_FILE}" 2>/dev/null | cut -d: -f1)
        echo -e "  ${BOLD}Mode:${NC}        Login required"
        echo -e "  ${BOLD}User:${NC}        ${G}${cred_user}${NC}"
        echo -e "  ${BOLD}Pass:${NC}        (stored in ${PASSWORD_FILE})"
    fi
    echo ""
    echo -e "  ${BOLD}Group:${NC}       $(cat "${GROUP_FILE}" 2>/dev/null || echo "${DEFAULT_GROUP}")"
    echo -e "  ${BOLD}Discovery:${NC}   HTTP gossip (auto-discover LAN + seed peers)"
    local seed_count=0
    [ -s "${SEED_PEERS_FILE}" ] && seed_count=$(grep -c . "${SEED_PEERS_FILE}" 2>/dev/null) || true
    [ "${seed_count:-0}" -gt 0 ] 2>/dev/null && echo -e "  ${BOLD}Seed peers:${NC}  ${seed_count} (cross-subnet)"
    echo -e "  ${BOLD}Config:${NC}      ${CONFIG_DIR}/"
    echo -e "  ${BOLD}Stop:${NC}        $0 --stop"
    echo -e "  ${BOLD}Status:${NC}      $0 --status"
    echo ""
    echo -e "  ${BOLD}Also available behind this URL:${NC}"
    echo -e "    /netdata/       Raw Netdata dashboard"
    echo -e "    /prometheus/    Prometheus query UI"
    echo -e "    /metrics/       Fleet metrics (no auth)"
    echo -e "    /discovery      Fleet identity (no auth)"
    echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
    echo ""
}

main "$@"

# =============================================================================
# NOSweb — Development Notes
# =============================================================================
#
# PHASE 1 (v0.01.x) — COMPLETE
#   Single-host monitoring stack. Five containers: netdata, dcgm-exporter,
#   prometheus, grafana, nginx proxy. GPU Overview dashboard (16 panels),
#   Host Overview dashboard (4 panels). Throttle detection via bitmask.
#   Prometheus self-scraping for stack resource monitoring.
#   DCGM custom counters (30 fields). Anonymous auth disabled.
#
# PHASE 2 (v0.02.x) — IN PROGRESS
#   Fleet discovery via HTTP gossip (replaced failed UDP broadcast approach).
#   Persistent peer database. Prometheus file_sd for cross-host scraping.
#   Unauthenticated /metrics/ and /discovery endpoints.
#   Fleet Overview dashboard: compact table with gauge bars per GPU.
#   Status: Discovery works. Cross-host scraping targets generated.
#   TODO: Host selector dropdown on GPU/Host Overview dashboards.
#   TODO: Deduplicate discovery logs (only log state changes).
#
# PHASE 3 (planned)
#   Fleet-wide Grafana dashboards: aggregate GPU stats across all peers.
#   Alerting: thermal throttle notifications, host-down detection.
#   Group-based filtering in dashboards.
#
# DESIGN RULES:
#   - Single file, no external dependencies
#   - Zero host installs (containers only)
#   - set -euo pipefail (strict mode)
#   - Idempotent: re-run safe, --reset for full wipe
#   - Config persists in ~/.nosana-webui/
#   - Heredoc dashboards (single-quoted), version injected via sed
#   - mktemp on same filesystem as target (avoid cross-device mv)
#   - Alpine nginx: wget only (no curl), no jq, no socat
#
# KNOWN ISSUES:
#   - /api/live/ws 403 (Grafana live WebSocket — cosmetic)
#   - nginx proxy_temp buffering warnings on large assets (cosmetic)
#   - Discovery logs "peer: X online" every 30s even if known (noisy)
#   - Fleet disk panel depends on netdata metric name family="/" — may
#     need adjustment if Netdata labels differ across versions
#
# CAVEATS & GOTCHAS (hard-won lessons — do not re-learn these):
#   DOCKER:
#   - UDP broadcast from containers stays on Docker bridge — never reaches
#     physical LAN. Port-mapping forwards unicast only. This is why we use
#     HTTP gossip instead of UDP discovery.
#   - mktemp defaults to /tmp (tmpfs). Docker volumes are a different
#     filesystem. mv across filesystems fails on Alpine ("can't rename").
#     Always: mktemp -p /data (or same dir as target file).
#   - Container names must be unique per Docker host. We prefix NOSweb-.
#   ALPINE NGINX:
#   - Has wget, NOT curl. No jq. No socat. No bash (sh only inside container).
#   - sub_filter_types text/html is the default — adding it explicitly
#     causes "duplicate MIME type" warning.
#   - gzip_types * also triggers the duplicate text/html warning.
#     Use explicit type list instead.
#   GRAFANA:
#   - Panel heights are fixed in dashboard JSON — no auto-grow/shrink.
#     Tables scroll when content exceeds panel height. Set generous h values.
#   - Anonymous auth MUST be disabled or it bypasses nginx basic auth
#     entirely. We set GF_AUTH_ANONYMOUS_ENABLED=false.
#   - Heredoc dashboards are single-quoted (no variable expansion).
#     Version and hostname must be injected via sed AFTER generation.
#   - Dashboard UIDs must be stable across re-deploys or bookmarks break.
#     We hardcode: gpu-overview, host-overview, fleet-overview.
#   - Table panel gauge cells: use custom.cellOptions.type "gauge" with
#     mode "gradient" for colored bar-in-cell. Requires Grafana 10+.
#   - Table merge transformation: all queries must share the same label
#     set (e.g. host+gpu) or columns won't align after merge.
#   DCGM:
#   - CSV counter files cannot contain comments or blank lines — the
#     parser treats them as field definitions and fails silently.
#   - Consumer GPUs (GeForce) lack profiling metrics like sm_occupancy,
#     tensor_active, pcie_replay. These return "N/A" or error.
#     We only use universally-supported fields (30 total).
#   - DCGM container needs --cap-add SYS_ADMIN and --gpus all.
#   BASH:
#   - set -euo pipefail means ANY unbound variable crashes the script.
#     Every variable must be defined or use ${VAR:-default}.
#   - wc -l output has leading whitespace on some systems. Use
#     grep -c . file instead, and wrap with ${count:-0}.
#   - Heredocs: single-quoted delimiter ('EOF') = no expansion (safe for
#     JSON with $). Unquoted delimiter (EOF) = variables expand.
#   - File-level bind mounts: mv replaces the inode, breaking the mount.
#     Use cat "$tmp" > "$target" && rm "$tmp" to preserve the inode.
#     Directory-level mounts are fine with mv (atomic rename).
#   - Prometheus runs as uid 65534 (nobody). Any file it reads via
#     bind mount must be world-readable. chmod 644 before mv.
#
# CHANGELOG:
#   0.01.00  Initial Netdata-only deployment
#   0.01.04  Grafana+Prometheus+DCGM architecture
#   0.01.10  GPU dashboard: 16 panels, throttle detection, PCIe metrics
#   0.01.12  DCGM CSV fix, power gauge scaling, fallback mechanism
#   0.01.16  Throttle redesign (Idle/OK/Throttled!), NOSweb Stack panel
#   0.02.00  Phase 2: UDP discovery (failed — Docker broadcast limitation)
#   0.02.01  HTTP gossip migration (partial — missing /discovery endpoint)
#   0.02.02  /discovery endpoint, version in dashboard titles
#   0.02.03  Fix DISCOVERY_PORT unbound variable
#   0.02.04  NOSweb Stack version label, mv cross-device fix, MIME fix
#   0.02.05  Fleet Overview dashboard: compact GPU table with gauge bars,
#            15m throttle lookback, host disk usage bar gauge panel
#   0.02.06  Fix fleet.json always empty — file bind mount inode replaced by mv
#   0.02.07  Fix fleet.json permission denied — chmod 644 for Prometheus nobody user
#   0.02.08  Fleet dashboard: GPU Model column via DCGM modelName label_replace
#   0.02.09  Wallet detection + Explorer column: Nosana wallet address from keypair,
#            /metrics/info endpoint, clickable link to explore.nosana.com
#   0.02.10  Fleet: PC/GPUid rename+reorder, Bus column (PCIe gen*100+width encoding),
#            throttle type: OK/Power/Heat/P+H, compact sizing, disk as table.
#            GPU Overview: PCIe panel uses same combined format and color scheme.
#   0.02.11  Compact panel sizing (h=8+4), --home fleet|gpu|host flag,
#            fleet-overview as default landing, throttle labels: Power/Heat.
#   0.02.12  Empty username prompt (no default), reworded setup tip,
#            fleet panel heights: GPU h=20 (~18 rows), disk h=10 (~8 hosts).
#   0.02.13  Fleet: SSD gauge column (disk per host), Explorer moved to col 1,
#            removed separate disk panel, h=14, tighter column widths.
#   0.02.14  Fleet: SSD→Storage, SOL/STK/NOS balance columns via Solana RPC.
#            Discovery script fetches wallet balances every 5m from mainnet.
#            SOL: red<0.0065, orange<0.01, green>=0.01.
#            /metrics/balance endpoint + Prometheus balance scrape jobs.
#   0.02.15  Bus: Gen1="waiting" grey. NOS: 3 decimals. Throttle OK=dark grey.
#            Temp: dark-green<78/orange<83/red>=83. Fan: dark-green<60/orange<80/red.
#            Power: orange>80/red>95. NOS RPC: retry+fallback, sed-based parsing.
#   0.02.16  Fix throttle: check ALL DCGM bits (4,128=power; 8,32,64=thermal).
#            Fix NOS parsing: revert to grep (Alpine busybox sed incompatible).
#            Stagger balance fetch by IP to avoid RPC rate limits.
#            GPU Overview: same throttle+PCIe fixes.
#   0.02.17  Balance via gossip: each host fetches own wallet only, shares
#            balances in discovery.json. Peers pick up balances over LAN.
#            Removed balance-fleet Prometheus job — no cross-host scraping.
#            peers.dat extended: ip|host|group|port|ts|status|sol|nos|stk.
#   0.02.18  Column renames: GPU Utilization, Temperature, GPU Power, Fan Speed,
#            Storage / Root. Throttle OK→"ok". SOL/STK/NOS: 0→"waiting" grey.
#            Gauges: basic mode (solid color, shorter bars at fixed widths).
#   0.02.19  Perf column (P-state P0-P12) after Bus. Footer: sum SOL/STK/NOS.
#            Info bubble: operator throttle guidance. Process col deferred (needs sidecar).
#   0.02.20  Pwr Limit=orange (normal), Heat/HW Brake=red (needs attention).
#            Explorer shows only on GPUid 0 (no repeats per host).
#            Footer: countRows + crypto sums. NOS: 0 decimals.
#   0.02.21  Pwr Limit=yellow. Explorer reverted to all rows (per-GPU wallet
#            mapping needs docker socket — not available in containers).
#            NOS back to 3 decimals (Grafana footer inherits cell formatting).
#            Combined throttle states: Brake+Pwr, Brake+Heat, Brake+Heat+Pwr.
# =============================================================================
