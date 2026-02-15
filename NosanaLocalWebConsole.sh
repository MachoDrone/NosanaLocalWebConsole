#!/usr/bin/env bash
# Usage: bash <(wget -qO- https://raw.githubusercontent.com/MachoDrone/NosanaLocalWebConsole/refs/heads/main/NosanaLocalWebConsole.sh)
echo "v0.01.12"
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
    echo ""
    local default_user
    default_user=$(whoami)
    read -rp "  Username [${default_user}]: " input_user
    local auth_user="${input_user:-${default_user}}"
    echo ""
    echo "  Enter the password you want for the WebUI."
    echo "  (Tip: use your Ubuntu login password so you don't forget it.)"
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
  "version": 3,
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
      "gridPos": {"h": 6, "w": 6, "x": 0, "y": 6},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [{"refId": "A", "expr": "max by (gpu)(DCGM_FI_DEV_FAN_SPEED)", "legendFormat": "GPU {{gpu}}"}],
      "fieldConfig": {"defaults": {"unit": "percent", "decimals": 0, "min": 0, "max": 100,
        "thresholds": {"mode": "absolute", "steps": [
          {"value": null, "color": "green"}, {"value": 60, "color": "yellow"}, {"value": 85, "color": "red"}
        ]}}}
    },
    {
      "id": 13, "type": "stat", "title": "Throttle Status",
      "description": "SW = software power cap (bit 0x4). HW = hardware thermal slowdown (bit 0x8). Uses real-time DCGM bitmask.",
      "gridPos": {"h": 6, "w": 6, "x": 6, "y": 6},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [
        {"refId": "A", "expr": "clamp_max(max by (gpu)(DCGM_FI_DEV_CLOCK_THROTTLE_REASONS) / 4 % 2, 1)", "legendFormat": "GPU {{gpu}} SW"},
        {"refId": "B", "expr": "clamp_max(max by (gpu)(DCGM_FI_DEV_CLOCK_THROTTLE_REASONS) / 8 % 2, 1)", "legendFormat": "GPU {{gpu}} HW"}
      ],
      "fieldConfig": {"defaults": {
        "noValue": "OK",
        "mappings": [
          {"type": "value", "options": {"0": {"text": "OK", "color": "green"}}},
          {"type": "value", "options": {"1": {"text": "ACTIVE", "color": "red"}}}
        ],
        "thresholds": {"mode": "absolute", "steps": [
          {"value": null, "color": "green"}, {"value": 1, "color": "red"}
        ]}}},
      "options": {"graphMode": "none", "colorMode": "background", "textMode": "auto", "reduceOptions": {"calcs": ["lastNotNull"]}}
    },
    {
      "id": 14, "type": "stat", "title": "PCIe Link",
      "description": "Current negotiated PCIe generation and lane width. Gen drops at idle (ASPM power saving).",
      "gridPos": {"h": 6, "w": 6, "x": 12, "y": 6},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [
        {"refId": "A", "expr": "max by (gpu)(DCGM_FI_DEV_PCIE_LINK_GEN)", "legendFormat": "GPU {{gpu}} Gen"},
        {"refId": "B", "expr": "max by (gpu)(DCGM_FI_DEV_PCIE_LINK_WIDTH)", "legendFormat": "GPU {{gpu}} x"}
      ],
      "fieldConfig": {"defaults": {"decimals": 0, "noValue": "N/A",
        "thresholds": {"mode": "absolute", "steps": [
          {"value": null, "color": "blue"}
        ]}}},
      "options": {"graphMode": "none", "colorMode": "value", "textMode": "auto", "reduceOptions": {"calcs": ["lastNotNull"]}}
    },
    {
      "id": 17, "type": "gauge", "title": "Encoder / Decoder",
      "gridPos": {"h": 6, "w": 6, "x": 18, "y": 6},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [
        {"refId": "A", "expr": "max by (gpu)(DCGM_FI_DEV_ENC_UTIL)", "legendFormat": "GPU {{gpu}} Enc"},
        {"refId": "B", "expr": "max by (gpu)(DCGM_FI_DEV_DEC_UTIL)", "legendFormat": "GPU {{gpu}} Dec"}
      ],
      "fieldConfig": {"defaults": {"unit": "percent", "decimals": 0, "min": 0, "max": 100,
        "thresholds": {"mode": "absolute", "steps": [
          {"value": null, "color": "green"}, {"value": 70, "color": "yellow"}, {"value": 90, "color": "red"}
        ]}}}
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
      "description": "SW = software power cap. HW = hardware thermal. Bitmask bits 0x4 and 0x8. Value of 1 = actively throttling.",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 28},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [
        {"refId": "A", "expr": "clamp_max(max by (gpu)(DCGM_FI_DEV_CLOCK_THROTTLE_REASONS) / 4 % 2, 1)", "legendFormat": "GPU {{gpu}} SW (power)"},
        {"refId": "B", "expr": "clamp_max(max by (gpu)(DCGM_FI_DEV_CLOCK_THROTTLE_REASONS) / 8 % 2, 1)", "legendFormat": "GPU {{gpu}} HW (thermal)"}
      ],
      "fieldConfig": {"defaults": {"decimals": 0, "min": 0, "max": 1, "color": {"mode": "palette-classic"},
        "custom": {"lineWidth": 2, "fillOpacity": 50, "spanNulls": true, "drawStyle": "bars"},
        "mappings": [
          {"type": "value", "options": {"0": {"text": "OK"}}},
          {"type": "value", "options": {"1": {"text": "THROTTLE"}}}
        ]}}
    },
    {
      "id": 10, "type": "timeseries", "title": "PCIe Throughput",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 36},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [
        {"refId": "A", "expr": "max by (gpu)(rate(DCGM_FI_DEV_PCIE_TX_THROUGHPUT[2m]))", "legendFormat": "GPU {{gpu}} TX"},
        {"refId": "B", "expr": "max by (gpu)(rate(DCGM_FI_DEV_PCIE_RX_THROUGHPUT[2m]))", "legendFormat": "GPU {{gpu}} RX"}
      ],
      "fieldConfig": {"defaults": {"unit": "KBs", "decimals": 0, "color": {"mode": "palette-classic"},
        "custom": {"lineWidth": 2, "fillOpacity": 15, "spanNulls": true}}}
    },
    {
      "id": 16, "type": "timeseries", "title": "Fan Speed Over Time",
      "gridPos": {"h": 8, "w": 12, "x": 12, "y": 36},
      "datasource": {"type": "prometheus", "uid": "prometheus"},
      "targets": [{"refId": "A", "expr": "max by (gpu)(DCGM_FI_DEV_FAN_SPEED)", "legendFormat": "GPU {{gpu}}"}],
      "fieldConfig": {"defaults": {"unit": "percent", "decimals": 0, "min": 0, "max": 100, "color": {"mode": "palette-classic"},
        "custom": {"lineWidth": 2, "fillOpacity": 15, "spanNulls": true}}}
    },
    {
      "id": 18, "type": "timeseries", "title": "PCIe Link Speed Over Time",
      "description": "PCIe generation and lane width. Drops at idle due to ASPM power saving.",
      "gridPos": {"h": 8, "w": 12, "x": 0, "y": 44},
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

generate_dashboards() {
    generate_gpu_dashboard
    generate_host_dashboard
    info "Grafana dashboards generated."
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
            sub_filter_types text/html;
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
            gzip_types *;
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
            step "UFW: allowing port ${public_port}..."
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
        -e GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH=/var/lib/grafana/dashboards/gpu-overview.json \
        -e GF_USERS_DEFAULT_THEME=dark \
        -e GF_HIDE_VERSION=true \
        -e "GF_SERVER_ROOT_URL=http://localhost:${DEFAULT_PORT}/" \
        "${IMG_GRAFANA}" \
    && info "Grafana started." || { err "Grafana failed."; return 1; }

    local ip; ip=$(container_ip "${C_GRAFANA}")
    [ -n "$ip" ] && wait_for_http "http://${ip}:${PORT_GRAFANA}/api/health" "Grafana" 30 || true
}

launch_proxy() {
    step "Pulling Nginx..."
    docker pull "${IMG_NGINX}"

    step "Launching proxy on port ${DEFAULT_PORT}..."
    local -a cmd=(
        docker run -d
        --name "${C_PROXY}"
        --restart unless-stopped
        --network "${DOCKER_NETWORK}"
        -p "${DEFAULT_PORT}:80"
        -v "${NGINX_CONF}:/etc/nginx/nginx.conf:ro"
    )

    [ "${NOLOGIN}" = false ] && [ -f "${HTPASSWD_FILE}" ] && \
        cmd+=(-v "${HTPASSWD_FILE}:/etc/nginx/.htpasswd:ro")

    cmd+=("${IMG_NGINX}")
    "${cmd[@]}" && info "Proxy started." || { err "Proxy failed."; return 1; }

    # Verify proxy is responding (don't use -f flag — 401 is expected and valid)
    sleep 2
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

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --port)            port="$2"; DEFAULT_PORT="$2"; shift 2 ;;
            --nologin)         NOLOGIN=true; shift ;;
            --group)           group_arg="$2"; shift 2 ;;
            --stop)            action="stop"; shift ;;
            --status)          action="status"; shift ;;
            --reset-password)  action="reset-pw"; shift ;;
            --reset)           action="reset"; shift ;;
            --help|-h)
                echo "Usage: $0 [OPTIONS]"
                echo "  --group NAME       Group name (default: Unassigned)"
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
    generate_prometheus_config
    generate_grafana_provisioning
    generate_dashboards
    generate_nginx_conf
    echo ""

    launch_netdata;   echo ""
    launch_dcgm;      echo ""
    launch_prometheus; echo ""
    launch_grafana;    echo ""
    launch_proxy

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
    echo -e "  ${BOLD}Config:${NC}      ${CONFIG_DIR}/"
    echo -e "  ${BOLD}Stop:${NC}        $0 --stop"
    echo -e "  ${BOLD}Status:${NC}      $0 --status"
    echo ""
    echo -e "  ${BOLD}Also available behind this URL:${NC}"
    echo -e "    /netdata/       Raw Netdata dashboard"
    echo -e "    /prometheus/    Prometheus query UI"
    echo -e "${BOLD}════════════════════════════════════════════════════════${NC}"
    echo ""
}

main "$@"
