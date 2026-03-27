#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════
# ORED AI SOC Employees — Quick Install
# ═══════════════════════════════════════════════
# Usage:
#   git clone https://github.com/oredsecurity/ored-soc-employees.git
#   cd ored-soc-employees
#
#   ./install.sh              # Full stack: MCP server + Hermes agent
#   ./install.sh --mcp-only   # MCP server only (Hermes installed natively)
#
# Supported distros:
#   - Amazon Linux 2023 (dnf)
#   - Ubuntu 20.04 / 22.04 / 24.04 (apt)
#   - Debian 11 / 12 (apt)
#   - Any distro with Docker CE + compose plugin already installed
#
# Prerequisites (install before running this script):
#   - git and curl: sudo dnf install -y git curl   (Amazon Linux)
#                   sudo apt install -y git curl    (Ubuntu/Debian)
#
# What this script handles automatically:
#   1. Detects OS and package manager (dnf/yum vs apt)
#   2. Installs curl if missing
#   3. Installs Docker Engine if missing
#   4. Installs docker-compose-plugin and docker-buildx-plugin if missing
#      (Amazon Linux ships Docker CE without these)
#   5. Enables loginctl linger so containers survive SSH disconnect
#   6. Detects compose command: "docker compose" (plugin) or "docker-compose" (standalone)
#   7. Validates .env configuration
#   8. Builds and launches the stack

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
CYAN="\033[36m"
RESET="\033[0m"

info()  { echo -e "${GREEN}[INFO]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }

# ── Parse flags ─────────────────────────────
MCP_ONLY=false
for arg in "$@"; do
    case "$arg" in
        --mcp-only) MCP_ONLY=true ;;
        -h|--help)
            echo "Usage: ./install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --mcp-only   Run MCP server only (for hosts with Hermes installed natively)"
            echo "  -h, --help   Show this help"
            echo ""
            echo "Modes:"
            echo "  Full stack:  ./install.sh            Runs wazuh-mcp-server + hermes-agent"
            echo "  MCP only:    ./install.sh --mcp-only  Runs wazuh-mcp-server only"
            exit 0
            ;;
        *) error "Unknown option: $arg (use --help for usage)" ;;
    esac
done

if [ "$MCP_ONLY" = true ]; then
    MODE_LABEL="MCP Server Only"
    MODE_DESC="Hermes agent will NOT be started (assumes native install on host)"
else
    MODE_LABEL="Full Stack"
    MODE_DESC="MCP server + Hermes agent containers"
fi

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════╗"
echo "║   ORED AI SOC Employees — Installer     ║"
echo "║   Autonomous Security Operations        ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${RESET}"
echo -e "  Mode: ${CYAN}${MODE_LABEL}${RESET}"
echo -e "  ${MODE_DESC}"
echo ""

# ── OS Detection ──────────────────────────────
detect_os() {
    if [ -f /etc/os-release ]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-unknown}"
        OS_NAME="${PRETTY_NAME:-unknown}"
    else
        OS_ID="unknown"
        OS_VERSION="unknown"
        OS_NAME="unknown"
    fi

    # Determine package manager
    if command -v dnf >/dev/null 2>&1; then
        PKG_MGR="dnf"
    elif command -v yum >/dev/null 2>&1; then
        PKG_MGR="yum"
    elif command -v apt-get >/dev/null 2>&1; then
        PKG_MGR="apt"
    else
        PKG_MGR="unknown"
    fi

    info "OS: ${OS_NAME} (${OS_ID} ${OS_VERSION})"
    info "Package manager: ${PKG_MGR}"
}

# ── Ensure root/sudo ─────────────────────────
need_sudo() {
    if [ "$(id -u)" -eq 0 ]; then
        SUDO=""
    elif command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        error "This script needs root privileges to install packages. Run as root or install sudo."
    fi
}

# ── Install Docker Engine if missing ──────────
install_docker() {
    info "Docker not found. Installing Docker Engine..."
    need_sudo

    case "$PKG_MGR" in
        dnf|yum)
            # Amazon Linux 2023 / RHEL / Fedora
            $SUDO $PKG_MGR install -y docker
            $SUDO systemctl enable --now docker
            ;;
        apt)
            # Ubuntu / Debian: install from Docker's official repo
            $SUDO apt-get update -y
            $SUDO apt-get install -y ca-certificates curl gnupg

            # Add Docker GPG key
            $SUDO install -m 0755 -d /etc/apt/keyrings
            if [ ! -f /etc/apt/keyrings/docker.gpg ]; then
                curl -fsSL "https://download.docker.com/linux/${OS_ID}/gpg" \
                    | $SUDO gpg --dearmor -o /etc/apt/keyrings/docker.gpg
                $SUDO chmod a+r /etc/apt/keyrings/docker.gpg
            fi

            # Add Docker repo
            if [ ! -f /etc/apt/sources.list.d/docker.list ]; then
                echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/${OS_ID} $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
                    | $SUDO tee /etc/apt/sources.list.d/docker.list > /dev/null
            fi

            $SUDO apt-get update -y
            $SUDO apt-get install -y docker-ce docker-ce-cli containerd.io \
                docker-buildx-plugin docker-compose-plugin
            ;;
        *)
            error "Unsupported package manager: ${PKG_MGR}. Install Docker manually: https://docs.docker.com/get-docker/"
            ;;
    esac

    # Add current user to docker group (non-root)
    if [ "$(id -u)" -ne 0 ]; then
        if ! groups | grep -q docker; then
            $SUDO usermod -aG docker "$USER"
            info "Added $USER to docker group."
        fi
    fi

    info "Docker installed successfully."
}

# ── Docker command wrapper ────────────────────
# After installing Docker + adding user to docker group, the current
# shell doesn't have the new group yet. Use sudo as fallback when
# the socket isn't accessible.
docker_cmd() {
    if docker "$@" 2>/dev/null; then
        return 0
    elif [ "$(id -u)" -ne 0 ] && command -v sudo >/dev/null 2>&1; then
        sudo docker "$@"
    else
        docker "$@"
    fi
}

# ── Check if buildx version meets minimum ─────
# compose v5+ requires buildx >= 0.17.0
buildx_too_old() {
    local MIN_MAJOR=0 MIN_MINOR=17
    local version_str
    version_str=$(docker_cmd buildx version 2>/dev/null | grep -oE '[0-9]+\.[0-9]+\.[0-9]+' | head -1)
    if [ -z "$version_str" ]; then
        return 0  # missing = too old
    fi
    local major minor
    major=$(echo "$version_str" | cut -d. -f1)
    minor=$(echo "$version_str" | cut -d. -f2)
    if [ "$major" -gt "$MIN_MAJOR" ]; then
        return 1  # newer major = fine
    elif [ "$major" -eq "$MIN_MAJOR" ] && [ "$minor" -ge "$MIN_MINOR" ]; then
        return 1  # meets minimum
    fi
    return 0  # too old
}

# ── Install missing compose/buildx plugins ────
install_docker_plugins() {
    local MISSING_PLUGINS=()

    if ! docker_cmd compose version >/dev/null 2>&1; then
        MISSING_PLUGINS+=("compose")
    fi

    if ! docker_cmd buildx version >/dev/null 2>&1 || buildx_too_old; then
        MISSING_PLUGINS+=("buildx")
    fi

    if [ ${#MISSING_PLUGINS[@]} -eq 0 ]; then
        return 0
    fi

    info "Missing or outdated Docker plugins: ${MISSING_PLUGINS[*]}. Installing..."
    need_sudo

    case "$PKG_MGR" in
        dnf|yum)
            # Amazon Linux 2023: Docker CE from amazon repo lacks compose/buildx.
            # Install plugins from Docker's official repo or direct download.

            # Try package install first (works if Docker official repo is configured)
            local PKG_INSTALL_OK=true
            for plugin in "${MISSING_PLUGINS[@]}"; do
                if ! $SUDO $PKG_MGR install -y "docker-${plugin}-plugin" 2>/dev/null; then
                    PKG_INSTALL_OK=false
                    break
                fi
            done

            # Fallback: direct binary install from GitHub releases
            if [ "$PKG_INSTALL_OK" = false ]; then
                warn "Package install failed, downloading plugins directly..."
                local ARCH
                ARCH=$(uname -m)
                case "$ARCH" in
                    x86_64)  ARCH="x86_64" ;;
                    aarch64) ARCH="aarch64" ;;
                    *) error "Unsupported architecture: ${ARCH}" ;;
                esac

                local CLI_PLUGINS_DIR="/usr/local/lib/docker/cli-plugins"
                $SUDO mkdir -p "$CLI_PLUGINS_DIR"

                # Helper: fetch latest GitHub release tag without triggering
                # broken-pipe errors under set -o pipefail.
                # curl | grep | head causes curl to get SIGPIPE when head exits.
                # Instead, capture full output first, then parse.
                get_latest_tag() {
                    local api_response
                    api_response=$(curl -fsSL "$1" 2>/dev/null) || true
                    echo "$api_response" | grep '"tag_name"' | head -1 | cut -d'"' -f4
                }

                for plugin in "${MISSING_PLUGINS[@]}"; do
                    if [ "$plugin" = "compose" ] && ! docker compose version >/dev/null 2>&1; then
                        info "Downloading docker-compose plugin..."
                        local COMPOSE_VERSION
                        COMPOSE_VERSION=$(get_latest_tag "https://api.github.com/repos/docker/compose/releases/latest")
                        if [ -z "$COMPOSE_VERSION" ]; then
                            COMPOSE_VERSION="v2.36.1"
                            warn "Could not detect latest compose version, using ${COMPOSE_VERSION}"
                        fi
                        # compose release URLs use x86_64/aarch64
                        curl -fsSL "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-linux-${ARCH}" \
                            -o /tmp/docker-compose
                        $SUDO mv /tmp/docker-compose "${CLI_PLUGINS_DIR}/docker-compose"
                        $SUDO chmod +x "${CLI_PLUGINS_DIR}/docker-compose"
                        info "docker-compose plugin ${COMPOSE_VERSION} installed."
                    fi

                    if [ "$plugin" = "buildx" ] && ! docker buildx version >/dev/null 2>&1; then
                        info "Downloading docker-buildx plugin..."
                        local BUILDX_VERSION
                        BUILDX_VERSION=$(get_latest_tag "https://api.github.com/repos/docker/buildx/releases/latest")
                        if [ -z "$BUILDX_VERSION" ]; then
                            BUILDX_VERSION="v0.24.0"
                            warn "Could not detect latest buildx version, using ${BUILDX_VERSION}"
                        fi
                        local BUILDX_ARCH
                        case "$ARCH" in
                            x86_64)  BUILDX_ARCH="amd64" ;;
                            aarch64) BUILDX_ARCH="arm64" ;;
                        esac
                        curl -fsSL "https://github.com/docker/buildx/releases/download/${BUILDX_VERSION}/buildx-${BUILDX_VERSION}.linux-${BUILDX_ARCH}" \
                            -o /tmp/docker-buildx
                        $SUDO mv /tmp/docker-buildx "${CLI_PLUGINS_DIR}/docker-buildx"
                        $SUDO chmod +x "${CLI_PLUGINS_DIR}/docker-buildx"
                        info "docker-buildx plugin ${BUILDX_VERSION} installed."
                    fi
                done
            fi
            ;;
        apt)
            # Ubuntu / Debian: install from Docker's official repo
            $SUDO apt-get update -y
            for plugin in "${MISSING_PLUGINS[@]}"; do
                $SUDO apt-get install -y "docker-${plugin}-plugin"
            done
            ;;
        *)
            error "Cannot auto-install Docker plugins on ${PKG_MGR}. Install docker-compose-plugin and docker-buildx-plugin manually."
            ;;
    esac

    # Verify
    for plugin in "${MISSING_PLUGINS[@]}"; do
        if [ "$plugin" = "compose" ] && ! docker_cmd compose version >/dev/null 2>&1; then
            error "docker-compose-plugin installation failed. Install manually."
        fi
        if [ "$plugin" = "buildx" ] && ! docker_cmd buildx version >/dev/null 2>&1; then
            error "docker-buildx-plugin installation failed. Install manually."
        fi
    done

    info "Docker plugins installed successfully."
}

# ── Install base prerequisites (curl) ─────────
install_prereqs() {
    local NEED_INSTALL=false

    if ! command -v curl >/dev/null 2>&1; then
        NEED_INSTALL=true
    fi

    if [ "$NEED_INSTALL" = true ]; then
        info "Installing prerequisites (curl)..."
        need_sudo
        case "$PKG_MGR" in
            dnf|yum) $SUDO $PKG_MGR install -y curl ;;
            apt)     $SUDO apt-get update -y && $SUDO apt-get install -y curl ;;
            *)       error "Cannot install curl automatically. Install it manually and re-run." ;;
        esac
    fi
}

# ── Enable linger for current user ────────────
# Without linger, systemd kills user processes (including containers)
# when the SSH session disconnects. This makes containers persistent.
enable_linger() {
    # Only relevant for non-root users with systemd
    if [ "$(id -u)" -eq 0 ]; then
        return 0
    fi

    if ! command -v loginctl >/dev/null 2>&1; then
        return 0
    fi

    # Check if linger is already enabled
    if loginctl show-user "$USER" --property=Linger 2>/dev/null | grep -q "Linger=yes"; then
        return 0
    fi

    info "Enabling loginctl linger for ${USER} (keeps containers running after SSH disconnect)..."
    need_sudo
    $SUDO loginctl enable-linger "$USER"
    info "Linger enabled."
}

# ── Pre-flight checks ────────────────────────
info "Running pre-flight checks..."
detect_os

# Step 0: Base prerequisites
install_prereqs

# Step 1: Ensure Docker Engine is present
if ! command -v docker >/dev/null 2>&1; then
    install_docker
fi

# Step 2: Ensure compose and buildx plugins are present
install_docker_plugins

# Step 3: Enable linger so containers survive SSH disconnect
enable_linger

# Step 4: Determine if sudo is needed for docker commands
# (user may have been added to docker group but current shell doesn't have it yet)
DOCKER="docker"
if ! docker version >/dev/null 2>&1; then
    if [ "$(id -u)" -ne 0 ] && sudo docker version >/dev/null 2>&1; then
        DOCKER="sudo docker"
        info "Using sudo for docker (group membership will apply on next login)."
    fi
fi

# Step 5: Detect compose command (plugin should be installed by now, standalone as fallback)
if $DOCKER compose version >/dev/null 2>&1; then
    DC="$DOCKER compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DC="docker-compose"
else
    error "Docker Compose is not available. This should not happen after plugin install."
fi

DOCKER_VERSION=$($DOCKER version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")
DC_VERSION=$($DC version --short 2>/dev/null || $DC version 2>/dev/null | head -1 || echo "unknown")
BUILDX_VERSION=$($DOCKER buildx version 2>/dev/null | head -1 || echo "unknown")
info "Docker version: ${DOCKER_VERSION}"
info "Compose: ${DC} (${DC_VERSION})"
info "Buildx: ${BUILDX_VERSION}"

# ── Environment setup ────────────────────────
if [ ! -f .env ]; then
    info "Creating .env from template..."
    cp .env.example .env
    warn ".env created. You MUST edit it with your credentials before continuing."
    echo ""
    warn "Required:"
    warn "  WAZUH_HOST     — Your Wazuh manager URL"
    warn "  WAZUH_USER     — Wazuh API username"
    warn "  WAZUH_PASS     — Wazuh API password"
    if [ "$MCP_ONLY" = false ]; then
        warn "  LLM_API_KEY    — API key for your LLM provider"
    fi
    echo ""
    read -rp "Press Enter after editing .env, or Ctrl+C to abort... "
else
    info ".env already exists, using existing configuration."
fi

# ── Validate required vars ───────────────────
source .env 2>/dev/null || true

[ -z "${WAZUH_HOST:-}" ] && error "WAZUH_HOST is not set in .env"
[ -z "${WAZUH_USER:-}" ] && error "WAZUH_USER is not set in .env"
[ -z "${WAZUH_PASS:-}" ] && error "WAZUH_PASS is not set in .env"
[ "${WAZUH_PASS:-}" = "CHANGE_ME" ] && error "WAZUH_PASS is still set to CHANGE_ME — update it in .env"

if [ "$MCP_ONLY" = false ]; then
    [ -z "${LLM_API_KEY:-}" ] && error "LLM_API_KEY is not set in .env (required for full-stack mode)"
    [ "${LLM_API_KEY:-}" = "***" ] && error "LLM_API_KEY is still the placeholder — update it in .env"
fi

info "Environment validated."

# ── Build & Launch ───────────────────────────
if [ "$MCP_ONLY" = true ]; then
    info "Building MCP server container..."
    $DC build wazuh-mcp-server

    info "Starting MCP server..."
    $DC up -d wazuh-mcp-server
else
    info "Building containers..."
    $DC --profile full build

    info "Starting services..."
    $DC --profile full up -d
fi

echo ""
info "Waiting for MCP server health check..."
sleep 5

# Check health
if $DC exec wazuh-mcp-server curl -sf http://localhost:3000/health >/dev/null 2>&1; then
    info "MCP server is healthy."
else
    warn "MCP server health check pending — it may still be starting."
    warn "Check status with: $DC logs wazuh-mcp-server"
fi

echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════${RESET}"
if [ "$MCP_ONLY" = true ]; then
    echo -e "${BOLD}${GREEN}  ORED MCP Server is running!${RESET}"
else
    echo -e "${BOLD}${GREEN}  ORED AI SOC Employee is running!${RESET}"
fi
echo -e "${BOLD}${GREEN}════════════════════════════════════════════${RESET}"
echo ""
echo "  MCP Server:  http://localhost:${MCP_PORT:-3000}"
echo "  Health:      http://localhost:${MCP_PORT:-3000}/health"
echo "  Logs:        $DC logs -f"
echo ""
echo "  Useful commands:"
echo "    $DC logs -f wazuh-mcp-server  # MCP server logs"
if [ "$MCP_ONLY" = false ]; then
    echo "    $DC logs -f hermes-agent       # Agent logs"
fi
echo "    $DC restart                    # Restart all"
echo "    $DC down                       # Stop all"
echo ""
if [ "$MCP_ONLY" = true ]; then
    echo "  To connect your native Hermes instance:"
    echo "    Add to ~/.hermes/config.yaml under mcp_servers:"
    echo "      wazuh:"
    echo "        url: http://localhost:${MCP_PORT:-3000}/mcp"
    echo ""
fi
