#!/usr/bin/env bash
set -euo pipefail

# ===============================================
# ORED AI SOC Employees: Quick Install
# ===============================================
# Usage:
#   git clone https://github.com/oredsecurity/ored-soc-employees.git
#   cd ored-soc-employees
#   ./install.sh
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
#   5. Enables loginctl linger so containers survive SSH disconnect
#   6. Detects compose command: "docker compose" (plugin) or "docker-compose" (standalone)
#   7. Installs Hermes (Claude Code) natively if not in PATH
#   8. Validates .env configuration
#   9. Builds and launches the MCP server container
#  10. Waits for health check

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
CYAN="\033[36m"
RESET="\033[0m"

info()  { echo -e "${GREEN}[INFO]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }

# Parse flags
for arg in "$@"; do
    case "$arg" in
        -h|--help)
            echo "Usage: ./install.sh [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  -h, --help   Show this help"
            echo ""
            echo "Installs the MCP server (Docker) and Hermes agent (native)."
            exit 0
            ;;
        *) error "Unknown option: $arg (use --help for usage)" ;;
    esac
done

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════╗"
echo "║   ORED AI SOC Employees: Installer      ║"
echo "║   Autonomous Security Operations        ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${RESET}"
echo -e "  MCP server via Docker, Hermes agent native"
echo ""

# == OS Detection ============================================
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

# == Ensure root/sudo ========================================
need_sudo() {
    if [ "$(id -u)" -eq 0 ]; then
        SUDO=""
    elif command -v sudo >/dev/null 2>&1; then
        SUDO="sudo"
    else
        error "This script needs root privileges to install packages. Run as root or install sudo."
    fi
}

# == Install Docker Engine if missing ========================
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

# == Docker command wrapper ==================================
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

# == Check if buildx version meets minimum ===================
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

# == Install missing compose/buildx plugins ==================
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
                get_latest_tag() {
                    local api_response
                    api_response=$(curl -fsSL "$1" 2>/dev/null) || true
                    echo "$api_response" | grep '"tag_name"' | head -1 | cut -d'"' -f4
                }

                for plugin in "${MISSING_PLUGINS[@]}"; do
                    if [ "$plugin" = "compose" ]; then
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

                    if [ "$plugin" = "buildx" ]; then
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

# == Install base prerequisites (curl) =======================
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

# == Install Python3 if missing ==============================
install_python3() {
    if command -v python3 >/dev/null 2>&1; then
        return 0
    fi

    info "Python3 not found. Installing..."
    need_sudo

    case "$PKG_MGR" in
        dnf|yum) $SUDO $PKG_MGR install -y python3 python3-pip python3-venv ;;
        apt)     $SUDO apt-get update -y && $SUDO apt-get install -y python3 python3-pip python3-venv ;;
        *)       error "Cannot install python3 automatically. Install it manually and re-run." ;;
    esac

    if ! command -v python3 >/dev/null 2>&1; then
        error "Python3 installation failed. Install it manually."
    fi

    info "Python3 installed."
}

# == Install Hermes (Claude Code) natively ====================
install_hermes() {
    if command -v hermes >/dev/null 2>&1; then
        local hermes_ver
        hermes_ver=$(hermes --version 2>/dev/null || echo "unknown")
        info "Hermes already installed: ${hermes_ver}"
        return 0
    fi

    info "Hermes not found. Installing natively..."

    # Ensure Python3 is available
    install_python3

    # Ensure git is available
    if ! command -v git >/dev/null 2>&1; then
        info "Installing git..."
        need_sudo
        case "$PKG_MGR" in
            dnf|yum) $SUDO $PKG_MGR install -y git ;;
            apt)     $SUDO apt-get update -y && $SUDO apt-get install -y git ;;
            *)       error "Cannot install git automatically. Install it manually and re-run." ;;
        esac
    fi

    local HERMES_DIR="${HOME}/.hermes/hermes-agent"

    # Clone if not already present
    if [ ! -d "$HERMES_DIR" ]; then
        info "Cloning Hermes Agent..."
        mkdir -p "${HOME}/.hermes"
        git clone https://github.com/NousResearch/hermes-agent.git "$HERMES_DIR"
    else
        info "Hermes source already cloned, pulling latest..."
        git -C "$HERMES_DIR" pull || warn "Could not pull latest, using existing source."
    fi

    # Create venv and install
    info "Setting up Python virtual environment..."
    cd "$HERMES_DIR"
    python3 -m venv venv
    ./venv/bin/pip install --upgrade pip
    ./venv/bin/pip install -e .
    cd - >/dev/null

    # Create symlink
    mkdir -p "${HOME}/.local/bin"
    ln -sf "${HERMES_DIR}/venv/bin/hermes" "${HOME}/.local/bin/hermes"

    # Ensure ~/.local/bin is in PATH for verification
    export PATH="${HOME}/.local/bin:${PATH}"

    # Verify
    if command -v hermes >/dev/null 2>&1; then
        local hermes_ver
        hermes_ver=$(hermes --version 2>/dev/null || echo "unknown")
        info "Hermes installed successfully: ${hermes_ver}"
    else
        warn "Hermes installed but not found in PATH."
        warn "Add this to your shell profile: export PATH=\"\${HOME}/.local/bin:\${PATH}\""
    fi
}

# == Enable linger for current user ==========================
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

# ============================================================
# Main installation flow
# ============================================================

info "Running pre-flight checks..."
detect_os

# Step 1: Base prerequisites
install_prereqs

# Step 2: Ensure Docker Engine is present
if ! command -v docker >/dev/null 2>&1; then
    install_docker
fi

# Step 3: Ensure compose and buildx plugins are present
install_docker_plugins

# Step 4: Enable linger so containers survive SSH disconnect
enable_linger

# Step 5: Determine if sudo is needed for docker commands
DOCKER="docker"
if ! docker version >/dev/null 2>&1; then
    if [ "$(id -u)" -ne 0 ] && sudo docker version >/dev/null 2>&1; then
        DOCKER="sudo docker"
        info "Using sudo for docker (group membership will apply on next login)."
    fi
fi

# Step 6: Detect compose command (plugin should be installed by now, standalone as fallback)
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

# Step 7: Install Hermes (Claude Code) natively
install_hermes

# == Environment setup =======================================
if [ ! -f .env ]; then
    info "Creating .env from template..."
    cp .env.example .env
    warn ".env created. You MUST edit it with your credentials before continuing."
    echo ""
    warn "Required:"
    warn "  WAZUH_HOST              Your Wazuh manager URL"
    warn "  WAZUH_USER              Wazuh API username"
    warn "  WAZUH_PASS              Wazuh API password"
    echo ""
    read -rp "Press Enter after editing .env, or Ctrl+C to abort... "
else
    info ".env already exists, using existing configuration."
fi

# == Validate required vars ==================================
source .env 2>/dev/null || true

[ -z "${WAZUH_HOST:-}" ] && error "WAZUH_HOST is not set in .env"
[ -z "${WAZUH_USER:-}" ] && error "WAZUH_USER is not set in .env"
[ -z "${WAZUH_PASS:-}" ] && error "WAZUH_PASS is not set in .env"
[ "${WAZUH_PASS:-}" = "CHANGE_ME" ] && error "WAZUH_PASS is still set to CHANGE_ME, update it in .env"

info "Environment validated."

# == Build & Launch ==========================================
info "Building MCP server container..."
$DC up -d --build

echo ""
info "Waiting for MCP server health check..."
sleep 5

# Check health
if $DC exec wazuh-mcp curl -sf http://localhost:3000/health >/dev/null 2>&1; then
    info "MCP server is healthy."
else
    warn "MCP server health check pending, it may still be starting."
    warn "Check status with: $DC logs wazuh-mcp"
fi

echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${GREEN}  ORED SOC Employees: Install Complete${RESET}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════${RESET}"
echo ""
echo "  MCP Server:  http://localhost:${MCP_PORT:-3000}"
echo "  Health:      http://localhost:${MCP_PORT:-3000}/health"
echo "  Logs:        $DC logs -f"
echo ""
echo "  Useful commands:"
echo "    $DC logs -f wazuh-mcp        # MCP server logs"
echo "    $DC restart                  # Restart MCP server"
echo "    $DC down                     # Stop MCP server"
echo ""
echo -e "  ${CYAN}Next steps:${RESET}"
echo "    1. Provision a tenant profile:"
echo "       ./scripts/provision-tenant.sh <client-slug> --wazuh-url <url> --wazuh-pass <pass> --llm-api-key <key>"
echo ""
echo "    2. Start Hermes with the profile:"
echo "       hermes --profile <client-slug>"
echo ""
echo "    Ensure ~/.local/bin is in your PATH:"
echo "      export PATH=\"\${HOME}/.local/bin:\${PATH}\""
echo ""
