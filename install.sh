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

# ── Pre-flight checks ────────────────────────
info "Running pre-flight checks..."

command -v docker >/dev/null 2>&1 || error "Docker is not installed. Install it first: https://docs.docker.com/get-docker/"

# Detect docker compose: plugin syntax first, standalone fallback
if docker compose version >/dev/null 2>&1; then
    DC="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DC="docker-compose"
else
    error "Docker Compose is not installed. Install the docker-compose-plugin or standalone docker-compose."
fi

DOCKER_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")
DC_VERSION=$($DC version --short 2>/dev/null || $DC version 2>/dev/null | head -1 || echo "unknown")
info "Docker version: ${DOCKER_VERSION}"
info "Compose command: ${DC} (${DC_VERSION})"

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
    read -p "Press Enter after editing .env, or Ctrl+C to abort... "
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
