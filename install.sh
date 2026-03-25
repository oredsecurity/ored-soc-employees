#!/usr/bin/env bash
set -euo pipefail

# ═══════════════════════════════════════════════
# ORED AI SOC Employees — Quick Install
# ═══════════════════════════════════════════════
# Usage:
#   git clone https://github.com/oredsecurity/ored-soc-employees.git
#   cd ored-soc-employees
#   ./install.sh

BOLD="\033[1m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

info()  { echo -e "${GREEN}[INFO]${RESET} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${RESET} $*"; }
error() { echo -e "${RED}[ERROR]${RESET} $*"; exit 1; }

echo -e "${BOLD}"
echo "╔══════════════════════════════════════════╗"
echo "║   ORED AI SOC Employees — Installer     ║"
echo "║   Autonomous Security Operations        ║"
echo "╚══════════════════════════════════════════╝"
echo -e "${RESET}"

# ── Pre-flight checks ────────────────────────
info "Running pre-flight checks..."

command -v docker >/dev/null 2>&1 || error "Docker is not installed. Install it first: https://docs.docker.com/get-docker/"
command -v docker compose >/dev/null 2>&1 || command -v docker-compose >/dev/null 2>&1 || error "Docker Compose is not installed."

DOCKER_VERSION=$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo "unknown")
info "Docker version: ${DOCKER_VERSION}"

# ── Environment setup ────────────────────────
if [ ! -f .env ]; then
    info "Creating .env from template..."
    cp .env.example .env
    warn ".env created — you MUST edit it with your Wazuh credentials and API keys."
    warn "  Open .env in your editor and fill in the REQUIRED fields."
    echo ""
    warn "Required:"
    warn "  WAZUH_HOST     — Your Wazuh manager URL"
    warn "  WAZUH_USER     — Wazuh API username"
    warn "  WAZUH_PASS     — Wazuh API password"
    warn "  ANTHROPIC_API_KEY — Your Anthropic API key"
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
[ -z "${ANTHROPIC_API_KEY:-}" ] && error "ANTHROPIC_API_KEY is not set in .env"
[ "${ANTHROPIC_API_KEY:-}" = "sk-ant-CHANGE_ME" ] && error "ANTHROPIC_API_KEY is still the placeholder — update it in .env"

info "Environment validated."

# ── Build & Launch ───────────────────────────
info "Building containers..."
docker compose build

info "Starting services..."
docker compose up -d

echo ""
info "Waiting for MCP server health check..."
sleep 5

# Check health
if docker compose exec wazuh-mcp-server curl -sf http://localhost:3000/health >/dev/null 2>&1; then
    info "MCP server is healthy."
else
    warn "MCP server health check pending — it may still be starting."
    warn "Check status with: docker compose logs wazuh-mcp-server"
fi

echo ""
echo -e "${BOLD}${GREEN}════════════════════════════════════════════${RESET}"
echo -e "${BOLD}${GREEN}  ORED AI SOC Employee is running!${RESET}"
echo -e "${BOLD}${GREEN}════════════════════════════════════════════${RESET}"
echo ""
echo "  MCP Server:  http://localhost:${MCP_PORT:-3000}"
echo "  Health:      http://localhost:${MCP_PORT:-3000}/health"
echo "  Logs:        docker compose logs -f"
echo ""
echo "  Useful commands:"
echo "    docker compose logs -f wazuh-mcp-server  # MCP server logs"
echo "    docker compose logs -f hermes-agent       # Agent logs"
echo "    docker compose restart                    # Restart all"
echo "    docker compose down                       # Stop all"
echo ""
