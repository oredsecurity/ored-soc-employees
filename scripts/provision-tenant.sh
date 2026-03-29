#!/usr/bin/env bash
set -euo pipefail

# ORED AI SOC Employee - Tenant Provisioning Script
#
# Usage: ./scripts/provision-tenant.sh <client-slug>
# Example: ./scripts/provision-tenant.sh acme
#
# What this script does:
#   1. Creates a deployment directory for the tenant
#   2. Copies the stack template (docker-compose, config, skills)
#   3. Walks you through .env generation with the credentials you created manually
#   4. Starts the stack
#   5. Validates health
#
# What you must do BEFORE running this script:
#   Create the required Wazuh resources (API user, agent group, indexer role)
#   before running this script. The script validates credentials but does not
#   create Wazuh resources.

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
DEPLOYMENTS_DIR="${ORED_DEPLOYMENTS_DIR:-/opt/ored/deployments}"

# --- Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m'

info()  { echo -e "${CYAN}[INFO]${NC} $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*"; }
ok()    { echo -e "${GREEN}[OK]${NC} $*"; }

# --- Argument validation ---
if [[ $# -lt 1 ]]; then
    echo -e "${BOLD}Usage:${NC} $0 <client-slug>"
    echo ""
    echo "  client-slug:  lowercase identifier for the client (e.g., acme, contoso)"
    echo ""
    echo "  Before running this script, complete Steps 1-7 in docs/client-onboarding.md"
    exit 1
fi

CLIENT_SLUG="$1"

# Validate slug format
if [[ ! "$CLIENT_SLUG" =~ ^[a-z][a-z0-9-]{1,30}$ ]]; then
    error "Client slug must be lowercase, start with a letter, contain only a-z, 0-9, hyphens. Max 31 chars."
    exit 1
fi

CLIENT_DIR="${DEPLOYMENTS_DIR}/${CLIENT_SLUG}"
CLIENT_GROUP="client-${CLIENT_SLUG}"

echo ""
echo -e "${BOLD}================================================${NC}"
echo -e "${BOLD}  ORED AI SOC Employee - Tenant Provisioning${NC}"
echo -e "${BOLD}================================================${NC}"
echo ""
echo -e "  Client:      ${CYAN}${CLIENT_SLUG}${NC}"
echo -e "  Agent group:  ${CYAN}${CLIENT_GROUP}${NC}"
echo -e "  Deploy to:    ${CYAN}${CLIENT_DIR}${NC}"
echo ""

# --- Pre-flight checks ---
info "Running pre-flight checks..."

if [[ -d "$CLIENT_DIR" ]]; then
    error "Deployment directory already exists: ${CLIENT_DIR}"
    error "If re-provisioning, remove it first: rm -rf ${CLIENT_DIR}"
    exit 1
fi

# Check docker
if command -v docker compose &>/dev/null; then
    DC="docker compose"
elif command -v docker-compose &>/dev/null; then
    DC="docker-compose"
else
    error "Docker Compose not found. Run install.sh first."
    exit 1
fi

ok "Docker Compose found: ${DC}"

# --- Manual steps reminder ---
echo ""
echo -e "${BOLD}================================================${NC}"
echo -e "${BOLD}  Pre-Provisioning Checklist${NC}"
echo -e "${BOLD}================================================${NC}"
echo ""
echo -e "  Before continuing, confirm you have completed these steps"
echo -e "  on the Wazuh manager and indexer:"
echo ""
echo -e "  ${YELLOW}[ ]${NC} 1. Created agent group:          ${CYAN}${CLIENT_GROUP}${NC}"
echo -e "  ${YELLOW}[ ]${NC} 2. Created shared agent.conf:     ${CYAN}/var/ossec/etc/shared/${CLIENT_GROUP}/agent.conf${NC}"
echo -e "  ${YELLOW}[ ]${NC} 3. Assigned client agents to group"
echo -e "  ${YELLOW}[ ]${NC} 4. Created DLS role:              ${CYAN}${CLIENT_SLUG//-/_}_readonly${NC}"
echo -e "  ${YELLOW}[ ]${NC} 5. Created tenant:                ${CYAN}${CLIENT_SLUG//-/_}_tenant${NC}"
echo -e "  ${YELLOW}[ ]${NC} 6. Created dashboard user:        ${CYAN}${CLIENT_SLUG}_viewer${NC}"
echo -e "  ${YELLOW}[ ]${NC} 7. Created Wazuh API user:        ${CYAN}${CLIENT_SLUG}_soc${NC}"
echo ""
read -r -p "Have you completed all 7 steps? (yes/no): " CONFIRM
if [[ "$CONFIRM" != "yes" ]]; then
    warn "Complete the manual steps first, then re-run this script."
    echo "  Refer to your internal onboarding documentation."
    exit 0
fi

# --- Create deployment directory ---
info "Creating deployment directory..."
mkdir -p "$CLIENT_DIR"

# Copy stack template
cp "$REPO_DIR/docker-compose.yml" "$CLIENT_DIR/"
cp "$REPO_DIR/install.sh" "$CLIENT_DIR/"
cp -r "$REPO_DIR/hermes" "$CLIENT_DIR/"
cp -r "$REPO_DIR/mcp-server" "$CLIENT_DIR/"

# Copy skills if they exist
if [[ -d "$REPO_DIR/skills" ]]; then
    cp -r "$REPO_DIR/skills" "$CLIENT_DIR/"
fi

ok "Stack template copied to ${CLIENT_DIR}"

# --- Generate .env ---
echo ""
echo -e "${BOLD}================================================${NC}"
echo -e "${BOLD}  Credential Configuration${NC}"
echo -e "${BOLD}================================================${NC}"
echo ""
info "Enter the credentials for client: ${CLIENT_SLUG}"
echo ""

# Wazuh API
read -r -p "Wazuh Manager URL (e.g., https://10.0.1.50): " WAZUH_URL
read -r -p "Wazuh API Port [55000]: " WAZUH_PORT
WAZUH_PORT="${WAZUH_PORT:-55000}"
read -r -p "Wazuh API Username [${CLIENT_SLUG}_soc]: " WAZUH_USER
WAZUH_USER="${WAZUH_USER:-${CLIENT_SLUG}_soc}"
read -r -s -p "Wazuh API Password: " WAZUH_PASS
echo ""

if [[ -z "$WAZUH_PASS" ]]; then
    error "Wazuh API password cannot be empty."
    rm -rf "$CLIENT_DIR"
    exit 1
fi

# LLM Provider
echo ""
info "LLM Configuration"
echo "  Providers: anthropic, openrouter, minimax, ollama, or any OpenAI-compatible API"
echo ""
read -r -p "LLM Provider [anthropic]: " LLM_PROVIDER
LLM_PROVIDER="${LLM_PROVIDER:-anthropic}"
read -r -p "LLM Model [claude-sonnet-4-20250514]: " LLM_MODEL
LLM_MODEL="${LLM_MODEL:-claude-sonnet-4-20250514}"
read -r -p "LLM Base URL (leave blank for default): " LLM_BASE_URL
read -r -s -p "LLM API Key: " LLM_API_KEY
echo ""

if [[ -z "$LLM_API_KEY" ]]; then
    error "LLM API key cannot be empty."
    rm -rf "$CLIENT_DIR"
    exit 1
fi

# Telegram
echo ""
info "Telegram Approval Bot (optional, press Enter to skip)"
read -r -p "Telegram Bot Token (or Enter to skip): " TELEGRAM_TOKEN
TELEGRAM_CHAT_ID=""
if [[ -n "$TELEGRAM_TOKEN" ]]; then
    read -r -p "Telegram Chat ID: " TELEGRAM_CHAT_ID
fi

# Write .env
cat > "$CLIENT_DIR/.env" << EOF
# ORED AI SOC Employee - Client: ${CLIENT_SLUG}
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Wazuh API
WAZUH_API_URL=${WAZUH_URL}
WAZUH_API_PORT=${WAZUH_PORT}
WAZUH_USER=${WAZUH_USER}
WAZUH_PASS=${WAZUH_PASS}
VERIFY_SSL=false

# Client identity
CLIENT_SLUG=${CLIENT_SLUG}
CLIENT_GROUP=${CLIENT_GROUP}

# LLM
LLM_PROVIDER=${LLM_PROVIDER}
LLM_MODEL=${LLM_MODEL}
LLM_BASE_URL=${LLM_BASE_URL}
LLM_API_KEY=${LLM_API_KEY}

# Telegram Approval Bot
TELEGRAM_BOT_TOKEN=${TELEGRAM_TOKEN}
TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID}
EOF

chmod 600 "$CLIENT_DIR/.env"
ok ".env generated (permissions: 600)"

# --- Validate Wazuh API connectivity ---
echo ""
info "Validating Wazuh API connectivity..."

# Get auth token
AUTH_RESPONSE=$(curl -sk -w "\n%{http_code}" \
    -u "${WAZUH_USER}:${WAZUH_PASS}" \
    -X POST "${WAZUH_URL}:${WAZUH_PORT}/security/user/authenticate" 2>/dev/null) || true

HTTP_CODE=$(echo "$AUTH_RESPONSE" | tail -1)
BODY=$(echo "$AUTH_RESPONSE" | head -n -1)

if [[ "$HTTP_CODE" == "200" ]]; then
    ok "Wazuh API authentication successful (user: ${WAZUH_USER})"

    # Extract token and check agent group visibility
    TOKEN=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])" 2>/dev/null) || true

    if [[ -n "$TOKEN" ]]; then
        # Check if this user can see agents in the client group
        AGENTS_RESPONSE=$(curl -sk \
            -H "Authorization: Bearer $TOKEN" \
            "${WAZUH_URL}:${WAZUH_PORT}/agents?group=${CLIENT_GROUP}&limit=1" 2>/dev/null) || true

        AGENT_COUNT=$(echo "$AGENTS_RESPONSE" | python3 -c "import sys,json; print(json.load(sys.stdin).get('data',{}).get('total_affected_items',0))" 2>/dev/null) || AGENT_COUNT="unknown"

        if [[ "$AGENT_COUNT" == "0" ]]; then
            warn "No agents found in group '${CLIENT_GROUP}'. Have agents been assigned to this group?"
        elif [[ "$AGENT_COUNT" == "unknown" ]]; then
            warn "Could not query agents. The API user may not have permission to list agents in group '${CLIENT_GROUP}'."
        else
            ok "Found ${AGENT_COUNT} agent(s) in group '${CLIENT_GROUP}'"
        fi
    fi
else
    warn "Wazuh API authentication failed (HTTP ${HTTP_CODE}). Check credentials."
    warn "The stack will start but the SOC agent won't be able to connect."
    read -r -p "Continue anyway? (yes/no): " CONTINUE
    if [[ "$CONTINUE" != "yes" ]]; then
        rm -rf "$CLIENT_DIR"
        exit 1
    fi
fi

# --- Start the stack ---
echo ""
info "Starting SOC agent stack for client: ${CLIENT_SLUG}..."

cd "$CLIENT_DIR"

# Build and start (MCP server only by default, full stack if LLM is configured)
if [[ -n "$LLM_API_KEY" ]]; then
    $DC --env-file .env up -d --build 2>&1 | tail -5
else
    $DC --env-file .env --profile mcp-only up -d --build 2>&1 | tail -5
fi

# --- Health check ---
echo ""
info "Running health checks..."

# Wait for MCP server
MAX_WAIT=30
WAITED=0
while [[ $WAITED -lt $MAX_WAIT ]]; do
    if $DC ps 2>/dev/null | grep -q "healthy"; then
        break
    fi
    sleep 2
    WAITED=$((WAITED + 2))
done

if [[ $WAITED -ge $MAX_WAIT ]]; then
    warn "Health check timed out after ${MAX_WAIT}s. Check logs:"
    echo "  $DC -f ${CLIENT_DIR}/docker-compose.yml logs"
else
    ok "Stack is healthy"
fi

# --- Summary ---
echo ""
echo -e "${BOLD}================================================${NC}"
echo -e "${GREEN}${BOLD}  Tenant Provisioned Successfully${NC}"
echo -e "${BOLD}================================================${NC}"
echo ""
echo -e "  Client:        ${CYAN}${CLIENT_SLUG}${NC}"
echo -e "  Agent group:   ${CYAN}${CLIENT_GROUP}${NC}"
echo -e "  Deployment:    ${CYAN}${CLIENT_DIR}${NC}"
echo -e "  Wazuh API:     ${CYAN}${WAZUH_URL}:${WAZUH_PORT}${NC}"
echo -e "  LLM:           ${CYAN}${LLM_PROVIDER}/${LLM_MODEL}${NC}"
if [[ -n "$TELEGRAM_TOKEN" ]]; then
echo -e "  Telegram:      ${CYAN}Configured${NC}"
else
echo -e "  Telegram:      ${YELLOW}Not configured${NC}"
fi
echo ""
echo -e "  ${BOLD}Management commands:${NC}"
echo -e "  Logs:    ${CYAN}$DC -f ${CLIENT_DIR}/docker-compose.yml logs -f${NC}"
echo -e "  Stop:    ${CYAN}$DC -f ${CLIENT_DIR}/docker-compose.yml down${NC}"
echo -e "  Restart: ${CYAN}$DC -f ${CLIENT_DIR}/docker-compose.yml restart${NC}"
echo ""
