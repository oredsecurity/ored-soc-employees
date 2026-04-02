#!/usr/bin/env bash
set -euo pipefail

# ORED AI SOC Employee - Tenant Provisioning Script (v2 - Native Architecture)
#
# Usage: ./scripts/provision-tenant.sh <client-slug> [options]
#
# This script provisions a new tenant using the native architecture:
#   1. Creates a Hermes profile for tenant isolation
#   2. Copies ORED identity, skills, and plugins into the profile
#   3. Deploys a dedicated MCP server container for the tenant
#   4. Configures Hermes to connect to the tenant's MCP server
#
# Prerequisites (Wazuh-side, done manually before running):
#   - Agent group created
#   - DLS role, tenant, dashboard user created
#   - Wazuh API user created

# ============================================================================
#  Constants & Setup
# ============================================================================

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_DIR="$(dirname "$SCRIPT_DIR")"
MCP_BASE_DIR="/opt/ored/mcp"
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
MCP_PORT_RANGE_START=3100

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
step()  { echo -e "${BOLD}[STEP]${NC} $*"; }

# ============================================================================
#  Usage
# ============================================================================

usage() {
    cat <<EOF
${BOLD}ORED AI SOC Employee - Tenant Provisioning${NC}

${BOLD}Usage:${NC} $0 <client-slug> [options]

${BOLD}Arguments:${NC}
  client-slug               Lowercase identifier (a-z0-9 and hyphens, max 31 chars)

${BOLD}Options:${NC}
  --wazuh-url <url>         Wazuh Manager URL (required)
  --wazuh-port <port>       Wazuh API port (default: 55000)
  --wazuh-user <user>       Wazuh API user (default: <slug>_soc)
  --wazuh-pass <pass>       Wazuh API password (required)
  --llm-provider <provider> LLM provider (default: anthropic)
  --llm-model <model>       LLM model (default: claude-sonnet-4-20250514)
  --llm-base-url <url>      LLM base URL (optional)
  --llm-api-key <key>       LLM API key (required)
  --telegram-token <token>  Telegram bot token (optional)
  --telegram-chat-id <id>   Telegram chat ID (optional)
  --mcp-port <port>         MCP server port (default: auto-assigned from ${MCP_PORT_RANGE_START}+)
  --non-interactive         Skip all prompts; fail if required args missing

${BOLD}Examples:${NC}
  $0 acme --wazuh-url https://10.0.1.50 --wazuh-pass 'S3cret!' --llm-api-key sk-...
  $0 acme   # interactive mode - prompts for missing values
EOF
    exit "${1:-0}"
}

# ============================================================================
#  Argument Parsing
# ============================================================================

if [[ $# -lt 1 ]] || [[ "$1" == "--help" ]] || [[ "$1" == "-h" ]]; then
    usage 0
fi

CLIENT_SLUG="$1"
shift

# Defaults
WAZUH_URL=""
WAZUH_PORT="55000"
WAZUH_USER=""
WAZUH_PASS=""
LLM_PROVIDER="anthropic"
LLM_MODEL="claude-sonnet-4-20250514"
LLM_BASE_URL=""
LLM_API_KEY=""
TELEGRAM_TOKEN=""
TELEGRAM_CHAT_ID=""
MCP_PORT=""
NON_INTERACTIVE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --wazuh-url)      WAZUH_URL="$2"; shift 2 ;;
        --wazuh-port)     WAZUH_PORT="$2"; shift 2 ;;
        --wazuh-user)     WAZUH_USER="$2"; shift 2 ;;
        --wazuh-pass)     WAZUH_PASS="$2"; shift 2 ;;
        --llm-provider)   LLM_PROVIDER="$2"; shift 2 ;;
        --llm-model)      LLM_MODEL="$2"; shift 2 ;;
        --llm-base-url)   LLM_BASE_URL="$2"; shift 2 ;;
        --llm-api-key)    LLM_API_KEY="$2"; shift 2 ;;
        --telegram-token) TELEGRAM_TOKEN="$2"; shift 2 ;;
        --telegram-chat-id) TELEGRAM_CHAT_ID="$2"; shift 2 ;;
        --mcp-port)       MCP_PORT="$2"; shift 2 ;;
        --non-interactive) NON_INTERACTIVE=true; shift ;;
        --help|-h)        usage 0 ;;
        *)
            error "Unknown option: $1"
            usage 1
            ;;
    esac
done

# ============================================================================
#  Helper: prompt for value (respects --non-interactive)
# ============================================================================

prompt_value() {
    local var_name="$1"
    local prompt_text="$2"
    local default_value="${3:-}"
    local is_secret="${4:-false}"
    local is_required="${5:-true}"

    # Get current value
    local current_value="${!var_name}"

    # If already set, return
    if [[ -n "$current_value" ]]; then
        return 0
    fi

    # If default exists and non-interactive, use default
    if [[ -n "$default_value" ]] && $NON_INTERACTIVE; then
        eval "$var_name=\"$default_value\""
        return 0
    fi

    # Non-interactive with no value and no default
    if $NON_INTERACTIVE; then
        if [[ "$is_required" == "true" ]]; then
            error "Required argument missing: --$(echo "$var_name" | tr '[:upper:]' '[:lower:]' | tr '_' '-')"
            exit 1
        fi
        return 0
    fi

    # Interactive prompt
    local prompt_suffix=""
    if [[ -n "$default_value" ]]; then
        prompt_suffix=" [${default_value}]"
    fi

    if [[ "$is_secret" == "true" ]]; then
        read -r -s -p "${prompt_text}${prompt_suffix}: " input_value
        echo ""
    else
        read -r -p "${prompt_text}${prompt_suffix}: " input_value
    fi

    if [[ -z "$input_value" ]] && [[ -n "$default_value" ]]; then
        input_value="$default_value"
    fi

    if [[ -z "$input_value" ]] && [[ "$is_required" == "true" ]]; then
        error "This value is required."
        exit 1
    fi

    eval "$var_name=\"$input_value\""
}

# ============================================================================
#  Cleanup on failure
# ============================================================================

CLEANUP_ITEMS=()

cleanup_on_failure() {
    if [[ ${#CLEANUP_ITEMS[@]} -eq 0 ]]; then
        return
    fi
    echo ""
    warn "Provisioning failed. Cleaning up..."
    for item in "${CLEANUP_ITEMS[@]}"; do
        case "$item" in
            profile:*)
                local profile_name="${item#profile:}"
                info "Removing Hermes profile: ${profile_name}"
                hermes profile delete "$profile_name" --force 2>/dev/null || rm -rf "${HERMES_HOME}/profiles/${profile_name}" 2>/dev/null || true
                ;;
            dir:*)
                local dir_path="${item#dir:}"
                info "Removing directory: ${dir_path}"
                rm -rf "$dir_path" 2>/dev/null || true
                ;;
            container:*)
                local container_name="${item#container:}"
                info "Stopping container: ${container_name}"
                docker rm -f "$container_name" 2>/dev/null || true
                ;;
        esac
    done
    warn "Cleanup complete."
}

trap 'cleanup_on_failure' EXIT

# ============================================================================
#  Step 1: Validate client slug
# ============================================================================

echo ""
echo -e "${BOLD}================================================${NC}"
echo -e "${BOLD}  ORED AI SOC Employee - Tenant Provisioning${NC}"
echo -e "${BOLD}================================================${NC}"
echo ""

step "1/12  Validating client slug..."

if [[ ! "$CLIENT_SLUG" =~ ^[a-z][a-z0-9-]{0,30}$ ]]; then
    error "Client slug must: start with a letter, contain only a-z, 0-9, hyphens, max 31 chars."
    error "Got: '${CLIENT_SLUG}'"
    exit 1
fi

CLIENT_GROUP="client-${CLIENT_SLUG}"
PROFILE_DIR="${HERMES_HOME}/profiles/${CLIENT_SLUG}"
MCP_DIR="${MCP_BASE_DIR}/${CLIENT_SLUG}"

ok "Slug valid: ${CLIENT_SLUG}"

# ============================================================================
#  Step 2: Check prerequisites
# ============================================================================

step "2/12  Checking prerequisites..."

# Check hermes
if ! command -v hermes &>/dev/null; then
    error "hermes binary not found in PATH."
    error "Install Hermes first: https://github.com/your-org/hermes"
    exit 1
fi
ok "hermes binary found: $(command -v hermes)"

# Check docker
if ! command -v docker &>/dev/null; then
    error "docker not found. Install Docker first."
    exit 1
fi

if docker compose version &>/dev/null; then
    DC="docker compose"
elif command -v docker-compose &>/dev/null; then
    DC="docker-compose"
else
    error "Docker Compose not found (need 'docker compose' or 'docker-compose')."
    exit 1
fi
ok "Docker Compose found: ${DC}"

# Check for existing deployments
if [[ -d "$PROFILE_DIR" ]]; then
    error "Hermes profile already exists: ${PROFILE_DIR}"
    error "To re-provision, first run: hermes profile delete ${CLIENT_SLUG}"
    exit 1
fi

if [[ -d "$MCP_DIR" ]]; then
    error "MCP deployment directory already exists: ${MCP_DIR}"
    error "To re-provision, remove it first: rm -rf ${MCP_DIR}"
    exit 1
fi

if docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q "^ored-mcp-${CLIENT_SLUG}$"; then
    error "Docker container ored-mcp-${CLIENT_SLUG} already exists."
    error "Remove it first: docker rm -f ored-mcp-${CLIENT_SLUG}"
    exit 1
fi

ok "No existing deployment found for '${CLIENT_SLUG}'"

# ============================================================================
#  Step 3: Collect credentials (interactive prompts or CLI args)
# ============================================================================

step "3/12  Collecting configuration..."

# Set default for WAZUH_USER if not provided
if [[ -z "$WAZUH_USER" ]]; then
    WAZUH_USER="${CLIENT_SLUG}_soc"
fi

echo ""
if ! $NON_INTERACTIVE; then
    echo -e "  ${BOLD}Wazuh Configuration${NC}"
fi

prompt_value WAZUH_URL    "Wazuh Manager URL (e.g., https://10.0.1.50)" "" false true
prompt_value WAZUH_PORT   "Wazuh API Port" "55000" false false
prompt_value WAZUH_USER   "Wazuh API Username" "${CLIENT_SLUG}_soc" false false
prompt_value WAZUH_PASS   "Wazuh API Password" "" true true

if ! $NON_INTERACTIVE; then
    echo ""
    echo -e "  ${BOLD}LLM Configuration${NC}"
    echo -e "  Providers: anthropic, openrouter, minimax, ollama, or any OpenAI-compatible API"
fi

prompt_value LLM_PROVIDER "LLM Provider" "anthropic" false false
prompt_value LLM_MODEL    "LLM Model" "claude-sonnet-4-20250514" false false
prompt_value LLM_BASE_URL "LLM Base URL (leave blank for default)" "" false false
prompt_value LLM_API_KEY  "LLM API Key" "" true true

if ! $NON_INTERACTIVE; then
    echo ""
    echo -e "  ${BOLD}Telegram Configuration (optional)${NC}"
fi

prompt_value TELEGRAM_TOKEN   "Telegram Bot Token (Enter to skip)" "" false false
if [[ -n "$TELEGRAM_TOKEN" ]]; then
    prompt_value TELEGRAM_CHAT_ID "Telegram Chat ID" "" false false
fi

ok "Configuration collected"

# ============================================================================
#  Step 4: Auto-assign MCP port
# ============================================================================

step "4/12  Assigning MCP server port..."

if [[ -z "$MCP_PORT" ]]; then
    MCP_PORT=$MCP_PORT_RANGE_START
    # Scan existing ored-mcp-* containers for used ports
    while true; do
        if ! docker ps -a --format '{{.Ports}}' --filter "name=ored-mcp-" 2>/dev/null | grep -q ":${MCP_PORT}->"; then
            # Also check if port is in use by anything else
            if ! ss -tlnp 2>/dev/null | grep -q ":${MCP_PORT} " && \
               ! netstat -tlnp 2>/dev/null | grep -q ":${MCP_PORT} "; then
                break
            fi
        fi
        MCP_PORT=$((MCP_PORT + 1))
        if [[ $MCP_PORT -gt 3999 ]]; then
            error "No available MCP ports in range ${MCP_PORT_RANGE_START}-3999."
            exit 1
        fi
    done
fi

ok "MCP port assigned: ${MCP_PORT}"

# ============================================================================
#  Step 5: Pre-provisioning checklist (informational)
# ============================================================================

step "5/12  Pre-provisioning checklist..."

echo ""
echo -e "  ${BOLD}Wazuh Resources (should exist before continuing):${NC}"
echo ""
echo -e "  ${YELLOW}[?]${NC} 1. Agent group:          ${CYAN}${CLIENT_GROUP}${NC}"
echo -e "  ${YELLOW}[?]${NC} 2. Shared agent.conf:     ${CYAN}/var/ossec/etc/shared/${CLIENT_GROUP}/agent.conf${NC}"
echo -e "  ${YELLOW}[?]${NC} 3. Agents assigned to group"
echo -e "  ${YELLOW}[?]${NC} 4. DLS role:              ${CYAN}${CLIENT_SLUG//-/_}_readonly${NC}"
echo -e "  ${YELLOW}[?]${NC} 5. Tenant:                ${CYAN}${CLIENT_SLUG//-/_}_tenant${NC}"
echo -e "  ${YELLOW}[?]${NC} 6. Dashboard user:        ${CYAN}${CLIENT_SLUG}_viewer${NC}"
echo -e "  ${YELLOW}[?]${NC} 7. Wazuh API user:        ${CYAN}${WAZUH_USER}${NC}"
echo ""

if ! $NON_INTERACTIVE; then
    read -r -p "Have you completed these Wazuh-side steps? (yes/no): " CONFIRM
    if [[ "$CONFIRM" != "yes" ]]; then
        warn "These resources should exist for the SOC agent to function."
        read -r -p "Continue anyway? (yes/no): " CONTINUE
        if [[ "$CONTINUE" != "yes" ]]; then
            exit 0
        fi
    fi
else
    warn "Non-interactive mode: skipping Wazuh checklist confirmation."
fi

# ============================================================================
#  Step 6: Create Hermes profile
# ============================================================================

step "6/12  Creating Hermes profile: ${CLIENT_SLUG}..."

hermes profile create "$CLIENT_SLUG" --clone 2>&1 | while IFS= read -r line; do
    info "  $line"
done

CLEANUP_ITEMS+=("profile:${CLIENT_SLUG}")

if [[ ! -d "$PROFILE_DIR" ]]; then
    error "Hermes profile directory not created at ${PROFILE_DIR}"
    exit 1
fi

ok "Hermes profile created: ${PROFILE_DIR}"

# ============================================================================
#  Step 7: Copy ORED-specific files into profile
# ============================================================================

step "7/12  Installing ORED identity, skills, and plugins..."

# Copy SOUL.md (ARGOS identity)
if [[ -f "${REPO_DIR}/hermes/config/SOUL.md" ]]; then
    cp "${REPO_DIR}/hermes/config/SOUL.md" "${PROFILE_DIR}/SOUL.md"
    ok "SOUL.md installed (ARGOS identity)"
else
    warn "SOUL.md not found at ${REPO_DIR}/hermes/config/SOUL.md"
fi

# Copy skills
mkdir -p "${PROFILE_DIR}/skills"
if [[ -d "${REPO_DIR}/hermes/skills" ]]; then
    find "${REPO_DIR}/hermes/skills" -name '*.SKILL.md' -exec cp {} "${PROFILE_DIR}/skills/" \; 2>/dev/null || true
    SKILL_COUNT=$(find "${PROFILE_DIR}/skills" -name '*.SKILL.md' 2>/dev/null | wc -l)
    ok "Skills installed: ${SKILL_COUNT} skill file(s)"
else
    warn "No skills directory found at ${REPO_DIR}/hermes/skills/"
fi

# Copy plugin (ored-soc-policy)
mkdir -p "${PROFILE_DIR}/plugins"
if [[ -d "${REPO_DIR}/hermes/plugins/ored-soc-policy" ]]; then
    cp -r "${REPO_DIR}/hermes/plugins/ored-soc-policy" "${PROFILE_DIR}/plugins/"
    ok "Plugin installed: ored-soc-policy"
else
    warn "Plugin not found at ${REPO_DIR}/hermes/plugins/ored-soc-policy/"
fi

# ============================================================================
#  Step 8: Generate MCP server deployment
# ============================================================================

step "8/12  Generating MCP server deployment..."

mkdir -p "$MCP_DIR"
CLEANUP_ITEMS+=("dir:${MCP_DIR}")

# --- MCP .env file ---
cat > "${MCP_DIR}/.env" <<EOF
# ORED MCP Server - Client: ${CLIENT_SLUG}
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

# Telegram Approval Bot
TELEGRAM_BOT_TOKEN=${TELEGRAM_TOKEN}
TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID}
EOF

chmod 600 "${MCP_DIR}/.env"
ok "MCP .env generated: ${MCP_DIR}/.env (mode 600)"

# --- MCP docker-compose.yml ---
cat > "${MCP_DIR}/docker-compose.yml" <<EOF
# ORED MCP Server - Client: ${CLIENT_SLUG}
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

services:
  wazuh-mcp:
    container_name: ored-mcp-${CLIENT_SLUG}
    build:
      context: ${REPO_DIR}/mcp-server
    env_file: .env
    ports:
      - "${MCP_PORT}:3000"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-sf", "http://localhost:3000/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 15s
    mem_limit: 512m
    cpus: 0.5
EOF

ok "MCP docker-compose.yml generated: ${MCP_DIR}/docker-compose.yml"

# ============================================================================
#  Step 9: Configure Hermes profile
# ============================================================================

step "9/12  Configuring Hermes profile..."

# --- Hermes config.yaml with MCP server connection ---
cat > "${PROFILE_DIR}/config.yaml" <<EOF
# ORED SOC Employee - Hermes Profile Config
# Client: ${CLIENT_SLUG}
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

mcp_servers:
  wazuh:
    transport: http
    url: http://localhost:${MCP_PORT}
    timeout: 120
EOF

ok "Hermes config.yaml written: ${PROFILE_DIR}/config.yaml"

# --- Hermes .env with LLM credentials ---
cat > "${PROFILE_DIR}/.env" <<EOF
# ORED SOC Employee - Hermes Profile Environment
# Client: ${CLIENT_SLUG}
# Generated: $(date -u +"%Y-%m-%dT%H:%M:%SZ")

# LLM
LLM_PROVIDER=${LLM_PROVIDER}
LLM_MODEL=${LLM_MODEL}
LLM_BASE_URL=${LLM_BASE_URL}
LLM_API_KEY=${LLM_API_KEY}
EOF

chmod 600 "${PROFILE_DIR}/.env"
ok "Hermes .env written: ${PROFILE_DIR}/.env (mode 600)"

# ============================================================================
#  Step 10: Validate Wazuh API connectivity
# ============================================================================

step "10/12 Validating Wazuh API connectivity..."

AUTH_RESPONSE=$(curl -sk -w "\n%{http_code}" \
    -u "${WAZUH_USER}:${WAZUH_PASS}" \
    -X POST "${WAZUH_URL}:${WAZUH_PORT}/security/user/authenticate" 2>/dev/null) || true

HTTP_CODE=$(echo "$AUTH_RESPONSE" | tail -1)
BODY=$(echo "$AUTH_RESPONSE" | head -n -1)

if [[ "$HTTP_CODE" == "200" ]]; then
    ok "Wazuh API authentication successful (user: ${WAZUH_USER})"

    # Check agent group visibility
    TOKEN=$(echo "$BODY" | python3 -c "import sys,json; print(json.load(sys.stdin)['data']['token'])" 2>/dev/null) || true

    if [[ -n "$TOKEN" ]]; then
        AGENTS_RESPONSE=$(curl -sk \
            -H "Authorization: Bearer ${TOKEN}" \
            "${WAZUH_URL}:${WAZUH_PORT}/agents?group=${CLIENT_GROUP}&limit=1" 2>/dev/null) || true

        AGENT_COUNT=$(echo "$AGENTS_RESPONSE" | python3 -c \
            "import sys,json; print(json.load(sys.stdin).get('data',{}).get('total_affected_items',0))" 2>/dev/null) || AGENT_COUNT="unknown"

        if [[ "$AGENT_COUNT" == "0" ]]; then
            warn "No agents found in group '${CLIENT_GROUP}'. Have agents been assigned?"
        elif [[ "$AGENT_COUNT" == "unknown" ]]; then
            warn "Could not query agents. API user may lack permissions for group '${CLIENT_GROUP}'."
        else
            ok "Found ${AGENT_COUNT} agent(s) in group '${CLIENT_GROUP}'"
        fi
    fi
else
    warn "Wazuh API authentication failed (HTTP ${HTTP_CODE})."
    warn "The MCP server will start but won't be able to query Wazuh."
    if ! $NON_INTERACTIVE; then
        read -r -p "Continue anyway? (yes/no): " CONTINUE
        if [[ "$CONTINUE" != "yes" ]]; then
            exit 1
        fi
    else
        warn "Non-interactive mode: continuing despite auth failure."
    fi
fi

# ============================================================================
#  Step 11: Start MCP server container
# ============================================================================

step "11/12 Starting MCP server container..."

cd "$MCP_DIR"
$DC up -d --build 2>&1 | tail -10

CLEANUP_ITEMS+=("container:ored-mcp-${CLIENT_SLUG}")

# ============================================================================
#  Step 12: Wait for health check
# ============================================================================

step "12/12 Waiting for MCP server health check..."

MAX_WAIT=60
WAITED=0
HEALTHY=false

while [[ $WAITED -lt $MAX_WAIT ]]; do
    HEALTH_STATUS=$(docker inspect --format='{{.State.Health.Status}}' "ored-mcp-${CLIENT_SLUG}" 2>/dev/null) || true

    if [[ "$HEALTH_STATUS" == "healthy" ]]; then
        HEALTHY=true
        break
    fi

    if [[ "$HEALTH_STATUS" == "unhealthy" ]]; then
        warn "Container reported unhealthy after ${WAITED}s."
        break
    fi

    # Also try a direct curl as a fallback
    if curl -sf "http://localhost:${MCP_PORT}/health" &>/dev/null; then
        HEALTHY=true
        break
    fi

    sleep 3
    WAITED=$((WAITED + 3))
    printf "\r  Waiting... %ds / %ds" "$WAITED" "$MAX_WAIT"
done
echo ""

if $HEALTHY; then
    ok "MCP server is healthy (port ${MCP_PORT})"
else
    warn "Health check timed out after ${MAX_WAIT}s. Check logs:"
    echo -e "    ${CYAN}$DC -f ${MCP_DIR}/docker-compose.yml logs${NC}"
fi

# ============================================================================
#  Success - clear cleanup trap
# ============================================================================

# Remove the failure cleanup trap since we succeeded
CLEANUP_ITEMS=()
trap - EXIT

# ============================================================================
#  Summary
# ============================================================================

echo ""
echo -e "${BOLD}================================================${NC}"
echo -e "${GREEN}${BOLD}  Tenant Provisioned Successfully${NC}"
echo -e "${BOLD}================================================${NC}"
echo ""
echo -e "  ${BOLD}Tenant:${NC}          ${CYAN}${CLIENT_SLUG}${NC}"
echo -e "  ${BOLD}Agent group:${NC}     ${CYAN}${CLIENT_GROUP}${NC}"
echo -e "  ${BOLD}Hermes profile:${NC}  ${CYAN}${PROFILE_DIR}${NC}"
echo -e "  ${BOLD}MCP deployment:${NC}  ${CYAN}${MCP_DIR}${NC}"
echo -e "  ${BOLD}MCP container:${NC}   ${CYAN}ored-mcp-${CLIENT_SLUG}${NC}"
echo -e "  ${BOLD}MCP port:${NC}        ${CYAN}${MCP_PORT}${NC}"
echo -e "  ${BOLD}Wazuh API:${NC}       ${CYAN}${WAZUH_URL}:${WAZUH_PORT}${NC}"
echo -e "  ${BOLD}LLM:${NC}             ${CYAN}${LLM_PROVIDER}/${LLM_MODEL}${NC}"
if [[ -n "$TELEGRAM_TOKEN" ]]; then
echo -e "  ${BOLD}Telegram:${NC}        ${CYAN}Configured${NC}"
else
echo -e "  ${BOLD}Telegram:${NC}        ${YELLOW}Not configured${NC}"
fi
echo ""
echo -e "  ${BOLD}Usage:${NC}"
echo -e "    Start ARGOS:   ${CYAN}hermes --profile ${CLIENT_SLUG}${NC}"
echo ""
echo -e "  ${BOLD}MCP Management:${NC}"
echo -e "    Logs:          ${CYAN}$DC -f ${MCP_DIR}/docker-compose.yml logs -f${NC}"
echo -e "    Stop:          ${CYAN}$DC -f ${MCP_DIR}/docker-compose.yml down${NC}"
echo -e "    Restart:       ${CYAN}$DC -f ${MCP_DIR}/docker-compose.yml restart${NC}"
echo ""
echo -e "  ${BOLD}Profile Management:${NC}"
echo -e "    List profiles: ${CYAN}hermes profile list${NC}"
echo -e "    Switch:        ${CYAN}hermes --profile ${CLIENT_SLUG}${NC}"
echo -e "    Delete:        ${CYAN}hermes profile delete ${CLIENT_SLUG}${NC}"
echo ""
