#!/bin/sh
set -e

# ─────────────────────────────────────────────────────────────────────
# ORED SOC Employee — Container Entrypoint
# Bridges generic .env vars (LLM_API_KEY) to Hermes-specific config
# (~/.hermes/.env and ~/.hermes/config.yaml)
# ─────────────────────────────────────────────────────────────────────

mkdir -p /root/.hermes

# Helper: strip surrounding quotes from a value
strip_quotes() {
    local val="$1"
    val="${val#\"}" ; val="${val%\"}"
    val="${val#\'}" ; val="${val%\'}"
    echo "$val"
}

# ── 1. Build ~/.hermes/.env ──────────────────────────────────────────
> /root/.hermes/.env

# Strip quotes from all credential values (users often quote .env values)
LLM_API_KEY=$(strip_quotes "${LLM_API_KEY:-}")
LLM_BASE_URL=$(strip_quotes "${LLM_BASE_URL:-}")
LLM_MODEL=$(strip_quotes "${LLM_MODEL:-}")
LLM_PROVIDER=$(strip_quotes "${LLM_PROVIDER:-}")
TELEGRAM_BOT_TOKEN=$(strip_quotes "${TELEGRAM_BOT_TOKEN:-}")
TELEGRAM_CHAT_ID=$(strip_quotes "${TELEGRAM_CHAT_ID:-}")
TELEGRAM_ALLOWED_USERS=$(strip_quotes "${TELEGRAM_ALLOWED_USERS:-}")

if [ -n "${LLM_API_KEY:-}" ]; then
    PROVIDER="${LLM_PROVIDER:-}"

    # Fallback: auto-detect from model name if provider not set
    if [ -z "$PROVIDER" ]; then
        case "${LLM_MODEL:-}" in
            MiniMax*|minimax*)   PROVIDER="minimax" ;;
            claude*|Claude*)     PROVIDER="anthropic" ;;
            deepseek*|DeepSeek*) PROVIDER="deepseek" ;;
            gpt-*|o1-*|o3-*|o4-*) PROVIDER="openai" ;;
            *)                   PROVIDER="openai" ;;
        esac
        echo "[entrypoint] LLM_PROVIDER not set, auto-detected: ${PROVIDER}"
    fi

    # Map generic LLM_API_KEY to the provider-specific env var Hermes expects
    case "$PROVIDER" in
        anthropic)
            echo "ANTHROPIC_API_KEY=${LLM_API_KEY}" >> /root/.hermes/.env
            ;;
        minimax)
            echo "MINIMAX_API_KEY=${LLM_API_KEY}" >> /root/.hermes/.env
            ;;
        minimax-cn)
            echo "MINIMAX_CN_API_KEY=${LLM_API_KEY}" >> /root/.hermes/.env
            ;;
        deepseek)
            echo "DEEPSEEK_API_KEY=${LLM_API_KEY}" >> /root/.hermes/.env
            ;;
        openrouter)
            echo "OPENROUTER_API_KEY=${LLM_API_KEY}" >> /root/.hermes/.env
            ;;
        *)
            # openai or any OpenAI-compatible provider
            echo "OPENAI_API_KEY=${LLM_API_KEY}" >> /root/.hermes/.env
            ;;
    esac
fi

# Base URL (for custom endpoints)
if [ -n "${LLM_BASE_URL:-}" ]; then
    echo "OPENAI_BASE_URL=${LLM_BASE_URL}" >> /root/.hermes/.env
fi

# Telegram
[ -n "${TELEGRAM_BOT_TOKEN:-}" ] && echo "TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}" >> /root/.hermes/.env
[ -n "${TELEGRAM_CHAT_ID:-}" ] && echo "TELEGRAM_HOME_CHANNEL=${TELEGRAM_CHAT_ID}" >> /root/.hermes/.env
[ -n "${TELEGRAM_ALLOWED_USERS:-}" ] && echo "TELEGRAM_ALLOWED_USERS=${TELEGRAM_ALLOWED_USERS}" >> /root/.hermes/.env

echo "[entrypoint] ~/.hermes/.env keys:"
grep -oP '^[^=]+' /root/.hermes/.env || true

# ── 2. Patch config.yaml with model and provider ────────────────────
if [ -f /root/.hermes/config.yaml ]; then
    cp /root/.hermes/config.yaml /tmp/hermes-config.yaml
else
    echo "" > /tmp/hermes-config.yaml
fi

if [ -n "${LLM_MODEL:-}" ]; then
    if grep -q '^model:' /tmp/hermes-config.yaml 2>/dev/null; then
        sed -i "s|^model:.*|model: \"${LLM_MODEL}\"|" /tmp/hermes-config.yaml
    else
        sed -i "1i model: \"${LLM_MODEL}\"" /tmp/hermes-config.yaml
    fi
fi

if [ -n "${PROVIDER:-}" ] && [ "$PROVIDER" != "openai" ]; then
    if grep -q '^provider:' /tmp/hermes-config.yaml 2>/dev/null; then
        sed -i "s|^provider:.*|provider: \"${PROVIDER}\"|" /tmp/hermes-config.yaml
    else
        sed -i "1i provider: \"${PROVIDER}\"" /tmp/hermes-config.yaml
    fi
fi

cp -f /tmp/hermes-config.yaml /root/.hermes/config.yaml 2>/dev/null || true

echo "[entrypoint] config.yaml:"
cat /root/.hermes/config.yaml

# ── 3. Hand off to CMD ──────────────────────────────────────────────
exec "$@"
