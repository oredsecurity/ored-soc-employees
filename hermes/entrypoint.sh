#!/bin/sh
set -e

# ORED SOC Employee container entrypoint.
# Writes runtime secrets to HERMES_HOME/.env and renders config.yaml from the
# read-only template mounted at /opt/ored/config/config.yaml.

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
CONFIG_TEMPLATE="${HERMES_CONFIG_TEMPLATE:-/opt/ored/config/config.yaml}"

mkdir -p "$HERMES_HOME" "$HERMES_HOME/cache" "$HERMES_HOME/logs" "$HERMES_HOME/sessions" "$HERMES_HOME/cron"

strip_quotes() {
    printf '%s' "$1" | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//"
}

: > "$HERMES_HOME/.env"
chmod 600 "$HERMES_HOME/.env" 2>/dev/null || true

LLM_API_KEY=$(strip_quotes "${LLM_API_KEY:-}")
LLM_BASE_URL=$(strip_quotes "${LLM_BASE_URL:-}")
LLM_MODEL=$(strip_quotes "${LLM_MODEL:-}")
LLM_PROVIDER=$(strip_quotes "${LLM_PROVIDER:-}")
TELEGRAM_BOT_TOKEN=$(strip_quotes "${TELEGRAM_BOT_TOKEN:-}")
TELEGRAM_CHAT_ID=$(strip_quotes "${TELEGRAM_CHAT_ID:-}")
TELEGRAM_ALLOWED_USERS=$(strip_quotes "${TELEGRAM_ALLOWED_USERS:-}")

PROVIDER="${LLM_PROVIDER:-}"
if [ -n "${LLM_API_KEY:-}" ]; then
    if [ -z "$PROVIDER" ]; then
        case "${LLM_MODEL:-}" in
            MiniMax*|minimax*) PROVIDER="minimax" ;;
            claude*|Claude*) PROVIDER="anthropic" ;;
            deepseek*|DeepSeek*) PROVIDER="deepseek" ;;
            gpt-*|o1-*|o3-*|o4-*) PROVIDER="openai" ;;
            *) PROVIDER="openai" ;;
        esac
        echo "[entrypoint] LLM_PROVIDER not set, auto-detected: ${PROVIDER}"
    fi

    case "$PROVIDER" in
        anthropic) echo "ANTHROPIC_API_KEY=${LLM_API_KEY}" >> "$HERMES_HOME/.env" ;;
        minimax) echo "MINIMAX_API_KEY=${LLM_API_KEY}" >> "$HERMES_HOME/.env" ;;
        minimax-cn) echo "MINIMAX_CN_API_KEY=${LLM_API_KEY}" >> "$HERMES_HOME/.env" ;;
        deepseek) echo "DEEPSEEK_API_KEY=${LLM_API_KEY}" >> "$HERMES_HOME/.env" ;;
        openrouter) echo "OPENROUTER_API_KEY=${LLM_API_KEY}" >> "$HERMES_HOME/.env" ;;
        *) echo "OPENAI_API_KEY=${LLM_API_KEY}" >> "$HERMES_HOME/.env" ;;
    esac
fi

[ -n "${LLM_BASE_URL:-}" ] && echo "OPENAI_BASE_URL=${LLM_BASE_URL}" >> "$HERMES_HOME/.env"
[ -n "${TELEGRAM_BOT_TOKEN:-}" ] && echo "TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}" >> "$HERMES_HOME/.env"
[ -n "${TELEGRAM_CHAT_ID:-}" ] && echo "TELEGRAM_HOME_CHANNEL=${TELEGRAM_CHAT_ID}" >> "$HERMES_HOME/.env"
[ -n "${TELEGRAM_ALLOWED_USERS:-}" ] && echo "TELEGRAM_ALLOWED_USERS=${TELEGRAM_ALLOWED_USERS}" >> "$HERMES_HOME/.env"

echo "[entrypoint] HERMES_HOME=${HERMES_HOME}"
echo "[entrypoint] ${HERMES_HOME}/.env keys:"
grep -o '^[^=]*' "$HERMES_HOME/.env" || true

if [ -f "$CONFIG_TEMPLATE" ]; then
    cp "$CONFIG_TEMPLATE" /tmp/hermes-config.yaml
elif [ -f "$HERMES_HOME/config.yaml" ]; then
    cp "$HERMES_HOME/config.yaml" /tmp/hermes-config.yaml
else
    : > /tmp/hermes-config.yaml
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

cp -f /tmp/hermes-config.yaml "$HERMES_HOME/config.yaml"
chmod 600 "$HERMES_HOME/config.yaml" 2>/dev/null || true

echo "[entrypoint] config.yaml:"
cat "$HERMES_HOME/config.yaml"

exec "$@"
