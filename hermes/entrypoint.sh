#!/bin/sh
set -e

# ORED SOC Employee container entrypoint.
# Writes runtime secrets to HERMES_HOME/.env and renders config.yaml from the
# read-only template mounted at /opt/ored/config/config.yaml.

HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"
CONFIG_TEMPLATE="${HERMES_CONFIG_TEMPLATE:-/opt/ored/config/config.yaml}"
export HERMES_HOME
export XDG_CACHE_HOME="${XDG_CACHE_HOME:-$HERMES_HOME/cache}"
export XDG_STATE_HOME="${XDG_STATE_HOME:-$HERMES_HOME/state}"
export XDG_DATA_HOME="${XDG_DATA_HOME:-$HERMES_HOME/share}"
export XDG_CONFIG_HOME="${XDG_CONFIG_HOME:-$HERMES_HOME/config-home}"

mkdir -p "$HERMES_HOME" "$XDG_CACHE_HOME" "$XDG_STATE_HOME" "$XDG_DATA_HOME" "$XDG_CONFIG_HOME" "$HERMES_HOME/local" "$HERMES_HOME/logs" "$HERMES_HOME/sessions" "$HERMES_HOME/cron"

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
        anthropic) echo "ANTHROPIC_API_KEY=${LLM_API_KEY}" >> "$HERMES_HOME/.env"; export ANTHROPIC_API_KEY="$LLM_API_KEY" ;;
        minimax) echo "MINIMAX_API_KEY=${LLM_API_KEY}" >> "$HERMES_HOME/.env"; export MINIMAX_API_KEY="$LLM_API_KEY" ;;
        minimax-cn) echo "MINIMAX_CN_API_KEY=${LLM_API_KEY}" >> "$HERMES_HOME/.env"; export MINIMAX_CN_API_KEY="$LLM_API_KEY" ;;
        deepseek) echo "DEEPSEEK_API_KEY=${LLM_API_KEY}" >> "$HERMES_HOME/.env"; export DEEPSEEK_API_KEY="$LLM_API_KEY" ;;
        openrouter) echo "OPENROUTER_API_KEY=${LLM_API_KEY}" >> "$HERMES_HOME/.env"; export OPENROUTER_API_KEY="$LLM_API_KEY" ;;
        *) echo "OPENAI_API_KEY=${LLM_API_KEY}" >> "$HERMES_HOME/.env"; export OPENAI_API_KEY="$LLM_API_KEY" ;;
    esac
fi

if [ -n "${PROVIDER:-}" ]; then
    export HERMES_INFERENCE_PROVIDER="$PROVIDER"
fi

[ -n "${LLM_BASE_URL:-}" ] && echo "OPENAI_BASE_URL=${LLM_BASE_URL}" >> "$HERMES_HOME/.env" && export OPENAI_BASE_URL="$LLM_BASE_URL"
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

python - "$LLM_MODEL" "$PROVIDER" "$LLM_BASE_URL" /tmp/hermes-config.yaml /tmp/hermes-config.rendered.yaml <<'PY'
import sys
import yaml

model, provider, base_url, source, target = sys.argv[1:]

with open(source, "r", encoding="utf-8") as fh:
    loaded = yaml.safe_load(fh) or {}

config = loaded if isinstance(loaded, dict) else {}
model_config = config.get("model")
if not isinstance(model_config, dict):
    model_config = {}

if model:
    model_config["default"] = model
if provider:
    model_config["provider"] = provider
if base_url:
    model_config["base_url"] = base_url

if model_config:
    config["model"] = model_config

config.pop("provider", None)

with open(target, "w", encoding="utf-8") as fh:
    yaml.safe_dump(config, fh, sort_keys=False)
PY

cp -f /tmp/hermes-config.rendered.yaml "$HERMES_HOME/config.yaml"
chmod 600 "$HERMES_HOME/config.yaml" 2>/dev/null || true

echo "[entrypoint] config.yaml:"
cat "$HERMES_HOME/config.yaml"

exec "$@"
