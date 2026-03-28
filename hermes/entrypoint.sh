#!/bin/sh
set -e

# Write environment variables to ~/.hermes/.env so Hermes gateway can read them.
# Docker compose passes env vars from the host .env, but Hermes reads from
# ~/.hermes/.env inside the container. This bridge script maps between them.
mkdir -p /root/.hermes

# Start fresh
> /root/.hermes/.env

# Map LLM_API_KEY to the correct provider-specific env var.
# Hermes expects provider-specific names, not a generic LLM_API_KEY.
# We detect the provider from LLM_BASE_URL or LLM_PROVIDER, and fall back
# to OPENAI_API_KEY (which works with OpenRouter and OpenAI-compatible APIs).
if [ -n "${LLM_API_KEY:-}" ]; then
    PROVIDER="${LLM_PROVIDER:-}"

    # Auto-detect provider from base URL if not explicitly set
    if [ -z "$PROVIDER" ] && [ -n "${LLM_BASE_URL:-}" ]; then
        case "$LLM_BASE_URL" in
            *anthropic*)    PROVIDER="anthropic" ;;
            *minimax.io*)   PROVIDER="minimax" ;;
            *minimaxi.com*) PROVIDER="minimax-cn" ;;
            *openrouter*)   PROVIDER="openrouter" ;;
            *deepseek*)     PROVIDER="deepseek" ;;
            *)              PROVIDER="openai" ;;
        esac
    fi

    # Auto-detect provider from model name as fallback
    if [ -z "$PROVIDER" ] && [ -n "${LLM_MODEL:-}" ]; then
        case "$LLM_MODEL" in
            MiniMax*|minimax*)  PROVIDER="minimax" ;;
            claude*|Claude*)    PROVIDER="anthropic" ;;
            deepseek*|DeepSeek*) PROVIDER="deepseek" ;;
        esac
    fi

    # Write the correct env var name for the detected provider
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
        *)
            # Default: OPENAI_API_KEY works for OpenRouter and any OpenAI-compatible API
            echo "OPENAI_API_KEY=${LLM_API_KEY}" >> /root/.hermes/.env
            ;;
    esac
fi

# Pass through base URL if set
[ -n "${LLM_BASE_URL:-}" ] && echo "OPENAI_BASE_URL=${LLM_BASE_URL}" >> /root/.hermes/.env

# Config.yaml is mounted read-only, so we copy it and patch the copy
# The volume mount puts it at /root/.hermes/config.yaml (ro)
# We copy to a temp location, patch it, then replace
if [ -f /root/.hermes/config.yaml ]; then
    cp /root/.hermes/config.yaml /tmp/hermes-config.yaml
else
    echo "" > /tmp/hermes-config.yaml
fi

# Set model if LLM_MODEL is provided
if [ -n "${LLM_MODEL:-}" ]; then
    if grep -q '^model:' /tmp/hermes-config.yaml 2>/dev/null; then
        sed -i "s|^model:.*|model: \"${LLM_MODEL}\"|" /tmp/hermes-config.yaml
    else
        sed -i "1i model: \"${LLM_MODEL}\"" /tmp/hermes-config.yaml
    fi
fi

# Set provider if detected
if [ -n "${PROVIDER:-}" ]; then
    if grep -q '^provider:' /tmp/hermes-config.yaml 2>/dev/null; then
        sed -i "s|^provider:.*|provider: \"${PROVIDER}\"|" /tmp/hermes-config.yaml
    else
        sed -i "1i provider: \"${PROVIDER}\"" /tmp/hermes-config.yaml
    fi
fi

# Replace the read-only mount with our patched version
cp -f /tmp/hermes-config.yaml /root/.hermes/config.yaml 2>/dev/null || {
    # If ro mount blocks cp, use bind mount workaround
    mount --bind /tmp/hermes-config.yaml /root/.hermes/config.yaml 2>/dev/null || true
}

echo "[entrypoint] Config:"
cat /root/.hermes/config.yaml

# Telegram credentials
[ -n "${TELEGRAM_BOT_TOKEN:-}" ] && echo "TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}" >> /root/.hermes/.env
[ -n "${TELEGRAM_CHAT_ID:-}" ] && echo "TELEGRAM_HOME_CHANNEL=${TELEGRAM_CHAT_ID}" >> /root/.hermes/.env

echo "[entrypoint] Wrote /root/.hermes/.env with keys:"
grep -oP '^[^=]+' /root/.hermes/.env

exec "$@"
