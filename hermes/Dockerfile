# ORED AI SOC Employee — Hermes Agent Container
# Autonomous AI SOC analyst powered by Hermes Agent
FROM python:3.12-slim

# System dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Install Hermes Agent from source
RUN git clone --depth 1 https://github.com/NousResearch/hermes-agent.git /opt/hermes-agent && \
    cd /opt/hermes-agent && \
    pip install --no-cache-dir -e ".[messaging,cron,mcp]"

WORKDIR /root

# Copy ORED SOC config and identity
COPY config/config.yaml /root/.hermes/config.yaml
COPY config/SOUL.md /root/.hermes/SOUL.md
COPY skills/ /root/.hermes/skills/ored-soc/

# Entrypoint: writes env vars to ~/.hermes/.env before starting
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]

# Default: run as Telegram gateway (persistent SOC employee)
CMD ["hermes", "gateway"]
