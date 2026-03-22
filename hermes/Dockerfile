# ORED Hermes SOC Agent
# Autonomous AI SOC employee powered by Hermes Agent
FROM node:20-slim AS base

# Install system deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    git curl python3 python3-pip ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Install Hermes Agent
RUN npm install -g hermes-agent

# Install MCP SDK for native MCP client
RUN pip install --no-cache-dir --break-system-packages mcp

WORKDIR /root

# Copy config and soul
COPY config/ /root/.hermes/
COPY skills/ /root/.hermes/skills/ored-soc/

# The agent runs as a persistent process
# In production, this will be triggered by cron or webhook
CMD ["hermes-agent", "start"]
