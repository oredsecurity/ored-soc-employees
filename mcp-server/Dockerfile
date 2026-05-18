# ORED Wazuh MCP Server
# Forked from gensecaihq/Wazuh-MCP-Server with ORED hardening layer
FROM python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd -r mcp && \
    useradd -r -g mcp -d /app -s /usr/sbin/nologin mcp && \
    mkdir -p /var/log/ored-soc && \
    chown -R mcp:mcp /var/log/ored-soc

WORKDIR /app

RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-cache-dir -e ".[redis]" && \
    pip install --no-cache-dir uvicorn[standard]

USER mcp

HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

EXPOSE 3000

CMD ["python", "-m", "wazuh_mcp_server"]
