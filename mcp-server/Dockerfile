# ORED Wazuh MCP Server
# Forked from gensecaihq/Wazuh-MCP-Server with ORED hardening layer
FROM python:3.12-slim AS base

# Security: non-root user
RUN groupadd -r mcp && useradd -r -g mcp -d /app -s /sbin/nologin mcp

WORKDIR /app

# Install system deps
RUN apt-get update && \
    apt-get install -y --no-install-recommends curl && \
    rm -rf /var/lib/apt/lists/*

# Copy and install Python deps
COPY pyproject.toml ./
COPY src/ ./src/

RUN pip install --no-cache-dir -e ".[redis]" && \
    pip install --no-cache-dir uvicorn[standard]

# Security: drop to non-root
USER mcp

# Health check endpoint
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost:3000/health || exit 1

EXPOSE 3000

CMD ["python", "-m", "wazuh_mcp_server"]
