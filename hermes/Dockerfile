# ORED AI SOC Employee - Hermes Agent Container
# Autonomous AI SOC analyst powered by Hermes Agent
FROM python:3.12-slim

ARG HERMES_REF=v2026.5.16

ENV HOME=/home/hermes \
    HERMES_HOME=/home/hermes/.hermes \
    XDG_CACHE_HOME=/home/hermes/.hermes/cache \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

RUN groupadd --gid 10001 hermes && \
    useradd --uid 10001 --gid hermes --create-home \
      --home-dir /home/hermes --shell /usr/sbin/nologin hermes

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      git curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN git clone --depth 1 --branch "${HERMES_REF}" \
      https://github.com/NousResearch/hermes-agent.git /opt/hermes-agent && \
    cd /opt/hermes-agent && \
    pip install --no-cache-dir -e ".[messaging,cron,mcp]"

WORKDIR /home/hermes

RUN mkdir -p /opt/ored/config \
      /home/hermes/.hermes/skills/ored-soc \
      /home/hermes/.hermes/plugins \
      /home/hermes/.hermes/cache
COPY --chown=hermes:hermes config/config.yaml /opt/ored/config/config.yaml
COPY --chown=hermes:hermes config/SOUL.md /home/hermes/.hermes/SOUL.md
COPY --chown=hermes:hermes skills/ /home/hermes/.hermes/skills/ored-soc/
COPY --chown=hermes:hermes plugins/ /home/hermes/.hermes/plugins/
COPY entrypoint.sh /entrypoint.sh
RUN chmod 0755 /entrypoint.sh && \
    chown -R hermes:hermes /home/hermes /opt/ored

USER hermes

ENTRYPOINT ["/entrypoint.sh"]
CMD ["hermes", "gateway"]
