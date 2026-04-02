# ORED AI SOC Employees

> Autonomous, self-improving, fully-auditable AI SOC employees for any SIEM.
> Launching with Wazuh. Built by ORED Labs.

---

## What This Is

Most AI security tools are chatbots with a SIEM connection.
This is different.

ORED AI SOC Employees are persistent, self-improving agents that work
24/7, triaging alerts, enriching threats, requesting human approval
for destructive actions, and learning from every incident they handle.
Every action is logged back into Wazuh. Nothing happens without an
audit trail.

On first connection to a live Wazuh instance, the agent autonomously:
- Ingested a full SCA assessment from a live Windows endpoint
- Classified findings into severity tiers with MITRE mapping
- Identified critical authentication and access control failures
- Delivered a structured approval request to Telegram
- Logged the full decision trail back to Wazuh

No configuration beyond credentials. No human guidance during triage.

---

## Architecture

```
Wazuh Manager (your existing deployment)
    | REST API
ORED Wazuh MCP Server (Docker, 48+ security tools + hardening layer)
    | MCP Protocol
Hermes Agent (native, profiles for tenant isolation)
    |-- ored-soc-policy plugin (action enforcement)
    |-- SOC skills (triage, enrichment, incident workflow, baseline)
    |-- SOUL.md (ARGOS identity)
    |
Telegram/Slack (human approval for destructive actions)
    |
Action executed via Wazuh active response
    |
Every action logged back into Wazuh (full audit trail)
```

The MCP server runs in Docker. The Hermes agent runs natively on the
host, using profiles for multi-tenant isolation. Each tenant gets:
- Its own Hermes profile (isolated config, memory, sessions, skills)
- Its own MCP server container (isolated Wazuh credentials, port)

---

## Action Policy (enforced at two layers)

| Classification | Actions | Policy |
|---|---|---|
| Auto-allowed | Query, analyze, enrich, report, threat intel | Executes immediately |
| Approval required | Block IP, isolate host, quarantine file, kill process, disable user | Telegram approval + audit |
| Forbidden | Restart Wazuh, modify rules, delete logs | Hard blocked, 403 |

Enforcement is defense-in-depth:
- **Client-side**: ored-soc-policy plugin intercepts tool calls before they leave the agent
- **Server-side**: MCP server middleware blocks forbidden actions with 403 responses

Unknown actions default to approval required. Fail-closed, always.

---

## Quick Start

```bash
# Clone and install
git clone https://github.com/oredsecurity/ored-soc-employees.git
cd ored-soc-employees
cp .env.example .env
# Edit .env with your Wazuh credentials
./install.sh
```

This installs Docker (if needed), builds the MCP server container,
and installs Hermes natively. Then provision your first tenant:

```bash
./scripts/provision-tenant.sh acme \
  --wazuh-url https://your-wazuh-manager \
  --wazuh-pass 'your-password' \
  --llm-api-key sk-your-key
```

This creates:
- A Hermes profile at ~/.hermes/profiles/acme/
- An MCP server container (ored-mcp-acme) on an auto-assigned port
- All config, skills, plugins, and credentials wired up

Start the SOC agent:

```bash
hermes --profile acme
```

Requirements:
- Wazuh Manager 4.8+ (API accessible)
- Docker and Docker Compose
- Python 3.11+
- LLM API key (Anthropic, OpenRouter, MiniMax, or any OpenAI-compatible)
- Telegram bot token + chat ID (for approval workflows)

---

## What's Inside

| Component | Description |
|---|---|
| mcp-server/ | Forked Wazuh MCP Server with ORED hardening layer |
| mcp-server/ored_audit.py | Action classifier, parameter sanitizer, audit middleware |
| mcp-server/ored_approval.py | Telegram approval bot (fail-closed, 5-min timeout) |
| mcp-server/ored_wazuh_audit.py | Audit loop: logs agent actions back to Wazuh |
| hermes/plugins/ored-soc-policy/ | Hermes plugin: client-side action enforcement |
| hermes/skills/ | Four SOC skill files (triage, enrichment, incident, baseline) |
| hermes/config/SOUL.md | Agent identity (ARGOS) and behavioral rules |
| scripts/provision-tenant.sh | One-command tenant onboarding |
| install.sh | System setup (Docker, Hermes, MCP server) |

---

## Multi-Tenant

Each client gets isolated infrastructure:

```bash
# Provision multiple tenants
./scripts/provision-tenant.sh acme    --wazuh-url https://wazuh-1 ...
./scripts/provision-tenant.sh contoso --wazuh-url https://wazuh-2 ...

# Each runs independently
hermes --profile acme
hermes --profile contoso

# Manage
hermes profile list
docker ps --filter "name=ored-mcp-"
```

Isolation boundaries:
- Hermes profiles: separate config, memory, sessions, skills, credentials
- MCP containers: separate Wazuh credentials, ports, resource limits
- Wazuh RBAC: API users scoped to agent groups (configured on Wazuh side)

---

## Roadmap

- [x] Wazuh connector (live)
- [x] Human-in-the-loop approval system
- [x] Full audit trail back to Wazuh
- [x] Self-improving skill memory
- [x] Client-side action enforcement plugin
- [x] Multi-tenant provisioning
- [ ] Webhook receiver (real-time alert processing)
- [ ] Priority queue (critical-first triage)
- [ ] Batch digest for low-severity alerts
- [ ] Microsoft Sentinel connector
- [ ] Elastic connector
- [ ] Splunk connector

---

## License

MIT. See [LICENSE](LICENSE).

---

## Credits

- [Hermes Agent](https://github.com/NousResearch/hermes-agent)
  by Nous Research: agent framework
- [Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server)
  by GenSecAI: Wazuh tool layer
- Built by [ORED Labs](https://oredlabs.com)
  for [ORED Security](https://oredsecurity.com)
