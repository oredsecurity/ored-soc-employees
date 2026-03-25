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

## What ORED Built

This project is built on top of the Hermes Agent framework and the
Wazuh MCP Server. ORED Labs designed and built:

- Hardening layer: audit middleware, 3-tier action classification
  (auto/approval/forbidden), parameter sanitization, 403 blocks before
  Wazuh sees forbidden requests
- Human-in-the-loop approval system: three security invariants:
  one request at a time, mandatory 5-minute timeout, fail-closed on
  every failure path
- Audit loop: every agent action logged back to Wazuh as a
  structured event with full traceability
- Security framework: RBAC, prompt integrity validation, egress
  controls, memory integrity checks
- SOC-native skill pack: four SKILL.md files encoding real SOC
  methodology: triage, enrichment, incident workflow, baseline learning
- Multi-tenant ready architecture: designed for isolated per-client
  memory and dedicated approval channels from day one

---

## How It Works

```
Wazuh Manager (your existing deployment)
    ↓ REST API
ORED Wazuh MCP Server (48+ security tools + hardening layer)
    ↓ MCP Protocol
Hermes Agent (persistent memory + self-improving skills)
    ↓
Telegram/Slack (human approval for destructive actions)
    ↓
Action executed via Wazuh active response
    ↓
Every action logged back into Wazuh (full audit trail)
```

---

## Action Policy

| Classification | Actions | Policy |
|---|---|---|
| Auto-allowed | Query, analyze, enrich, report, threat intel | Executes immediately |
| Approval required | Block IP, isolate host, quarantine file, kill process, disable user | Telegram approval + audit |
| Forbidden | Modify rules, delete logs, change agent config | Blocked at MCP layer, 403 |

Unknown actions default to approval required. Fail-closed, always.

---

## Quick Start

```bash
git clone https://github.com/oredsecurity/ored-soc-employees.git
cd ored-soc-employees
cp .env.example .env
# Edit .env with your Wazuh credentials and Telegram bot token
./install.sh
```

Requirements:
- Wazuh Manager 4.8+ (API accessible)
- Docker & Docker Compose
- Anthropic API key (via OpenRouter or direct)
- Telegram bot token + chat ID

Full configuration reference in .env.example.

---

## What's Inside

| Component | Description |
|---|---|
| mcp-server/ | Forked Wazuh MCP Server with ORED hardening layer |
| mcp-server/ored_audit.py | Action classifier, parameter sanitizer, audit middleware |
| mcp-server/ored_approval.py | Telegram approval bot (3 invariants) |
| mcp-server/ored_wazuh_audit.py | Audit loop back to Wazuh |
| mcp-server/security.py | RBAC, egress controls, prompt integrity |
| hermes/skills/ | Four core SOC skill files |
| hermes/config/SOUL.md | Agent identity and action policy |

---

## Roadmap

- [x] Wazuh connector (launching now)
- [x] Human-in-the-loop approval system
- [x] Full audit trail back to Wazuh
- [x] Self-improving skill memory
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
