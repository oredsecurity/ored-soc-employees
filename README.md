# ORED AI SOC Employees

**Autonomous, self-improving, fully-auditable AI SOC employees for any SIEM.**
Launching with Wazuh. Built on [Hermes Agent](https://github.com/NousResearch/hermes-agent).

> Built by [ORED Labs](https://ored.security) — frontier AI security operations.

## What This Is

A production-ready stack that turns your Wazuh SIEM into an autonomous security operations center. The AI SOC employee:

- **Triages alerts** with persistent memory and MITRE ATT&CK mapping
- **Enriches threats** with multi-source intelligence
- **Takes action** (block, isolate, quarantine) with human approval
- **Learns and improves** from every alert it handles
- **Logs everything** back into Wazuh for full audit trail

## Quick Start

```bash
git clone https://github.com/oredsecurity/ored-soc-employees.git
cd ored-soc-employees
./install.sh
```

You need:
- A running Wazuh instance (manager API accessible)
- Docker & Docker Compose
- An Anthropic API key

## Architecture

```
Wazuh Manager (your existing deployment)
   ↓ REST API
ORED Wazuh MCP Server (48+ security tools)
   ↓ MCP Protocol
Hermes Agent (persistent memory + self-improving skills)
   ↓
Telegram/Slack (human approval for destructive actions)
   ↓
Actions logged back into Wazuh (full audit trail)
```

## Action Policy

| Action Type | Policy |
|------------|--------|
| Query, analyze, enrich, report | Auto-allowed |
| Block IP, isolate host, quarantine file, kill process, disable user | Human approval required |
| Modify rules, delete logs, change config | Forbidden |

## Stack

| Component | Description |
|-----------|-------------|
| `wazuh-mcp-server` | Forked [gensecaihq/Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server) with ORED hardening |
| `hermes-agent` | [Hermes Agent](https://github.com/NousResearch/hermes-agent) configured as SOC employee |
| Skills | Four core skill files for triage, enrichment, workflow, and baseline learning |

## Configuration

Copy `.env.example` to `.env` and configure:

```bash
cp .env.example .env
```

Required variables:
- `WAZUH_HOST` — Your Wazuh manager URL
- `WAZUH_USER` / `WAZUH_PASS` — Wazuh API credentials
- `ANTHROPIC_API_KEY` — For the LLM backend

See `.env.example` for all options.

## License

MIT

## Credits

- [Hermes Agent](https://github.com/NousResearch/hermes-agent) by NousResearch
- [Wazuh MCP Server](https://github.com/gensecaihq/Wazuh-MCP-Server) by GenSecAI
- Built by ORED Labs for ORED Security
