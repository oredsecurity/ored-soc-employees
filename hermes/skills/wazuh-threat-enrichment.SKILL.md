---
name: wazuh-threat-enrichment
description: Enrich Wazuh alerts with threat intelligence — IOC reputation, MITRE context, agent forensics, and vulnerability correlation.
version: 1.0.0
author: ORED Labs
license: MIT
metadata:
  hermes:
    tags: [SOC, Wazuh, Threat-Intel, Enrichment, IOC]
    related_skills: [wazuh-alert-triage, wazuh-incident-workflow]
---

# Wazuh Threat Enrichment

Enrich triaged alerts with threat intelligence and contextual data. Runs after triage classifies an alert as Medium or above.

## When to Use

- Alert classified as Medium+ by wazuh-alert-triage skill
- Manual investigation request from operator
- Proactive threat hunt across alert data

## Enrichment Pipeline

### Step 1: Extract Indicators

From the alert data, extract all observable indicators:
- **IP addresses**: source IP, destination IP (from alert data fields)
- **Hostnames/domains**: from DNS-related alerts or URL fields
- **File hashes**: from FIM (file integrity monitoring) alerts
- **User accounts**: from authentication alerts
- **Process names**: from process monitoring alerts

### Step 2: IOC Reputation Check

Use MCP tool: `mcp_wazuh_check_ioc_reputation`
- Check each extracted IP/domain/hash against threat intel
- Document reputation score and associated threat categories

If web search is available, also query:
- VirusTotal (if API key configured)
- AbuseIPDB for IP reputation
- Known malware hash databases

### Step 3: Agent Context

For the affected agent, gather:
1. **Agent health**: `mcp_wazuh_check_agent_health` — is it responding normally?
2. **Running processes**: `mcp_wazuh_get_agent_processes` — anything suspicious?
3. **Open ports**: `mcp_wazuh_get_agent_ports` — unexpected listeners?
4. **Recent alerts**: `mcp_wazuh_get_wazuh_alerts` filtered to this agent — pattern?
5. **Vulnerabilities**: `mcp_wazuh_get_wazuh_vulnerabilities` for this agent — exploitable?

### Step 4: Vulnerability Correlation

Use MCP tool: `mcp_wazuh_get_wazuh_vulnerabilities`
- Check if the affected agent has known vulnerabilities
- Cross-reference with the alert type — is this an exploitation attempt against a known vuln?
- If CVE data available, check CVSS score and exploitability

### Step 5: MITRE ATT&CK Deep Mapping

Beyond the basic mapping from triage:
- Identify the full kill chain position (which tactic stage?)
- Check if related techniques have been seen on the same agent
- Look for lateral movement indicators if the alert is post-exploitation

### Step 6: Risk Assessment

Use MCP tool: `mcp_wazuh_perform_risk_assessment`
- Combine all enrichment data into a risk score
- Factor in: alert severity + IOC reputation + agent vulnerability exposure + pattern context

### Step 7: Produce Enrichment Report

Structure your findings as:

```
ENRICHMENT REPORT — Alert [rule_id] on Agent [agent_id]
═══════════════════════════════════════════════════════
Severity: [level] | MITRE: [technique] | Risk: [score]

Indicators:
  - IP [x.x.x.x]: [reputation result]
  - Hash [abc123]: [reputation result]

Agent Context:
  - Health: [status]
  - Suspicious processes: [list or none]
  - Open ports: [list]
  - Known vulns: [count, critical count]

Correlation:
  - Related alerts (last 24h): [count]
  - Kill chain position: [tactic]
  - Lateral movement indicators: [yes/no]

Recommendation: [auto-close | monitor | escalate | respond]
```

Save this report to memory for future reference.

## Key MCP Tools

| Tool | Purpose |
|------|---------|
| `mcp_wazuh_check_ioc_reputation` | Check indicator reputation |
| `mcp_wazuh_analyze_security_threat` | Deep threat analysis |
| `mcp_wazuh_perform_risk_assessment` | Combined risk scoring |
| `mcp_wazuh_get_agent_processes` | Agent process inventory |
| `mcp_wazuh_get_agent_ports` | Agent network listeners |
| `mcp_wazuh_get_wazuh_vulnerabilities` | Agent vulnerability data |
| `mcp_wazuh_get_wazuh_critical_vulnerabilities` | Critical vulns only |

## Pitfalls

- Do NOT treat IOC reputation as absolute truth — false positives exist in threat intel too
- Do NOT skip agent context — an alert without agent context is half-investigated
- Always check if the agent has relevant vulnerabilities before dismissing an exploit attempt
- Save enrichment results to memory — re-enriching the same IOC wastes time and API calls
- If enrichment reveals High/Critical risk, hand off to wazuh-incident-workflow immediately
