---
name: wazuh-alert-triage
description: Triage Wazuh SIEM alerts — severity classification, MITRE ATT&CK mapping, context enrichment, and escalation decisions.
version: 1.0.0
author: ORED Labs
license: MIT
metadata:
  hermes:
    tags: [SOC, Wazuh, Triage, MITRE, Alerts]
    related_skills: [wazuh-threat-enrichment, wazuh-incident-workflow]
---

# Wazuh Alert Triage

Triage incoming Wazuh alerts systematically. Every alert gets classified, contextualized, and routed.

## When to Use

- A new alert arrives from Wazuh (via cron poll or webhook trigger)
- You are reviewing a batch of recent alerts
- An alert needs re-evaluation after new context

## Triage Process

### Step 1: Fetch Recent Alerts

Use MCP tool: `mcp_wazuh_get_wazuh_alerts`
- Default: last 100 alerts, sorted by timestamp descending
- For targeted review: filter by agent_id, rule_id, or severity

### Step 2: Classify Each Alert

For each alert, determine:

1. **Severity** (from Wazuh rule level):
   - Level 0-4: Informational → auto-document, no action
   - Level 5-7: Low → log and monitor, check for patterns
   - Level 8-10: Medium → investigate, enrich with threat intel
   - Level 11-12: High → investigate + prepare response actions
   - Level 13-15: Critical → immediate escalation + approval request

2. **MITRE ATT&CK Mapping** (from rule.mitre fields):
   - Extract technique IDs (e.g., T1055, T1059)
   - Map to tactic (Initial Access, Execution, Persistence, etc.)
   - Note if technique is associated with known threat groups

3. **Context Check** — before escalating, always check:
   - Is this a known false positive? (check your memory for this rule_id + agent combo)
   - Is this part of a pattern? (use `mcp_wazuh_analyze_alert_patterns`)
   - Is the source agent healthy? (use `mcp_wazuh_check_agent_health`)

### Step 3: Route the Alert

Based on classification:

| Classification | Action |
|---------------|--------|
| Informational/Known FP | Document in memory, no action |
| Low — isolated | Log, add to baseline monitoring |
| Low — pattern detected | Escalate to Medium |
| Medium | Trigger wazuh-threat-enrichment skill |
| High/Critical | Trigger wazuh-incident-workflow skill |

### Step 4: Document Decision

For every alert triaged, save to memory:
- Rule ID + agent ID + your classification
- Whether it was a false positive
- What action was taken (or not taken, and why)

This builds your baseline over time. After 100+ triaged alerts for a given rule, you can auto-classify with high confidence.

## False Positive Management

When you identify a false positive:
1. Check if you have seen this exact pattern before (rule_id + agent + similar params)
2. If seen 3+ times with same conclusion → mark as known FP in memory
3. Known FPs still get logged but skip enrichment and escalation
4. NEVER suppress an alert permanently — always re-evaluate if context changes

## Batch Triage

When processing multiple alerts:
1. Group by rule_id first (same rule = same initial classification)
2. Within each group, look for patterns (same source IP, same agent, time clustering)
3. Process informational alerts in bulk (document as batch)
4. Process medium+ alerts individually

## Key MCP Tools

| Tool | Purpose |
|------|---------|
| `mcp_wazuh_get_wazuh_alerts` | Fetch alerts with filters |
| `mcp_wazuh_get_wazuh_alert_summary` | Quick overview of alert landscape |
| `mcp_wazuh_analyze_alert_patterns` | Detect patterns across alerts |
| `mcp_wazuh_search_security_events` | Deep search with custom queries |
| `mcp_wazuh_check_agent_health` | Verify agent status before acting |

## Pitfalls

- Do NOT auto-close high/critical alerts even if they look like FPs — always escalate
- Do NOT base triage solely on rule level — context matters (a level 5 from a DMZ host is different from a level 5 on a domain controller)
- Do NOT skip the pattern check — isolated alerts often aren't isolated
- Always check your memory before re-investigating a known pattern
