---
name: wazuh-incident-workflow
description: End-to-end incident response workflow — investigation, response actions with human approval, containment, and documentation.
version: 1.0.0
author: ORED Labs
license: MIT
metadata:
  hermes:
    tags: [SOC, Wazuh, Incident-Response, Approval, Containment]
    related_skills: [wazuh-alert-triage, wazuh-threat-enrichment]
---

# Wazuh Incident Workflow

Handle security incidents from detection through containment and documentation. This skill orchestrates response actions that require human approval.

## When to Use

- Alert classified as High/Critical by triage
- Enrichment reveals active threat indicators
- Operator requests manual incident investigation
- Multiple related alerts suggest coordinated activity

## Incident Response Process

### Step 1: Confirm the Incident

Before requesting any destructive action:
1. Review the triage classification — is it still High/Critical?
2. Review the enrichment report — what evidence supports this?
3. Check for false positive indicators in your memory
4. Verify the affected agent is real and active: `mcp_wazuh_check_agent_health`

### Step 2: Determine Response Actions

Based on the incident type, identify required response actions:

| Incident Type | Typical Response |
|--------------|-----------------|
| Brute force / credential stuffing | Block source IP |
| Malware detected (FIM) | Quarantine file, isolate host |
| Unauthorized process | Kill process, investigate persistence |
| Compromised account | Disable user account |
| Network-based attack | Firewall drop source IP |
| Lateral movement | Isolate affected host(s) |

### Step 3: Request Human Approval

**CRITICAL: Never execute destructive actions without approval.**

Format the approval request clearly:

```
🚨 INCIDENT RESPONSE — Approval Required
══════════════════════════════════════════
Alert: [rule description]
Agent: [agent name] ([agent ID])
Severity: [level] — [classification]
MITRE: [technique ID] — [technique name]

Evidence:
  [bullet points of key findings from enrichment]

Proposed Actions:
  1. [action] — [justification]
  2. [action] — [justification]

Risk if NO action: [assessment]
Risk if action taken: [assessment]

Reply ✅ to approve, ❌ to deny, or provide alternative instructions.
```

Send via Telegram/Slack approval interface. WAIT for response.

### Step 4: Execute Approved Actions

Only after receiving approval. Active response is OS-aware and fail-closed: always target one specific active `agent_id`. If Wazuh cannot identify the endpoint OS, the agent is disconnected, or the action is not safely reversible for that OS, report that action is blocked. Do not target `all agents`.

1. **Block IP**: `mcp_wazuh_wazuh_block_ip`
   - Params: ip_address, agent_id
   - Linux-only in the current deployment. Windows built-in `netsh.exe` and ORED wrapper paths remain blocked until rollback is validated.
   - Verify: `mcp_wazuh_wazuh_check_blocked_ip`

2. **Firewall Drop**: `mcp_wazuh_wazuh_firewall_drop`
   - Params: agent_id, source IP
   - Linux-only in the current deployment. Windows built-in `netsh.exe` and ORED wrapper paths remain blocked until rollback is validated.
   - Verify: `mcp_wazuh_wazuh_check_blocked_ip`

3. **Host Deny**: `mcp_wazuh_wazuh_host_deny`
   - Params: agent_id, source IP
   - Linux-only; blocked on Windows

4. **Disable User**: `mcp_wazuh_wazuh_disable_user`
   - Params: agent_id, username
   - Linux-only in the current deployment; blocked on Windows
   - Verify: `mcp_wazuh_wazuh_check_user_status`

5. **Not configured yet**
   - Host isolation, process kill, and file quarantine are approval-required but blocked until tested scripts are installed on the manager/agent. Explain this instead of attempting them.

ALWAYS verify after execution. If verification fails, report immediately.

### Step 5: Document the Incident

After all actions are complete, create an incident report:

```
INCIDENT REPORT — [Date] [Time UTC]
═════════════════════════════════════
Incident ID: INC-[YYYYMMDD]-[sequence]
Severity: [Critical/High]
Status: [Contained/Monitoring/Resolved]

Timeline:
  [HH:MM] Alert received — [description]
  [HH:MM] Triage completed — classified as [level]
  [HH:MM] Enrichment completed — [key finding]
  [HH:MM] Approval requested — [actions proposed]
  [HH:MM] Approval received from [operator]
  [HH:MM] Actions executed — [list]
  [HH:MM] Verification — [results]

Affected Assets:
  - Agent: [name] ([ID])
  - IP: [addresses]
  - Users: [accounts]

Actions Taken:
  - [action]: [result]

Indicators of Compromise:
  - [type]: [value] — [reputation]

MITRE ATT&CK:
  - [Tactic] > [Technique] ([ID])

Recommendations:
  - [follow-up actions]

Lessons Learned:
  - [what to improve for next time]
```

Save the full report to memory. This builds institutional knowledge.

### Step 6: Post-Incident Monitoring

After containment:
1. Set up enhanced monitoring for the affected agent (increase alert polling frequency)
2. Watch for related alerts on other agents (lateral movement detection)
3. Schedule a follow-up check (use cron) at +1h, +4h, +24h
4. If clean after 24h, document as resolved

## Action Policy Reminder

| Action | Policy | Tool |
|--------|--------|------|
| Block IP | Approval required, Linux-only until Windows rollback is validated | `wazuh_block_ip` |
| Firewall drop | Approval required, Linux-only until Windows rollback is validated | `wazuh_firewall_drop` |
| Host deny | Approval required, Linux-only | `wazuh_host_deny` |
| Disable user | Approval required, Linux-only in current deployment | `wazuh_disable_user` |
| Isolate host | Approval required but not configured yet | `wazuh_isolate_host` |
| Kill process | Approval required but not configured yet | `wazuh_kill_process` |
| Quarantine file | Approval required but not configured yet | `wazuh_quarantine_file` |
| Restart Wazuh | FORBIDDEN | - |
| Modify rules | FORBIDDEN | - |
| Delete logs | FORBIDDEN | - |

## Pitfalls

- NEVER execute a response action without confirmed human approval
- NEVER skip the verification step after executing an action
- Document EVERYTHING — the incident report is evidence
- If approval is denied, document why and what alternative was chosen
- Do not isolate a host that is the only path to other critical systems without explicit confirmation
- If the incident involves multiple agents, handle them as a single coordinated incident, not separate ones
