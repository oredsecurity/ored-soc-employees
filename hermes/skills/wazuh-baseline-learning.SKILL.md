---
name: wazuh-baseline-learning
description: Build and maintain behavioral baselines per agent — normal alert patterns, false positive tracking, and self-improving triage accuracy.
version: 1.0.0
author: ORED Labs
license: MIT
metadata:
  hermes:
    tags: [SOC, Wazuh, Baseline, Learning, Memory]
    related_skills: [wazuh-alert-triage, wazuh-threat-enrichment]
---

# Wazuh Baseline Learning

Build behavioral baselines for each monitored agent. Learn what is normal so you can detect what is not. This is the self-improvement loop.

## When to Use

- Scheduled: Run baseline collection daily (via cron job)
- After triage: Update baselines with new alert data
- On demand: When investigating an agent, compare against baseline
- Weekly: Run baseline integrity check (memory health)

## Baseline Collection Process

### Step 1: Gather Agent Inventory

Use MCP tool: `mcp_wazuh_get_wazuh_agents`
- Get full list of active agents
- Record: agent ID, name, OS, IP, group, last keep-alive

### Step 2: Per-Agent Alert Profile

For each agent, collect (over rolling 7-day window):

1. **Alert frequency**: `mcp_wazuh_get_wazuh_alert_summary`
   - Average alerts per day
   - Alert count by rule level
   - Most common rule IDs

2. **Top rules triggered**: `mcp_wazuh_analyze_alert_patterns`
   - Top 10 rules by frequency
   - Time-of-day distribution
   - Day-of-week distribution

3. **Network profile**: `mcp_wazuh_get_agent_ports`
   - Normal listening ports
   - Expected services

4. **Process profile**: `mcp_wazuh_get_agent_processes`
   - Normal running processes
   - Expected process count range

### Step 3: Store Baseline in Memory

Save a structured baseline per agent:

```
BASELINE — Agent [name] ([ID])
Last updated: [date]
OS: [os info]
Profile period: [start] to [end]

Alert Profile:
  - Avg alerts/day: [n]
  - Common rules: [rule_id: count, ...]
  - Peak hours: [HH-HH]
  - Quiet hours: [HH-HH]

Network Profile:
  - Normal ports: [list]
  - Expected services: [list]

Process Profile:
  - Normal process count: [range]
  - Expected processes: [list]

Known False Positives:
  - Rule [id] + [condition]: seen [n] times, always FP
  - Rule [id] + [condition]: seen [n] times, always FP

Anomaly Thresholds:
  - Alert spike: >[2x avg] alerts in 1 hour
  - New port: any port not in normal list
  - New process: any process not in expected list
  - Rule level spike: any level 10+ on rules normally level 5-
```

### Step 4: Anomaly Detection

When triaging alerts, compare against the baseline:

1. **Alert frequency anomaly**: Is this agent generating significantly more alerts than usual?
2. **New rule trigger**: Is this rule ID new for this agent?
3. **Time anomaly**: Is this alert occurring outside the agent's normal active hours?
4. **Behavioral change**: Has the agent's process or port profile changed?

Flag anomalies in triage — even a low-severity alert becomes interesting if it's anomalous for that agent.

## False Positive Learning

### Tracking FPs

Every time you classify an alert as a false positive during triage:
1. Record: rule_id + agent_id + key distinguishing parameters
2. Increment the FP counter for this combination
3. After 3 FP classifications for the same pattern → mark as "known FP"
4. After 10 FP classifications → mark as "confirmed FP" (high confidence auto-skip)

### FP Decay

False positive classifications are not permanent:
- If a "known FP" pattern triggers a high-severity alert → re-evaluate
- If 30+ days pass without seeing a pattern → archive it (don't delete)
- If the agent's OS or role changes → reset its FP profile

### FP Reporting

Weekly, generate a false positive summary:
- Total FP rate (FP alerts / total alerts)
- Top 10 FP rules
- Agents with highest FP rates
- Recommendations for rule tuning (report only — never modify rules)

## Memory Integrity Check

### Why

Your memory is your most valuable asset — and your biggest attack surface. Memory poisoning (OWASP ASI06) means an attacker could manipulate your baseline data to make you ignore real threats.

### Weekly Integrity Check

Run weekly (via cron):

1. **Baseline hash**: Calculate a hash of each agent's baseline data
   - Compare against last week's hash
   - If changed, verify the changes are explained by your own triage logs
   - If unexplained changes exist → alert the operator

2. **FP list review**: Check all "known FP" entries
   - Are any suspiciously broad? (e.g., "all alerts from agent X are FP")
   - Are any recently added without corresponding triage logs?
   - Flag suspicious entries for human review

3. **Skill file integrity**: Verify your skill files haven't been modified
   - Compare against known-good hashes from initial deployment
   - If modified → alert immediately

4. **Memory size check**: Is memory growing abnormally?
   - Unusual growth could indicate injection attempts
   - Compare against expected growth rate based on alert volume

### Reporting

Output a memory health report:

```
MEMORY INTEGRITY REPORT — [Date]
═════════════════════════════════
Baselines checked: [n] agents
Baseline changes: [n] (all explained: yes/no)
FP entries: [n] total ([n] new this week)
Suspicious entries: [list or none]
Skill file integrity: [OK/ALERT]
Memory size: [current] ([delta] from last week)
Status: HEALTHY / REVIEW NEEDED / ALERT
```

## Cron Schedule

| Job | Schedule | Description |
|-----|----------|-------------|
| Baseline collection | Daily 02:00 UTC | Refresh agent baselines |
| Alert poll | Every 5 minutes | Check for new alerts, run triage |
| FP summary | Weekly Monday 06:00 UTC | False positive report |
| Integrity check | Weekly Sunday 03:00 UTC | Memory health verification |

## Pitfalls

- Do NOT let baselines grow unbounded — archive data older than 90 days
- Do NOT auto-tune Wazuh rules based on FP data — report only, human decides
- Do NOT trust baselines blindly — an attacker who was present during baseline collection will be in your "normal"
- Always compare baselines across similar agents — if one agent differs significantly from its peers, investigate
- The integrity check is non-negotiable — run it every week, no exceptions
