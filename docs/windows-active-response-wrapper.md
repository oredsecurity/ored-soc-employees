# Windows Active Response Wrapper

Status: live-tested for explicit add and rollback on `001 / ored-win-01`. ARGOS may use this wrapper for one active Windows agent after human approval. Generic raw Windows `netsh` remains blocked.

## Why This Exists

Wazuh API active-response success means the manager accepted and dispatched a command. It does not prove the endpoint changed firewall state. The built-in Windows `netsh.exe` active-response can create a block, but rollback through the same path was unreliable.

The ORED wrapper is intended to make Windows containment explicit and reversible:

- create only rules named `ORED ARGOS BLOCKED IP`;
- block one IP at a time;
- remove only matching ORED-owned rules;
- verify final firewall state before returning success;
- log endpoint evidence to `active-responses.log`.

## Current Findings From June 17, 2026

What worked:

- Native MinGW-built Windows executables launch from Wazuh when the command is present in generated `ar.conf`.
- `ored-win-firewall-v2.exe` successfully created an inbound Windows firewall block for `203.0.113.62` through Wazuh API.
- Endpoint evidence confirmed the rule existed:
  - Display name: `ORED ARGOS BLOCKED IP`
  - Remote address: `203.0.113.62`
- Wrapper evidence confirmed add success:
  - `ored-win-firewall: requested action=add srcip=203.0.113.62`
  - `ored-win-firewall: add srcip=203.0.113.62 rc=0`

What changed after implementing the Wazuh protocol:

- The wrapper now emits `check_keys` and waits for Wazuh's `continue` response before acting.
- The wrapper uses different keys for add and rollback: `ored-win-firewall:add:<ip>` and `ored-win-firewall:delete:<ip>`.
- `!ored-win-firewall-v3` successfully added `203.0.113.80`.
- `!ored-win-firewall-rollback` successfully removed `203.0.113.80`.
- Endpoint logs showed both `add ... rc=0` and `delete ... rc=0`.

## Safe Live State After Test

The live manager-generated `ar.conf` now includes the tested wrapper commands:

```text
ored-win-firewall-v30 - ored-win-firewall-v3.exe - 0
ored-win-firewall-rollback0 - ored-win-firewall-rollback.exe - 0
```

The Windows endpoint was cleaned:

- no `ORED ARGOS BLOCKED IP` rules remained;
- the old pre-existing `WAZUH ACTIVE RESPONSE BLOCKED IP` rule for `72.49.230.60` was left untouched;
- original Wazuh `netsh.exe` was restored.

## Files

Source and installer artifacts live in:

```text
scripts/active-response/windows/ored-win-firewall-native.c
scripts/active-response/windows/install-ored-win-firewall-native.cmd
```

Build command:

```bash
x86_64-w64-mingw32-gcc -O2 -static -Wall -Wextra -o scripts/active-response/windows/ored-win-firewall.exe scripts/active-response/windows/ored-win-firewall-native.c
```

## Next Engineering Direction

Windows containment can be enabled through the high-level guarded ARGOS tools only:

1. `wazuh_firewall_drop` / `wazuh_block_ip` maps Windows targets to `!ored-win-firewall-v3`.
2. `wazuh_firewall_allow` maps Windows targets to `!ored-win-firewall-rollback`.
3. Generic `wazuh_active_response` must continue to reject raw `netsh` and unlisted Windows commands.
4. Timed Windows auto-rollback remains unsupported; use explicit `firewall_allow`.

## References

- Wazuh custom active response scripts: https://documentation.wazuh.com/current/user-manual/capabilities/active-response/custom-active-response-scripts.html
- Wazuh active response configuration: https://documentation.wazuh.com/current/user-manual/capabilities/active-response/how-to-configure.html
- Wazuh `ossec.conf` active-response reference: https://documentation.wazuh.com/current/user-manual/reference/ossec-conf/active-response.html


## Final June 17 Note

The first rollback attempts were not reliable because the wrapper did not yet implement Wazuh's custom active-response stdin/stdout protocol. After adding the protocol handshake, separate add/delete command names, and action-specific keys, the wrapper passed live block and rollback validation on `001 / ored-win-01`.

Current product behavior: Windows firewall containment is allowed only through ARGOS high-level guarded tools after human approval. Generic raw `netsh` and arbitrary Windows active-response commands remain blocked.

### Deployed MCP Verification

After rebuilding and restarting `wazuh-mcp-server` and `hermes-agent` on AgentInstance, the high-level MCP client path was verified with `203.0.113.81`:

- `WazuhClient.firewall_drop("001", "203.0.113.81")` selected `!ored-win-firewall-v3` for Windows.
- `WazuhClient.firewall_allow("001", "203.0.113.81")` selected `!ored-win-firewall-rollback` for Windows.
- Endpoint log confirmed `add srcip=203.0.113.81 rc=0`.
- Endpoint log confirmed `delete srcip=203.0.113.81 rc=0`.
- Final endpoint firewall check showed no remaining `ORED ARGOS BLOCKED IP` rule.

## Verified Live Deployment

June 17 follow-up verification confirmed the full deployed path, not only direct API dispatch:

- WazuhInstance manager config was updated and restarted successfully.
- Generated manager `ar.conf` includes both wrapper commands:

```text
ored-win-firewall-v30 - ored-win-firewall-v3.exe - 0
ored-win-firewall-rollback0 - ored-win-firewall-rollback.exe - 0
```

- The endpoint wrapper binaries match the repo-built `scripts/active-response/windows/ored-win-firewall.exe` SHA256: `3ed677d16f368e2720a53bac0df977542f84b2afa85547b41257ff93b874cc9c`.
- `WazuhConfig` accepts `WAZUH_VERIFY_SSL=false`, which matches the AgentInstance `.env` and prevents self-signed Wazuh API certificate failures.
- Direct Wazuh API validation with `203.0.113.82` completed add/delete with endpoint `rc=0` evidence.
- High-level MCP client validation with `203.0.113.83` completed add/delete through `WazuhClient.firewall_drop` and `WazuhClient.firewall_allow` with endpoint `rc=0` evidence.
- Final endpoint state had no `ORED ARGOS BLOCKED IP` rules and no stuck wrapper processes.
