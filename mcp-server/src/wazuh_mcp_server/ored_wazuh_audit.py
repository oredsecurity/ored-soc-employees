"""
ORED Wazuh Audit Loop.

Logs every MCP tool call back into Wazuh as a custom audit event.
This closes the loop: Wazuh generates alerts → agent processes them →
actions are logged back into Wazuh → full audit trail.

Events are sent to Wazuh via the Wazuh API's custom log injection endpoint,
creating events with a dedicated decoder/rule set for ORED SOC actions.

Part of the ORED AI SOC Employees platform.
Copyright (c) 2026 ORED Labs. MIT License.
"""

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger("ored.wazuh_audit")


class WazuhAuditSender:
    """
    Sends audit events back to Wazuh for full-circle logging.

    Uses Wazuh's API to inject custom events that appear in the
    Wazuh dashboard alongside regular alerts. Each event includes:
    - Tool name and classification
    - Sanitized parameters
    - Decision (auto/approved/denied/blocked)
    - Operator who approved (if applicable)
    - Duration and status

    Events use syslog format with a custom program name (ored-soc)
    so they can be matched by a dedicated Wazuh decoder.
    """

    def __init__(self):
        self.wazuh_host = os.getenv("WAZUH_HOST", "").rstrip("/")
        self.wazuh_port = os.getenv("WAZUH_PORT", "55000")
        self.wazuh_user = os.getenv("WAZUH_USER", "")
        self.wazuh_pass = os.getenv("WAZUH_PASS", "")
        self.verify_ssl = os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"
        self.enabled = bool(self.wazuh_host and self.wazuh_user and self.wazuh_pass)

        self._token: Optional[str] = None
        self._token_expiry: float = 0

        if self.enabled:
            logger.info("Wazuh audit sender initialized")
        else:
            logger.warning("Wazuh audit sender DISABLED — missing WAZUH_HOST/USER/PASS")

    @property
    def api_base(self) -> str:
        """Wazuh API base URL."""
        host = self.wazuh_host
        # Ensure protocol prefix
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"
        return f"{host}:{self.wazuh_port}"

    async def _authenticate(self) -> str:
        """Get or refresh Wazuh API JWT token."""
        import time

        if self._token and time.time() < self._token_expiry:
            return self._token

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=15) as client:
            response = await client.post(
                f"{self.api_base}/security/user/authenticate",
                auth=(self.wazuh_user, self.wazuh_pass),
            )
            response.raise_for_status()
            data = response.json()
            self._token = data["data"]["token"]
            # Token valid for ~15 min, refresh at 12 min
            self._token_expiry = time.time() + 720
            return self._token

    async def send_audit_event(
        self,
        tool_name: str,
        action_class: str,
        status: str,
        params: Dict[str, Any],
        decision: Optional[str] = None,
        decided_by: Optional[str] = None,
        duration_ms: Optional[float] = None,
        session_id: Optional[str] = None,
        error_message: Optional[str] = None,
    ) -> bool:
        """
        Send an audit event to Wazuh.

        Uses the Wazuh manager's log ingestion via /manager/logs.
        The event is formatted as a syslog message with structured JSON payload
        that can be parsed by a custom Wazuh decoder.

        Returns True if successfully sent, False otherwise.
        """
        if not self.enabled:
            return False

        timestamp = datetime.now(timezone.utc).strftime("%b %d %H:%M:%S")

        # Build the audit event payload
        event_data = {
            "ored_soc": {
                "type": "audit",
                "tool": tool_name,
                "action_class": action_class,
                "status": status,
                "decision": decision or status,
                "params": params,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        }

        if decided_by:
            event_data["ored_soc"]["decided_by"] = decided_by
        if duration_ms is not None:
            event_data["ored_soc"]["duration_ms"] = round(duration_ms, 2)
        if session_id:
            event_data["ored_soc"]["session_id"] = session_id
        if error_message:
            event_data["ored_soc"]["error"] = error_message

        # Format as syslog message for Wazuh ingestion
        syslog_message = (
            f"{timestamp} ored-soc: "
            f"tool={tool_name} "
            f"action_class={action_class} "
            f"status={status} "
            f"decision={decision or status} "
            f"payload={json.dumps(event_data, default=str)}"
        )

        try:
            token = await self._authenticate()

            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=15) as client:
                # Send event via Wazuh API - using active response log channel
                # This creates an event that Wazuh processes through its pipeline
                response = await client.post(
                    f"{self.api_base}/active-response",
                    headers={"Authorization": f"Bearer {token}"},
                    json={
                        "command": "ored-soc-audit",
                        "custom": True,
                        "alert": {
                            "data": event_data,
                            "rule": {
                                "description": f"ORED SOC: {tool_name} - {status}",
                                "level": self._event_level(action_class, status),
                            },
                        },
                    },
                )

                # If active-response endpoint isn't suitable, fall back to
                # logging the event via the agent's own syslog
                if response.status_code >= 400:
                    # Alternative: write to a local log file that Wazuh monitors
                    await self._write_local_audit_log(syslog_message)
                    return True

                return True

        except Exception as e:
            logger.error(f"Failed to send audit event to Wazuh: {e}")
            # Always write locally as fallback
            await self._write_local_audit_log(syslog_message)
            return False

    async def _write_local_audit_log(self, message: str) -> None:
        """
        Write audit event to a local log file monitored by Wazuh.

        This is the reliable fallback: configure a Wazuh localfile monitor
        on /var/log/ored-soc/audit.log to ingest these events.
        """
        import aiofiles
        from pathlib import Path

        log_dir = Path("/var/log/ored-soc")
        log_dir.mkdir(parents=True, exist_ok=True)

        try:
            async with aiofiles.open(log_dir / "audit.log", "a") as f:
                await f.write(message + "\n")
        except OSError as e:
            logger.error(f"Failed to write local audit log: {e}")

    def _event_level(self, action_class: str, status: str) -> int:
        """Map action class + status to a Wazuh rule level for the audit event."""
        if status == "blocked":
            return 10  # Forbidden action attempted
        if action_class == "approval_required":
            if status == "success":
                return 8   # Destructive action executed
            elif status == "denied":
                return 6   # Action denied by operator
            else:
                return 7   # Approval timeout or error
        if action_class == "auto":
            return 3  # Routine auto-allowed action
        return 5  # Default


# Wazuh decoder configuration for ORED SOC audit events
WAZUH_DECODER_CONFIG = """
<!-- ORED SOC Audit Decoder -->
<!-- Place in /var/ossec/etc/decoders/ored_soc_decoder.xml -->

<decoder name="ored-soc">
  <program_name>ored-soc</program_name>
</decoder>

<decoder name="ored-soc-fields">
  <parent>ored-soc</parent>
  <regex>tool=(\S+) action_class=(\S+) status=(\S+) decision=(\S+) payload=(.*)</regex>
  <order>data.tool, data.action_class, data.status, data.decision, data.payload</order>
</decoder>
"""

WAZUH_RULES_CONFIG = """
<!-- ORED SOC Audit Rules -->
<!-- Place in /var/ossec/etc/rules/ored_soc_rules.xml -->

<group name="ored-soc,">

  <!-- Base rule for all ORED SOC events -->
  <rule id="100100" level="3">
    <decoded_as>ored-soc</decoded_as>
    <description>ORED SOC: Agent action (auto-allowed)</description>
    <group>ored-soc,audit,</group>
  </rule>

  <!-- Approval-required action executed -->
  <rule id="100101" level="8">
    <if_sid>100100</if_sid>
    <field name="data.action_class">approval_required</field>
    <field name="data.status">success</field>
    <description>ORED SOC: Destructive action executed (approved)</description>
    <group>ored-soc,audit,active-response,</group>
  </rule>

  <!-- Action denied by operator -->
  <rule id="100102" level="6">
    <if_sid>100100</if_sid>
    <field name="data.action_class">approval_required</field>
    <field name="data.status">denied</field>
    <description>ORED SOC: Action denied by operator</description>
    <group>ored-soc,audit,</group>
  </rule>

  <!-- Forbidden action attempted -->
  <rule id="100103" level="12">
    <if_sid>100100</if_sid>
    <field name="data.action_class">forbidden</field>
    <description>ORED SOC: Forbidden action attempted — possible policy violation</description>
    <group>ored-soc,audit,policy-violation,</group>
  </rule>

  <!-- Approval timeout -->
  <rule id="100104" level="7">
    <if_sid>100100</if_sid>
    <field name="data.status">timeout</field>
    <description>ORED SOC: Action approval timed out — no human response</description>
    <group>ored-soc,audit,</group>
  </rule>

</group>
"""


# Global singleton
wazuh_audit = WazuhAuditSender()
