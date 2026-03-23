"""
ORED Telegram Approval Interface.

Handles human-in-the-loop approval for destructive MCP tool calls.
When a tool is classified as APPROVAL_REQUIRED, this module:
1. Queues the request (one at a time — never concurrent)
2. Sends a formatted approval request to Telegram
3. Waits for human response (approve/deny)
4. Returns the decision to the middleware

THREE NON-NEGOTIABLE CONSTRAINTS:
- One request at a time. Concurrent requests queue, not spam.
- Timeout is mandatory. 5 minutes, then TIMEOUT_ABORT. Never hang.
- Abort is always safe. Any failure = abort, not proceed. Fail closed.

Part of the ORED AI SOC Employees platform.
Copyright (c) 2026 ORED Labs. MIT License.
"""

import asyncio
import json
import logging
import os
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Deque, Dict, Optional

import httpx

logger = logging.getLogger("ored.approval")


class ApprovalDecision(str, Enum):
    """Human approval decision."""
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT_ABORT = "timeout_abort"
    ERROR_ABORT = "error_abort"


@dataclass
class AlertContext:
    """
    Alert context passed from the agent to the approval request.
    Populates the formatted Telegram message.
    """
    alert_id: str = "N/A"
    rule_name: str = "N/A"
    severity: str = "Medium"  # Critical / High / Medium
    asset: str = "N/A"       # Hostname / IP / Agent ID
    reason: str = "No reason provided."


@dataclass
class ApprovalRequest:
    """Tracks a pending approval request."""
    request_id: str
    tool_name: str
    params: Dict[str, Any]
    alert_context: AlertContext
    session_id: Optional[str]
    created_at: datetime
    decision: Optional[ApprovalDecision] = None
    decided_by: Optional[str] = None
    decided_at: Optional[datetime] = None
    message_id: Optional[int] = None
    denial_reason: Optional[str] = None


class TelegramApprovalBot:
    """
    Telegram bot for SOC action approvals.

    Enforces three invariants:
    1. ONE request at a time. If a second fires while one is pending,
       it queues silently. No concurrent Telegram messages.
    2. MANDATORY timeout. 5 minutes (configurable), then auto-abort.
       Logged as TIMEOUT_ABORT. Never hangs.
    3. FAIL CLOSED. If Telegram is down, network drops, bot crashes,
       parsing fails — the default is ABORT, never proceed.
    """

    TIMEOUT_SECONDS_DEFAULT = 300  # 5 minutes
    POLL_INTERVAL_SECONDS = 2

    def __init__(self):
        self.bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
        self.timeout_seconds = int(
            os.getenv("ORED_APPROVAL_TIMEOUT", str(self.TIMEOUT_SECONDS_DEFAULT))
        )
        self.enabled = bool(self.bot_token and self.chat_id)

        # Active request — only ONE at a time
        self._active: Optional[ApprovalRequest] = None
        # Queue for requests that arrive while one is active
        self._queue: Deque[asyncio.Future] = deque()
        # Serialization lock — ensures one-at-a-time processing
        self._lock = asyncio.Lock()

        self._last_update_id: int = 0

        if self.enabled:
            logger.info("Telegram approval bot initialized (timeout=%ds)", self.timeout_seconds)
        else:
            logger.warning(
                "Telegram approval bot DISABLED — set TELEGRAM_BOT_TOKEN and "
                "TELEGRAM_CHAT_ID to enable human-in-the-loop approvals"
            )

    @property
    def api_base(self) -> str:
        return f"https://api.telegram.org/bot{self.bot_token}"

    # ─────────────────────────────────────────────
    # Public API
    # ─────────────────────────────────────────────

    async def request_approval(
        self,
        tool_name: str,
        params: Dict[str, Any],
        alert_context: Optional[AlertContext] = None,
        session_id: Optional[str] = None,
    ) -> ApprovalRequest:
        """
        Request human approval for a destructive action.

        If Telegram is not configured → auto-abort (fail closed).
        If another request is pending → queue and wait.
        If timeout expires → TIMEOUT_ABORT.
        If anything fails → ERROR_ABORT.

        Never returns "proceed" on failure. Ever.
        """
        if alert_context is None:
            alert_context = AlertContext()

        request_id = str(uuid.uuid4())[:8]
        approval = ApprovalRequest(
            request_id=request_id,
            tool_name=tool_name,
            params=params,
            alert_context=alert_context,
            session_id=session_id,
            created_at=datetime.now(timezone.utc),
        )

        # Fail closed: Telegram not configured = abort
        if not self.enabled:
            logger.warning(
                "Approval required for %s but Telegram not configured — ABORTING (fail closed)",
                tool_name,
            )
            approval.decision = ApprovalDecision.ERROR_ABORT
            approval.denial_reason = "Telegram approval bot not configured — fail closed"
            return approval

        # Serialize: one request at a time
        async with self._lock:
            return await self._process_approval(approval)

    async def _process_approval(self, approval: ApprovalRequest) -> ApprovalRequest:
        """
        Process a single approval request. Called under lock.
        Sends message, polls for response, handles timeout.
        """
        self._active = approval

        try:
            message_id = await self._send_approval_message(approval)
            approval.message_id = message_id
        except Exception as e:
            # Fail closed: can't send message = abort
            logger.error("Failed to send approval message: %s — ABORTING", e)
            approval.decision = ApprovalDecision.ERROR_ABORT
            approval.denial_reason = f"Failed to send Telegram message: {e}"
            self._active = None
            return approval

        # Poll for response until decision or timeout
        try:
            await self._wait_for_decision(approval)
        except Exception as e:
            # Fail closed: polling crashed = abort
            logger.error("Approval polling failed: %s — ABORTING", e)
            if approval.decision is None:
                approval.decision = ApprovalDecision.ERROR_ABORT
                approval.denial_reason = f"Polling failure: {e}"

        self._active = None
        return approval

    # ─────────────────────────────────────────────
    # Message Formatting
    # ─────────────────────────────────────────────

    def _format_approval_message(self, approval: ApprovalRequest) -> str:
        """
        Format the approval request message per the ORED spec.

        Format:
            🚨 APPROVAL REQUIRED — FORGE

            Alert: [Alert ID] | Rule: [Rule Name]
            Severity: [Critical/High/Medium]
            Asset: [Hostname / IP / Agent ID]

            Action: [Exact action FORGE wants to execute]
            Reason: [One sentence. Why this action, why now.]

            ⏱ Timeout: 5 minutes (auto-abort if no response)

            ✅ Approve | ❌ Abort
        """
        ctx = approval.alert_context

        # Build the action description from tool name + key params
        action_desc = self._describe_action(approval.tool_name, approval.params)

        timeout_min = self.timeout_seconds // 60
        timeout_label = f"{timeout_min} minute{'s' if timeout_min != 1 else ''}"

        text = (
            f"🚨 <b>APPROVAL REQUIRED — FORGE</b>\n"
            f"\n"
            f"<b>Alert:</b> {_escape_html(ctx.alert_id)} | <b>Rule:</b> {_escape_html(ctx.rule_name)}\n"
            f"<b>Severity:</b> {_escape_html(ctx.severity)}\n"
            f"<b>Asset:</b> {_escape_html(ctx.asset)}\n"
            f"\n"
            f"<b>Action:</b> {_escape_html(action_desc)}\n"
            f"<b>Reason:</b> {_escape_html(ctx.reason)}\n"
            f"\n"
            f"⏱ <b>Timeout:</b> {timeout_label} (auto-abort if no response)\n"
            f"\n"
            f"<code>{approval.request_id}</code>"
        )

        return text

    def _describe_action(self, tool_name: str, params: Dict[str, Any]) -> str:
        """Build a human-readable action description from tool name + params."""
        # Map tool names to readable descriptions
        descriptions = {
            "wazuh_block_ip": lambda p: f"Block IP {p.get('ip', 'unknown')}",
            "wazuh_isolate_host": lambda p: f"Isolate host (agent {p.get('agent_id', 'unknown')})",
            "wazuh_kill_process": lambda p: f"Kill process {p.get('process_name', p.get('pid', 'unknown'))} on agent {p.get('agent_id', 'unknown')}",
            "wazuh_disable_user": lambda p: f"Disable user {p.get('username', 'unknown')}",
            "wazuh_quarantine_file": lambda p: f"Quarantine file {p.get('file_path', 'unknown')} on agent {p.get('agent_id', 'unknown')}",
            "wazuh_firewall_drop": lambda p: f"Firewall drop {p.get('ip', p.get('srcip', 'unknown'))}",
            "wazuh_host_deny": lambda p: f"Host deny {p.get('ip', p.get('srcip', 'unknown'))}",
            "wazuh_active_response": lambda p: f"Active response: {p.get('command', 'unknown')} on agent {p.get('agent_id', 'unknown')}",
            "wazuh_unisolate_host": lambda p: f"Un-isolate host (agent {p.get('agent_id', 'unknown')})",
            "wazuh_enable_user": lambda p: f"Enable user {p.get('username', 'unknown')}",
            "wazuh_restore_file": lambda p: f"Restore file {p.get('file_path', 'unknown')}",
            "wazuh_firewall_allow": lambda p: f"Firewall allow {p.get('ip', p.get('srcip', 'unknown'))}",
            "wazuh_host_allow": lambda p: f"Host allow {p.get('ip', p.get('srcip', 'unknown'))}",
        }

        formatter = descriptions.get(tool_name)
        if formatter:
            try:
                return formatter(params)
            except Exception:
                pass

        # Fallback: tool name + sanitized params
        from wazuh_mcp_server.ored_audit import sanitize_params
        safe = sanitize_params(params)
        param_str = ", ".join(f"{k}={v}" for k, v in safe.items()) if safe else "no params"
        return f"{tool_name}({param_str})"

    # ─────────────────────────────────────────────
    # Telegram API
    # ─────────────────────────────────────────────

    async def _send_approval_message(self, approval: ApprovalRequest) -> int:
        """Send formatted approval request with inline keyboard."""
        text = self._format_approval_message(approval)

        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "✅ Approve", "callback_data": f"approve:{approval.request_id}"},
                    {"text": "❌ Abort", "callback_data": f"abort:{approval.request_id}"},
                ]
            ]
        }

        async with httpx.AsyncClient(timeout=30) as client:
            response = await client.post(
                f"{self.api_base}/sendMessage",
                json={
                    "chat_id": self.chat_id,
                    "text": text,
                    "parse_mode": "HTML",
                    "reply_markup": keyboard,
                },
            )
            response.raise_for_status()
            data = response.json()

            if not data.get("ok"):
                raise RuntimeError(f"Telegram API error: {data}")

            return data["result"]["message_id"]

    async def _wait_for_decision(self, approval: ApprovalRequest) -> None:
        """Poll Telegram for callback query response until decision or timeout."""
        deadline = time.monotonic() + self.timeout_seconds

        while time.monotonic() < deadline:
            if approval.decision is not None:
                return

            try:
                await self._poll_updates()
            except Exception as e:
                logger.warning("Telegram poll error (continuing): %s", e)

            await asyncio.sleep(self.POLL_INTERVAL_SECONDS)

        # TIMEOUT — abort (non-negotiable)
        if approval.decision is None:
            approval.decision = ApprovalDecision.TIMEOUT_ABORT
            approval.denial_reason = f"No response within {self.timeout_seconds}s — auto-aborted"
            logger.warning(
                "Approval %s TIMEOUT_ABORT for %s after %ds",
                approval.request_id, approval.tool_name, self.timeout_seconds,
            )
            await self._update_message_status(
                approval, "⏰ TIMED OUT — action aborted (no response)"
            )

    async def _poll_updates(self) -> None:
        """Poll Telegram for callback query updates."""
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                f"{self.api_base}/getUpdates",
                params={
                    "offset": self._last_update_id + 1,
                    "timeout": 1,
                    "allowed_updates": json.dumps(["callback_query"]),
                },
            )
            response.raise_for_status()
            data = response.json()

            if not data.get("ok"):
                return

            for update in data.get("result", []):
                self._last_update_id = update["update_id"]

                callback = update.get("callback_query")
                if callback:
                    await self._handle_callback(callback)

    async def _handle_callback(self, callback: Dict[str, Any]) -> None:
        """Process an inline keyboard callback (approve/abort button press)."""
        callback_data = callback.get("data", "")
        callback_id = callback.get("id")
        user = callback.get("from", {})
        username = user.get("username", user.get("first_name", "unknown"))

        parts = callback_data.split(":", 1)
        if len(parts) != 2:
            return

        action, request_id = parts

        # Only process if this matches the active request
        if not self._active or self._active.request_id != request_id:
            await self._answer_callback(callback_id, "Request expired or already handled")
            return

        approval = self._active

        if action == "approve":
            approval.decision = ApprovalDecision.APPROVED
            approval.decided_by = username
            approval.decided_at = datetime.now(timezone.utc)
            await self._answer_callback(callback_id, "✅ Approved")
            await self._update_message_status(approval, f"✅ APPROVED by @{username}")
            logger.info(
                "Approval %s APPROVED by @%s for %s",
                approval.request_id, username, approval.tool_name,
            )

        elif action == "abort":
            approval.decision = ApprovalDecision.DENIED
            approval.decided_by = username
            approval.decided_at = datetime.now(timezone.utc)
            await self._answer_callback(callback_id, "❌ Aborted")
            await self._update_message_status(approval, f"❌ ABORTED by @{username}")
            logger.info(
                "Approval %s DENIED by @%s for %s",
                approval.request_id, username, approval.tool_name,
            )

    async def _answer_callback(self, callback_id: str, text: str) -> None:
        """Acknowledge a callback query."""
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(
                    f"{self.api_base}/answerCallbackQuery",
                    json={"callback_query_id": callback_id, "text": text},
                )
        except Exception as e:
            logger.warning("Failed to answer callback: %s", e)

    async def _update_message_status(self, approval: ApprovalRequest, status_text: str) -> None:
        """Edit the approval message to show the final decision and remove buttons."""
        if not approval.message_id:
            return

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                # Remove inline keyboard
                await client.post(
                    f"{self.api_base}/editMessageReplyMarkup",
                    json={
                        "chat_id": self.chat_id,
                        "message_id": approval.message_id,
                        "reply_markup": {"inline_keyboard": []},
                    },
                )

                # Reply with status
                await client.post(
                    f"{self.api_base}/sendMessage",
                    json={
                        "chat_id": self.chat_id,
                        "text": f"{status_text}\n<code>{approval.request_id}</code>",
                        "parse_mode": "HTML",
                        "reply_to_message_id": approval.message_id,
                    },
                )
        except Exception as e:
            logger.warning("Failed to update approval message: %s", e)

    async def send_notification(self, text: str) -> None:
        """Send a plain notification (non-approval) to the Telegram chat."""
        if not self.enabled:
            return

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(
                    f"{self.api_base}/sendMessage",
                    json={
                        "chat_id": self.chat_id,
                        "text": text,
                        "parse_mode": "HTML",
                    },
                )
        except Exception as e:
            logger.warning("Failed to send notification: %s", e)


def _escape_html(text: str) -> str:
    """Escape HTML special characters for Telegram HTML parse mode."""
    return (
        str(text)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


# Global singleton
approval_bot = TelegramApprovalBot()
