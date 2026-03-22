"""
ORED Telegram Approval Interface.

Handles human-in-the-loop approval for destructive MCP tool calls.
When a tool is classified as APPROVAL_REQUIRED, this module:
1. Sends a formatted approval request to Telegram
2. Waits for human response (approve/deny)
3. Returns the decision to the middleware

Supports inline keyboard buttons for quick approve/deny.

Part of the ORED AI SOC Employees platform.
Copyright (c) 2026 ORED Labs. MIT License.
"""

import asyncio
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional

import httpx

logger = logging.getLogger("ored.approval")


class ApprovalDecision(str, Enum):
    """Human approval decision."""
    APPROVED = "approved"
    DENIED = "denied"
    TIMEOUT = "timeout"
    ERROR = "error"


@dataclass
class ApprovalRequest:
    """Tracks a pending approval request."""
    request_id: str
    tool_name: str
    params: Dict[str, Any]
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

    Sends approval requests with inline keyboard buttons.
    Polls for callback query responses.
    Thread-safe for concurrent approval requests.
    """

    def __init__(self):
        self.bot_token = os.getenv("TELEGRAM_BOT_TOKEN", "")
        self.chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
        self.timeout_seconds = int(os.getenv("ORED_APPROVAL_TIMEOUT", "300"))  # 5 min default
        self.enabled = bool(self.bot_token and self.chat_id)

        # Track pending approvals
        self._pending: Dict[str, ApprovalRequest] = {}
        self._poll_task: Optional[asyncio.Task] = None
        self._last_update_id: int = 0

        if self.enabled:
            logger.info("Telegram approval bot initialized")
        else:
            logger.warning(
                "Telegram approval bot DISABLED — set TELEGRAM_BOT_TOKEN and "
                "TELEGRAM_CHAT_ID to enable human-in-the-loop approvals"
            )

    @property
    def api_base(self) -> str:
        return f"https://api.telegram.org/bot{self.bot_token}"

    async def request_approval(
        self,
        tool_name: str,
        params: Dict[str, Any],
        session_id: Optional[str] = None,
    ) -> ApprovalRequest:
        """
        Send an approval request to Telegram and wait for a response.

        If Telegram is not configured, auto-denies with a warning.
        Times out after ORED_APPROVAL_TIMEOUT seconds (default 300).
        """
        request_id = str(uuid.uuid4())[:8]
        approval = ApprovalRequest(
            request_id=request_id,
            tool_name=tool_name,
            params=params,
            session_id=session_id,
            created_at=datetime.now(timezone.utc),
        )

        if not self.enabled:
            logger.warning(
                f"Approval required for {tool_name} but Telegram not configured — auto-denying"
            )
            approval.decision = ApprovalDecision.DENIED
            approval.denial_reason = "Telegram approval bot not configured"
            return approval

        # Send the message
        try:
            message_id = await self._send_approval_message(approval)
            approval.message_id = message_id
            self._pending[request_id] = approval

            # Wait for response
            decision = await self._wait_for_decision(request_id)
            return self._pending.pop(request_id, approval)

        except Exception as e:
            logger.error(f"Approval request failed: {e}")
            approval.decision = ApprovalDecision.ERROR
            approval.denial_reason = str(e)
            self._pending.pop(request_id, None)
            return approval

    async def _send_approval_message(self, approval: ApprovalRequest) -> int:
        """Send formatted approval request with inline keyboard."""
        # Sanitize params for display (reuse audit sanitizer)
        from wazuh_mcp_server.ored_audit import sanitize_params
        safe_params = sanitize_params(approval.params)

        # Format the message
        param_lines = ""
        for key, value in safe_params.items():
            param_lines += f"  • {key}: {value}\n"

        text = (
            f"🚨 <b>ACTION APPROVAL REQUIRED</b>\n"
            f"━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n"
            f"\n"
            f"<b>Tool:</b> <code>{approval.tool_name}</code>\n"
            f"<b>Request ID:</b> <code>{approval.request_id}</code>\n"
            f"<b>Time:</b> {approval.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}\n"
            f"\n"
            f"<b>Parameters:</b>\n"
            f"{param_lines}\n"
            f"<b>Timeout:</b> {self.timeout_seconds}s\n"
            f"\n"
            f"<i>Reply with the buttons below or type a reason to deny.</i>"
        )

        # Inline keyboard with approve/deny buttons
        keyboard = {
            "inline_keyboard": [
                [
                    {"text": "✅ Approve", "callback_data": f"approve:{approval.request_id}"},
                    {"text": "❌ Deny", "callback_data": f"deny:{approval.request_id}"},
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

    async def _wait_for_decision(self, request_id: str) -> ApprovalDecision:
        """Poll Telegram for callback query response until decision or timeout."""
        deadline = time.monotonic() + self.timeout_seconds

        while time.monotonic() < deadline:
            approval = self._pending.get(request_id)
            if not approval:
                return ApprovalDecision.ERROR

            if approval.decision is not None:
                return approval.decision

            # Poll for updates
            try:
                await self._poll_updates()
            except Exception as e:
                logger.warning(f"Telegram poll error: {e}")

            await asyncio.sleep(2)  # Poll every 2 seconds

        # Timeout
        approval = self._pending.get(request_id)
        if approval and approval.decision is None:
            approval.decision = ApprovalDecision.TIMEOUT
            approval.denial_reason = f"No response within {self.timeout_seconds}s"

            # Edit the message to show timeout
            await self._update_message(approval, "⏰ TIMED OUT — action denied")

        return ApprovalDecision.TIMEOUT

    async def _poll_updates(self) -> None:
        """Poll Telegram for callback query updates."""
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(
                f"{self.api_base}/getUpdates",
                params={
                    "offset": self._last_update_id + 1,
                    "timeout": 1,
                    "allowed_updates": json.dumps(["callback_query", "message"]),
                },
            )
            response.raise_for_status()
            data = response.json()

            if not data.get("ok"):
                return

            for update in data.get("result", []):
                self._last_update_id = update["update_id"]

                # Handle callback queries (button presses)
                callback = update.get("callback_query")
                if callback:
                    await self._handle_callback(callback)
                    continue

                # Handle text messages (denial reasons)
                message = update.get("message")
                if message and message.get("text"):
                    await self._handle_text_reply(message)

    async def _handle_callback(self, callback: Dict[str, Any]) -> None:
        """Process an inline keyboard callback (approve/deny button press)."""
        callback_data = callback.get("data", "")
        callback_id = callback.get("id")
        user = callback.get("from", {})
        username = user.get("username", user.get("first_name", "unknown"))

        parts = callback_data.split(":", 1)
        if len(parts) != 2:
            return

        action, request_id = parts
        approval = self._pending.get(request_id)
        if not approval:
            # Answer the callback to remove the loading state
            await self._answer_callback(callback_id, "Request expired or already handled")
            return

        if action == "approve":
            approval.decision = ApprovalDecision.APPROVED
            approval.decided_by = username
            approval.decided_at = datetime.now(timezone.utc)
            await self._answer_callback(callback_id, "✅ Approved")
            await self._update_message(approval, f"✅ APPROVED by @{username}")

        elif action == "deny":
            approval.decision = ApprovalDecision.DENIED
            approval.decided_by = username
            approval.decided_at = datetime.now(timezone.utc)
            await self._answer_callback(callback_id, "❌ Denied")
            await self._update_message(approval, f"❌ DENIED by @{username}")

    async def _handle_text_reply(self, message: Dict[str, Any]) -> None:
        """Handle text replies as denial reasons for the most recent pending request."""
        # If there's exactly one pending request, treat text as denial reason
        if len(self._pending) == 1:
            request_id = next(iter(self._pending))
            approval = self._pending[request_id]
            if approval.decision is None:
                user = message.get("from", {})
                username = user.get("username", user.get("first_name", "unknown"))
                approval.decision = ApprovalDecision.DENIED
                approval.decided_by = username
                approval.decided_at = datetime.now(timezone.utc)
                approval.denial_reason = message["text"]
                await self._update_message(
                    approval,
                    f"❌ DENIED by @{username}: {message['text']}"
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
            logger.warning(f"Failed to answer callback: {e}")

    async def _update_message(self, approval: ApprovalRequest, status_text: str) -> None:
        """Edit the approval message to show the final decision."""
        if not approval.message_id:
            return

        try:
            async with httpx.AsyncClient(timeout=10) as client:
                await client.post(
                    f"{self.api_base}/editMessageReplyMarkup",
                    json={
                        "chat_id": self.chat_id,
                        "message_id": approval.message_id,
                        "reply_markup": {"inline_keyboard": []},
                    },
                )

                # Add status as a reply
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
            logger.warning(f"Failed to update approval message: {e}")

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
            logger.warning(f"Failed to send notification: {e}")


# Global singleton
approval_bot = TelegramApprovalBot()
