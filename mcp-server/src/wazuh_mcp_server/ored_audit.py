"""
ORED Audit & Hardening Layer for Wazuh MCP Server.

Provides:
- Action classification (auto/approval_required/forbidden)
- Parameter sanitization (strips credentials from logs)
- Structured JSON audit logging (stdout + optional file)
- FastAPI middleware for intercepting all MCP tool calls

Part of the ORED AI SOC Employees platform.
https://github.com/oredsecurity/hermes-soc-employees

Copyright (c) 2026 ORED Labs. MIT License.
"""

import json
import logging
import os
import re
import time
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, Optional, Set

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

logger = logging.getLogger("ored.audit")

# Lazy imports to avoid circular dependencies
_approval_bot = None
_wazuh_audit = None


def _get_approval_bot():
    """Lazy-load the Telegram approval bot."""
    global _approval_bot
    if _approval_bot is None:
        from wazuh_mcp_server.ored_approval import approval_bot
        _approval_bot = approval_bot
    return _approval_bot


def _get_wazuh_audit():
    """Lazy-load the Wazuh audit sender."""
    global _wazuh_audit
    if _wazuh_audit is None:
        from wazuh_mcp_server.ored_wazuh_audit import wazuh_audit
        _wazuh_audit = wazuh_audit
    return _wazuh_audit


# ─────────────────────────────────────────────
# Action Classification
# ─────────────────────────────────────────────

class ActionClass(str, Enum):
    """Classification of MCP tool actions by risk level."""
    AUTO = "auto"
    APPROVAL_REQUIRED = "approval_required"
    FORBIDDEN = "forbidden"


# Tools that can run without human approval (read-only operations)
AUTO_ALLOWED_TOOLS: Set[str] = {
    # Alert tools
    "get_wazuh_alerts",
    "get_wazuh_alert_summary",
    "analyze_alert_patterns",
    "search_security_events",
    # Agent tools
    "get_wazuh_agents",
    "get_wazuh_running_agents",
    "check_agent_health",
    "get_agent_processes",
    "get_agent_ports",
    "get_agent_configuration",
    # Vulnerability tools
    "get_wazuh_vulnerabilities",
    "get_wazuh_critical_vulnerabilities",
    "get_wazuh_vulnerability_summary",
    # Threat intel tools
    "analyze_security_threat",
    "check_ioc_reputation",
    "perform_risk_assessment",
    "get_top_security_threats",
    # Reporting tools
    "generate_security_report",
    "run_compliance_check",
    # Statistics tools
    "get_wazuh_statistics",
    "get_wazuh_weekly_stats",
    "get_wazuh_cluster_health",
    "get_wazuh_cluster_nodes",
    "get_wazuh_rules_summary",
    "get_wazuh_remoted_stats",
    "get_wazuh_log_collector_stats",
    # Log tools
    "search_wazuh_manager_logs",
    "get_wazuh_manager_error_logs",
    # Connection tools
    "validate_wazuh_connection",
    # Status check tools (read-only checks on active responses)
    "wazuh_check_blocked_ip",
    "wazuh_check_agent_isolation",
    "wazuh_check_process",
    "wazuh_check_user_status",
    "wazuh_check_file_quarantine",
}

# Tools that require human approval before execution
APPROVAL_REQUIRED_TOOLS: Set[str] = {
    # Active response — offensive actions
    "wazuh_block_ip",
    "wazuh_isolate_host",
    "wazuh_kill_process",
    "wazuh_disable_user",
    "wazuh_quarantine_file",
    "wazuh_active_response",
    "wazuh_firewall_drop",
    "wazuh_host_deny",
    # Active response — reversal actions (still need approval)
    "wazuh_unisolate_host",
    "wazuh_enable_user",
    "wazuh_restore_file",
    "wazuh_firewall_allow",
    "wazuh_host_allow",
}

# Tools that are never allowed to execute
FORBIDDEN_TOOLS: Set[str] = {
    "wazuh_restart",
}


def classify_action(tool_name: str) -> ActionClass:
    """
    Classify a tool call by its risk level.

    Returns:
        ActionClass.AUTO — safe to execute without approval
        ActionClass.APPROVAL_REQUIRED — needs human confirmation
        ActionClass.FORBIDDEN — never execute

    Unknown tools default to APPROVAL_REQUIRED (fail-safe).
    """
    if tool_name in FORBIDDEN_TOOLS:
        return ActionClass.FORBIDDEN
    if tool_name in AUTO_ALLOWED_TOOLS:
        return ActionClass.AUTO
    if tool_name in APPROVAL_REQUIRED_TOOLS:
        return ActionClass.APPROVAL_REQUIRED
    # Unknown tool — default to requiring approval (fail-safe)
    return ActionClass.APPROVAL_REQUIRED


# ─────────────────────────────────────────────
# Parameter Sanitization
# ─────────────────────────────────────────────

# Patterns that indicate sensitive values
_SENSITIVE_KEYS = re.compile(
    r"(password|passwd|pass|secret|token|api_key|apikey|"
    r"authorization|auth|credential|private_key|access_key)",
    re.IGNORECASE,
)

# Patterns that look like credentials in values
_CREDENTIAL_PATTERNS = [
    re.compile(r"sk-[a-zA-Z0-9\-_]{20,}"),      # Anthropic/OpenAI keys
    re.compile(r"ghp_[a-zA-Z0-9]{36,}"),          # GitHub PATs
    re.compile(r"Bearer\s+[a-zA-Z0-9\-_.]+"),     # Bearer tokens
    re.compile(r"Basic\s+[a-zA-Z0-9+/=]+"),       # Basic auth
    re.compile(r"wazuh_[a-zA-Z0-9\-_]{20,}"),     # Wazuh API keys
]


def sanitize_params(params: Any, depth: int = 0) -> Any:
    """
    Recursively sanitize parameters, replacing sensitive values with '***REDACTED***'.

    Handles dicts, lists, and string values. Max recursion depth of 10
    to prevent stack overflow on malformed input.
    """
    if depth > 10:
        return "***TRUNCATED***"

    if isinstance(params, dict):
        sanitized = {}
        for key, value in params.items():
            if _SENSITIVE_KEYS.search(str(key)):
                sanitized[key] = "***REDACTED***"
            else:
                sanitized[key] = sanitize_params(value, depth + 1)
        return sanitized

    if isinstance(params, list):
        return [sanitize_params(item, depth + 1) for item in params]

    if isinstance(params, str):
        result = params
        for pattern in _CREDENTIAL_PATTERNS:
            result = pattern.sub("***REDACTED***", result)
        return result

    return params


# ─────────────────────────────────────────────
# Audit Logger
# ─────────────────────────────────────────────

class AuditLogger:
    """
    Structured JSON audit logger for MCP tool calls.

    Writes to:
    - stdout (always, for container log aggregation)
    - File at ORED_AUDIT_LOG_PATH if set (default: /var/log/ored-audit/audit.log)
    """

    def __init__(self):
        self._log_path: Optional[Path] = None
        self._file_handle = None

        log_path = os.getenv("ORED_AUDIT_LOG_PATH", "")
        if log_path:
            self._log_path = Path(log_path)
            self._log_path.parent.mkdir(parents=True, exist_ok=True)

    def log(
        self,
        tool_name: str,
        params: Dict[str, Any],
        action_class: ActionClass,
        status: str,
        session_id: Optional[str] = None,
        duration_ms: Optional[float] = None,
        error_message: Optional[str] = None,
    ) -> None:
        """Write a structured audit log entry."""
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "type": "ored_audit",
            "tool": tool_name,
            "action_class": action_class.value,
            "status": status,
            "params": sanitize_params(params),
            "session_id": session_id,
            "duration_ms": round(duration_ms, 2) if duration_ms else None,
        }

        if error_message:
            entry["error"] = sanitize_params(error_message)

        line = json.dumps(entry, default=str)

        # Always log to stdout (container logs)
        logger.info(line)

        # Optionally log to file
        if self._log_path:
            try:
                with open(self._log_path, "a") as f:
                    f.write(line + "\n")
            except OSError as e:
                logger.warning(f"Failed to write audit log to {self._log_path}: {e}")


# Global audit logger instance
audit_logger = AuditLogger()


# ─────────────────────────────────────────────
# FastAPI Middleware
# ─────────────────────────────────────────────

class OREDAuditMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware that intercepts MCP tool calls and:
    1. Extracts the tool name from JSON-RPC requests
    2. Classifies the action
    3. Blocks forbidden actions
    4. Logs everything to the audit trail

    Only intercepts POST requests to MCP endpoints (/ and /mcp).
    Non-MCP requests pass through untouched.
    """

    async def dispatch(self, request: Request, call_next) -> Response:
        # Only intercept POST requests to MCP endpoints
        if request.method != "POST" or request.url.path not in ("/", "/mcp"):
            return await call_next(request)

        # Read and cache the request body
        body = await request.body()

        # Try to parse as JSON-RPC
        tool_name = None
        tool_params = {}
        session_id = request.headers.get("mcp-session-id")

        try:
            data = json.loads(body)
            method = data.get("method", "")

            # MCP tool calls come as "tools/call"
            if method == "tools/call":
                params = data.get("params", {})
                tool_name = params.get("name", "unknown")
                tool_params = params.get("arguments", {})
        except (json.JSONDecodeError, AttributeError):
            pass

        # If this isn't a tool call, pass through
        if not tool_name:
            return await call_next(request)

        # Classify the action
        action_class = classify_action(tool_name)

        # Block forbidden actions immediately
        if action_class == ActionClass.FORBIDDEN:
            audit_logger.log(
                tool_name=tool_name,
                params=tool_params,
                action_class=action_class,
                status="blocked",
                session_id=session_id,
                error_message=f"Tool '{tool_name}' is forbidden by ORED security policy",
            )

            # Log to Wazuh audit trail
            try:
                await _get_wazuh_audit().send_audit_event(
                    tool_name=tool_name,
                    action_class=action_class.value,
                    status="blocked",
                    params=sanitize_params(tool_params),
                    decision="blocked",
                    session_id=session_id,
                    error_message="Forbidden by ORED security policy",
                )
            except Exception as e:
                logger.warning(f"Failed to send forbidden audit to Wazuh: {e}")

            from starlette.responses import JSONResponse
            return JSONResponse(
                status_code=403,
                content={
                    "jsonrpc": "2.0",
                    "id": json.loads(body).get("id"),
                    "error": {
                        "code": -32600,
                        "message": f"ORED SECURITY POLICY: Tool '{tool_name}' is forbidden. "
                                   f"This action is never allowed by the configured security policy.",
                    },
                },
            )

        # Handle approval-required actions
        if action_class == ActionClass.APPROVAL_REQUIRED:
            bot = _get_approval_bot()
            approval = await bot.request_approval(
                tool_name=tool_name,
                params=sanitize_params(tool_params),
                session_id=session_id,
            )

            if approval.decision != "approved":
                # Denied, timed out, or errored — block the action
                deny_reason = approval.denial_reason or approval.decision
                audit_logger.log(
                    tool_name=tool_name,
                    params=tool_params,
                    action_class=action_class,
                    status=str(approval.decision),
                    session_id=session_id,
                    error_message=f"Action {approval.decision}: {deny_reason}",
                )

                # Log denial to Wazuh
                try:
                    await _get_wazuh_audit().send_audit_event(
                        tool_name=tool_name,
                        action_class=action_class.value,
                        status=str(approval.decision),
                        params=sanitize_params(tool_params),
                        decision=str(approval.decision),
                        decided_by=approval.decided_by,
                        session_id=session_id,
                        error_message=deny_reason,
                    )
                except Exception as e:
                    logger.warning(f"Failed to send denial audit to Wazuh: {e}")

                from starlette.responses import JSONResponse
                return JSONResponse(
                    status_code=403,
                    content={
                        "jsonrpc": "2.0",
                        "id": json.loads(body).get("id"),
                        "error": {
                            "code": -32600,
                            "message": f"ORED SECURITY POLICY: Action '{tool_name}' was "
                                       f"{approval.decision}. {deny_reason}",
                        },
                    },
                )

            # Approved — fall through to execution
            logger.info(
                f"Action '{tool_name}' APPROVED by {approval.decided_by} "
                f"(request {approval.request_id})"
            )

        # Execute the request and measure duration
        start_time = time.monotonic()
        try:
            response = await call_next(request)
            duration_ms = (time.monotonic() - start_time) * 1000

            status = "success" if response.status_code < 400 else "error"
            decided_by = None
            if action_class == ActionClass.APPROVAL_REQUIRED:
                decided_by = approval.decided_by if 'approval' in dir() else None

            audit_logger.log(
                tool_name=tool_name,
                params=tool_params,
                action_class=action_class,
                status=status,
                session_id=session_id,
                duration_ms=duration_ms,
            )

            # Log to Wazuh audit trail
            try:
                await _get_wazuh_audit().send_audit_event(
                    tool_name=tool_name,
                    action_class=action_class.value,
                    status=status,
                    params=sanitize_params(tool_params),
                    decision="approved" if action_class == ActionClass.APPROVAL_REQUIRED else "auto",
                    decided_by=decided_by,
                    duration_ms=duration_ms,
                    session_id=session_id,
                )
            except Exception as e:
                logger.warning(f"Failed to send audit to Wazuh: {e}")

            return response

        except Exception as e:
            duration_ms = (time.monotonic() - start_time) * 1000
            audit_logger.log(
                tool_name=tool_name,
                params=tool_params,
                action_class=action_class,
                status="error",
                session_id=session_id,
                duration_ms=duration_ms,
                error_message=str(e),
            )

            # Log error to Wazuh
            try:
                await _get_wazuh_audit().send_audit_event(
                    tool_name=tool_name,
                    action_class=action_class.value,
                    status="error",
                    params=sanitize_params(tool_params),
                    duration_ms=duration_ms,
                    session_id=session_id,
                    error_message=str(e),
                )
            except Exception as ex:
                logger.warning(f"Failed to send error audit to Wazuh: {ex}")

            raise
