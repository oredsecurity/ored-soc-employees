"""
ORED SOC Policy Plugin
======================

Enforces the ORED Security three-tier action policy on every MCP tool call:

  1. AUTO-ALLOWED  : query, analyze, enrich, report (no gate)
  2. APPROVAL-REQ  : block IP, isolate host, kill process, etc. (Telegram approval)
  3. FORBIDDEN     : modify rules, delete logs, change agent config (hard block)

Uses Hermes pre_tool_call hook to block before execution.
Uses post_tool_call hook to log every action for audit.

NOTE: This plugin enforces policy on the Hermes agent side (client-side).
      The MCP server hardening layer provides independent server-side enforcement.
      Both must agree for a dangerous action to execute (defense in depth).
"""

from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("ored-soc-policy")

# ---------------------------------------------------------------------------
# Action classification
# ---------------------------------------------------------------------------

# Tools that require human approval before execution.
# These can cause operational impact on monitored systems.
APPROVAL_REQUIRED: set[str] = {
    # Active response: blocking
    "mcp_wazuh_wazuh_block_ip",
    "mcp_wazuh_wazuh_firewall_drop",
    "mcp_wazuh_wazuh_host_deny",
    # Active response: isolation
    "mcp_wazuh_wazuh_isolate_host",
    # Active response: process/user/file
    "mcp_wazuh_wazuh_kill_process",
    "mcp_wazuh_wazuh_disable_user",
    "mcp_wazuh_wazuh_quarantine_file",
    # Active response: generic
    "mcp_wazuh_wazuh_active_response",
    # Reversal actions (also require approval: undoing a response is a response)
    "mcp_wazuh_wazuh_unisolate_host",
    "mcp_wazuh_wazuh_enable_user",
    "mcp_wazuh_wazuh_restore_file",
    "mcp_wazuh_wazuh_firewall_allow",
    "mcp_wazuh_wazuh_host_allow",
}

# Tools that are always forbidden. No approval path, hard block.
# These could compromise the integrity of the monitoring platform itself.
FORBIDDEN: set[str] = {
    # Restart can disrupt the monitoring platform itself
    "mcp_wazuh_wazuh_restart",
    # Future-proofing: if these ever appear, they're blocked
    # "mcp_wazuh_modify_rules",
    # "mcp_wazuh_delete_logs",
    # "mcp_wazuh_update_agent_config",
}

# Everything else is auto-allowed (query, analyze, enrich, report).
# We don't enumerate them because new read-only tools should work
# without a plugin update. The policy is: if it's not in APPROVAL_REQUIRED
# or FORBIDDEN, it's allowed.

# ---------------------------------------------------------------------------
# Approval state
# ---------------------------------------------------------------------------

# In-memory approval state. One pending approval at a time.
# This is intentionally simple. The approval flow works like this:
#   1. pre_tool_call detects an approval-required tool
#   2. Returns {"block": True, "reason": "..."} which goes back to the LLM
#   3. The LLM should then use Hermes' built-in approval tool to request approval
#   4. On next attempt after approval, we check if the tool was approved
#
# For v1, we rely on the LLM understanding the block reason and using
# the approval tool. The MCP server provides a second enforcement layer.

_pending_approval: Dict[str, Any] = {}
_approval_timeout_seconds: int = 300  # 5 minutes
_approved_actions: Dict[str, float] = {}  # tool_call_key -> approval_timestamp

# ---------------------------------------------------------------------------
# Audit log
# ---------------------------------------------------------------------------

_AUDIT_LOG_DIR = Path(os.environ.get("HERMES_HOME", os.path.expanduser("~/.hermes"))) / "audit"


def _write_audit_log(entry: Dict[str, Any]) -> None:
    """Append a JSON audit entry to the daily log file."""
    try:
        _AUDIT_LOG_DIR.mkdir(parents=True, exist_ok=True)
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        log_file = _AUDIT_LOG_DIR / f"soc-policy-{today}.jsonl"
        with open(log_file, "a") as f:
            f.write(json.dumps(entry, default=str) + "\n")
    except Exception as exc:
        logger.error("Failed to write audit log: %s", exc)


def _make_tool_key(tool_name: str, args: Any) -> str:
    """Create a stable key for a specific tool invocation."""
    # Use tool name + sorted args hash for dedup
    args_str = json.dumps(args, sort_keys=True, default=str) if args else ""
    return f"{tool_name}:{hash(args_str)}"


# ---------------------------------------------------------------------------
# Policy logic
# ---------------------------------------------------------------------------

def _classify_action(tool_name: str) -> str:
    """Classify a tool call into one of three tiers.

    Returns: 'auto', 'approval', or 'forbidden'
    """
    if tool_name in FORBIDDEN:
        return "forbidden"
    if tool_name in APPROVAL_REQUIRED:
        return "approval"
    return "auto"


def _check_unknown_mcp_tool(tool_name: str) -> Optional[Dict[str, Any]]:
    """Safety check: if a new MCP tool appears that looks like an active
    response action but isn't in our classification, block it.

    This prevents a newly-added dangerous tool from slipping through
    because the policy wasn't updated.
    """
    # Only applies to MCP wazuh tools
    if not tool_name.startswith("mcp_wazuh_"):
        return None

    # Heuristic: tool names containing these words are likely dangerous
    dangerous_patterns = [
        "_block_", "_isolate_", "_kill_", "_disable_", "_quarantine_",
        "_delete_", "_modify_", "_update_config", "_restart",
        "_drop_", "_deny_", "_active_response",
        "_unisolate_", "_enable_", "_restore_", "_allow_",
    ]

    for pattern in dangerous_patterns:
        if pattern in tool_name:
            # It matches a dangerous pattern but isn't classified
            if tool_name not in APPROVAL_REQUIRED and tool_name not in FORBIDDEN:
                return {
                    "block": True,
                    "reason": (
                        f"[ORED Policy] BLOCKED: '{tool_name}' matches a dangerous action pattern "
                        f"but is not in the policy classification. This is a safety tripwire. "
                        f"The tool must be explicitly added to APPROVAL_REQUIRED or FORBIDDEN "
                        f"in the ored-soc-policy plugin before it can execute."
                    ),
                }
    return None


# ---------------------------------------------------------------------------
# Hook implementations
# ---------------------------------------------------------------------------

def _on_session_start(**kwargs: Any) -> None:
    """Reset approval state at session start."""
    _pending_approval.clear()
    _approved_actions.clear()
    logger.info("ORED SOC Policy: session started, approval state reset")
    _write_audit_log({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "session_start",
        "session_id": kwargs.get("session_id", "unknown"),
    })


def _pre_tool_call(**kwargs: Any) -> Optional[Dict[str, Any]]:
    """Enforce action policy before tool execution.

    Returns None to allow, or {"block": True, "reason": "..."} to block.
    """
    tool_name: str = kwargs.get("tool_name", "")
    args: Any = kwargs.get("args", {})

    # Only enforce on MCP wazuh tools. Let all other Hermes tools through.
    if not tool_name.startswith("mcp_wazuh_"):
        return None

    classification = _classify_action(tool_name)
    now = time.time()

    # Log the attempt
    _write_audit_log({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "tool_call_attempt",
        "tool": tool_name,
        "classification": classification,
        "args": _sanitize_args(args),
    })

    # FORBIDDEN: hard block, no path forward
    if classification == "forbidden":
        reason = (
            f"[ORED Policy] FORBIDDEN: '{tool_name}' is permanently blocked. "
            f"This action could compromise monitoring platform integrity. "
            f"No approval path exists. Do not retry."
        )
        _write_audit_log({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "tool_call_blocked",
            "tool": tool_name,
            "classification": "forbidden",
            "args": _sanitize_args(args),
        })
        logger.warning("ORED Policy FORBIDDEN: %s", tool_name)
        return {"block": True, "reason": reason}

    # APPROVAL REQUIRED: check if already approved
    if classification == "approval":
        tool_key = _make_tool_key(tool_name, args)

        # Check for valid approval
        if tool_key in _approved_actions:
            approval_time = _approved_actions[tool_key]
            if (now - approval_time) < _approval_timeout_seconds:
                # Approval valid, consume it (one-time use)
                del _approved_actions[tool_key]
                logger.info("ORED Policy: approved action executing: %s", tool_name)
                _write_audit_log({
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "event": "tool_call_approved",
                    "tool": tool_name,
                    "args": _sanitize_args(args),
                })
                return None  # Allow
            else:
                # Approval expired
                del _approved_actions[tool_key]

        # No valid approval: block and instruct the LLM to request approval
        reason = (
            f"[ORED Policy] APPROVAL REQUIRED: '{tool_name}' requires human approval before execution. "
            f"This is a destructive/response action. Request approval from the SOC operator "
            f"via the approval tool before retrying. Include the action details: {_describe_action(tool_name, args)}"
        )
        _write_audit_log({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "tool_call_pending_approval",
            "tool": tool_name,
            "args": _sanitize_args(args),
        })
        logger.info("ORED Policy: approval required for %s", tool_name)
        return {"block": True, "reason": reason}

    # AUTO-ALLOWED: but check for unknown dangerous patterns first
    tripwire = _check_unknown_mcp_tool(tool_name)
    if tripwire:
        _write_audit_log({
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "event": "tool_call_tripwire",
            "tool": tool_name,
            "args": _sanitize_args(args),
        })
        logger.warning("ORED Policy TRIPWIRE: %s", tool_name)
        return tripwire

    # Auto-allowed
    return None


def _post_tool_call(**kwargs: Any) -> None:
    """Log every completed tool call for audit trail."""
    tool_name: str = kwargs.get("tool_name", "")
    args: Any = kwargs.get("args", {})
    result: Any = kwargs.get("result", "")

    # Only audit MCP wazuh tools
    if not tool_name.startswith("mcp_wazuh_"):
        return

    # Truncate result for logging (can be very large)
    result_str = str(result)
    if len(result_str) > 2000:
        result_str = result_str[:2000] + "...[truncated]"

    _write_audit_log({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "tool_call_completed",
        "tool": tool_name,
        "classification": _classify_action(tool_name),
        "args": _sanitize_args(args),
        "result_preview": result_str[:500],
        "result_length": len(result_str),
    })


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _sanitize_args(args: Any) -> Any:
    """Remove sensitive values from args before logging."""
    if not isinstance(args, (dict, str)):
        return str(args)
    if isinstance(args, str):
        try:
            args = json.loads(args)
        except (json.JSONDecodeError, TypeError):
            return args

    sanitized = {}
    sensitive_keys = {"password", "token", "secret", "api_key", "credentials"}
    for k, v in args.items():
        if any(s in k.lower() for s in sensitive_keys):
            sanitized[k] = "[REDACTED]"
        else:
            sanitized[k] = v
    return sanitized


def _describe_action(tool_name: str, args: Any) -> str:
    """Human-readable description of the action for approval requests."""
    # Strip the mcp_wazuh_ prefix for readability
    action = tool_name.replace("mcp_wazuh_wazuh_", "").replace("mcp_wazuh_", "")
    action = action.replace("_", " ").title()

    if isinstance(args, str):
        try:
            args = json.loads(args)
        except (json.JSONDecodeError, TypeError):
            return f"{action} with args: {args}"

    if isinstance(args, dict):
        parts = [f"{k}={v}" for k, v in args.items() if v]
        return f"{action}: {', '.join(parts)}" if parts else action

    return action


# ---------------------------------------------------------------------------
# Public API for external approval integration
# ---------------------------------------------------------------------------

def grant_approval(tool_name: str, args: Any = None) -> None:
    """Grant approval for a specific tool call.

    Called by external systems (e.g., Telegram bot, approval API) to
    approve a pending action. The approval is single-use and expires
    after _approval_timeout_seconds.
    """
    tool_key = _make_tool_key(tool_name, args)
    _approved_actions[tool_key] = time.time()
    logger.info("ORED Policy: approval granted for %s", tool_name)
    _write_audit_log({
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "event": "approval_granted",
        "tool": tool_name,
        "args": _sanitize_args(args),
    })


# ---------------------------------------------------------------------------
# Plugin registration
# ---------------------------------------------------------------------------

def register(ctx) -> None:
    """Called by Hermes plugin system during discovery."""
    ctx.register_hook("pre_tool_call", _pre_tool_call)
    ctx.register_hook("post_tool_call", _post_tool_call)
    ctx.register_hook("on_session_start", _on_session_start)
    logger.info(
        "ORED SOC Policy plugin loaded: %d approval-required tools, %d forbidden tools, tripwire active",
        len(APPROVAL_REQUIRED),
        len(FORBIDDEN),
    )
