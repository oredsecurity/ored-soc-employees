"""
ORED Alert Poller.

Polls Wazuh for new alerts at a configurable interval and forwards
them to the SOC employee agent for triage. This is the component
that turns the system from pull-based into autonomous.

Configuration via environment variables:
    ORED_POLL_ENABLED=true          # Enable/disable polling
    ORED_POLL_INTERVAL=60           # Seconds between polls
    ORED_POLL_MIN_LEVEL=5           # Minimum rule level to surface
    ORED_POLL_BATCH_SIZE=100        # Max alerts per poll cycle

Part of the ORED AI SOC Employees platform.
Copyright (c) 2026 ORED Labs OU. MIT License.
"""

import asyncio
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set

import httpx

logger = logging.getLogger("ored.poller")


@dataclass
class PollerConfig:
    """Polling configuration, all sourced from environment variables."""

    enabled: bool = True
    interval: int = 60
    min_level: int = 5
    batch_size: int = 100

    @classmethod
    def from_env(cls) -> "PollerConfig":
        return cls(
            enabled=os.getenv("ORED_POLL_ENABLED", "true").lower() == "true",
            interval=int(os.getenv("ORED_POLL_INTERVAL", "60")),
            min_level=int(os.getenv("ORED_POLL_MIN_LEVEL", "5")),
            batch_size=int(os.getenv("ORED_POLL_BATCH_SIZE", "100")),
        )


@dataclass
class PollState:
    """Tracks polling state across cycles to avoid reprocessing."""

    last_poll_time: Optional[str] = None
    seen_alert_ids: Set[str] = field(default_factory=set)
    total_polls: int = 0
    total_alerts_processed: int = 0
    total_alerts_skipped: int = 0
    last_error: Optional[str] = None
    consecutive_errors: int = 0

    # Cap the seen set to prevent unbounded memory growth
    MAX_SEEN: int = 10000

    def mark_seen(self, alert_id: str) -> None:
        if len(self.seen_alert_ids) >= self.MAX_SEEN:
            # Evict oldest half (set is unordered, but this prevents unbounded growth)
            to_remove = list(self.seen_alert_ids)[: self.MAX_SEEN // 2]
            for item in to_remove:
                self.seen_alert_ids.discard(item)
        self.seen_alert_ids.add(alert_id)

    def is_seen(self, alert_id: str) -> bool:
        return alert_id in self.seen_alert_ids


class WazuhAlertPoller:
    """
    Polls Wazuh API for new alerts and forwards them for triage.

    The poller runs as an async background task. Each cycle:
    1. Authenticates with the Wazuh API (token cached)
    2. Fetches alerts newer than the last poll timestamp
    3. Filters by minimum severity level
    4. Deduplicates against previously seen alert IDs
    5. Forwards new alerts to the callback for triage
    6. Updates state for the next cycle

    On error: logs, increments error counter, backs off exponentially,
    continues polling. Never crashes the server.
    """

    def __init__(
        self,
        config: Optional[PollerConfig] = None,
        on_new_alerts: Optional[callable] = None,
    ):
        self.config = config or PollerConfig.from_env()
        self.state = PollState()
        self.on_new_alerts = on_new_alerts
        self._running = False
        self._task: Optional[asyncio.Task] = None

        # Wazuh connection (from env, same as MCP server)
        self.wazuh_host = os.getenv("WAZUH_HOST", "").rstrip("/")
        self.wazuh_port = os.getenv("WAZUH_PORT", "55000")
        self.wazuh_user = os.getenv("WAZUH_USER", "")
        self.wazuh_pass = os.getenv("WAZUH_PASS", "")
        self.verify_ssl = os.getenv("WAZUH_VERIFY_SSL", "false").lower() == "true"

        self._token: Optional[str] = None
        self._token_expiry: float = 0

    @property
    def api_base(self) -> str:
        host = self.wazuh_host
        if not host.startswith(("http://", "https://")):
            host = f"https://{host}"
        return f"{host}:{self.wazuh_port}"

    async def _authenticate(self) -> str:
        """Get or refresh Wazuh API JWT token."""
        if self._token and time.time() < self._token_expiry:
            return self._token

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=15) as client:
            response = await client.post(
                f"{self.api_base}/security/user/authenticate",
                auth=(self.wazuh_user, self.wazuh_pass),
            )
            response.raise_for_status()
            data = response.json()
            self._token = data.get("data", {}).get("token", "")
            # Refresh at 12 minutes (token valid ~15 min)
            self._token_expiry = time.time() + 720
            return self._token

    async def _fetch_alerts(self) -> List[Dict[str, Any]]:
        """Fetch alerts from Wazuh API, filtered by time and severity."""
        token = await self._authenticate()

        params = {
            "limit": self.config.batch_size,
            "sort": "-timestamp",
            "pretty": "true",
        }

        # Filter by time if we have a last poll timestamp
        if self.state.last_poll_time:
            params["q"] = f"timestamp>{self.state.last_poll_time}"

        headers = {"Authorization": f"Bearer {token}"}

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30) as client:
            # Try the alerts endpoint first
            response = await client.get(
                f"{self.api_base}/alerts",
                params=params,
                headers=headers,
            )

            if response.status_code == 404:
                # Alerts endpoint not available, fall back to manager logs
                # This happens on some Wazuh versions where alerts are
                # only in the indexer, not the API
                logger.info("Alerts API not available, falling back to log monitoring")
                return await self._fetch_alerts_from_logs(headers)

            response.raise_for_status()
            data = response.json()
            return data.get("data", {}).get("affected_items", [])

    async def _fetch_alerts_from_logs(
        self, headers: Dict[str, str]
    ) -> List[Dict[str, Any]]:
        """
        Fallback: fetch recent manager logs and SCA results.

        When the /alerts endpoint is not available (common on Wazuh 4.8+
        where alerts live in the indexer), we monitor through:
        1. Manager logs for new security events
        2. SCA check results for compliance changes
        3. Agent health changes
        """
        alerts = []

        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=30) as client:
            # Check for new SCA results across all agents
            try:
                response = await client.get(
                    f"{self.api_base}/agents",
                    params={"status": "active", "limit": 500},
                    headers=headers,
                )
                response.raise_for_status()
                agents = response.json().get("data", {}).get("affected_items", [])

                for agent in agents:
                    agent_id = agent.get("id", "000")
                    # Check SCA for each agent
                    try:
                        sca_response = await client.get(
                            f"{self.api_base}/sca/{agent_id}",
                            headers=headers,
                        )
                        if sca_response.status_code == 200:
                            sca_data = sca_response.json()
                            for policy in sca_data.get("data", {}).get(
                                "affected_items", []
                            ):
                                scan_time = policy.get("end_scan", "")
                                # Only include if scan is newer than last poll
                                if (
                                    not self.state.last_poll_time
                                    or scan_time > self.state.last_poll_time
                                ):
                                    alerts.append(
                                        {
                                            "type": "sca_scan",
                                            "agent": agent,
                                            "policy": policy,
                                            "timestamp": scan_time,
                                            "id": f"sca-{agent_id}-{policy.get('policy_id', '')}-{scan_time}",
                                        }
                                    )
                    except Exception as e:
                        logger.debug(f"SCA check failed for agent {agent_id}: {e}")

            except Exception as e:
                logger.warning(f"Agent enumeration failed: {e}")

        return alerts

    def _filter_alerts(self, alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Filter alerts by severity and deduplication."""
        new_alerts = []

        for alert in alerts:
            # Generate a unique ID for dedup
            alert_id = alert.get("id", "")
            if not alert_id:
                # Construct from available fields
                rule_id = alert.get("rule", {}).get("id", "")
                agent_id = alert.get("agent", {}).get("id", "")
                timestamp = alert.get("timestamp", "")
                alert_id = f"{rule_id}-{agent_id}-{timestamp}"

            # Skip if already seen
            if self.state.is_seen(alert_id):
                self.state.total_alerts_skipped += 1
                continue

            # Check severity (for standard alerts with rule levels)
            rule_level = alert.get("rule", {}).get("level", 0)
            if isinstance(rule_level, str):
                try:
                    rule_level = int(rule_level)
                except ValueError:
                    rule_level = 0

            # SCA scan results always pass through (they have no rule level)
            alert_type = alert.get("type", "")
            if alert_type != "sca_scan" and rule_level < self.config.min_level:
                self.state.total_alerts_skipped += 1
                continue

            # New alert, mark as seen
            self.state.mark_seen(alert_id)
            new_alerts.append(alert)

        return new_alerts

    async def _poll_cycle(self) -> None:
        """Execute one poll cycle."""
        try:
            raw_alerts = await self._fetch_alerts()
            new_alerts = self._filter_alerts(raw_alerts)

            if new_alerts:
                logger.info(
                    f"Poll cycle {self.state.total_polls}: "
                    f"{len(new_alerts)} new alerts "
                    f"({len(raw_alerts)} fetched, "
                    f"{len(raw_alerts) - len(new_alerts)} filtered)"
                )

                if self.on_new_alerts:
                    await self.on_new_alerts(new_alerts)

                self.state.total_alerts_processed += len(new_alerts)
            else:
                logger.debug(
                    f"Poll cycle {self.state.total_polls}: no new alerts"
                )

            # Update timestamp for next cycle
            self.state.last_poll_time = datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S+00:00"
            )
            self.state.total_polls += 1
            self.state.consecutive_errors = 0
            self.state.last_error = None

        except Exception as e:
            self.state.consecutive_errors += 1
            self.state.last_error = str(e)
            logger.error(
                f"Poll cycle failed (attempt {self.state.consecutive_errors}): {e}"
            )
            # Invalidate token on auth errors
            if "401" in str(e) or "403" in str(e):
                self._token = None
                self._token_expiry = 0

    def _backoff_interval(self) -> int:
        """Calculate backoff interval based on consecutive errors."""
        if self.state.consecutive_errors == 0:
            return self.config.interval

        # Exponential backoff: interval * 2^errors, capped at 5 minutes
        backoff = self.config.interval * (2 ** self.state.consecutive_errors)
        return min(backoff, 300)

    async def _run_loop(self) -> None:
        """Main polling loop. Runs until stopped."""
        logger.info(
            f"Poller started: interval={self.config.interval}s, "
            f"min_level={self.config.min_level}, "
            f"batch_size={self.config.batch_size}"
        )

        while self._running:
            await self._poll_cycle()
            interval = self._backoff_interval()

            if self.state.consecutive_errors > 0:
                logger.warning(
                    f"Backing off: next poll in {interval}s "
                    f"(error count: {self.state.consecutive_errors})"
                )

            # Sleep in small increments so we can stop quickly
            elapsed = 0
            while elapsed < interval and self._running:
                await asyncio.sleep(min(5, interval - elapsed))
                elapsed += 5

        logger.info("Poller stopped.")

    def start(self) -> None:
        """Start the polling loop as a background task."""
        if not self.config.enabled:
            logger.info("Poller disabled (ORED_POLL_ENABLED=false)")
            return

        if not self.wazuh_host or not self.wazuh_user:
            logger.warning("Poller disabled: missing Wazuh credentials")
            return

        if self._running:
            logger.warning("Poller already running")
            return

        self._running = True
        self._task = asyncio.create_task(self._run_loop())
        logger.info("Poller background task created")

    async def stop(self) -> None:
        """Stop the polling loop gracefully."""
        if not self._running:
            return

        self._running = False
        if self._task:
            self._task.cancel()
            try:
                await self._task
            except asyncio.CancelledError:
                pass
        logger.info("Poller stopped")

    def status(self) -> Dict[str, Any]:
        """Return current poller status for health checks."""
        return {
            "enabled": self.config.enabled,
            "running": self._running,
            "interval": self.config.interval,
            "min_level": self.config.min_level,
            "total_polls": self.state.total_polls,
            "total_alerts_processed": self.state.total_alerts_processed,
            "total_alerts_skipped": self.state.total_alerts_skipped,
            "last_poll_time": self.state.last_poll_time,
            "last_error": self.state.last_error,
            "consecutive_errors": self.state.consecutive_errors,
            "seen_cache_size": len(self.state.seen_alert_ids),
        }
