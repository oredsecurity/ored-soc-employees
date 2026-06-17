import pytest

from wazuh_mcp_server.api.wazuh_client import WazuhClient


class FakeWazuhClient(WazuhClient):
    def __init__(self, agent):
        self.agent = agent
        self.executed = []

    async def get_agents(self, agent_id=None, status=None, limit=100, **params):
        return {"data": {"affected_items": [self.agent]}}

    async def execute_active_response(self, data):
        self.executed.append(data)
        return {"data": {"total_affected_items": 1, "total_failed_items": 0}}


class FakeIndexer:
    def __init__(self, alerts):
        self.alerts = alerts

    async def get_alerts(self, limit=50):
        return {"data": {"affected_items": self.alerts[:limit]}}

def agent(platform, status="active", name="test-agent"):
    os_name = "Microsoft Windows 11 Pro" if platform == "windows" else "Ubuntu"
    return {
        "id": "001",
        "name": name,
        "status": status,
        "ip": "192.0.2.10",
        "lastKeepAlive": "2026-06-17T12:00:00+00:00",
        "os": {"name": os_name, "platform": platform, "version": "test"},
    }


@pytest.mark.asyncio
async def test_block_ip_refuses_disconnected_agent():
    client = FakeWazuhClient(agent("windows", status="disconnected"))

    with pytest.raises(ValueError, match="not 'active'"):
        await client.block_ip("203.0.113.7", agent_id="001")

    assert client.executed == []


@pytest.mark.asyncio
async def test_block_ip_uses_windows_wrapper_for_windows_agent():
    client = FakeWazuhClient(agent("windows"))

    result = await client.block_ip("203.0.113.7", agent_id="001")

    assert client.executed[0]["command"] == "!ored-win-firewall-v3"
    assert client.executed[0]["arguments"] == ["srcip=203.0.113.7"]
    assert result["data"]["ored_response_guard"]["os_detected"] == "windows"


@pytest.mark.asyncio
async def test_block_ip_refuses_timed_windows_block():
    client = FakeWazuhClient(agent("windows"))

    with pytest.raises(ValueError, match="timed auto-rollback"):
        await client.block_ip("203.0.113.7", duration=60, agent_id="001")


@pytest.mark.asyncio
async def test_firewall_drop_uses_firewall_drop_for_linux_agent():
    client = FakeWazuhClient(agent("linux"))

    result = await client.firewall_drop("001", "203.0.113.8")

    assert client.executed[0]["command"] == "!firewall-drop"
    assert result["data"]["ored_response_guard"]["os_detected"] == "linux"


@pytest.mark.asyncio
async def test_firewall_drop_uses_windows_wrapper_for_windows_agent():
    client = FakeWazuhClient(agent("windows"))

    result = await client.firewall_drop("001", "203.0.113.8")

    assert client.executed[0]["command"] == "!ored-win-firewall-v3"
    assert client.executed[0]["arguments"] == ["srcip=203.0.113.8"]
    assert result["data"]["ored_response_guard"]["os_detected"] == "windows"


@pytest.mark.asyncio
async def test_firewall_allow_uses_windows_rollback_wrapper():
    client = FakeWazuhClient(agent("windows"))

    result = await client.firewall_allow("001", "203.0.113.8")

    assert client.executed[0]["command"] == "!ored-win-firewall-rollback"
    assert client.executed[0]["arguments"] == ["srcip=203.0.113.8"]
    assert result["data"]["ored_response_guard"]["os_detected"] == "windows"


@pytest.mark.asyncio
async def test_generic_active_response_blocks_restart_wazuh():
    client = FakeWazuhClient(agent("linux"))

    with pytest.raises(ValueError, match="Forbidden active response command"):
        await client.run_active_response("001", "restart-wazuh")

    assert client.executed == []


@pytest.mark.asyncio
async def test_generic_active_response_normalizes_command_name():
    client = FakeWazuhClient(agent("linux"))

    await client.run_active_response("001", "firewall-drop", {"srcip": "203.0.113.9"})

    assert client.executed[0]["command"] == "!firewall-drop"


@pytest.mark.asyncio
async def test_generic_active_response_blocks_builtin_netsh():
    client = FakeWazuhClient(agent("windows"))

    with pytest.raises(ValueError, match="Unknown active response command"):
        await client.run_active_response("001", "netsh")

    assert client.executed == []


@pytest.mark.asyncio
async def test_check_blocked_ip_recognizes_windows_wrapper_evidence():
    client = FakeWazuhClient(agent("windows"))
    client._indexer_client = FakeIndexer(
        [
            {"rule": {"description": "Active response: ored-win-firewall-v3 - add"}, "data": {"srcip": "203.0.113.8"}},
        ]
    )

    result = await client.check_blocked_ip("203.0.113.8")
