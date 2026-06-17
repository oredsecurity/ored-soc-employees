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
async def test_block_ip_refuses_windows_until_netsh_rollback_exists():
    client = FakeWazuhClient(agent("windows"))

    with pytest.raises(ValueError, match="OS 'windows' is not supported"):
        await client.block_ip("203.0.113.7", duration=60, agent_id="001")

    assert client.executed == []


@pytest.mark.asyncio
async def test_firewall_drop_uses_firewall_drop_for_linux_agent():
    client = FakeWazuhClient(agent("linux"))

    result = await client.firewall_drop("001", "203.0.113.8")

    assert client.executed[0]["command"] == "!firewall-drop"
    assert result["data"]["ored_response_guard"]["os_detected"] == "linux"


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
async def test_generic_active_response_blocks_netsh_until_rollback_exists():
    client = FakeWazuhClient(agent("windows"))

    with pytest.raises(ValueError, match="Unknown active response command"):
        await client.run_active_response("001", "netsh")

    assert client.executed == []
