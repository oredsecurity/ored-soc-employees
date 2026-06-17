from wazuh_mcp_server.config import WazuhConfig


def set_required_wazuh_env(monkeypatch):
    monkeypatch.setenv("WAZUH_HOST", "https://wazuh.example.test")
    monkeypatch.setenv("WAZUH_USER", "api-user")
    monkeypatch.setenv("WAZUH_PASS", "api-pass")


def test_wazuh_verify_ssl_env_takes_precedence(monkeypatch):
    set_required_wazuh_env(monkeypatch)
    monkeypatch.setenv("VERIFY_SSL", "true")
    monkeypatch.setenv("WAZUH_VERIFY_SSL", "false")

    config = WazuhConfig.from_env()

    assert config.verify_ssl is False


def test_verify_ssl_env_remains_backward_compatible(monkeypatch):
    set_required_wazuh_env(monkeypatch)
    monkeypatch.delenv("WAZUH_VERIFY_SSL", raising=False)
    monkeypatch.setenv("VERIFY_SSL", "false")

    config = WazuhConfig.from_env()

    assert config.verify_ssl is False


def test_wazuh_verify_ssl_defaults_to_enabled(monkeypatch):
    set_required_wazuh_env(monkeypatch)
    monkeypatch.delenv("WAZUH_VERIFY_SSL", raising=False)
