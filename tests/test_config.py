"""Tests for sandbox_runtime.config module."""

import pytest
from pydantic import ValidationError

from sandbox_runtime.config import (
    FilesystemConfig,
    NetworkConfig,
    RipgrepConfig,
    SandboxRuntimeConfig,
    _validate_domain_pattern,
)


class TestValidateDomainPattern:
    """Tests for domain pattern validation."""

    def test_valid_simple_domain(self):
        """Test that simple domains are accepted."""
        assert _validate_domain_pattern("example.com") == "example.com"
        assert _validate_domain_pattern("api.github.com") == "api.github.com"
        assert _validate_domain_pattern("sub.domain.example.org") == "sub.domain.example.org"

    def test_valid_localhost(self):
        """Test that localhost is accepted."""
        assert _validate_domain_pattern("localhost") == "localhost"

    def test_valid_wildcard_domain(self):
        """Test that valid wildcard domains are accepted."""
        assert _validate_domain_pattern("*.example.com") == "*.example.com"
        assert _validate_domain_pattern("*.github.com") == "*.github.com"
        assert _validate_domain_pattern("*.api.example.org") == "*.api.example.org"

    def test_invalid_domain_with_protocol(self):
        """Test that domains with protocols are rejected."""
        with pytest.raises(ValueError, match="must not contain protocols"):
            _validate_domain_pattern("https://example.com")
        with pytest.raises(ValueError, match="must not contain protocols"):
            _validate_domain_pattern("http://example.com")

    def test_invalid_domain_with_path(self):
        """Test that domains with paths are rejected."""
        with pytest.raises(ValueError, match="must not contain protocols, paths"):
            _validate_domain_pattern("example.com/path")

    def test_invalid_domain_with_port(self):
        """Test that domains with ports are rejected."""
        with pytest.raises(ValueError, match="must not contain protocols, paths, or ports"):
            _validate_domain_pattern("example.com:8080")

    def test_invalid_broad_wildcard(self):
        """Test that overly broad wildcards are rejected."""
        with pytest.raises(ValueError, match="at least two parts"):
            _validate_domain_pattern("*.com")
        with pytest.raises(ValueError, match="at least two parts"):
            _validate_domain_pattern("*.org")

    def test_invalid_wildcard_in_middle(self):
        """Test that wildcards in the middle are rejected."""
        with pytest.raises(ValueError, match="only allowed at the start"):
            _validate_domain_pattern("sub.*.example.com")
        with pytest.raises(ValueError, match="only allowed at the start"):
            _validate_domain_pattern("example*.com")

    def test_invalid_domain_without_dot(self):
        """Test that single-word domains (except localhost) are rejected."""
        with pytest.raises(ValueError, match="must be a valid domain"):
            _validate_domain_pattern("example")

    def test_invalid_domain_with_leading_dot(self):
        """Test that domains with leading dots are rejected."""
        with pytest.raises(ValueError, match="must be a valid domain"):
            _validate_domain_pattern(".example.com")

    def test_invalid_domain_with_trailing_dot(self):
        """Test that domains with trailing dots are rejected."""
        with pytest.raises(ValueError, match="must be a valid domain"):
            _validate_domain_pattern("example.com.")


class TestNetworkConfig:
    """Tests for NetworkConfig model."""

    def test_default_values(self):
        """Test that defaults are properly set."""
        config = NetworkConfig()
        assert config.allowed_domains == []
        assert config.denied_domains == []
        assert config.allow_unix_sockets is None
        assert config.allow_all_unix_sockets is None
        assert config.allow_local_binding is None
        assert config.http_proxy_port is None
        assert config.socks_proxy_port is None

    def test_with_valid_domains(self):
        """Test configuration with valid domains."""
        config = NetworkConfig(
            allowed_domains=["example.com", "*.github.com"],
            denied_domains=["malicious.com"],
        )
        assert config.allowed_domains == ["example.com", "*.github.com"]
        assert config.denied_domains == ["malicious.com"]

    def test_with_invalid_domain_raises(self):
        """Test that invalid domains raise validation errors."""
        with pytest.raises(ValidationError):
            NetworkConfig(allowed_domains=["https://example.com"])

    def test_proxy_port_validation(self):
        """Test that proxy ports are validated."""
        # Valid ports
        config = NetworkConfig(http_proxy_port=8080, socks_proxy_port=1080)
        assert config.http_proxy_port == 8080
        assert config.socks_proxy_port == 1080

        # Invalid ports
        with pytest.raises(ValidationError):
            NetworkConfig(http_proxy_port=0)
        with pytest.raises(ValidationError):
            NetworkConfig(http_proxy_port=70000)

    def test_with_unix_sockets(self):
        """Test configuration with unix sockets."""
        config = NetworkConfig(
            allow_unix_sockets=["/var/run/docker.sock"],
            allow_all_unix_sockets=False,
        )
        assert config.allow_unix_sockets == ["/var/run/docker.sock"]
        assert config.allow_all_unix_sockets is False


class TestFilesystemConfig:
    """Tests for FilesystemConfig model."""

    def test_default_values(self):
        """Test that defaults are properly set."""
        config = FilesystemConfig()
        assert config.deny_read == []
        assert config.allow_write == []
        assert config.deny_write == []
        assert config.allow_git_config is None

    def test_with_paths(self):
        """Test configuration with paths."""
        config = FilesystemConfig(
            deny_read=["~/.ssh", "~/.aws"],
            allow_write=[".", "/tmp"],
            deny_write=[".env", "*.secret"],
        )
        assert config.deny_read == ["~/.ssh", "~/.aws"]
        assert config.allow_write == [".", "/tmp"]
        assert config.deny_write == [".env", "*.secret"]

    def test_empty_path_raises(self):
        """Test that empty paths raise validation errors."""
        with pytest.raises(ValidationError):
            FilesystemConfig(deny_read=[""])

    def test_allow_git_config(self):
        """Test allow_git_config option."""
        config = FilesystemConfig(allow_git_config=True)
        assert config.allow_git_config is True


class TestRipgrepConfig:
    """Tests for RipgrepConfig model."""

    def test_default_values(self):
        """Test that defaults are properly set."""
        config = RipgrepConfig()
        assert config.command == "rg"
        assert config.args is None

    def test_custom_values(self):
        """Test custom configuration."""
        config = RipgrepConfig(command="custom-rg", args=["--hidden", "--no-ignore"])
        assert config.command == "custom-rg"
        assert config.args == ["--hidden", "--no-ignore"]


class TestSandboxRuntimeConfig:
    """Tests for SandboxRuntimeConfig model."""

    def test_minimal_config(self):
        """Test minimal required configuration."""
        config = SandboxRuntimeConfig(
            network={"allowed_domains": [], "denied_domains": []},
            filesystem={"deny_read": [], "allow_write": [], "deny_write": []},
        )
        assert isinstance(config.network, NetworkConfig)
        assert isinstance(config.filesystem, FilesystemConfig)

    def test_full_config(self):
        """Test full configuration with all options."""
        config = SandboxRuntimeConfig(
            network={
                "allowed_domains": ["example.com"],
                "denied_domains": ["bad.com"],
                "http_proxy_port": 8080,
            },
            filesystem={
                "deny_read": ["~/.ssh"],
                "allow_write": ["."],
                "deny_write": [".env"],
                "allow_git_config": True,
            },
            ignore_violations={"*": ["/some/path"]},
            enable_weaker_nested_sandbox=True,
            ripgrep={"command": "rg", "args": ["--hidden"]},
            mandatory_deny_search_depth=5,
            allow_pty=True,
        )
        assert config.network.allowed_domains == ["example.com"]
        assert config.filesystem.deny_read == ["~/.ssh"]
        assert config.ignore_violations == {"*": ["/some/path"]}
        assert config.enable_weaker_nested_sandbox is True
        assert config.ripgrep is not None
        assert config.ripgrep.command == "rg"
        assert config.mandatory_deny_search_depth == 5
        assert config.allow_pty is True

    def test_extra_fields_forbidden(self):
        """Test that extra fields are rejected."""
        with pytest.raises(ValidationError):
            SandboxRuntimeConfig(
                network={"allowed_domains": [], "denied_domains": []},
                filesystem={"deny_read": [], "allow_write": [], "deny_write": []},
                unknown_field="value",  # type: ignore
            )

    def test_mandatory_deny_search_depth_validation(self):
        """Test mandatory_deny_search_depth is bounded."""
        # Valid values
        config = SandboxRuntimeConfig(
            network={"allowed_domains": [], "denied_domains": []},
            filesystem={"deny_read": [], "allow_write": [], "deny_write": []},
            mandatory_deny_search_depth=5,
        )
        assert config.mandatory_deny_search_depth == 5

        # Invalid values
        with pytest.raises(ValidationError):
            SandboxRuntimeConfig(
                network={"allowed_domains": [], "denied_domains": []},
                filesystem={"deny_read": [], "allow_write": [], "deny_write": []},
                mandatory_deny_search_depth=0,
            )
        with pytest.raises(ValidationError):
            SandboxRuntimeConfig(
                network={"allowed_domains": [], "denied_domains": []},
                filesystem={"deny_read": [], "allow_write": [], "deny_write": []},
                mandatory_deny_search_depth=15,
            )

    def test_model_dump(self):
        """Test that configuration can be serialized."""
        config = SandboxRuntimeConfig(
            network={"allowed_domains": ["example.com"], "denied_domains": []},
            filesystem={"deny_read": [], "allow_write": ["."], "deny_write": []},
        )
        data = config.model_dump()
        assert "network" in data
        assert "filesystem" in data
        assert data["network"]["allowed_domains"] == ["example.com"]

    def test_model_json_schema(self):
        """Test that JSON schema can be generated."""
        schema = SandboxRuntimeConfig.model_json_schema()
        assert "properties" in schema
        assert "network" in schema["properties"]
        assert "filesystem" in schema["properties"]
