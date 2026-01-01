"""Tests for camelCase alias support in config models."""

from sandbox_runtime.config import FilesystemConfig, NetworkConfig, SandboxRuntimeConfig


class TestNetworkConfigAliases:
    """Test that NetworkConfig accepts both camelCase and snake_case."""

    def test_snake_case_fields(self):
        """Test snake_case field names (primary)."""
        config = NetworkConfig(
            allowed_domains=["pypi.org", "*.npmjs.org"],
            denied_domains=["malware.com"],
        )
        assert config.allowed_domains == ["pypi.org", "*.npmjs.org"]
        assert config.denied_domains == ["malware.com"]

    def test_camelcase_aliases(self):
        """Test camelCase aliases work via model_validate."""
        config = NetworkConfig.model_validate(
            {
                "allowedDomains": ["pypi.org", "*.npmjs.org"],
                "deniedDomains": ["malware.com"],
            }
        )
        assert config.allowed_domains == ["pypi.org", "*.npmjs.org"]
        assert config.denied_domains == ["malware.com"]

    def test_mixed_case_formats(self):
        """Test mixing camelCase and snake_case works."""
        config = NetworkConfig.model_validate(
            {
                "allowedDomains": ["pypi.org"],  # camelCase
                "denied_domains": ["malware.com"],  # snake_case
            }
        )
        assert config.allowed_domains == ["pypi.org"]
        assert config.denied_domains == ["malware.com"]


class TestFilesystemConfigAliases:
    """Test that FilesystemConfig accepts both camelCase and snake_case."""

    def test_snake_case_fields(self):
        """Test snake_case field names (primary)."""
        config = FilesystemConfig(
            deny_read=["~/.ssh"],
            allow_write=[".", "/tmp"],
            deny_write=[".git"],
        )
        assert config.deny_read == ["~/.ssh"]
        assert config.allow_write == [".", "/tmp"]
        assert config.deny_write == [".git"]

    def test_camelcase_aliases(self):
        """Test camelCase aliases work via model_validate."""
        config = FilesystemConfig.model_validate(
            {
                "denyRead": ["~/.ssh"],
                "allowWrite": [".", "/tmp"],
                "denyWrite": [".git"],
            }
        )
        assert config.deny_read == ["~/.ssh"]
        assert config.allow_write == [".", "/tmp"]
        assert config.deny_write == [".git"]

    def test_mixed_case_formats(self):
        """Test mixing camelCase and snake_case works."""
        config = FilesystemConfig.model_validate(
            {
                "denyRead": ["~/.ssh"],  # camelCase
                "allow_write": [".", "/tmp"],  # snake_case
                "denyWrite": [".git"],  # camelCase
            }
        )
        assert config.deny_read == ["~/.ssh"]
        assert config.allow_write == [".", "/tmp"]
        assert config.deny_write == [".git"]


class TestSandboxRuntimeConfigAliases:
    """Test that full SandboxRuntimeConfig works with camelCase."""

    def test_full_config_with_camelcase(self):
        """Test complete config using camelCase aliases."""
        config = SandboxRuntimeConfig.model_validate(
            {
                "network": {
                    "allowedDomains": ["pypi.org", "*.pypi.org"],
                    "deniedDomains": [],
                },
                "filesystem": {
                    "denyRead": ["~/.ssh"],
                    "allowWrite": [".", "/private/tmp"],
                    "denyWrite": [],
                },
            }
        )
        assert config.network.allowed_domains == ["pypi.org", "*.pypi.org"]
        assert config.network.denied_domains == []
        assert config.filesystem.deny_read == ["~/.ssh"]
        assert config.filesystem.allow_write == [".", "/private/tmp"]
        assert config.filesystem.deny_write == []

    def test_full_config_with_snake_case(self):
        """Test complete config using snake_case (primary)."""
        config = SandboxRuntimeConfig(
            network={
                "allowed_domains": ["pypi.org", "*.pypi.org"],
                "denied_domains": [],
            },
            filesystem={
                "deny_read": ["~/.ssh"],
                "allow_write": [".", "/private/tmp"],
                "deny_write": [],
            },
        )
        assert config.network.allowed_domains == ["pypi.org", "*.pypi.org"]
        assert config.network.denied_domains == []
        assert config.filesystem.deny_read == ["~/.ssh"]
        assert config.filesystem.allow_write == [".", "/private/tmp"]
        assert config.filesystem.deny_write == []

    def test_full_config_mixed_formats(self):
        """Test complete config mixing camelCase and snake_case."""
        config = SandboxRuntimeConfig.model_validate(
            {
                "network": {
                    "allowedDomains": ["pypi.org"],  # camelCase
                    "denied_domains": [],  # snake_case
                },
                "filesystem": {
                    "deny_read": ["~/.ssh"],  # snake_case
                    "allowWrite": [".", "/private/tmp"],  # camelCase
                    "denyWrite": [],  # camelCase
                },
            }
        )
        assert config.network.allowed_domains == ["pypi.org"]
        assert config.network.denied_domains == []
        assert config.filesystem.deny_read == ["~/.ssh"]
        assert config.filesystem.allow_write == [".", "/private/tmp"]
        assert config.filesystem.deny_write == []


class TestConfigSerializationWithAliases:
    """Test that config serialization preserves snake_case."""

    def test_model_dump_uses_snake_case(self):
        """Test that model_dump returns snake_case field names."""
        config = NetworkConfig.model_validate(
            {
                "allowedDomains": ["pypi.org"],
                "deniedDomains": ["malware.com"],
            }
        )
        dumped = config.model_dump()
        assert "allowed_domains" in dumped
        assert "denied_domains" in dumped
        assert "allowedDomains" not in dumped
        assert "deniedDomains" not in dumped

    def test_model_dump_json_uses_snake_case(self):
        """Test that JSON serialization uses snake_case by default."""
        config = FilesystemConfig.model_validate(
            {
                "denyRead": ["~/.ssh"],
                "allowWrite": ["."],
                "denyWrite": [],
            }
        )
        json_str = config.model_dump_json()
        assert "deny_read" in json_str
        assert "allow_write" in json_str
        assert "deny_write" in json_str
        assert "denyRead" not in json_str
        assert "allowWrite" not in json_str
