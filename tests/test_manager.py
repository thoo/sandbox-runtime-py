"""Tests for sandbox_runtime.manager module."""

import sys
from unittest.mock import patch

import pytest

from sandbox_runtime.config import SandboxRuntimeConfig
from sandbox_runtime.manager import (
    SandboxManager,
    _matches_domain_pattern,
)


class TestMatchesDomainPattern:
    """Tests for _matches_domain_pattern function."""

    def test_exact_match(self):
        """Test exact domain match."""
        assert _matches_domain_pattern("example.com", "example.com") is True
        assert _matches_domain_pattern("example.com", "other.com") is False

    def test_case_insensitive(self):
        """Test case-insensitive matching."""
        assert _matches_domain_pattern("Example.COM", "example.com") is True
        assert _matches_domain_pattern("example.com", "EXAMPLE.COM") is True

    def test_wildcard_pattern(self):
        """Test wildcard pattern matching."""
        assert _matches_domain_pattern("sub.example.com", "*.example.com") is True
        # Note: *.example.com matches any subdomain, including deep subdomains
        assert _matches_domain_pattern("deep.sub.example.com", "*.example.com") is True
        assert _matches_domain_pattern("example.com", "*.example.com") is False

    def test_wildcard_no_match(self):
        """Test wildcard pattern not matching."""
        assert _matches_domain_pattern("other.com", "*.example.com") is False


class TestSandboxManagerState:
    """Tests for SandboxManager static state methods."""

    def test_is_sandboxing_enabled_before_init(self):
        """Test is_sandboxing_enabled returns False before initialization."""
        # Reset state
        import sandbox_runtime.manager as manager_module

        manager_module._config = None
        assert SandboxManager.is_sandboxing_enabled() is False

    def test_is_supported_platform(self):
        """Test is_supported_platform method."""
        assert SandboxManager.is_supported_platform("macos") is True
        assert SandboxManager.is_supported_platform("linux") is True
        assert SandboxManager.is_supported_platform("windows") is False
        assert SandboxManager.is_supported_platform("unknown") is False


class TestSandboxManagerConfig:
    """Tests for SandboxManager configuration methods."""

    @pytest.fixture
    def sample_config(self):
        """Create a sample configuration."""
        return SandboxRuntimeConfig(
            network={
                "allowed_domains": ["example.com", "*.github.com"],
                "denied_domains": ["malicious.com"],
            },
            filesystem={
                "deny_read": ["~/.ssh"],
                "allow_write": ["."],
                "deny_write": [".env"],
                "allow_git_config": True,
            },
            ripgrep={"command": "rg"},
            mandatory_deny_search_depth=5,
        )

    def test_get_config_before_init(self):
        """Test get_config returns None before initialization."""
        import sandbox_runtime.manager as manager_module

        manager_module._config = None
        assert SandboxManager.get_config() is None

    def test_update_config(self, sample_config):
        """Test update_config method."""
        import sandbox_runtime.manager as manager_module

        manager_module._config = None
        SandboxManager.update_config(sample_config)

        config = SandboxManager.get_config()
        assert config is not None
        assert config.network.allowed_domains == ["example.com", "*.github.com"]

        # Cleanup
        manager_module._config = None

    def test_get_fs_read_config(self, sample_config):
        """Test get_fs_read_config method."""
        import sandbox_runtime.manager as manager_module

        manager_module._config = sample_config

        read_config = SandboxManager.get_fs_read_config()
        assert "~/.ssh" in read_config.deny_only or any(".ssh" in path for path in read_config.deny_only)

        # Cleanup
        manager_module._config = None

    def test_get_fs_write_config(self, sample_config):
        """Test get_fs_write_config method."""
        import sandbox_runtime.manager as manager_module

        manager_module._config = sample_config

        write_config = SandboxManager.get_fs_write_config()
        assert ".env" in write_config.deny_within_allow
        # Should include default write paths
        assert any("/dev/null" in p for p in write_config.allow_only)

        # Cleanup
        manager_module._config = None

    def test_get_network_restriction_config(self, sample_config):
        """Test get_network_restriction_config method."""
        import sandbox_runtime.manager as manager_module

        manager_module._config = sample_config

        network_config = SandboxManager.get_network_restriction_config()
        assert network_config.allowed_hosts == ["example.com", "*.github.com"]
        assert network_config.denied_hosts == ["malicious.com"]

        # Cleanup
        manager_module._config = None

    def test_get_allow_git_config(self, sample_config):
        """Test get_allow_git_config method."""
        import sandbox_runtime.manager as manager_module

        manager_module._config = sample_config
        assert SandboxManager.get_allow_git_config() is True

        # Cleanup
        manager_module._config = None

    def test_get_mandatory_deny_search_depth(self, sample_config):
        """Test get_mandatory_deny_search_depth method."""
        import sandbox_runtime.manager as manager_module

        manager_module._config = sample_config
        assert SandboxManager.get_mandatory_deny_search_depth() == 5

        # Cleanup
        manager_module._config = None

    def test_get_ripgrep_config(self, sample_config):
        """Test get_ripgrep_config method."""
        import sandbox_runtime.manager as manager_module

        manager_module._config = sample_config

        rg_config = SandboxManager.get_ripgrep_config()
        assert rg_config.command == "rg"

        # Cleanup
        manager_module._config = None


class TestSandboxManagerAsync:
    """Async tests for SandboxManager."""

    @pytest.fixture
    def minimal_config(self):
        """Create a minimal configuration."""
        return SandboxRuntimeConfig(
            network={"allowed_domains": [], "denied_domains": []},
            filesystem={"deny_read": [], "allow_write": [], "deny_write": []},
        )

    async def test_reset_without_init(self):
        """Test reset without initialization is safe."""
        # Should not raise
        await SandboxManager.reset()

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only test")
    async def test_initialize_and_reset(self, minimal_config):
        """Test initialize and reset cycle."""
        try:
            await SandboxManager.initialize(minimal_config)
            assert SandboxManager.is_sandboxing_enabled() is True
        finally:
            await SandboxManager.reset()
            # Config is still set after reset
            import sandbox_runtime.manager as manager_module

            manager_module._config = None

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only test")
    async def test_initialize_starts_proxy_servers(self, minimal_config):
        """Test that initialize starts proxy servers."""
        try:
            # Modify config to include allowed domains so proxies start
            config = SandboxRuntimeConfig(
                network={"allowed_domains": ["example.com"], "denied_domains": []},
                filesystem={"deny_read": [], "allow_write": [], "deny_write": []},
            )
            await SandboxManager.initialize(config)

            # Proxy ports should be set
            assert SandboxManager.get_proxy_port() is not None
            assert SandboxManager.get_socks_proxy_port() is not None
        finally:
            await SandboxManager.reset()
            import sandbox_runtime.manager as manager_module

            manager_module._config = None

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only test")
    async def test_wrap_with_sandbox_no_network_restrictions(self, minimal_config):
        """Test wrap_with_sandbox with no network restrictions still applies filesystem restrictions."""
        try:
            await SandboxManager.initialize(minimal_config)

            wrapped = await SandboxManager.wrap_with_sandbox("ls -la")
            # Command is still wrapped because filesystem restrictions always apply
            # (mandatory deny patterns for security)
            assert "sandbox-exec" in wrapped
            assert "ls -la" in wrapped
        finally:
            await SandboxManager.reset()
            import sandbox_runtime.manager as manager_module

            manager_module._config = None

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only test")
    async def test_wrap_with_sandbox_with_restrictions(self):
        """Test wrap_with_sandbox with restrictions."""
        config = SandboxRuntimeConfig(
            network={"allowed_domains": ["example.com"], "denied_domains": []},
            filesystem={"deny_read": ["~/.ssh"], "allow_write": ["."], "deny_write": []},
        )
        try:
            await SandboxManager.initialize(config)

            wrapped = await SandboxManager.wrap_with_sandbox("curl example.com")
            # Should be wrapped with sandbox-exec on macOS
            assert "sandbox-exec" in wrapped
        finally:
            await SandboxManager.reset()
            import sandbox_runtime.manager as manager_module

            manager_module._config = None

    async def test_wait_for_network_initialization_no_config(self):
        """Test wait_for_network_initialization returns False when no config."""
        import sandbox_runtime.manager as manager_module

        manager_module._config = None
        result = await SandboxManager.wait_for_network_initialization()
        assert result is False


class TestSandboxManagerViolations:
    """Tests for sandbox violation tracking."""

    def test_get_sandbox_violation_store(self):
        """Test get_sandbox_violation_store returns store."""
        store = SandboxManager.get_sandbox_violation_store()
        assert store is not None

    def test_annotate_stderr_no_config(self):
        """Test annotate_stderr_with_sandbox_failures with no config."""
        import sandbox_runtime.manager as manager_module

        manager_module._config = None

        result = SandboxManager.annotate_stderr_with_sandbox_failures("cmd", "error output")
        assert result == "error output"

    def test_get_linux_glob_pattern_warnings_on_macos(self):
        """Test get_linux_glob_pattern_warnings returns empty on macOS."""
        if sys.platform != "darwin":
            pytest.skip("macOS-only test")

        warnings = SandboxManager.get_linux_glob_pattern_warnings()
        assert warnings == []


class TestSandboxManagerDependencies:
    """Tests for dependency checking."""

    def test_check_dependencies_unsupported_platform(self):
        """Test check_dependencies returns False for unsupported platforms."""
        with patch("sandbox_runtime.manager.get_platform", return_value="windows"):
            result = SandboxManager.check_dependencies()
            assert result is False

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only test")
    def test_check_dependencies_macos(self):
        """Test check_dependencies on macOS."""
        with patch("sandbox_runtime.manager.has_ripgrep_sync", return_value=True):
            result = SandboxManager.check_dependencies()
            assert result is True

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only test")
    def test_check_dependencies_no_ripgrep(self):
        """Test check_dependencies fails without ripgrep."""
        with patch("sandbox_runtime.manager.has_ripgrep_sync", return_value=False):
            result = SandboxManager.check_dependencies()
            assert result is False
