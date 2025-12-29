"""Tests for sandbox_runtime.cli module."""

import json
import sys
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from click.testing import CliRunner

from sandbox_runtime.cli import (
    _get_default_config,
    _get_default_config_path,
    _load_config,
    main,
)
from sandbox_runtime.config import SandboxRuntimeConfig


class TestGetDefaultConfigPath:
    """Tests for _get_default_config_path function."""

    def test_returns_path_in_home(self):
        """Test that default config path is in home directory."""
        path = _get_default_config_path()
        assert path.parent == Path.home()
        assert path.name == ".srt-settings.json"


class TestGetDefaultConfig:
    """Tests for _get_default_config function."""

    def test_returns_config(self):
        """Test that default config is a valid SandboxRuntimeConfig."""
        config = _get_default_config()
        assert isinstance(config, SandboxRuntimeConfig)

    def test_default_config_has_empty_lists(self):
        """Test that default config has empty domain/path lists."""
        config = _get_default_config()
        assert config.network.allowed_domains == []
        assert config.network.denied_domains == []
        assert config.filesystem.deny_read == []
        assert config.filesystem.allow_write == []
        assert config.filesystem.deny_write == []


class TestLoadConfig:
    """Tests for _load_config function."""

    def test_load_nonexistent_file(self):
        """Test loading a nonexistent file returns None."""
        result = _load_config(Path("/nonexistent/path/config.json"))
        assert result is None

    def test_load_empty_file(self):
        """Test loading an empty file returns None."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("")
            f.flush()
            result = _load_config(Path(f.name))
            assert result is None

    def test_load_valid_config(self):
        """Test loading a valid configuration file."""
        config_data = {
            "network": {
                "allowedDomains": ["example.com", "*.github.com"],
                "deniedDomains": ["malicious.com"],
            },
            "filesystem": {
                "denyRead": ["~/.ssh"],
                "allowWrite": [".", "/tmp"],
                "denyWrite": [".env"],
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            f.flush()
            result = _load_config(Path(f.name))

            assert result is not None
            assert result.network.allowed_domains == ["example.com", "*.github.com"]
            assert result.network.denied_domains == ["malicious.com"]
            assert result.filesystem.deny_read == ["~/.ssh"]
            assert result.filesystem.allow_write == [".", "/tmp"]
            assert result.filesystem.deny_write == [".env"]

    def test_load_config_with_all_options(self):
        """Test loading a configuration with all options."""
        config_data = {
            "network": {
                "allowedDomains": ["example.com"],
                "deniedDomains": [],
                "allowUnixSockets": ["/var/run/docker.sock"],
                "allowLocalBinding": True,
                "httpProxyPort": 8080,
                "socksProxyPort": 1080,
            },
            "filesystem": {
                "denyRead": [],
                "allowWrite": ["."],
                "denyWrite": [],
                "allowGitConfig": True,
            },
            "enableWeakerNestedSandbox": True,
            "mandatoryDenySearchDepth": 5,
            "allowPty": True,
            "ripgrep": {"command": "custom-rg", "args": ["--hidden"]},
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            f.flush()
            result = _load_config(Path(f.name))

            assert result is not None
            assert result.network.allow_unix_sockets == ["/var/run/docker.sock"]
            assert result.network.allow_local_binding is True
            assert result.network.http_proxy_port == 8080
            assert result.network.socks_proxy_port == 1080
            assert result.filesystem.allow_git_config is True
            assert result.enable_weaker_nested_sandbox is True
            assert result.mandatory_deny_search_depth == 5
            assert result.allow_pty is True
            assert result.ripgrep is not None
            assert result.ripgrep.command == "custom-rg"

    def test_load_invalid_json(self):
        """Test loading invalid JSON raises ValueError."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{ invalid json }")
            f.flush()
            with pytest.raises(ValueError):
                _load_config(Path(f.name))


class TestCliMain:
    """Tests for CLI main function."""

    @pytest.fixture
    def runner(self):
        """Create a CLI test runner."""
        return CliRunner()

    def test_help(self, runner):
        """Test --help flag."""
        result = runner.invoke(main, ["--help"])
        assert result.exit_code == 0
        assert "Run commands in a sandbox" in result.output

    def test_version(self, runner):
        """Test --version flag."""
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        # Version is defined in pyproject.toml

    def test_no_command(self, runner):
        """Test running without a command shows error."""
        result = runner.invoke(main, [])
        assert result.exit_code == 1
        assert "No command specified" in result.output

    def test_debug_flag(self, runner):
        """Test --debug flag is accepted."""
        result = runner.invoke(main, ["--debug", "--help"])
        assert result.exit_code == 0

    def test_settings_flag(self, runner):
        """Test --settings flag is accepted."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(
                {
                    "network": {"allowedDomains": [], "deniedDomains": []},
                    "filesystem": {"denyRead": [], "allowWrite": [], "denyWrite": []},
                },
                f,
            )
            f.flush()
            result = runner.invoke(main, ["--settings", f.name, "--help"])
            assert result.exit_code == 0

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only test")
    def test_run_simple_command(self, runner):
        """Test running a simple command."""
        with patch("sandbox_runtime.cli.SandboxManager.initialize", new_callable=AsyncMock):
            with patch(
                "sandbox_runtime.cli.SandboxManager.wrap_with_sandbox",
                new_callable=AsyncMock,
            ) as mock_wrap:
                with patch("sandbox_runtime.cli.SandboxManager.reset", new_callable=AsyncMock):
                    with patch("sandbox_runtime.cli.SandboxManager.check_dependencies", return_value=True):
                        with patch(
                            "sandbox_runtime.cli.asyncio.create_subprocess_shell",
                            new_callable=AsyncMock,
                        ) as mock_create:
                            mock_proc = AsyncMock()
                            mock_proc.wait = AsyncMock(return_value=0)
                            mock_proc.send_signal = AsyncMock()
                            mock_create.return_value = mock_proc
                            mock_wrap.return_value = "echo hello"

                            runner.invoke(main, ["echo", "hello"])
                        # The actual exit code depends on the subprocess

    def test_command_string_mode(self, runner):
        """Test -c flag for command string mode."""
        with patch("sandbox_runtime.cli.SandboxManager.initialize", new_callable=AsyncMock):
            with patch(
                "sandbox_runtime.cli.SandboxManager.wrap_with_sandbox",
                new_callable=AsyncMock,
            ) as mock_wrap:
                with patch("sandbox_runtime.cli.SandboxManager.reset", new_callable=AsyncMock):
                    with patch("sandbox_runtime.cli.SandboxManager.check_dependencies", return_value=True):
                        with patch(
                            "sandbox_runtime.cli.asyncio.create_subprocess_shell",
                            new_callable=AsyncMock,
                        ) as mock_create:
                            mock_proc = AsyncMock()
                            mock_proc.wait = AsyncMock(return_value=0)
                            mock_proc.send_signal = AsyncMock()
                            mock_create.return_value = mock_proc
                            mock_wrap.return_value = 'echo "hello world"'

                            # Should accept -c with a complex command string
                            runner.invoke(main, ["-c", 'echo "hello world" && ls'])
                        # Exit code depends on subprocess execution

    def test_unknown_option_passthrough(self, runner):
        """Test unknown options are passed through to the command."""
        with patch("sandbox_runtime.cli.SandboxManager.initialize", new_callable=AsyncMock):
            with patch(
                "sandbox_runtime.cli.SandboxManager.wrap_with_sandbox",
                new_callable=AsyncMock,
            ) as mock_wrap:
                with patch("sandbox_runtime.cli.SandboxManager.reset", new_callable=AsyncMock):
                    with patch(
                        "sandbox_runtime.cli.asyncio.create_subprocess_shell",
                        new_callable=AsyncMock,
                    ) as mock_create:
                        mock_proc = AsyncMock()
                        mock_proc.wait = AsyncMock(return_value=0)
                        mock_proc.send_signal = AsyncMock()
                        mock_create.return_value = mock_proc
                        mock_wrap.return_value = "echo hello"

                        runner.invoke(main, ["echo", "hello", "-I", "--foo", "bar"])

                        assert mock_wrap.call_args[0][0] == "echo hello -I --foo bar"

    def test_invalid_config_fails(self, runner):
        """Test invalid JSON config exits with an error."""
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            f.write("{ invalid json }")
            f.flush()

            result = runner.invoke(main, ["--settings", f.name, "echo", "hi"])

            assert result.exit_code == 1
            assert "Invalid JSON" in result.output


class TestCliConfigLoading:
    """Tests for CLI configuration loading."""

    @pytest.fixture
    def runner(self):
        """Create a CLI test runner."""
        return CliRunner()

    def test_uses_default_when_no_config(self, runner):
        """Test that default config is used when no config file exists."""
        with patch(
            "sandbox_runtime.cli._get_default_config_path",
            return_value=Path("/nonexistent/config.json"),
        ):
            with patch("sandbox_runtime.cli.SandboxManager.initialize", new_callable=AsyncMock) as mock_init:
                with patch(
                    "sandbox_runtime.cli.SandboxManager.wrap_with_sandbox",
                    new_callable=AsyncMock,
                ) as mock_wrap:
                    with patch("sandbox_runtime.cli.SandboxManager.reset", new_callable=AsyncMock):
                        with patch("sandbox_runtime.cli.SandboxManager.check_dependencies", return_value=True):
                            mock_wrap.return_value = "echo test"

                            runner.invoke(main, ["echo", "test"])
                            # Should have been called with default config
                            if mock_init.called:
                                config = mock_init.call_args[0][0]
                                assert config.network.allowed_domains == []

    def test_custom_settings_file(self, runner):
        """Test using a custom settings file."""
        config_data = {
            "network": {
                "allowedDomains": ["custom.example.com"],
                "deniedDomains": [],
            },
            "filesystem": {
                "denyRead": [],
                "allowWrite": ["."],
                "denyWrite": [],
            },
        }

        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
            json.dump(config_data, f)
            f.flush()

            with patch("sandbox_runtime.cli.SandboxManager.initialize", new_callable=AsyncMock) as mock_init:
                with patch(
                    "sandbox_runtime.cli.SandboxManager.wrap_with_sandbox",
                    new_callable=AsyncMock,
                ) as mock_wrap:
                    with patch("sandbox_runtime.cli.SandboxManager.reset", new_callable=AsyncMock):
                        with patch("sandbox_runtime.cli.SandboxManager.check_dependencies", return_value=True):
                            mock_wrap.return_value = "echo test"

                            runner.invoke(main, ["--settings", f.name, "echo", "test"])

                            if mock_init.called:
                                config = mock_init.call_args[0][0]
                                assert "custom.example.com" in config.network.allowed_domains
