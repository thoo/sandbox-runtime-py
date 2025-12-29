"""Tests for sandbox_runtime.macos_sandbox module."""

import os
import sys
from unittest.mock import patch

import pytest

from sandbox_runtime.macos_sandbox import (
    MacOSSandboxParams,
    SandboxViolationEvent,
    _escape_path,
    _generate_log_tag,
    _get_ancestor_directories,
    _get_tmpdir_parent_if_macos_pattern,
    get_mandatory_deny_patterns,
    glob_to_regex,
    wrap_command_macos,
)
from sandbox_runtime.schemas import FsReadRestrictionConfig, FsWriteRestrictionConfig


class TestGlobToRegex:
    """Tests for glob_to_regex function."""

    def test_simple_glob(self):
        """Test simple * glob pattern."""
        regex = glob_to_regex("*.txt")
        assert regex == "^[^/]*\\.txt$"

    def test_double_star(self):
        """Test ** glob pattern."""
        regex = glob_to_regex("**/*.ts")
        assert ".*" in regex

    def test_question_mark(self):
        """Test ? glob pattern."""
        regex = glob_to_regex("file?.txt")
        assert "[^/]" in regex

    def test_character_class(self):
        """Test [abc] character class."""
        regex = glob_to_regex("file[0-9].txt")
        assert "[0-9]" in regex

    def test_path_with_glob(self):
        """Test path with glob."""
        regex = glob_to_regex("/path/to/**/*.py")
        assert regex.startswith("^")
        assert regex.endswith("$")
        assert ".*" in regex
        assert "\\.py" in regex

    def test_escapes_special_chars(self):
        """Test that regex special characters are escaped."""
        regex = glob_to_regex("/path.to/file.txt")
        assert "\\." in regex

    def test_literal_path(self):
        """Test literal path without globs."""
        regex = glob_to_regex("/exact/path/to/file")
        # Should just escape special chars and add anchors
        assert regex == "^/exact/path/to/file$"

    def test_double_star_slash_pattern(self):
        """Test **/ pattern (matches zero or more directories)."""
        regex = glob_to_regex("**/.gitconfig")
        assert "(.*/)?" in regex or ".*" in regex


class TestEscapePath:
    """Tests for _escape_path function."""

    def test_simple_path(self):
        """Test simple path escaping."""
        result = _escape_path("/path/to/file")
        assert result == '"/path/to/file"'

    def test_path_with_quotes(self):
        """Test path with quotes."""
        result = _escape_path('/path/with"quote')
        assert '\\"' in result

    def test_path_with_spaces(self):
        """Test path with spaces."""
        result = _escape_path("/path/with space/file")
        assert result == '"/path/with space/file"'


class TestGenerateLogTag:
    """Tests for _generate_log_tag function."""

    def test_generates_tag(self):
        """Test that log tag is generated."""
        tag = _generate_log_tag("ls -la")
        assert "CMD64_" in tag
        assert "_END_" in tag
        assert "_SBX" in tag

    def test_different_commands_different_tags(self):
        """Test that different commands produce different tags."""
        tag1 = _generate_log_tag("ls -la")
        tag2 = _generate_log_tag("cat file.txt")
        # The encoded command part should be different
        assert tag1 != tag2


class TestGetAncestorDirectories:
    """Tests for _get_ancestor_directories function."""

    def test_gets_ancestors(self):
        """Test getting ancestor directories."""
        ancestors = _get_ancestor_directories("/a/b/c/d")
        assert "/a/b/c" in ancestors
        assert "/a/b" in ancestors
        assert "/a" in ancestors
        assert "/" not in ancestors

    def test_root_has_no_ancestors(self):
        """Test that root has no ancestors."""
        ancestors = _get_ancestor_directories("/")
        assert ancestors == []

    def test_single_level(self):
        """Test single level path."""
        ancestors = _get_ancestor_directories("/a")
        assert ancestors == []


class TestGetTmpdirParentIfMacosPattern:
    """Tests for _get_tmpdir_parent_if_macos_pattern function."""

    def test_with_macos_tmpdir(self):
        """Test with macOS-style TMPDIR."""
        with patch.dict(os.environ, {"TMPDIR": "/var/folders/ab/cdefg/T/"}):
            result = _get_tmpdir_parent_if_macos_pattern()
            assert len(result) == 2
            assert "/var/folders/ab/cdefg" in result
            assert "/private/var/folders/ab/cdefg" in result

    def test_with_non_macos_tmpdir(self):
        """Test with non-macOS TMPDIR."""
        with patch.dict(os.environ, {"TMPDIR": "/tmp"}):
            result = _get_tmpdir_parent_if_macos_pattern()
            assert result == []

    def test_with_no_tmpdir(self):
        """Test with no TMPDIR set."""
        with patch.dict(os.environ, {}, clear=True):
            # Need to also remove TMPDIR if it exists
            env = dict(os.environ)
            env.pop("TMPDIR", None)
            with patch.dict(os.environ, env, clear=True):
                result = _get_tmpdir_parent_if_macos_pattern()
                assert result == []


class TestGetMandatoryDenyPatterns:
    """Tests for get_mandatory_deny_patterns function."""

    def test_includes_dangerous_files(self):
        """Test that dangerous files are included."""
        patterns = get_mandatory_deny_patterns()
        # Should include patterns for .bashrc, .gitconfig, etc.
        assert any(".bashrc" in p for p in patterns)
        assert any(".gitconfig" in p for p in patterns)
        assert any(".zshrc" in p for p in patterns)

    def test_includes_git_hooks(self):
        """Test that .git/hooks is always blocked."""
        patterns = get_mandatory_deny_patterns()
        assert any(".git/hooks" in p for p in patterns)

    def test_git_config_blocked_by_default(self):
        """Test that .git/config is blocked by default."""
        patterns = get_mandatory_deny_patterns()
        assert any(".git/config" in p for p in patterns)

    def test_git_config_allowed_when_specified(self):
        """Test that .git/config is not blocked when allow_git_config=True."""
        patterns = get_mandatory_deny_patterns(allow_git_config=True)
        # .git/config should not be in the deny patterns
        # But .git/hooks should still be blocked
        git_config_patterns = [p for p in patterns if ".git/config" in p and "hooks" not in p]
        assert len(git_config_patterns) == 0

    def test_returns_unique_patterns(self):
        """Test that patterns are unique."""
        patterns = get_mandatory_deny_patterns()
        assert len(patterns) == len(set(patterns))


class TestSandboxViolationEvent:
    """Tests for SandboxViolationEvent dataclass."""

    def test_create_event(self):
        """Test creating a violation event."""
        event = SandboxViolationEvent(
            line="deny file-read",
            command="cat /etc/passwd",
            encoded_command="Y2F0IC9ldGMvcGFzc3dk",
        )
        assert event.line == "deny file-read"
        assert event.command == "cat /etc/passwd"

    def test_event_with_defaults(self):
        """Test event with minimal parameters."""
        event = SandboxViolationEvent(line="violation")
        assert event.line == "violation"
        assert event.command is None


class TestMacOSSandboxParams:
    """Tests for MacOSSandboxParams dataclass."""

    def test_minimal_params(self):
        """Test minimal parameters."""
        params = MacOSSandboxParams(
            command="ls -la",
            needs_network_restriction=False,
        )
        assert params.command == "ls -la"
        assert params.needs_network_restriction is False
        assert params.http_proxy_port is None

    def test_full_params(self):
        """Test full parameters."""
        params = MacOSSandboxParams(
            command="curl example.com",
            needs_network_restriction=True,
            http_proxy_port=8080,
            socks_proxy_port=1080,
            allow_unix_sockets=["/var/run/docker.sock"],
            allow_local_binding=True,
            read_config=FsReadRestrictionConfig(deny_only=["~/.ssh"]),
            write_config=FsWriteRestrictionConfig(allow_only=["."], deny_within_allow=[".env"]),
        )
        assert params.http_proxy_port == 8080
        assert params.allow_local_binding is True


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only tests")
class TestWrapCommandMacos:
    """Tests for wrap_command_macos function."""

    def test_no_restrictions_returns_original(self):
        """Test that no restrictions returns original command."""
        params = MacOSSandboxParams(
            command="ls -la",
            needs_network_restriction=False,
            read_config=None,
            write_config=None,
        )
        result = wrap_command_macos(params)
        assert result == "ls -la"

    def test_with_network_restriction(self):
        """Test with network restriction."""
        params = MacOSSandboxParams(
            command="curl example.com",
            needs_network_restriction=True,
            http_proxy_port=8080,
        )
        result = wrap_command_macos(params)
        assert "sandbox-exec" in result
        assert "env" in result

    def test_with_read_restrictions(self):
        """Test with read restrictions."""
        params = MacOSSandboxParams(
            command="cat /etc/passwd",
            needs_network_restriction=False,
            read_config=FsReadRestrictionConfig(deny_only=["~/.ssh"]),
        )
        result = wrap_command_macos(params)
        assert "sandbox-exec" in result

    def test_with_write_restrictions(self):
        """Test with write restrictions."""
        params = MacOSSandboxParams(
            command="touch file.txt",
            needs_network_restriction=False,
            write_config=FsWriteRestrictionConfig(
                allow_only=["/tmp"],
                deny_within_allow=[".env"],
            ),
        )
        result = wrap_command_macos(params)
        assert "sandbox-exec" in result

    def test_includes_proxy_env_vars(self):
        """Test that proxy environment variables are included."""
        params = MacOSSandboxParams(
            command="curl example.com",
            needs_network_restriction=True,
            http_proxy_port=8080,
            socks_proxy_port=1080,
        )
        result = wrap_command_macos(params)
        assert "HTTP_PROXY" in result or "http_proxy" in result
        assert "SOCKS" in result.upper() or "ALL_PROXY" in result

    def test_uses_correct_shell(self):
        """Test that the correct shell is used."""
        params = MacOSSandboxParams(
            command="echo hello",
            needs_network_restriction=True,
            http_proxy_port=8080,
            bin_shell="zsh",
        )
        result = wrap_command_macos(params)
        assert "zsh" in result

    def test_command_properly_quoted(self):
        """Test that command with special chars is properly quoted."""
        params = MacOSSandboxParams(
            command="echo 'hello world' && ls -la",
            needs_network_restriction=True,
            http_proxy_port=8080,
        )
        result = wrap_command_macos(params)
        # The command should be preserved
        assert "hello world" in result or "hello" in result


class TestSandboxProfile:
    """Tests for sandbox profile generation."""

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only tests")
    def test_profile_contains_version(self):
        """Test that profile contains version."""
        params = MacOSSandboxParams(
            command="ls",
            needs_network_restriction=True,
            http_proxy_port=8080,
        )
        result = wrap_command_macos(params)
        assert "(version 1)" in result

    @pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only tests")
    def test_profile_contains_essential_permissions(self):
        """Test that profile contains essential permissions."""
        params = MacOSSandboxParams(
            command="ls",
            needs_network_restriction=True,
            http_proxy_port=8080,
        )
        result = wrap_command_macos(params)
        assert "process-exec" in result
        assert "process-fork" in result
