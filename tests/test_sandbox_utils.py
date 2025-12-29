"""Tests for sandbox_runtime.sandbox_utils module."""

import os
import tempfile
from pathlib import Path

from sandbox_runtime.sandbox_utils import (
    DANGEROUS_DIRECTORIES,
    DANGEROUS_FILES,
    contains_glob_chars,
    decode_sandboxed_command,
    encode_sandboxed_command,
    generate_proxy_env_vars,
    get_dangerous_directories,
    get_default_write_paths,
    is_symlink_outside_boundary,
    normalize_case_for_comparison,
    normalize_path_for_sandbox,
    remove_trailing_glob_suffix,
)


class TestDangerousFiles:
    """Tests for dangerous files/directories constants."""

    def test_dangerous_files_are_defined(self):
        """Test that dangerous files are defined."""
        assert len(DANGEROUS_FILES) > 0
        assert ".bashrc" in DANGEROUS_FILES
        assert ".gitconfig" in DANGEROUS_FILES
        assert ".zshrc" in DANGEROUS_FILES

    def test_dangerous_directories_are_defined(self):
        """Test that dangerous directories are defined."""
        assert len(DANGEROUS_DIRECTORIES) > 0
        assert ".git" in DANGEROUS_DIRECTORIES
        assert ".vscode" in DANGEROUS_DIRECTORIES

    def test_get_dangerous_directories(self):
        """Test that get_dangerous_directories excludes .git."""
        dirs = get_dangerous_directories()
        assert ".git" not in dirs
        assert ".vscode" in dirs
        assert ".claude/commands" in dirs
        assert ".claude/agents" in dirs


class TestNormalizeCaseForComparison:
    """Tests for normalize_case_for_comparison function."""

    def test_lowercase_conversion(self):
        """Test that paths are converted to lowercase."""
        assert normalize_case_for_comparison("/Path/To/File") == "/path/to/file"
        assert normalize_case_for_comparison(".CLAUDE/Settings.JSON") == ".claude/settings.json"

    def test_already_lowercase(self):
        """Test that lowercase paths are unchanged."""
        assert normalize_case_for_comparison("/path/to/file") == "/path/to/file"


class TestContainsGlobChars:
    """Tests for contains_glob_chars function."""

    def test_with_glob_chars(self):
        """Test detection of glob characters."""
        assert contains_glob_chars("*.txt") is True
        assert contains_glob_chars("/path/to/*.py") is True
        assert contains_glob_chars("file[0-9].txt") is True
        assert contains_glob_chars("file?.txt") is True

    def test_without_glob_chars(self):
        """Test that regular paths return False."""
        assert contains_glob_chars("/path/to/file.txt") is False
        assert contains_glob_chars("./relative/path") is False
        assert contains_glob_chars("~/.bashrc") is False


class TestRemoveTrailingGlobSuffix:
    """Tests for remove_trailing_glob_suffix function."""

    def test_with_trailing_glob(self):
        """Test removal of trailing /**."""
        assert remove_trailing_glob_suffix("/path/**") == "/path"
        assert remove_trailing_glob_suffix("/some/dir/**") == "/some/dir"

    def test_without_trailing_glob(self):
        """Test that paths without /** are unchanged."""
        assert remove_trailing_glob_suffix("/path/to/file") == "/path/to/file"
        assert remove_trailing_glob_suffix("/path/*.txt") == "/path/*.txt"
        assert remove_trailing_glob_suffix("/path/**/file") == "/path/**/file"


class TestIsSymlinkOutsideBoundary:
    """Tests for is_symlink_outside_boundary function."""

    def test_same_path(self):
        """Test that identical paths are within boundary."""
        assert is_symlink_outside_boundary("/path/to/file", "/path/to/file") is False

    def test_root_resolution(self):
        """Test that resolution to root is outside boundary."""
        assert is_symlink_outside_boundary("/some/path", "/") is True

    def test_ancestor_resolution(self):
        """Test that resolution to ancestor is outside boundary."""
        assert is_symlink_outside_boundary("/tmp/claude/foo", "/tmp") is True
        assert is_symlink_outside_boundary("/home/user/project", "/home") is True

    def test_macos_tmp_resolution(self):
        """Test macOS /tmp -> /private/tmp resolution."""
        assert is_symlink_outside_boundary("/tmp/foo", "/private/tmp/foo") is False
        assert is_symlink_outside_boundary("/var/run", "/private/var/run") is False

    def test_short_paths_outside(self):
        """Test that very short resolved paths are outside boundary."""
        assert is_symlink_outside_boundary("/some/deep/path", "/usr") is True


class TestNormalizePathForSandbox:
    """Tests for normalize_path_for_sandbox function."""

    def test_tilde_expansion(self):
        """Test that ~ is expanded to home directory."""
        home = str(Path.home())
        assert normalize_path_for_sandbox("~") == home
        assert normalize_path_for_sandbox("~/.ssh").startswith(home)
        assert normalize_path_for_sandbox("~/.ssh") == home + "/.ssh"

    def test_relative_path(self):
        """Test that relative paths are converted to absolute."""
        cwd = os.getcwd()
        result = normalize_path_for_sandbox("./foo")
        assert os.path.isabs(result)
        assert result.endswith("/foo") or result == os.path.join(cwd, "foo")

    def test_dot_path(self):
        """Test that '.' is converted to current directory."""
        # The result might be a symlink-resolved version of cwd
        result = normalize_path_for_sandbox(".")
        assert os.path.isabs(result)

    def test_absolute_path(self):
        """Test that absolute paths remain absolute."""
        result = normalize_path_for_sandbox("/usr/local/bin")
        assert result.startswith("/")
        assert "local" in result

    def test_glob_pattern_preservation(self):
        """Test that glob patterns are preserved."""
        result = normalize_path_for_sandbox("/path/to/*.txt")
        assert "*.txt" in result

    def test_with_temp_directory(self):
        """Test with actual temporary directory."""
        with tempfile.TemporaryDirectory() as tmpdir:
            result = normalize_path_for_sandbox(tmpdir)
            # Result should be an absolute path
            assert os.path.isabs(result)


class TestGetDefaultWritePaths:
    """Tests for get_default_write_paths function."""

    def test_returns_list(self):
        """Test that function returns a list."""
        paths = get_default_write_paths()
        assert isinstance(paths, list)
        assert len(paths) > 0

    def test_includes_dev_null(self):
        """Test that /dev/null is included."""
        paths = get_default_write_paths()
        assert "/dev/null" in paths

    def test_includes_dev_stdout(self):
        """Test that /dev/stdout is included."""
        paths = get_default_write_paths()
        assert "/dev/stdout" in paths

    def test_includes_claude_temp(self):
        """Test that Claude temp directories are included."""
        paths = get_default_write_paths()
        assert any("claude" in p for p in paths)


class TestGenerateProxyEnvVars:
    """Tests for generate_proxy_env_vars function."""

    def test_minimal_without_ports(self):
        """Test minimal output when no ports are provided."""
        env_vars = generate_proxy_env_vars()
        assert "SANDBOX_RUNTIME=1" in env_vars
        assert "TMPDIR=/tmp/claude" in env_vars
        assert len(env_vars) == 2

    def test_with_http_proxy_port(self):
        """Test with HTTP proxy port."""
        env_vars = generate_proxy_env_vars(http_proxy_port=8080)
        env_dict = {v.split("=")[0]: v.split("=", 1)[1] for v in env_vars}

        assert "HTTP_PROXY" in env_dict
        assert env_dict["HTTP_PROXY"] == "http://localhost:8080"
        assert "HTTPS_PROXY" in env_dict
        assert env_dict["HTTPS_PROXY"] == "http://localhost:8080"
        assert "http_proxy" in env_dict
        assert "https_proxy" in env_dict

    def test_with_socks_proxy_port(self):
        """Test with SOCKS proxy port."""
        env_vars = generate_proxy_env_vars(socks_proxy_port=1080)
        env_dict = {v.split("=")[0]: v.split("=", 1)[1] for v in env_vars}

        assert "ALL_PROXY" in env_dict
        assert "socks5h://localhost:1080" in env_dict["ALL_PROXY"]
        assert "all_proxy" in env_dict

    def test_with_both_ports(self):
        """Test with both HTTP and SOCKS proxy ports."""
        env_vars = generate_proxy_env_vars(http_proxy_port=8080, socks_proxy_port=1080)
        env_dict = {v.split("=")[0]: v.split("=", 1)[1] for v in env_vars}

        assert "HTTP_PROXY" in env_dict
        assert "ALL_PROXY" in env_dict
        assert "NO_PROXY" in env_dict

    def test_no_proxy_includes_localhost(self):
        """Test that NO_PROXY includes localhost."""
        env_vars = generate_proxy_env_vars(http_proxy_port=8080)
        env_dict = {v.split("=")[0]: v.split("=", 1)[1] for v in env_vars}

        assert "localhost" in env_dict.get("NO_PROXY", "")
        assert "127.0.0.1" in env_dict.get("NO_PROXY", "")


class TestEncodeSandboxedCommand:
    """Tests for encode/decode sandboxed command functions."""

    def test_encode_decode_roundtrip(self):
        """Test that encoding and decoding returns the original command."""
        command = "echo 'Hello, World!'"
        encoded = encode_sandboxed_command(command)
        decoded = decode_sandboxed_command(encoded)
        assert decoded == command

    def test_encoded_is_base64(self):
        """Test that encoded output is valid base64."""
        import base64

        command = "ls -la"
        encoded = encode_sandboxed_command(command)
        # Should not raise
        base64.b64decode(encoded)

    def test_truncation_at_100_chars(self):
        """Test that long commands are truncated to 100 characters."""
        long_command = "x" * 200
        encoded = encode_sandboxed_command(long_command)
        decoded = decode_sandboxed_command(encoded)
        assert len(decoded) == 100

    def test_special_characters(self):
        """Test encoding with special characters."""
        command = "echo $HOME && cat /etc/passwd | grep root"
        encoded = encode_sandboxed_command(command)
        decoded = decode_sandboxed_command(encoded)
        assert decoded == command

    def test_unicode_characters(self):
        """Test encoding with unicode characters."""
        command = "echo 'Hello 世界'"
        encoded = encode_sandboxed_command(command)
        decoded = decode_sandboxed_command(encoded)
        assert decoded == command
