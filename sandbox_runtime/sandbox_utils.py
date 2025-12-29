"""Shared utilities for sandbox operations."""

import base64
import os
from pathlib import Path

from .utils.platform import get_platform

# Dangerous files that should be protected from writes.
# These files can be used for code execution or data exfiltration.
DANGEROUS_FILES: tuple[str, ...] = (
    ".gitconfig",
    ".gitmodules",
    ".bashrc",
    ".bash_profile",
    ".zshrc",
    ".zprofile",
    ".profile",
    ".ripgreprc",
    ".mcp.json",
)

# Dangerous directories that should be protected from writes.
# These directories contain sensitive configuration or executable files.
DANGEROUS_DIRECTORIES: tuple[str, ...] = (".git", ".vscode", ".idea")


def get_dangerous_directories() -> list[str]:
    """
    Get the list of dangerous directories to deny writes to.

    Excludes .git since we need it writable for git operations -
    instead we block specific paths within .git (hooks and config).
    """
    return [d for d in DANGEROUS_DIRECTORIES if d != ".git"] + [".claude/commands", ".claude/agents"]


def normalize_case_for_comparison(path_str: str) -> str:
    """
    Normalize a path for case-insensitive comparison.

    This prevents bypassing security checks using mixed-case paths on case-insensitive
    filesystems (macOS/Windows) like `.cLauDe/Settings.locaL.json`.

    We always normalize to lowercase regardless of platform for consistent security.
    """
    return path_str.lower()


def contains_glob_chars(path_pattern: str) -> bool:
    """Check if a path pattern contains glob characters."""
    return any(c in path_pattern for c in ("*", "?", "[", "]"))


def remove_trailing_glob_suffix(path_pattern: str) -> str:
    """
    Remove trailing /** glob suffix from a path pattern.

    Used to normalize path patterns since /** just means "directory and everything under it"
    """
    if path_pattern.endswith("/**"):
        return path_pattern[:-3]
    return path_pattern


def is_symlink_outside_boundary(original_path: str, resolved_path: str) -> bool:
    """
    Check if a symlink resolution crosses expected path boundaries.

    When resolving symlinks for sandbox path normalization, we need to ensure
    the resolved path doesn't unexpectedly broaden the scope. This function
    returns True if the resolved path is an ancestor of the original path
    or resolves to a system root, which would indicate the symlink points
    outside expected boundaries.

    Args:
        original_path: The original path before symlink resolution
        resolved_path: The path after realpath resolution

    Returns:
        True if the resolved path is outside expected boundaries
    """
    normalized_original = os.path.normpath(original_path)
    normalized_resolved = os.path.normpath(resolved_path)

    # Same path after normalization - OK
    if normalized_resolved == normalized_original:
        return False

    # Handle macOS /tmp -> /private/tmp canonical resolution
    # This is a legitimate system symlink that should be allowed
    if normalized_original.startswith("/tmp/"):
        if normalized_resolved == "/private" + normalized_original:
            return False
    if normalized_original.startswith("/var/"):
        if normalized_resolved == "/private" + normalized_original:
            return False
    # Also handle the reverse: /private/tmp/... resolving to itself
    if normalized_original.startswith("/private/tmp/"):
        if normalized_resolved == normalized_original:
            return False
    if normalized_original.startswith("/private/var/"):
        if normalized_resolved == normalized_original:
            return False

    # If resolved path is "/" it's outside expected boundaries
    if normalized_resolved == "/":
        return True

    # If resolved path is very short (single component like /tmp, /usr, /var),
    # it's likely outside expected boundaries
    resolved_parts = [p for p in normalized_resolved.split("/") if p]
    if len(resolved_parts) <= 1:
        return True

    # If original path starts with resolved path, the resolved path is an ancestor
    # e.g., /tmp/claude -> /tmp means the symlink points to a broader scope
    if normalized_original.startswith(normalized_resolved + "/"):
        return True

    # Also check the canonical form of the original path for macOS
    canonical_original = normalized_original
    if normalized_original.startswith("/tmp/"):
        canonical_original = "/private" + normalized_original
    elif normalized_original.startswith("/var/"):
        canonical_original = "/private" + normalized_original

    if canonical_original != normalized_original:
        if canonical_original.startswith(normalized_resolved + "/"):
            return True

    # STRICT CHECK: Only allow resolutions that stay within the expected path tree
    resolved_starts_with_original = normalized_resolved.startswith(normalized_original + "/")
    resolved_starts_with_canonical = canonical_original != normalized_original and normalized_resolved.startswith(
        canonical_original + "/"
    )
    resolved_is_canonical = canonical_original != normalized_original and normalized_resolved == canonical_original
    resolved_is_same = normalized_resolved == normalized_original

    # If resolved path is not within expected tree, it's outside boundary
    if not (
        resolved_is_same or resolved_is_canonical or resolved_starts_with_original or resolved_starts_with_canonical
    ):
        return True

    # Allow resolution to same directory level or deeper within expected tree
    return False


def normalize_path_for_sandbox(path_pattern: str) -> str:
    """
    Normalize a path for use in sandbox configurations.

    Handles:
    - Tilde (~) expansion for home directory
    - Relative paths (./foo, ../foo, etc.) converted to absolute
    - Absolute paths remain unchanged
    - Symlinks are resolved to their real paths for non-glob patterns
    - Glob patterns preserve wildcards after path normalization

    Returns:
        The absolute path with symlinks resolved (or normalized glob pattern)
    """
    cwd = os.getcwd()
    normalized_path = path_pattern

    # Expand ~ to home directory
    if path_pattern == "~":
        normalized_path = str(Path.home())
    elif path_pattern.startswith("~/"):
        normalized_path = str(Path.home()) + path_pattern[1:]
    elif path_pattern.startswith("./") or path_pattern.startswith("../"):
        # Convert relative to absolute based on current working directory
        normalized_path = os.path.abspath(os.path.join(cwd, path_pattern))
    elif not os.path.isabs(path_pattern):
        # Handle other relative paths (e.g., ".", "..", "foo/bar")
        normalized_path = os.path.abspath(os.path.join(cwd, path_pattern))

    # For glob patterns, resolve symlinks for the directory portion only
    if contains_glob_chars(normalized_path):
        # Extract the static directory prefix before glob characters
        import re

        match = re.split(r"[*?\[\]]", normalized_path)
        static_prefix = match[0] if match else ""

        if static_prefix and static_prefix != "/":
            # Get the directory containing the glob pattern
            base_dir = static_prefix.rstrip("/")
            if not base_dir.endswith("/"):
                base_dir = os.path.dirname(static_prefix) if static_prefix else ""

            # Try to resolve symlinks for the base directory
            try:
                resolved_base_dir = os.path.realpath(base_dir)
                # Validate that resolution stays within expected boundaries
                if not is_symlink_outside_boundary(base_dir, resolved_base_dir):
                    # Reconstruct the pattern with the resolved directory
                    pattern_suffix = normalized_path[len(base_dir) :]
                    return resolved_base_dir + pattern_suffix
                # If resolution would broaden scope, keep original pattern
            except OSError:
                # If directory doesn't exist or can't be resolved, keep the original pattern
                pass

        return normalized_path

    # Resolve symlinks to real paths to avoid bwrap issues
    # Validate that the resolution stays within expected boundaries
    try:
        resolved_path = os.path.realpath(normalized_path)

        # Only use resolved path if it doesn't cross boundary
        if not is_symlink_outside_boundary(normalized_path, resolved_path):
            normalized_path = resolved_path
    except OSError:
        # If path doesn't exist or can't be resolved, keep the normalized path
        pass

    return normalized_path


def get_default_write_paths() -> list[str]:
    """
    Get recommended system paths that should be writable for commands to work properly.

    WARNING: These default paths are intentionally broad for compatibility but may
    allow access to files from other processes. In highly security-sensitive
    environments, you should configure more restrictive write paths.
    """
    home_dir = str(Path.home())
    return [
        "/dev/stdout",
        "/dev/stderr",
        "/dev/null",
        "/dev/tty",
        "/dev/dtracehelper",
        "/dev/autofs_nowait",
        "/tmp/claude",
        "/private/tmp/claude",
        os.path.join(home_dir, ".npm/_logs"),
        os.path.join(home_dir, ".claude/debug"),
    ]


def generate_proxy_env_vars(
    http_proxy_port: int | None = None,
    socks_proxy_port: int | None = None,
) -> list[str]:
    """
    Generate proxy environment variables for sandboxed processes.

    Args:
        http_proxy_port: Port for HTTP/HTTPS proxy
        socks_proxy_port: Port for SOCKS5 proxy

    Returns:
        List of environment variable strings in KEY=VALUE format
    """
    env_vars = ["SANDBOX_RUNTIME=1", "TMPDIR=/tmp/claude"]

    # If no proxy ports provided, return minimal env vars
    if not http_proxy_port and not socks_proxy_port:
        return env_vars

    # Always set NO_PROXY to exclude localhost and private networks from proxying
    no_proxy_addresses = ",".join(
        [
            "localhost",
            "127.0.0.1",
            "::1",
            "*.local",
            ".local",
            "169.254.0.0/16",  # Link-local
            "10.0.0.0/8",  # Private network
            "172.16.0.0/12",  # Private network
            "192.168.0.0/16",  # Private network
        ]
    )
    env_vars.append(f"NO_PROXY={no_proxy_addresses}")
    env_vars.append(f"no_proxy={no_proxy_addresses}")

    if http_proxy_port:
        env_vars.append(f"HTTP_PROXY=http://localhost:{http_proxy_port}")
        env_vars.append(f"HTTPS_PROXY=http://localhost:{http_proxy_port}")
        # Lowercase versions for compatibility with some tools
        env_vars.append(f"http_proxy=http://localhost:{http_proxy_port}")
        env_vars.append(f"https_proxy=http://localhost:{http_proxy_port}")

    if socks_proxy_port:
        # Use socks5h:// for proper DNS resolution through proxy
        env_vars.append(f"ALL_PROXY=socks5h://localhost:{socks_proxy_port}")
        env_vars.append(f"all_proxy=socks5h://localhost:{socks_proxy_port}")

        # Configure Git to use SSH through SOCKS proxy (platform-aware)
        if get_platform() == "macos":
            # macOS has nc available
            env_vars.append(f"GIT_SSH_COMMAND=ssh -o ProxyCommand='nc -X 5 -x localhost:{socks_proxy_port} %h %p'")

        # FTP proxy support (use socks5h for DNS resolution through proxy)
        env_vars.append(f"FTP_PROXY=socks5h://localhost:{socks_proxy_port}")
        env_vars.append(f"ftp_proxy=socks5h://localhost:{socks_proxy_port}")

        # rsync proxy support
        env_vars.append(f"RSYNC_PROXY=localhost:{socks_proxy_port}")

        # Docker CLI uses HTTP for the API
        proxy_port = http_proxy_port or socks_proxy_port
        env_vars.append(f"DOCKER_HTTP_PROXY=http://localhost:{proxy_port}")
        env_vars.append(f"DOCKER_HTTPS_PROXY=http://localhost:{proxy_port}")

        # Google Cloud SDK - has specific proxy settings
        if http_proxy_port:
            env_vars.append("CLOUDSDK_PROXY_TYPE=https")
            env_vars.append("CLOUDSDK_PROXY_ADDRESS=localhost")
            env_vars.append(f"CLOUDSDK_PROXY_PORT={http_proxy_port}")

        # gRPC-based tools - use standard proxy vars
        env_vars.append(f"GRPC_PROXY=socks5h://localhost:{socks_proxy_port}")
        env_vars.append(f"grpc_proxy=socks5h://localhost:{socks_proxy_port}")

    return env_vars


def encode_sandboxed_command(command: str) -> str:
    """
    Encode a command for sandbox monitoring.

    Truncates to 100 chars and base64 encodes to avoid parsing issues.
    """
    truncated_command = command[:100]
    return base64.b64encode(truncated_command.encode()).decode()


def decode_sandboxed_command(encoded_command: str) -> str:
    """Decode a base64-encoded command from sandbox monitoring."""
    return base64.b64decode(encoded_command.encode()).decode()
