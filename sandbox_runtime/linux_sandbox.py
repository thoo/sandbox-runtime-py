"""Linux sandbox utilities using bubblewrap (bwrap)."""

import asyncio
import os
import secrets
import shlex
import shutil
import tempfile
from dataclasses import dataclass

from .sandbox_utils import (
    DANGEROUS_FILES,
    generate_proxy_env_vars,
    get_dangerous_directories,
    normalize_case_for_comparison,
    normalize_path_for_sandbox,
)
from .schemas import FsReadRestrictionConfig, FsWriteRestrictionConfig
from .seccomp import (
    cleanup_seccomp_filter,
    get_apply_seccomp_binary_path,
    get_pre_generated_bpf_path,
    get_seccomp_filter_path,
)
from .utils.debug import log_for_debugging
from .utils.ripgrep import RipgrepConfig, ripgrep

# Default max depth for searching dangerous files
DEFAULT_MANDATORY_DENY_SEARCH_DEPTH = 3


@dataclass
class LinuxNetworkBridgeContext:
    """Context for Linux network bridge."""

    http_socket_path: str
    socks_socket_path: str
    http_bridge_process: asyncio.subprocess.Process
    socks_bridge_process: asyncio.subprocess.Process
    http_proxy_port: int
    socks_proxy_port: int


@dataclass
class LinuxSandboxParams:
    """Parameters for Linux sandbox configuration."""

    command: str
    needs_network_restriction: bool
    http_socket_path: str | None = None
    socks_socket_path: str | None = None
    http_proxy_port: int | None = None
    socks_proxy_port: int | None = None
    read_config: FsReadRestrictionConfig | None = None
    write_config: FsWriteRestrictionConfig | None = None
    enable_weaker_nested_sandbox: bool | None = None
    allow_all_unix_sockets: bool | None = None
    bin_shell: str | None = None
    ripgrep_config: RipgrepConfig | None = None
    mandatory_deny_search_depth: int = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH
    allow_git_config: bool = False


async def _get_mandatory_deny_paths(
    ripgrep_config: RipgrepConfig | None = None,
    max_depth: int = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
    allow_git_config: bool = False,
) -> list[str]:
    """
    Get mandatory deny paths using ripgrep (Linux only).

    Uses a SINGLE ripgrep call with multiple glob patterns for efficiency.
    """
    cwd = os.getcwd()
    rg_config = ripgrep_config or RipgrepConfig()
    dangerous_directories = get_dangerous_directories()

    deny_paths = [
        # Dangerous files in CWD
        *[os.path.join(cwd, f) for f in DANGEROUS_FILES],
        # Dangerous directories in CWD
        *[os.path.join(cwd, d) for d in dangerous_directories],
        # Git hooks always blocked for security
        os.path.join(cwd, ".git/hooks"),
    ]

    # Git config conditionally blocked
    if not allow_git_config:
        deny_paths.append(os.path.join(cwd, ".git/config"))

    # Build iglob args for all patterns in one ripgrep call
    iglob_args: list[str] = []
    for file_name in DANGEROUS_FILES:
        iglob_args.extend(["--iglob", file_name])
    for dir_name in dangerous_directories:
        iglob_args.extend(["--iglob", f"**/{dir_name}/**"])
    # Git hooks always blocked in nested repos
    iglob_args.extend(["--iglob", "**/.git/hooks/**"])

    # Git config conditionally blocked in nested repos
    if not allow_git_config:
        iglob_args.extend(["--iglob", "**/.git/config"])

    # Single ripgrep call to find all dangerous paths in subdirectories
    matches: list[str] = []
    try:
        matches = await ripgrep(
            [
                "--files",
                "--hidden",
                "--max-depth",
                str(max_depth),
                *iglob_args,
                "-g",
                "!**/node_modules/**",
            ],
            cwd,
            rg_config,
        )
    except Exception as e:
        log_for_debugging(f"[Sandbox] ripgrep scan failed: {e}")

    # Process matches
    for match in matches:
        absolute_path = os.path.abspath(os.path.join(cwd, match))

        # File inside a dangerous directory -> add the directory path
        found_dir = False
        for dir_name in [*dangerous_directories, ".git"]:
            normalized_dir_name = normalize_case_for_comparison(dir_name)
            segments = absolute_path.split(os.sep)
            try:
                dir_index = next(
                    i for i, s in enumerate(segments) if normalize_case_for_comparison(s) == normalized_dir_name
                )
                # For .git, we want hooks/ or config, not the whole .git dir
                if dir_name == ".git":
                    git_dir = os.sep.join(segments[: dir_index + 1])
                    if ".git/hooks" in match:
                        deny_paths.append(os.path.join(git_dir, "hooks"))
                    elif ".git/config" in match:
                        deny_paths.append(os.path.join(git_dir, "config"))
                else:
                    deny_paths.append(os.sep.join(segments[: dir_index + 1]))
                found_dir = True
                break
            except StopIteration:
                continue

        # Dangerous file match
        if not found_dir:
            deny_paths.append(absolute_path)

    return list(set(deny_paths))


def has_sandbox_dependencies_sync(allow_all_unix_sockets: bool = False) -> bool:
    """
    Check if Linux sandbox dependencies are available (synchronous).

    Returns True if bwrap and socat are installed.
    """
    try:
        bwrap_path = shutil.which("bwrap")
        socat_path = shutil.which("socat")

        has_basic_deps = bwrap_path is not None and socat_path is not None

        # Check for seccomp dependencies (optional security feature)
        if not allow_all_unix_sockets:
            has_pre_generated_bpf = get_pre_generated_bpf_path() is not None
            has_apply_seccomp_binary = get_apply_seccomp_binary_path() is not None

            if not has_pre_generated_bpf or not has_apply_seccomp_binary:
                log_for_debugging(
                    "[Sandbox Linux] Seccomp filtering not available (missing binaries). "
                    "Sandbox will run without Unix socket blocking (allowAllUnixSockets mode). "
                    "This is less restrictive but still provides filesystem and network isolation.",
                    level="warn",
                )

        return has_basic_deps
    except Exception:
        return False


async def initialize_network_bridge(
    http_proxy_port: int,
    socks_proxy_port: int,
) -> LinuxNetworkBridgeContext:
    """
    Initialize the Linux network bridge for sandbox networking.

    Uses socat to bridge Unix sockets to TCP ports.
    """
    socket_id = secrets.token_hex(8)
    tmpdir = tempfile.gettempdir()
    http_socket_path = os.path.join(tmpdir, f"claude-http-{socket_id}.sock")
    socks_socket_path = os.path.join(tmpdir, f"claude-socks-{socket_id}.sock")

    # Start HTTP bridge
    http_socat_args = [
        "socat",
        f"UNIX-LISTEN:{http_socket_path},fork,reuseaddr",
        f"TCP:localhost:{http_proxy_port},keepalive,keepidle=10,keepintvl=5,keepcnt=3",
    ]

    log_for_debugging(f"Starting HTTP bridge: {' '.join(http_socat_args)}")

    http_bridge_process = await asyncio.create_subprocess_exec(
        *http_socat_args,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )

    if http_bridge_process.returncode is not None:
        raise RuntimeError("Failed to start HTTP bridge process")

    # Start SOCKS bridge
    socks_socat_args = [
        "socat",
        f"UNIX-LISTEN:{socks_socket_path},fork,reuseaddr",
        f"TCP:localhost:{socks_proxy_port},keepalive,keepidle=10,keepintvl=5,keepcnt=3",
    ]

    log_for_debugging(f"Starting SOCKS bridge: {' '.join(socks_socat_args)}")

    socks_bridge_process = await asyncio.create_subprocess_exec(
        *socks_socat_args,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )

    if socks_bridge_process.returncode is not None:
        # Clean up HTTP bridge
        http_bridge_process.terminate()
        await http_bridge_process.wait()
        raise RuntimeError("Failed to start SOCKS bridge process")

    # Wait for both sockets to be ready
    max_attempts = 5
    for i in range(max_attempts):
        # Check if processes are still running
        if http_bridge_process.returncode is not None or socks_bridge_process.returncode is not None:
            raise RuntimeError("Linux bridge process died unexpectedly")

        if os.path.exists(http_socket_path) and os.path.exists(socks_socket_path):
            log_for_debugging(f"Linux bridges ready after {i + 1} attempts")
            break

        if i == max_attempts - 1:
            # Clean up both processes
            http_bridge_process.terminate()
            socks_bridge_process.terminate()
            await http_bridge_process.wait()
            await socks_bridge_process.wait()
            raise RuntimeError(f"Failed to create bridge sockets after {max_attempts} attempts")

        await asyncio.sleep(i * 0.1)

    return LinuxNetworkBridgeContext(
        http_socket_path=http_socket_path,
        socks_socket_path=socks_socket_path,
        http_bridge_process=http_bridge_process,
        socks_bridge_process=socks_bridge_process,
        http_proxy_port=http_proxy_port,
        socks_proxy_port=socks_proxy_port,
    )


def _build_sandbox_command(
    http_socket_path: str,
    socks_socket_path: str,
    user_command: str,
    seccomp_filter_path: str | None,
    shell: str | None = None,
) -> str:
    """
    Build the command that runs inside the sandbox.

    Sets up HTTP proxy on port 3128 and SOCKS proxy on port 1080.
    """
    shell_path = shell or "bash"

    socat_commands = [
        f"socat TCP-LISTEN:3128,fork,reuseaddr UNIX-CONNECT:{http_socket_path} >/dev/null 2>&1 &",
        f"socat TCP-LISTEN:1080,fork,reuseaddr UNIX-CONNECT:{socks_socket_path} >/dev/null 2>&1 &",
        'trap "kill %1 %2 2>/dev/null; exit" EXIT',
    ]

    if seccomp_filter_path:
        apply_seccomp_binary = get_apply_seccomp_binary_path()
        if not apply_seccomp_binary:
            raise RuntimeError(
                "apply-seccomp binary not found. This should have been caught earlier. "
                "Ensure vendor/seccomp/{x64,arm64}/apply-seccomp binaries are included."
            )

        apply_seccomp_cmd = " ".join(
            shlex.quote(part)
            for part in [
                apply_seccomp_binary,
                seccomp_filter_path,
                shell_path,
                "-c",
                user_command,
            ]
        )

        inner_script = "\n".join([*socat_commands, apply_seccomp_cmd])
        return f"{shell_path} -c {shlex.quote(inner_script)}"
    else:
        inner_script = "\n".join([*socat_commands, f"eval {shlex.quote(user_command)}"])
        return f"{shell_path} -c {shlex.quote(inner_script)}"


async def _generate_filesystem_args(
    read_config: FsReadRestrictionConfig | None,
    write_config: FsWriteRestrictionConfig | None,
    ripgrep_config: RipgrepConfig | None = None,
    mandatory_deny_search_depth: int = DEFAULT_MANDATORY_DENY_SEARCH_DEPTH,
    allow_git_config: bool = False,
) -> list[str]:
    """Generate filesystem bind mount arguments for bwrap."""
    args: list[str] = []

    # Determine initial root mount based on write restrictions
    if write_config:
        # Write restrictions: Start with read-only root, then allow writes to specific paths
        args.extend(["--ro-bind", "/", "/"])

        # Collect normalized allowed write paths for later checking
        allowed_write_paths: list[str] = []

        # Allow writes to specific paths
        for path_pattern in write_config.allow_only or []:
            normalized_path = normalize_path_for_sandbox(path_pattern)

            log_for_debugging(f"[Sandbox Linux] Processing write path: {path_pattern} -> {normalized_path}")

            # Skip /dev/* paths since --dev /dev already handles them
            if normalized_path.startswith("/dev/"):
                log_for_debugging(f"[Sandbox Linux] Skipping /dev path: {normalized_path}")
                continue

            if not os.path.exists(normalized_path):
                log_for_debugging(f"[Sandbox Linux] Skipping non-existent write path: {normalized_path}")
                continue

            args.extend(["--bind", normalized_path, normalized_path])
            allowed_write_paths.append(normalized_path)

        # Deny writes within allowed paths (user-specified + mandatory denies)
        deny_paths = list(write_config.deny_within_allow or []) + await _get_mandatory_deny_paths(
            ripgrep_config,
            mandatory_deny_search_depth,
            allow_git_config,
        )

        for path_pattern in deny_paths:
            normalized_path = normalize_path_for_sandbox(path_pattern)

            # Skip /dev/* paths
            if normalized_path.startswith("/dev/"):
                continue

            # Skip non-existent paths
            if not os.path.exists(normalized_path):
                log_for_debugging(f"[Sandbox Linux] Skipping non-existent deny path: {normalized_path}")
                continue

            # Only add deny binding if this path is within an allowed write path
            is_within_allowed_path = any(
                normalized_path.startswith(allowed_path + "/") or normalized_path == allowed_path
                for allowed_path in allowed_write_paths
            )

            if is_within_allowed_path:
                args.extend(["--ro-bind", normalized_path, normalized_path])
            else:
                log_for_debugging(f"[Sandbox Linux] Skipping deny path not within allowed paths: {normalized_path}")
    else:
        # No write restrictions: Allow all writes
        args.extend(["--bind", "/", "/"])

    # Handle read restrictions by mounting tmpfs over denied paths
    read_deny_paths = list((read_config.deny_only if read_config else []) or [])

    # Always hide /etc/ssh/ssh_config.d to avoid permission issues with OrbStack
    if os.path.exists("/etc/ssh/ssh_config.d"):
        read_deny_paths.append("/etc/ssh/ssh_config.d")

    for path_pattern in read_deny_paths:
        normalized_path = normalize_path_for_sandbox(path_pattern)
        if not os.path.exists(normalized_path):
            log_for_debugging(f"[Sandbox Linux] Skipping non-existent read deny path: {normalized_path}")
            continue

        if os.path.isdir(normalized_path):
            args.extend(["--tmpfs", normalized_path])
        else:
            # For files, bind /dev/null instead of tmpfs
            args.extend(["--ro-bind", "/dev/null", normalized_path])

    return args


async def wrap_command_linux(params: LinuxSandboxParams) -> str:
    """
    Wrap a command with sandbox restrictions on Linux.

    Uses bubblewrap (bwrap) for containerization with optional seccomp filtering.
    """
    # Determine if we have restrictions to apply
    has_read_restrictions = params.read_config is not None and len(params.read_config.deny_only) > 0
    has_write_restrictions = params.write_config is not None

    # Check if we need any sandboxing
    if not params.needs_network_restriction and not has_read_restrictions and not has_write_restrictions:
        return params.command

    bwrap_args: list[str] = ["--new-session", "--die-with-parent"]
    seccomp_filter_path: str | None = None

    try:
        # === SECCOMP FILTER (Unix Socket Blocking) ===
        if not params.allow_all_unix_sockets:
            seccomp_filter_path = get_seccomp_filter_path()
            if not seccomp_filter_path:
                log_for_debugging(
                    "[Sandbox Linux] Seccomp filter not available (missing binaries). "
                    "Continuing without Unix socket blocking - sandbox will still provide "
                    "filesystem and network isolation but Unix sockets will be allowed.",
                    level="warn",
                )
            else:
                log_for_debugging("[Sandbox Linux] Generated seccomp BPF filter for Unix socket blocking")
        else:
            log_for_debugging("[Sandbox Linux] Skipping seccomp filter - allowAllUnixSockets is enabled")

        # === NETWORK RESTRICTIONS ===
        if params.needs_network_restriction:
            # Always unshare network namespace to isolate network access
            bwrap_args.append("--unshare-net")

            if params.http_socket_path and params.socks_socket_path:
                # Verify socket files still exist
                if not os.path.exists(params.http_socket_path):
                    raise RuntimeError(
                        f"Linux HTTP bridge socket does not exist: {params.http_socket_path}. "
                        "The bridge process may have died. Try reinitializing the sandbox."
                    )
                if not os.path.exists(params.socks_socket_path):
                    raise RuntimeError(
                        f"Linux SOCKS bridge socket does not exist: {params.socks_socket_path}. "
                        "The bridge process may have died. Try reinitializing the sandbox."
                    )

                # Bind both sockets into the sandbox
                bwrap_args.extend(["--bind", params.http_socket_path, params.http_socket_path])
                bwrap_args.extend(["--bind", params.socks_socket_path, params.socks_socket_path])

                # Add proxy environment variables
                proxy_env = generate_proxy_env_vars(3128, 1080)
                for env in proxy_env:
                    first_eq = env.index("=")
                    key = env[:first_eq]
                    value = env[first_eq + 1 :]
                    bwrap_args.extend(["--setenv", key, value])

                # Add host proxy port environment variables for debugging
                if params.http_proxy_port is not None:
                    bwrap_args.extend(
                        [
                            "--setenv",
                            "CLAUDE_CODE_HOST_HTTP_PROXY_PORT",
                            str(params.http_proxy_port),
                        ]
                    )
                if params.socks_proxy_port is not None:
                    bwrap_args.extend(
                        [
                            "--setenv",
                            "CLAUDE_CODE_HOST_SOCKS_PROXY_PORT",
                            str(params.socks_proxy_port),
                        ]
                    )

        # === FILESYSTEM RESTRICTIONS ===
        fs_args = await _generate_filesystem_args(
            params.read_config,
            params.write_config,
            params.ripgrep_config,
            params.mandatory_deny_search_depth,
            params.allow_git_config,
        )
        bwrap_args.extend(fs_args)

        # Always bind /dev
        bwrap_args.extend(["--dev", "/dev"])

        # === PID NAMESPACE ISOLATION ===
        bwrap_args.append("--unshare-pid")
        if not params.enable_weaker_nested_sandbox:
            bwrap_args.extend(["--proc", "/proc"])

        # === COMMAND ===
        shell_name = params.bin_shell or "bash"
        shell_path = shutil.which(shell_name)
        if not shell_path:
            raise RuntimeError(f"Shell '{shell_name}' not found in PATH")

        bwrap_args.extend(["--", shell_path, "-c"])

        # Build the inner command
        if params.needs_network_restriction and params.http_socket_path and params.socks_socket_path:
            sandbox_command = _build_sandbox_command(
                params.http_socket_path,
                params.socks_socket_path,
                params.command,
                seccomp_filter_path,
                shell_path,
            )
            bwrap_args.append(sandbox_command)
        elif seccomp_filter_path:
            # No network restrictions but we have seccomp
            apply_seccomp_binary = get_apply_seccomp_binary_path()
            if not apply_seccomp_binary:
                raise RuntimeError("apply-seccomp binary not found. This should have been caught earlier.")

            apply_seccomp_cmd = " ".join(
                shlex.quote(part)
                for part in [
                    apply_seccomp_binary,
                    seccomp_filter_path,
                    shell_path,
                    "-c",
                    params.command,
                ]
            )
            bwrap_args.append(apply_seccomp_cmd)
        else:
            bwrap_args.append(params.command)

        # Build the outer bwrap command
        wrapped_command = " ".join(shlex.quote(part) for part in ["bwrap", *bwrap_args])

        restrictions = []
        if params.needs_network_restriction:
            restrictions.append("network")
        if has_read_restrictions or has_write_restrictions:
            restrictions.append("filesystem")
        if seccomp_filter_path:
            restrictions.append("seccomp(unix-block)")

        log_for_debugging(f"[Sandbox Linux] Wrapped command with bwrap ({', '.join(restrictions)} restrictions)")

        return wrapped_command

    except Exception:
        # Clean up seccomp filter on error (no-op for pre-generated filters)
        if seccomp_filter_path:
            cleanup_seccomp_filter(seccomp_filter_path)
        raise
