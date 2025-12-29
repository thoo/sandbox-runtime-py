"""macOS sandbox utilities using sandbox-exec (Seatbelt)."""

import asyncio
import json
import os
import random
import re
import shlex
import shutil
import string
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from .config import IgnoreViolationsConfig
from .sandbox_utils import (
    DANGEROUS_FILES,
    contains_glob_chars,
    decode_sandboxed_command,
    encode_sandboxed_command,
    generate_proxy_env_vars,
    get_dangerous_directories,
    normalize_path_for_sandbox,
)
from .schemas import FsReadRestrictionConfig, FsWriteRestrictionConfig
from .utils.debug import log_for_debugging


@dataclass
class MacOSSandboxParams:
    """Parameters for macOS sandbox configuration."""

    command: str
    needs_network_restriction: bool
    http_proxy_port: int | None = None
    socks_proxy_port: int | None = None
    allow_unix_sockets: list[str] | None = None
    allow_all_unix_sockets: bool | None = None
    allow_local_binding: bool | None = None
    read_config: FsReadRestrictionConfig | None = None
    write_config: FsWriteRestrictionConfig | None = None
    ignore_violations: IgnoreViolationsConfig | None = None
    allow_pty: bool | None = None
    allow_git_config: bool = False
    bin_shell: str | None = None


@dataclass
class SandboxViolationEvent:
    """A sandbox violation event."""

    line: str
    command: str | None = None
    encoded_command: str | None = None
    timestamp: datetime = field(default_factory=datetime.now)


# Type for the violation callback
SandboxViolationCallback = Callable[[SandboxViolationEvent], None]

# Session suffix for log tag matching
_session_suffix = f"_{''.join(random.choices(string.ascii_lowercase + string.digits, k=9))}_SBX"


def get_mandatory_deny_patterns(allow_git_config: bool = False) -> list[str]:
    """
    Get mandatory deny patterns as glob patterns (no filesystem scanning).

    macOS sandbox profile supports regex/glob matching directly via glob_to_regex().
    """
    cwd = os.getcwd()
    deny_paths: list[str] = []

    # Dangerous files - static paths in CWD + glob patterns for subtree
    for file_name in DANGEROUS_FILES:
        deny_paths.append(os.path.join(cwd, file_name))
        deny_paths.append(f"**/{file_name}")

    # Dangerous directories
    for dir_name in get_dangerous_directories():
        deny_paths.append(os.path.join(cwd, dir_name))
        deny_paths.append(f"**/{dir_name}/**")

    # Git hooks are always blocked for security
    deny_paths.append(os.path.join(cwd, ".git/hooks"))
    deny_paths.append("**/.git/hooks/**")

    # Git config - conditionally blocked based on allow_git_config setting
    if not allow_git_config:
        deny_paths.append(os.path.join(cwd, ".git/config"))
        deny_paths.append("**/.git/config")

    return list(set(deny_paths))


def glob_to_regex(glob_pattern: str) -> str:
    """
    Convert a glob pattern to a regular expression for macOS sandbox profiles.

    Implements gitignore-style pattern matching:
    - * matches any characters except / (e.g., *.ts matches foo.ts but not foo/bar.ts)
    - ** matches any characters including / (e.g., src/**/*.ts matches all .ts files in src/)
    - ? matches any single character except / (e.g., file?.txt matches file1.txt)
    - [abc] matches any character in the set (e.g., file[0-9].txt matches file3.txt)

    Note: This is designed for macOS sandbox (regex ...) syntax.
    """
    result = "^"

    # Escape regex special characters (except glob chars * ? [ ])
    escaped = re.sub(r"[.^$+{}()|\\]", r"\\\g<0>", glob_pattern)

    # Escape unclosed brackets (no matching ])
    escaped = re.sub(r"\[([^\]]*?)$", r"\\[\1", escaped)

    # Convert glob patterns to regex (order matters - ** before *)
    # Use placeholders for ** patterns first
    escaped = escaped.replace("**/", "__GLOBSTAR_SLASH__")
    escaped = escaped.replace("**", "__GLOBSTAR__")
    escaped = escaped.replace("*", "[^/]*")  # * matches anything except /
    escaped = escaped.replace("?", "[^/]")  # ? matches single character except /

    # Restore placeholders
    escaped = escaped.replace("__GLOBSTAR_SLASH__", "(.*/)?")  # **/ matches zero or more dirs
    escaped = escaped.replace("__GLOBSTAR__", ".*")  # ** matches anything including /

    result += escaped + "$"
    return result


def _generate_log_tag(command: str) -> str:
    """Generate a unique log tag for sandbox monitoring."""
    encoded_command = encode_sandboxed_command(command)
    return f"CMD64_{encoded_command}_END_{_session_suffix}"


def _escape_path(path_str: str) -> str:
    """Escape path for sandbox profile using JSON.stringify for proper escaping."""
    return json.dumps(path_str)


def _get_ancestor_directories(path_str: str) -> list[str]:
    """
    Get all ancestor directories for a path, up to (but not including) root.

    Example: /private/tmp/test/file.txt -> ["/private/tmp/test", "/private/tmp", "/private"]
    """
    ancestors: list[str] = []
    current_path = os.path.dirname(path_str)

    while current_path not in ("/", "."):
        ancestors.append(current_path)
        parent_path = os.path.dirname(current_path)
        if parent_path == current_path:
            break
        current_path = parent_path

    return ancestors


def _get_tmpdir_parent_if_macos_pattern() -> list[str]:
    """
    Get TMPDIR parent directory if it matches macOS pattern /var/folders/XX/YYY/T/.

    Returns both /var/ and /private/var/ versions since /var is a symlink.
    """
    tmpdir = os.environ.get("TMPDIR", "")
    if not tmpdir:
        return []

    match = re.match(r"^/(private/)?var/folders/[^/]{2}/[^/]+/T/?$", tmpdir)
    if not match:
        return []

    parent = re.sub(r"/T/?$", "", tmpdir)

    # Return both /var/ and /private/var/ versions since /var is a symlink
    if parent.startswith("/private/var/"):
        return [parent, parent.replace("/private", "")]
    elif parent.startswith("/var/"):
        return [parent, "/private" + parent]

    return [parent]


def _generate_move_blocking_rules(path_patterns: list[str], log_tag: str) -> list[str]:
    """
    Generate deny rules for file movement (file-write-unlink) to protect paths.

    This prevents bypassing read or write restrictions by moving files/directories.
    """
    rules: list[str] = []

    for path_pattern in path_patterns:
        normalized_path = normalize_path_for_sandbox(path_pattern)

        if contains_glob_chars(normalized_path):
            # Use regex matching for glob patterns
            regex_pattern = glob_to_regex(normalized_path)

            # Block moving/renaming files matching this pattern
            rules.extend(
                [
                    "(deny file-write-unlink",
                    f"  (regex {_escape_path(regex_pattern)})",
                    f'  (with message "{log_tag}"))',
                ]
            )

            # For glob patterns, extract the static prefix and block ancestor moves
            static_prefix = re.split(r"[*?\[\]]", normalized_path)[0]
            if static_prefix and static_prefix != "/":
                # Get the directory containing the glob pattern
                base_dir = static_prefix.rstrip("/")
                if not base_dir.endswith("/"):
                    base_dir = os.path.dirname(static_prefix) if static_prefix else ""

                if base_dir:
                    # Block moves of the base directory itself
                    rules.extend(
                        [
                            "(deny file-write-unlink",
                            f"  (literal {_escape_path(base_dir)})",
                            f'  (with message "{log_tag}"))',
                        ]
                    )

                    # Block moves of ancestor directories
                    for ancestor_dir in _get_ancestor_directories(base_dir):
                        rules.extend(
                            [
                                "(deny file-write-unlink",
                                f"  (literal {_escape_path(ancestor_dir)})",
                                f'  (with message "{log_tag}"))',
                            ]
                        )
        else:
            # Use subpath matching for literal paths
            rules.extend(
                [
                    "(deny file-write-unlink",
                    f"  (subpath {_escape_path(normalized_path)})",
                    f'  (with message "{log_tag}"))',
                ]
            )

            # Block moves of ancestor directories
            for ancestor_dir in _get_ancestor_directories(normalized_path):
                rules.extend(
                    [
                        "(deny file-write-unlink",
                        f"  (literal {_escape_path(ancestor_dir)})",
                        f'  (with message "{log_tag}"))',
                    ]
                )

    return rules


def _generate_read_rules(
    config: FsReadRestrictionConfig | None,
    log_tag: str,
) -> list[str]:
    """Generate filesystem read rules for sandbox profile."""
    if config is None:
        return ["(allow file-read*)"]

    rules: list[str] = []

    # Start by allowing everything
    rules.append("(allow file-read*)")

    # Then deny specific paths
    for path_pattern in config.deny_only or []:
        normalized_path = normalize_path_for_sandbox(path_pattern)

        if contains_glob_chars(normalized_path):
            # Use regex matching for glob patterns
            regex_pattern = glob_to_regex(normalized_path)
            rules.extend(
                [
                    "(deny file-read*",
                    f"  (regex {_escape_path(regex_pattern)})",
                    f'  (with message "{log_tag}"))',
                ]
            )
        else:
            # Use subpath matching for literal paths
            rules.extend(
                [
                    "(deny file-read*",
                    f"  (subpath {_escape_path(normalized_path)})",
                    f'  (with message "{log_tag}"))',
                ]
            )

    # Block file movement to prevent bypass via mv/rename
    rules.extend(_generate_move_blocking_rules(config.deny_only or [], log_tag))

    return rules


def _generate_write_rules(
    config: FsWriteRestrictionConfig | None,
    log_tag: str,
    allow_git_config: bool = False,
) -> list[str]:
    """Generate filesystem write rules for sandbox profile."""
    if config is None:
        return ["(allow file-write*)"]

    rules: list[str] = []

    # Automatically allow TMPDIR parent on macOS when write restrictions are enabled
    for tmpdir_parent in _get_tmpdir_parent_if_macos_pattern():
        normalized_path = normalize_path_for_sandbox(tmpdir_parent)
        rules.extend(
            [
                "(allow file-write*",
                f"  (subpath {_escape_path(normalized_path)})",
                f'  (with message "{log_tag}"))',
            ]
        )

    # Generate allow rules
    for path_pattern in config.allow_only or []:
        normalized_path = normalize_path_for_sandbox(path_pattern)

        if contains_glob_chars(normalized_path):
            # Use regex matching for glob patterns
            regex_pattern = glob_to_regex(normalized_path)
            rules.extend(
                [
                    "(allow file-write*",
                    f"  (regex {_escape_path(regex_pattern)})",
                    f'  (with message "{log_tag}"))',
                ]
            )
        else:
            # Use subpath matching for literal paths
            rules.extend(
                [
                    "(allow file-write*",
                    f"  (subpath {_escape_path(normalized_path)})",
                    f'  (with message "{log_tag}"))',
                ]
            )

    # Combine user-specified and mandatory deny patterns
    deny_paths = list(config.deny_within_allow or []) + get_mandatory_deny_patterns(allow_git_config)

    for path_pattern in deny_paths:
        normalized_path = normalize_path_for_sandbox(path_pattern)

        if contains_glob_chars(normalized_path):
            # Use regex matching for glob patterns
            regex_pattern = glob_to_regex(normalized_path)
            rules.extend(
                [
                    "(deny file-write*",
                    f"  (regex {_escape_path(regex_pattern)})",
                    f'  (with message "{log_tag}"))',
                ]
            )
        else:
            # Use subpath matching for literal paths
            rules.extend(
                [
                    "(deny file-write*",
                    f"  (subpath {_escape_path(normalized_path)})",
                    f'  (with message "{log_tag}"))',
                ]
            )

    # Block file movement to prevent bypass via mv/rename
    rules.extend(_generate_move_blocking_rules(deny_paths, log_tag))

    return rules


def _generate_sandbox_profile(
    read_config: FsReadRestrictionConfig | None,
    write_config: FsWriteRestrictionConfig | None,
    http_proxy_port: int | None,
    socks_proxy_port: int | None,
    needs_network_restriction: bool,
    allow_unix_sockets: list[str] | None,
    allow_all_unix_sockets: bool | None,
    allow_local_binding: bool | None,
    allow_pty: bool | None,
    allow_git_config: bool,
    log_tag: str,
) -> str:
    """Generate complete sandbox profile."""
    profile: list[str] = [
        "(version 1)",
        f'(deny default (with message "{log_tag}"))',
        "",
        f"; LogTag: {log_tag}",
        "",
        "; Essential permissions - based on Chrome sandbox policy",
        "; Process permissions",
        "(allow process-exec)",
        "(allow process-fork)",
        "(allow process-info* (target same-sandbox))",
        "(allow signal (target same-sandbox))",
        "(allow mach-priv-task-port (target same-sandbox))",
        "",
        "; User preferences",
        "(allow user-preference-read)",
        "",
        "; Mach IPC - specific services only (no wildcard)",
        "(allow mach-lookup",
        '  (global-name "com.apple.audio.systemsoundserver")',
        '  (global-name "com.apple.distributed_notifications@Uv3")',
        '  (global-name "com.apple.FontObjectsServer")',
        '  (global-name "com.apple.fonts")',
        '  (global-name "com.apple.logd")',
        '  (global-name "com.apple.lsd.mapdb")',
        '  (global-name "com.apple.PowerManagement.control")',
        '  (global-name "com.apple.system.logger")',
        '  (global-name "com.apple.system.notification_center")',
        '  (global-name "com.apple.trustd.agent")',
        '  (global-name "com.apple.system.opendirectoryd.libinfo")',
        '  (global-name "com.apple.system.opendirectoryd.membership")',
        '  (global-name "com.apple.bsd.dirhelper")',
        '  (global-name "com.apple.securityd.xpc")',
        '  (global-name "com.apple.coreservices.launchservicesd")',
        ")",
        "",
        "; POSIX IPC - shared memory",
        "(allow ipc-posix-shm)",
        "",
        "; POSIX IPC - semaphores for Python multiprocessing",
        "(allow ipc-posix-sem)",
        "",
        "; IOKit - specific operations only",
        "(allow iokit-open",
        '  (iokit-registry-entry-class "IOSurfaceRootUserClient")',
        '  (iokit-registry-entry-class "RootDomainUserClient")',
        '  (iokit-user-client-class "IOSurfaceSendRight")',
        ")",
        "",
        "; IOKit properties",
        "(allow iokit-get-properties)",
        "",
        "; Specific safe system-sockets, doesn't allow network access",
        "(allow system-socket (require-all (socket-domain AF_SYSTEM) (socket-protocol 2)))",
        "",
        "; sysctl - specific sysctls only",
        "(allow sysctl-read",
        '  (sysctl-name "hw.activecpu")',
        '  (sysctl-name "hw.busfrequency_compat")',
        '  (sysctl-name "hw.byteorder")',
        '  (sysctl-name "hw.cacheconfig")',
        '  (sysctl-name "hw.cachelinesize_compat")',
        '  (sysctl-name "hw.cpufamily")',
        '  (sysctl-name "hw.cpufrequency")',
        '  (sysctl-name "hw.cpufrequency_compat")',
        '  (sysctl-name "hw.cputype")',
        '  (sysctl-name "hw.l1dcachesize_compat")',
        '  (sysctl-name "hw.l1icachesize_compat")',
        '  (sysctl-name "hw.l2cachesize_compat")',
        '  (sysctl-name "hw.l3cachesize_compat")',
        '  (sysctl-name "hw.logicalcpu")',
        '  (sysctl-name "hw.logicalcpu_max")',
        '  (sysctl-name "hw.machine")',
        '  (sysctl-name "hw.memsize")',
        '  (sysctl-name "hw.ncpu")',
        '  (sysctl-name "hw.nperflevels")',
        '  (sysctl-name "hw.packages")',
        '  (sysctl-name "hw.pagesize_compat")',
        '  (sysctl-name "hw.pagesize")',
        '  (sysctl-name "hw.physicalcpu")',
        '  (sysctl-name "hw.physicalcpu_max")',
        '  (sysctl-name "hw.tbfrequency_compat")',
        '  (sysctl-name "hw.vectorunit")',
        '  (sysctl-name "kern.argmax")',
        '  (sysctl-name "kern.bootargs")',
        '  (sysctl-name "kern.hostname")',
        '  (sysctl-name "kern.maxfiles")',
        '  (sysctl-name "kern.maxfilesperproc")',
        '  (sysctl-name "kern.maxproc")',
        '  (sysctl-name "kern.ngroups")',
        '  (sysctl-name "kern.osproductversion")',
        '  (sysctl-name "kern.osrelease")',
        '  (sysctl-name "kern.ostype")',
        '  (sysctl-name "kern.osvariant_status")',
        '  (sysctl-name "kern.osversion")',
        '  (sysctl-name "kern.secure_kernel")',
        '  (sysctl-name "kern.tcsm_available")',
        '  (sysctl-name "kern.tcsm_enable")',
        '  (sysctl-name "kern.usrstack64")',
        '  (sysctl-name "kern.version")',
        '  (sysctl-name "kern.willshutdown")',
        '  (sysctl-name "machdep.cpu.brand_string")',
        '  (sysctl-name "machdep.ptrauth_enabled")',
        '  (sysctl-name "security.mac.lockdown_mode_state")',
        '  (sysctl-name "sysctl.proc_cputype")',
        '  (sysctl-name "vm.loadavg")',
        '  (sysctl-name-prefix "hw.optional.arm")',
        '  (sysctl-name-prefix "hw.optional.arm.")',
        '  (sysctl-name-prefix "hw.optional.armv8_")',
        '  (sysctl-name-prefix "hw.perflevel")',
        '  (sysctl-name-prefix "kern.proc.all")',
        '  (sysctl-name-prefix "kern.proc.pgrp.")',
        '  (sysctl-name-prefix "kern.proc.pid.")',
        '  (sysctl-name-prefix "machdep.cpu.")',
        '  (sysctl-name-prefix "net.routetable.")',
        ")",
        "",
        "; V8 thread calculations",
        "(allow sysctl-write",
        '  (sysctl-name "kern.tcsm_enable")',
        ")",
        "",
        "; Distributed notifications",
        "(allow distributed-notification-post)",
        "",
        "; Specific mach-lookup permissions for security operations",
        '(allow mach-lookup (global-name "com.apple.SecurityServer"))',
        "",
        "; File I/O on device files",
        '(allow file-ioctl (literal "/dev/null"))',
        '(allow file-ioctl (literal "/dev/zero"))',
        '(allow file-ioctl (literal "/dev/random"))',
        '(allow file-ioctl (literal "/dev/urandom"))',
        '(allow file-ioctl (literal "/dev/dtracehelper"))',
        '(allow file-ioctl (literal "/dev/tty"))',
        "",
        "(allow file-ioctl file-read-data file-write-data",
        "  (require-all",
        '    (literal "/dev/null")',
        "    (vnode-type CHARACTER-DEVICE)",
        "  )",
        ")",
        "",
    ]

    # Network rules
    profile.append("; Network")
    if not needs_network_restriction:
        profile.append("(allow network*)")
    else:
        # Allow local binding if requested
        if allow_local_binding:
            profile.append('(allow network-bind (local ip "localhost:*"))')
            profile.append('(allow network-inbound (local ip "localhost:*"))')
            profile.append('(allow network-outbound (local ip "localhost:*"))')

        # Unix domain sockets for local IPC (SSH agent, Docker, etc.)
        if allow_all_unix_sockets:
            # Allow all Unix socket paths
            profile.append('(allow network* (subpath "/"))')
        elif allow_unix_sockets:
            # Allow specific Unix socket paths
            for socket_path in allow_unix_sockets:
                normalized_path = normalize_path_for_sandbox(socket_path)
                profile.append(f"(allow network* (subpath {_escape_path(normalized_path)}))")

        # Allow localhost TCP operations for the HTTP proxy
        if http_proxy_port is not None:
            profile.append(f'(allow network-bind (local ip "localhost:{http_proxy_port}"))')
            profile.append(f'(allow network-inbound (local ip "localhost:{http_proxy_port}"))')
            profile.append(f'(allow network-outbound (remote ip "localhost:{http_proxy_port}"))')

        # Allow localhost TCP operations for the SOCKS proxy
        if socks_proxy_port is not None:
            profile.append(f'(allow network-bind (local ip "localhost:{socks_proxy_port}"))')
            profile.append(f'(allow network-inbound (local ip "localhost:{socks_proxy_port}"))')
            profile.append(f'(allow network-outbound (remote ip "localhost:{socks_proxy_port}"))')

    profile.append("")

    # Read rules
    profile.append("; File read")
    profile.extend(_generate_read_rules(read_config, log_tag))
    profile.append("")

    # Write rules
    profile.append("; File write")
    profile.extend(_generate_write_rules(write_config, log_tag, allow_git_config))

    # Pseudo-terminal (pty) support
    if allow_pty:
        profile.extend(
            [
                "",
                "; Pseudo-terminal (pty) support",
                "(allow pseudo-tty)",
                "(allow file-ioctl",
                '  (literal "/dev/ptmx")',
                '  (regex #"^/dev/ttys")',
                ")",
                "(allow file-read* file-write*",
                '  (literal "/dev/ptmx")',
                '  (regex #"^/dev/ttys")',
                ")",
            ]
        )

    return "\n".join(profile)


def wrap_command_macos(params: MacOSSandboxParams) -> str:
    """
    Wrap command with macOS sandbox.

    Args:
        params: Sandbox parameters

    Returns:
        The wrapped command string
    """
    # Determine if we have restrictions to apply
    has_read_restrictions = params.read_config is not None and len(params.read_config.deny_only) > 0
    has_write_restrictions = params.write_config is not None

    # No sandboxing needed
    if not params.needs_network_restriction and not has_read_restrictions and not has_write_restrictions:
        return params.command

    log_tag = _generate_log_tag(params.command)

    profile = _generate_sandbox_profile(
        read_config=params.read_config,
        write_config=params.write_config,
        http_proxy_port=params.http_proxy_port,
        socks_proxy_port=params.socks_proxy_port,
        needs_network_restriction=params.needs_network_restriction,
        allow_unix_sockets=params.allow_unix_sockets,
        allow_all_unix_sockets=params.allow_all_unix_sockets,
        allow_local_binding=params.allow_local_binding,
        allow_pty=params.allow_pty,
        allow_git_config=params.allow_git_config,
        log_tag=log_tag,
    )

    # Generate proxy environment variables using shared utility
    proxy_env_args = generate_proxy_env_vars(
        params.http_proxy_port,
        params.socks_proxy_port,
    )

    # Use the user's shell (zsh, bash, etc.) to ensure aliases/snapshots work
    shell_name = params.bin_shell or "bash"
    shell_path = shutil.which(shell_name)
    if not shell_path:
        raise RuntimeError(f"Shell '{shell_name}' not found in PATH")

    # Build the command using env to set environment variables
    cmd_parts = ["env"]
    cmd_parts.extend(proxy_env_args)
    cmd_parts.extend(
        [
            "sandbox-exec",
            "-p",
            profile,
            shell_path,
            "-c",
            params.command,
        ]
    )

    wrapped_command = " ".join(shlex.quote(part) for part in cmd_parts)

    has_network = params.http_proxy_port is not None or params.socks_proxy_port is not None
    log_for_debugging(
        f"[Sandbox macOS] Applied restrictions - network: {has_network}, "
        f"read: {'denyOnly' if params.read_config else 'none'}, "
        f"write: {'allowOnly' if params.write_config else 'none'}"
    )

    return wrapped_command


async def start_log_monitor(
    callback: SandboxViolationCallback,
    ignore_violations: IgnoreViolationsConfig | None = None,
) -> Callable[[], None]:
    """
    Start monitoring macOS system logs for sandbox violations.

    Args:
        callback: Function to call when a violation is detected
        ignore_violations: Configuration for ignoring specific violations

    Returns:
        A function to stop the log monitor
    """
    # Pre-compile regex patterns for better performance
    cmd_extract_regex = re.compile(r"CMD64_(.+?)_END")
    sandbox_extract_regex = re.compile(r"Sandbox:\s+(.+)$")

    # Pre-process ignore patterns for faster lookup
    wildcard_paths = (ignore_violations or {}).get("*", [])
    command_patterns = [(pattern, paths) for pattern, paths in (ignore_violations or {}).items() if pattern != "*"]

    # Stream and filter kernel logs for all sandbox violations
    process = await asyncio.create_subprocess_exec(
        "log",
        "stream",
        "--predicate",
        f'(eventMessage ENDSWITH "{_session_suffix}")',
        "--style",
        "compact",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    stop_event = asyncio.Event()

    async def read_logs() -> None:
        if process.stdout is None:
            return

        while not stop_event.is_set():
            try:
                line_bytes = await asyncio.wait_for(
                    process.stdout.readline(),
                    timeout=1.0,
                )
                if not line_bytes:
                    break

                line = line_bytes.decode(errors="replace")

                # Check if this is a sandbox violation
                if "Sandbox:" not in line or "deny" not in line:
                    continue

                # Extract violation details
                sandbox_match = sandbox_extract_regex.search(line)
                if not sandbox_match:
                    continue

                violation_details = sandbox_match.group(1)

                # Always filter out noisy violations
                if any(
                    noise in violation_details
                    for noise in [
                        "mDNSResponder",
                        "mach-lookup com.apple.diagnosticd",
                        "mach-lookup com.apple.analyticsd",
                    ]
                ):
                    continue

                # Try to extract command from the log
                command: str | None = None
                encoded_command: str | None = None
                cmd_match = cmd_extract_regex.search(line)
                if cmd_match:
                    encoded_command = cmd_match.group(1)
                    try:
                        command = decode_sandboxed_command(encoded_command)
                    except Exception:
                        pass

                # Check if we should ignore this violation
                if command:
                    # Check wildcard patterns first
                    if wildcard_paths:
                        if any(path in violation_details for path in wildcard_paths):
                            continue

                    # Check command-specific patterns
                    for pattern, paths in command_patterns:
                        if pattern in command:
                            if any(path in violation_details for path in paths):
                                continue

                # Not ignored - report the violation
                callback(
                    SandboxViolationEvent(
                        line=violation_details,
                        command=command,
                        encoded_command=encoded_command,
                    )
                )

            except TimeoutError:
                continue
            except Exception as e:
                log_for_debugging(f"[Sandbox Monitor] Error reading logs: {e}", level="error")
                break

    # Start reading logs in the background
    _task = asyncio.create_task(read_logs())  # noqa: F841

    def shutdown() -> None:
        log_for_debugging("[Sandbox Monitor] Stopping log monitor")
        stop_event.set()
        process.terminate()

    return shutdown
