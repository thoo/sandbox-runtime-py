"""Main sandbox manager that orchestrates network and filesystem restrictions."""

import asyncio
import atexit
import copy
import os
import signal
from collections.abc import Callable
from dataclasses import dataclass

from .config import SandboxRuntimeConfig
from .http_proxy import HttpProxyServer, create_http_proxy_server
from .linux_sandbox import (
    LinuxNetworkBridgeContext,
    LinuxSandboxParams,
    has_sandbox_dependencies_sync,
    initialize_network_bridge,
    wrap_command_linux,
)
from .macos_sandbox import (
    MacOSSandboxParams,
    start_log_monitor,
    wrap_command_macos,
)
from .sandbox_utils import (
    contains_glob_chars,
    get_default_write_paths,
    remove_trailing_glob_suffix,
)
from .schemas import (
    FsReadRestrictionConfig,
    FsWriteRestrictionConfig,
    NetworkHostPattern,
    NetworkRestrictionConfig,
    SandboxAskCallbackType,
)
from .socks_proxy import Socks5ProxyServer, create_socks_proxy_server
from .utils.debug import log_for_debugging
from .utils.platform import Platform, get_platform
from .utils.ripgrep import RipgrepConfig, has_ripgrep_sync
from .violation_store import SandboxViolationStore


@dataclass
class _HostNetworkManagerContext:
    """Context for the network manager."""

    http_proxy_port: int
    socks_proxy_port: int
    linux_bridge: LinuxNetworkBridgeContext | None = None


# Module-level state
_config: SandboxRuntimeConfig | None = None
_http_proxy_server: HttpProxyServer | None = None
_socks_proxy_server: Socks5ProxyServer | None = None
_manager_context: _HostNetworkManagerContext | None = None
_initialization_task: asyncio.Task[_HostNetworkManagerContext] | None = None
_cleanup_registered = False
_log_monitor_shutdown: Callable[[], None] | None = None
_sandbox_violation_store = SandboxViolationStore()


def _matches_domain_pattern(hostname: str, pattern: str) -> bool:
    """Check if a hostname matches a domain pattern."""
    # Support wildcard patterns like *.example.com
    if pattern.startswith("*."):
        base_domain = pattern[2:]  # Remove '*.'
        return hostname.lower().endswith("." + base_domain.lower())

    # Exact match for non-wildcard patterns
    return hostname.lower() == pattern.lower()


async def _filter_network_request(
    port: int,
    host: str,
    sandbox_ask_callback: SandboxAskCallbackType | None = None,
) -> bool:
    """Filter a network request based on configuration."""
    if _config is None:
        log_for_debugging("No config available, denying network request")
        return False

    # Check denied domains first
    for denied_domain in _config.network.denied_domains:
        if _matches_domain_pattern(host, denied_domain):
            log_for_debugging(f"Denied by config rule: {host}:{port}")
            return False

    # Check allowed domains
    for allowed_domain in _config.network.allowed_domains:
        if _matches_domain_pattern(host, allowed_domain):
            log_for_debugging(f"Allowed by config rule: {host}:{port}")
            return True

    # No matching rules - ask user or deny
    if sandbox_ask_callback is None:
        log_for_debugging(f"No matching config rule, denying: {host}:{port}")
        return False

    log_for_debugging(f"No matching config rule, asking user: {host}:{port}")
    try:
        user_allowed = await sandbox_ask_callback(NetworkHostPattern(host=host, port=port))
        if user_allowed:
            log_for_debugging(f"User allowed: {host}:{port}")
            return True
        else:
            log_for_debugging(f"User denied: {host}:{port}")
            return False
    except Exception as e:
        log_for_debugging(f"Error in permission callback: {e}", level="error")
        return False


class SandboxManager:
    """
    Global sandbox manager that handles both network and filesystem restrictions.

    This runs outside of the sandbox, on the host machine.
    """

    @staticmethod
    async def initialize(
        runtime_config: SandboxRuntimeConfig,
        sandbox_ask_callback: SandboxAskCallbackType | None = None,
        enable_log_monitor: bool = False,
    ) -> None:
        """
        Initialize the sandbox manager.

        Args:
            runtime_config: The sandbox configuration
            sandbox_ask_callback: Optional callback for asking user about network requests
            enable_log_monitor: Whether to enable macOS log monitoring
        """
        global _config, _initialization_task, _manager_context, _log_monitor_shutdown
        global _http_proxy_server, _socks_proxy_server

        # Return if already initializing
        if _initialization_task is not None:
            await _initialization_task
            return

        # Store config for use by other functions
        _config = runtime_config

        # Check dependencies
        if not SandboxManager.check_dependencies():
            platform = get_platform()
            error_message = "Sandbox dependencies are not available on this system."

            if platform == "linux":
                error_message += " Required: ripgrep (rg), bubblewrap (bwrap), and socat."
            elif platform == "macos":
                error_message += " Required: ripgrep (rg)."
            else:
                error_message += f" Platform '{platform}' is not supported."

            raise RuntimeError(error_message)

        # Start log monitor for macOS if enabled
        if enable_log_monitor and get_platform() == "macos":
            _log_monitor_shutdown = await start_log_monitor(
                _sandbox_violation_store.add_violation,
                _config.ignore_violations,
            )
            log_for_debugging("Started macOS sandbox log monitor")

        # Register cleanup handlers
        _register_cleanup()

        async def do_initialize() -> _HostNetworkManagerContext:
            global _http_proxy_server, _socks_proxy_server, _manager_context

            try:
                # Start HTTP proxy server
                http_proxy_port: int
                if _config.network.http_proxy_port is not None:
                    http_proxy_port = _config.network.http_proxy_port
                    log_for_debugging(f"Using external HTTP proxy on port {http_proxy_port}")
                else:
                    _http_proxy_server = create_http_proxy_server(
                        lambda port, host: _filter_network_request(port, host, sandbox_ask_callback)
                    )
                    http_proxy_port = await _http_proxy_server.start()

                # Start SOCKS proxy server
                socks_proxy_port: int
                if _config.network.socks_proxy_port is not None:
                    socks_proxy_port = _config.network.socks_proxy_port
                    log_for_debugging(f"Using external SOCKS proxy on port {socks_proxy_port}")
                else:
                    _socks_proxy_server = create_socks_proxy_server(
                        lambda port, host: _filter_network_request(port, host, sandbox_ask_callback)
                    )
                    socks_proxy_port = await _socks_proxy_server.start()

                # Initialize platform-specific infrastructure
                linux_bridge: LinuxNetworkBridgeContext | None = None
                if get_platform() == "linux":
                    linux_bridge = await initialize_network_bridge(
                        http_proxy_port,
                        socks_proxy_port,
                    )

                context = _HostNetworkManagerContext(
                    http_proxy_port=http_proxy_port,
                    socks_proxy_port=socks_proxy_port,
                    linux_bridge=linux_bridge,
                )
                _manager_context = context
                log_for_debugging("Network infrastructure initialized")
                return context

            except Exception:
                # Clear state on error so initialization can be retried
                _manager_context = None
                await SandboxManager.reset()
                raise

        _initialization_task = asyncio.create_task(do_initialize())
        await _initialization_task

    @staticmethod
    def is_supported_platform(platform: Platform) -> bool:
        """Check if a platform is supported."""
        return platform in ("macos", "linux")

    @staticmethod
    def is_sandboxing_enabled() -> bool:
        """Check if sandboxing is enabled (config has been set)."""
        return _config is not None

    @staticmethod
    def check_dependencies(
        ripgrep_config: RipgrepConfig | None = None,
    ) -> bool:
        """
        Check if all sandbox dependencies are available.

        Args:
            ripgrep_config: Optional ripgrep configuration to check

        Returns:
            True if all dependencies are available
        """
        platform = get_platform()

        # Check platform support
        if not SandboxManager.is_supported_platform(platform):
            return False

        # Determine which ripgrep to check
        rg_to_check = ripgrep_config
        if rg_to_check is None and _config is not None and _config.ripgrep is not None:
            rg_to_check = RipgrepConfig(
                command=_config.ripgrep.command,
                args=_config.ripgrep.args,
            )

        # Check ripgrep
        has_custom_ripgrep = rg_to_check is not None and rg_to_check.command != "rg"
        if not has_custom_ripgrep:
            if not has_ripgrep_sync():
                return False

        # Platform-specific checks
        if platform == "linux":
            allow_all_unix_sockets = (_config.network.allow_all_unix_sockets if _config else False) or False
            return has_sandbox_dependencies_sync(allow_all_unix_sockets)

        # macOS only needs ripgrep
        return True

    @staticmethod
    def get_fs_read_config() -> FsReadRestrictionConfig:
        """Get the filesystem read configuration."""
        if _config is None:
            return FsReadRestrictionConfig(deny_only=[])

        # Filter out glob patterns on Linux
        deny_paths = [remove_trailing_glob_suffix(path) for path in _config.filesystem.deny_read]
        deny_paths = [path for path in deny_paths if not (get_platform() == "linux" and contains_glob_chars(path))]

        return FsReadRestrictionConfig(deny_only=deny_paths)

    @staticmethod
    def get_fs_write_config() -> FsWriteRestrictionConfig:
        """Get the filesystem write configuration."""
        if _config is None:
            return FsWriteRestrictionConfig(
                allow_only=get_default_write_paths(),
                deny_within_allow=[],
            )

        # Filter out glob patterns on Linux
        platform = get_platform()

        allow_paths = [remove_trailing_glob_suffix(path) for path in _config.filesystem.allow_write]
        allow_paths = [path for path in allow_paths if not (platform == "linux" and contains_glob_chars(path))]

        deny_paths = [remove_trailing_glob_suffix(path) for path in _config.filesystem.deny_write]
        deny_paths = [path for path in deny_paths if not (platform == "linux" and contains_glob_chars(path))]

        return FsWriteRestrictionConfig(
            allow_only=[*get_default_write_paths(), *allow_paths],
            deny_within_allow=deny_paths,
        )

    @staticmethod
    def get_network_restriction_config() -> NetworkRestrictionConfig:
        """Get the network restriction configuration."""
        if _config is None:
            return NetworkRestrictionConfig()

        allowed_hosts = _config.network.allowed_domains
        denied_hosts = _config.network.denied_domains

        return NetworkRestrictionConfig(
            allowed_hosts=allowed_hosts if allowed_hosts else None,
            denied_hosts=denied_hosts if denied_hosts else None,
        )

    @staticmethod
    def get_allow_unix_sockets() -> list[str] | None:
        """Get the list of allowed Unix sockets."""
        return _config.network.allow_unix_sockets if _config else None

    @staticmethod
    def get_allow_all_unix_sockets() -> bool | None:
        """Check if all Unix sockets are allowed."""
        return _config.network.allow_all_unix_sockets if _config else None

    @staticmethod
    def get_allow_local_binding() -> bool | None:
        """Check if local binding is allowed."""
        return _config.network.allow_local_binding if _config else None

    @staticmethod
    def get_ignore_violations() -> dict[str, list[str]] | None:
        """Get the ignore violations configuration."""
        return _config.ignore_violations if _config else None

    @staticmethod
    def get_enable_weaker_nested_sandbox() -> bool | None:
        """Check if weaker nested sandbox mode is enabled."""
        return _config.enable_weaker_nested_sandbox if _config else None

    @staticmethod
    def get_ripgrep_config() -> RipgrepConfig:
        """Get the ripgrep configuration."""
        if _config is None or _config.ripgrep is None:
            return RipgrepConfig()
        return RipgrepConfig(
            command=_config.ripgrep.command,
            args=_config.ripgrep.args,
        )

    @staticmethod
    def get_mandatory_deny_search_depth() -> int:
        """Get the mandatory deny search depth."""
        return _config.mandatory_deny_search_depth if _config and _config.mandatory_deny_search_depth else 3

    @staticmethod
    def get_allow_git_config() -> bool:
        """Check if git config writes are allowed."""
        return _config.filesystem.allow_git_config if _config and _config.filesystem.allow_git_config else False

    @staticmethod
    def get_proxy_port() -> int | None:
        """Get the HTTP proxy port."""
        return _manager_context.http_proxy_port if _manager_context else None

    @staticmethod
    def get_socks_proxy_port() -> int | None:
        """Get the SOCKS proxy port."""
        return _manager_context.socks_proxy_port if _manager_context else None

    @staticmethod
    def get_linux_http_socket_path() -> str | None:
        """Get the Linux HTTP socket path."""
        if _manager_context and _manager_context.linux_bridge:
            return _manager_context.linux_bridge.http_socket_path
        return None

    @staticmethod
    def get_linux_socks_socket_path() -> str | None:
        """Get the Linux SOCKS socket path."""
        if _manager_context and _manager_context.linux_bridge:
            return _manager_context.linux_bridge.socks_socket_path
        return None

    @staticmethod
    async def wait_for_network_initialization() -> bool:
        """Wait for network initialization to complete."""
        if _config is None:
            return False
        if _initialization_task is not None:
            try:
                await _initialization_task
                return True
            except Exception:
                return False
        return _manager_context is not None

    @staticmethod
    async def wrap_with_sandbox(
        command: str,
        bin_shell: str | None = None,
        custom_config: SandboxRuntimeConfig | None = None,
    ) -> str:
        """
        Wrap a command with sandbox restrictions.

        Args:
            command: The command to wrap
            bin_shell: Optional shell binary to use
            custom_config: Optional custom configuration to use

        Returns:
            The wrapped command string
        """
        platform = get_platform()

        # Get configs
        user_allow_write = (
            custom_config.filesystem.allow_write
            if custom_config
            else (_config.filesystem.allow_write if _config else [])
        )
        write_config = FsWriteRestrictionConfig(
            allow_only=[*get_default_write_paths(), *user_allow_write],
            deny_within_allow=(
                custom_config.filesystem.deny_write
                if custom_config
                else (_config.filesystem.deny_write if _config else [])
            ),
        )
        read_config = FsReadRestrictionConfig(
            deny_only=(
                custom_config.filesystem.deny_read
                if custom_config
                else (_config.filesystem.deny_read if _config else [])
            ),
        )

        # Check if network config is specified
        has_network_config = (custom_config is not None and custom_config.network.allowed_domains is not None) or (
            _config is not None and _config.network.allowed_domains is not None
        )

        allowed_domains = (
            custom_config.network.allowed_domains
            if custom_config and custom_config.network.allowed_domains is not None
            else (_config.network.allowed_domains if _config else [])
        )

        needs_network_restriction = has_network_config
        needs_network_proxy = len(allowed_domains) > 0

        # Wait for network initialization if proxy is needed
        if needs_network_proxy:
            await SandboxManager.wait_for_network_initialization()

        # Check custom config for pty
        allow_pty = custom_config.allow_pty if custom_config else (_config.allow_pty if _config else None)

        if platform == "macos":
            return wrap_command_macos(
                MacOSSandboxParams(
                    command=command,
                    needs_network_restriction=needs_network_restriction,
                    http_proxy_port=SandboxManager.get_proxy_port() if needs_network_proxy else None,
                    socks_proxy_port=SandboxManager.get_socks_proxy_port() if needs_network_proxy else None,
                    read_config=read_config,
                    write_config=write_config,
                    allow_unix_sockets=SandboxManager.get_allow_unix_sockets(),
                    allow_all_unix_sockets=SandboxManager.get_allow_all_unix_sockets(),
                    allow_local_binding=SandboxManager.get_allow_local_binding(),
                    ignore_violations=SandboxManager.get_ignore_violations(),
                    allow_pty=allow_pty,
                    allow_git_config=SandboxManager.get_allow_git_config(),
                    bin_shell=bin_shell,
                )
            )

        elif platform == "linux":
            return await wrap_command_linux(
                LinuxSandboxParams(
                    command=command,
                    needs_network_restriction=needs_network_restriction,
                    http_socket_path=(SandboxManager.get_linux_http_socket_path() if needs_network_proxy else None),
                    socks_socket_path=(SandboxManager.get_linux_socks_socket_path() if needs_network_proxy else None),
                    http_proxy_port=(
                        _manager_context.http_proxy_port if _manager_context and needs_network_proxy else None
                    ),
                    socks_proxy_port=(
                        _manager_context.socks_proxy_port if _manager_context and needs_network_proxy else None
                    ),
                    read_config=read_config,
                    write_config=write_config,
                    enable_weaker_nested_sandbox=SandboxManager.get_enable_weaker_nested_sandbox(),
                    allow_all_unix_sockets=SandboxManager.get_allow_all_unix_sockets(),
                    bin_shell=bin_shell,
                    ripgrep_config=SandboxManager.get_ripgrep_config(),
                    mandatory_deny_search_depth=SandboxManager.get_mandatory_deny_search_depth(),
                    allow_git_config=SandboxManager.get_allow_git_config(),
                )
            )

        else:
            raise RuntimeError(f"Sandbox configuration is not supported on platform: {platform}")

    @staticmethod
    def get_config() -> SandboxRuntimeConfig | None:
        """Get the current sandbox configuration."""
        return _config

    @staticmethod
    def update_config(new_config: SandboxRuntimeConfig) -> None:
        """Update the sandbox configuration."""
        global _config
        _config = copy.deepcopy(new_config)
        log_for_debugging("Sandbox configuration updated")

    @staticmethod
    async def reset() -> None:
        """Reset the sandbox manager and clean up resources."""
        global _config, _manager_context, _initialization_task
        global _http_proxy_server, _socks_proxy_server, _log_monitor_shutdown

        # Stop log monitor
        if _log_monitor_shutdown is not None:
            _log_monitor_shutdown()
            _log_monitor_shutdown = None

        # Clean up Linux bridge
        if _manager_context and _manager_context.linux_bridge:
            bridge = _manager_context.linux_bridge

            # Terminate bridge processes
            for proc in [bridge.http_bridge_process, bridge.socks_bridge_process]:
                if proc.returncode is None:
                    proc.terminate()
                    try:
                        await asyncio.wait_for(proc.wait(), timeout=5.0)
                    except TimeoutError:
                        proc.kill()
                        await proc.wait()

            # Clean up socket files
            for socket_path in [bridge.http_socket_path, bridge.socks_socket_path]:
                try:
                    if os.path.exists(socket_path):
                        os.remove(socket_path)
                        log_for_debugging(f"Cleaned up socket: {socket_path}")
                except OSError as e:
                    log_for_debugging(f"Socket cleanup error: {e}", level="error")

        # Stop proxy servers
        if _http_proxy_server:
            await _http_proxy_server.stop()
            _http_proxy_server = None

        if _socks_proxy_server:
            await _socks_proxy_server.stop()
            _socks_proxy_server = None

        # Clear state
        _manager_context = None
        _initialization_task = None

    @staticmethod
    def get_sandbox_violation_store() -> SandboxViolationStore:
        """Get the sandbox violation store."""
        return _sandbox_violation_store

    @staticmethod
    def annotate_stderr_with_sandbox_failures(command: str, stderr: str) -> str:
        """Annotate stderr with sandbox violations for a command."""
        if _config is None:
            return stderr

        violations = _sandbox_violation_store.get_violations_for_command(command)
        if not violations:
            return stderr

        annotated = stderr
        annotated += "\n<sandbox_violations>\n"
        for violation in violations:
            annotated += violation.line + "\n"
        annotated += "</sandbox_violations>"

        return annotated

    @staticmethod
    def get_linux_glob_pattern_warnings() -> list[str]:
        """
        Get glob patterns that are not fully supported on Linux.

        Returns empty list on macOS or when sandboxing is disabled.
        """
        if get_platform() != "linux" or _config is None:
            return []

        glob_patterns: list[str] = []

        all_paths = [
            *_config.filesystem.deny_read,
            *_config.filesystem.allow_write,
            *_config.filesystem.deny_write,
        ]

        for path in all_paths:
            # Strip trailing /** since that's just a subpath
            path_without_trailing_star = remove_trailing_glob_suffix(path)

            if contains_glob_chars(path_without_trailing_star):
                glob_patterns.append(path)

        return glob_patterns


def _register_cleanup() -> None:
    """Register cleanup handlers for graceful shutdown."""
    global _cleanup_registered

    if _cleanup_registered:
        return

    def _schedule_cleanup() -> None:
        """Schedule cleanup without assuming an active event loop."""
        try:
            loop = asyncio.get_event_loop()
        except RuntimeError:
            loop = None

        try:
            if loop and loop.is_running():
                loop.create_task(SandboxManager.reset())
            else:
                asyncio.run(SandboxManager.reset())
        except Exception as e:
            log_for_debugging(f"Cleanup failed: {e}", level="error")

    def cleanup_handler(signum: int, frame: object) -> None:
        _schedule_cleanup()

    signal.signal(signal.SIGINT, cleanup_handler)
    signal.signal(signal.SIGTERM, cleanup_handler)
    atexit.register(_schedule_cleanup)

    _cleanup_registered = True
