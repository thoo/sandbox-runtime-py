#!/usr/bin/env python3
"""CLI entrypoint for the sandbox runtime."""

import asyncio
import json
import os
import signal
import sys
from pathlib import Path

import click
from dotenv import load_dotenv

from .config import SandboxRuntimeConfig
from .manager import SandboxManager
from .utils.debug import log_for_debugging

# Load environment variables
load_dotenv()


def _get_default_config_path() -> Path:
    """Get the default config file path."""
    return Path.home() / ".srt-settings.json"


def _get_default_config() -> SandboxRuntimeConfig:
    """Create a minimal default config if no config file exists."""
    return SandboxRuntimeConfig(
        network={"allowed_domains": [], "denied_domains": []},
        filesystem={"deny_read": [], "allow_write": [], "deny_write": []},
    )


def _load_config(file_path: Path) -> SandboxRuntimeConfig | None:
    """Load and validate sandbox configuration from a file."""
    try:
        if not file_path.exists():
            return None

        content = file_path.read_text()
        if not content.strip():
            return None

        # Parse JSON
        parsed = json.loads(content)

        # Convert snake_case Python to camelCase JSON format
        # The config file uses camelCase (matching the TypeScript version)
        config_dict = {
            "network": {
                "allowed_domains": parsed.get("network", {}).get("allowedDomains", []),
                "denied_domains": parsed.get("network", {}).get("deniedDomains", []),
                "allow_unix_sockets": parsed.get("network", {}).get("allowUnixSockets"),
                "allow_all_unix_sockets": parsed.get("network", {}).get("allowAllUnixSockets"),
                "allow_local_binding": parsed.get("network", {}).get("allowLocalBinding"),
                "http_proxy_port": parsed.get("network", {}).get("httpProxyPort"),
                "socks_proxy_port": parsed.get("network", {}).get("socksProxyPort"),
            },
            "filesystem": {
                "deny_read": parsed.get("filesystem", {}).get("denyRead", []),
                "allow_write": parsed.get("filesystem", {}).get("allowWrite", []),
                "deny_write": parsed.get("filesystem", {}).get("denyWrite", []),
                "allow_git_config": parsed.get("filesystem", {}).get("allowGitConfig"),
            },
            "ignore_violations": parsed.get("ignoreViolations"),
            "enable_weaker_nested_sandbox": parsed.get("enableWeakerNestedSandbox"),
            "mandatory_deny_search_depth": parsed.get("mandatoryDenySearchDepth"),
            "allow_pty": parsed.get("allowPty"),
        }

        # Handle ripgrep config
        if "ripgrep" in parsed:
            config_dict["ripgrep"] = {
                "command": parsed["ripgrep"].get("command", "rg"),
                "args": parsed["ripgrep"].get("args"),
            }

        # Validate with Pydantic
        return SandboxRuntimeConfig(**config_dict)

    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid JSON in config file {file_path}: {e}") from e
    except Exception as e:
        raise ValueError(f"Failed to load config from {file_path}: {e}") from e


async def _run_sandboxed_command(
    command: str,
    runtime_config: SandboxRuntimeConfig,
    debug: bool,
) -> int:
    """Run a command in the sandbox and return the exit code."""
    # Enable debug logging if requested
    if debug:
        os.environ["SRT_DEBUG"] = "true"

    # Initialize sandbox
    log_for_debugging("Initializing sandbox...")
    await SandboxManager.initialize(runtime_config)

    log_for_debugging(
        json.dumps(
            {
                "allowed_hosts": SandboxManager.get_network_restriction_config().allowed_hosts,
                "denied_hosts": SandboxManager.get_network_restriction_config().denied_hosts,
            },
            indent=2,
        )
    )

    # Wrap the command
    sandboxed_command = await SandboxManager.wrap_with_sandbox(command)

    # Execute the sandboxed command while keeping the event loop alive
    process = await asyncio.create_subprocess_shell(
        sandboxed_command,
        stdin=sys.stdin,
        stdout=sys.stdout,
        stderr=sys.stderr,
    )

    # Handle signals
    def signal_handler(signum: int, frame: object) -> None:
        process.send_signal(signum)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Wait for process to complete
    try:
        return_code = await process.wait()
        return return_code if return_code is not None else 0
    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        return 1
    finally:
        await SandboxManager.reset()


@click.command(context_settings={"ignore_unknown_options": True, "allow_extra_args": True})
@click.argument("command", nargs=-1, required=False)
@click.option("-d", "--debug", is_flag=True, help="Enable debug logging")
@click.option(
    "-s",
    "--settings",
    type=click.Path(exists=False),
    help="Path to config file (default: ~/.srt-settings.json)",
)
@click.option(
    "-c",
    "command_string",
    type=str,
    help="Run command string directly (like sh -c), no escaping applied",
)
@click.version_option(package_name="sandbox-runtime")
@click.pass_context
def main(
    ctx: click.Context,
    command: tuple[str, ...],
    debug: bool,
    settings: str | None,
    command_string: str | None,
) -> None:
    """
    Run commands in a sandbox with network and filesystem restrictions.

    COMMAND: The command to run in the sandbox
    """
    try:
        # Load config
        config_path = Path(settings) if settings else _get_default_config_path()
        runtime_config = _load_config(config_path)

        if runtime_config is None:
            log_for_debugging(f"No config found at {config_path}, using default config")
            runtime_config = _get_default_config()

        # Determine command string
        if command_string:
            # -c mode: use command string directly
            cmd = command_string
            log_for_debugging(f"Command string mode (-c): {cmd}")
        else:
            cmd_args = [*command, *ctx.args]
            if not cmd_args:
                click.echo(
                    "Error: No command specified. Use -c <command> or provide command arguments.",
                    err=True,
                )
                sys.exit(1)
            # Default mode: join arguments (including unknown options)
            cmd = " ".join(cmd_args)
            log_for_debugging(f"Original command: {cmd}")

        # Run the command
        exit_code = asyncio.run(_run_sandboxed_command(cmd, runtime_config, debug))
        sys.exit(exit_code)

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
        sys.exit(1)


if __name__ == "__main__":
    main()
