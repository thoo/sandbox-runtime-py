#!/usr/bin/env python3
"""
Sandbox runner subprocess.

Runs commands in an isolated sandbox and streams output as JSON events.
Designed to be spawned as a subprocess to isolate SandboxManager's global state.

Usage:
    echo '{"command": "echo hello"}' | python -m sandbox_runtime.runner

Protocol:
    - Input: Single JSON config line on stdin
    - Output: JSON event lines on stdout
    - Interactive: Additional JSON stdin commands after ready event

Event types:
    - ready: Sandbox initialized, command starting
    - stdout: Line from command's stdout
    - stderr: Line from command's stderr
    - exit: Command completed with exit code
    - timeout: Command exceeded timeout
    - error: Runner encountered an error
    - cancelled: Execution was cancelled (SIGTERM/SIGINT)
"""

import asyncio
import json
import os
import resource
import signal
import sys
import time
from dataclasses import dataclass, field

from .config import ResourceLimitsConfig, SandboxRuntimeConfig
from .manager import SandboxManager


@dataclass
class RunnerConfig:
    """Configuration for the runner subprocess."""

    command: str
    timeout_seconds: int = 60
    interactive: bool = False
    working_directory: str | None = None
    environment: dict[str, str] | None = field(default_factory=dict)
    sandbox_config: dict | None = None


def emit(event_type: str, **kwargs) -> None:
    """Emit a JSON event to stdout."""
    event = {"type": event_type, "ts": time.time(), **kwargs}
    print(json.dumps(event), flush=True)


# Signal numbers for resource limit violations
SIGXCPU = 24  # CPU time limit exceeded
SIGXFSZ = 25  # File size limit exceeded


def get_resource_violation_reason(return_code: int | None) -> str | None:
    """Check if the return code indicates a resource limit violation.

    Returns a human-readable reason or None if not a resource violation.
    """
    if return_code is None:
        return None

    # Negative return codes indicate the process was killed by a signal
    # The signal number is -return_code
    if return_code < 0:
        signal_num = -return_code
        if signal_num == SIGXCPU:
            return "CPU time limit exceeded"
        if signal_num == SIGXFSZ:
            return "File size limit exceeded"
        # SIGKILL can indicate memory limit (OOM killer)
        if signal_num == 9:  # SIGKILL
            return "Process killed (possibly memory limit exceeded)"

    # Some systems use 128 + signal_num as exit code
    if return_code > 128:
        signal_num = return_code - 128
        if signal_num == SIGXCPU:
            return "CPU time limit exceeded"
        if signal_num == SIGXFSZ:
            return "File size limit exceeded"

    return None


async def read_stdin_commands(process: asyncio.subprocess.Process) -> None:
    """Read stdin commands from parent and forward to child process."""
    loop = asyncio.get_event_loop()
    reader = asyncio.StreamReader()
    protocol = asyncio.StreamReaderProtocol(reader)

    try:
        await loop.connect_read_pipe(lambda: protocol, sys.stdin)
    except Exception:
        # stdin might not be available (e.g., when running in certain contexts)
        return

    while True:
        try:
            line = await reader.readline()
            if not line:
                break

            cmd = json.loads(line.decode())
            if cmd.get("type") == "stdin" and process.stdin:
                data = cmd.get("data", "")
                process.stdin.write(data.encode())
                await process.stdin.drain()
        except json.JSONDecodeError:
            # Ignore malformed JSON
            continue
        except (BrokenPipeError, ConnectionResetError):
            break
        except Exception:
            # Don't crash on stdin errors
            break


async def stream_output(
    stream: asyncio.StreamReader,
    event_type: str,
) -> None:
    """Stream lines from a subprocess stream as events."""
    while True:
        line = await stream.readline()
        if not line:
            break
        emit(event_type, data=line.decode(errors="replace"))


def get_default_sandbox_config() -> SandboxRuntimeConfig:
    """Create a minimal default sandbox config."""
    return SandboxRuntimeConfig(
        network={"allowed_domains": [], "denied_domains": []},
        filesystem={"deny_read": [], "allow_write": [], "deny_write": []},
    )


def create_resource_limiter(limits: ResourceLimitsConfig | None):
    """Create a preexec_fn that applies resource limits to the subprocess.

    This function is called after fork() but before exec() in the child process.
    """
    if limits is None:
        return None

    def set_limits() -> None:
        # Memory limit (virtual address space)
        if limits.max_memory_mb is not None:
            max_bytes = limits.max_memory_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (max_bytes, max_bytes))

        # CPU time limit
        if limits.max_cpu_seconds is not None:
            resource.setrlimit(resource.RLIMIT_CPU, (limits.max_cpu_seconds, limits.max_cpu_seconds))

        # File size limit
        if limits.max_file_size_mb is not None:
            max_bytes = limits.max_file_size_mb * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_FSIZE, (max_bytes, max_bytes))

        # Process limit
        if limits.max_processes is not None:
            resource.setrlimit(resource.RLIMIT_NPROC, (limits.max_processes, limits.max_processes))

    return set_limits


async def run(config: RunnerConfig) -> int:
    """Run a command in the sandbox."""
    start_time = time.time()

    # Build sandbox config
    if config.sandbox_config:
        try:
            sandbox_config = SandboxRuntimeConfig(**config.sandbox_config)
        except Exception as e:
            emit("error", message=f"Invalid sandbox config: {e}")
            return 1
    else:
        sandbox_config = get_default_sandbox_config()

    # Initialize sandbox
    try:
        await SandboxManager.initialize(sandbox_config)
    except Exception as e:
        emit("error", message=f"Failed to initialize sandbox: {e}")
        return 1

    try:
        # Wrap command with sandbox restrictions
        wrapped_command = await SandboxManager.wrap_with_sandbox(config.command)

        # Prepare environment
        env = os.environ.copy()
        if config.environment:
            env.update(config.environment)

        # Create resource limiter if limits are configured
        resource_limiter = create_resource_limiter(sandbox_config.resource_limits)

        # Start process
        process = await asyncio.create_subprocess_shell(
            wrapped_command,
            stdin=asyncio.subprocess.PIPE if config.interactive else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=config.working_directory,
            env=env,
            preexec_fn=resource_limiter,
        )

        emit("ready")

        # Set up signal handlers for graceful cancellation
        cancelled = False

        def handle_signal(signum: int, frame: object) -> None:
            nonlocal cancelled
            cancelled = True
            try:
                process.terminate()
            except ProcessLookupError:
                pass

        original_sigterm = signal.signal(signal.SIGTERM, handle_signal)
        original_sigint = signal.signal(signal.SIGINT, handle_signal)

        try:
            # Create streaming tasks for stdout/stderr
            stdout_task = asyncio.create_task(stream_output(process.stdout, "stdout"))
            stderr_task = asyncio.create_task(stream_output(process.stderr, "stderr"))

            # Create stdin task if interactive (will be cancelled when process exits)
            stdin_task = None
            if config.interactive:
                stdin_task = asyncio.create_task(read_stdin_commands(process))

            # Wait with timeout
            try:
                # Wait for process to exit
                await asyncio.wait_for(process.wait(), timeout=config.timeout_seconds)

                # Cancel stdin task since process has exited
                if stdin_task:
                    stdin_task.cancel()
                    try:
                        await stdin_task
                    except asyncio.CancelledError:
                        pass

                # Wait for output streams to drain
                await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

                if cancelled:
                    emit("cancelled")
                    duration_ms = int((time.time() - start_time) * 1000)
                    emit("exit", code=process.returncode, duration_ms=duration_ms)
                    return 130  # Standard cancellation exit code

                duration_ms = int((time.time() - start_time) * 1000)

                # Check for resource limit violations
                resource_violation = get_resource_violation_reason(process.returncode)
                if resource_violation:
                    emit("resource_limit", reason=resource_violation)

                emit("exit", code=process.returncode, duration_ms=duration_ms)
                return process.returncode or 0

            except TimeoutError:
                # Cancel all tasks
                if stdin_task:
                    stdin_task.cancel()
                stdout_task.cancel()
                stderr_task.cancel()

                process.kill()
                try:
                    await asyncio.wait_for(process.wait(), timeout=5.0)
                except TimeoutError:
                    pass
                await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)
                if stdin_task:
                    try:
                        await stdin_task
                    except asyncio.CancelledError:
                        pass
                emit("timeout", timeout_seconds=config.timeout_seconds)
                duration_ms = int((time.time() - start_time) * 1000)
                emit("exit", code=process.returncode, duration_ms=duration_ms)
                return 124  # Standard timeout exit code

        finally:
            # Restore signal handlers
            signal.signal(signal.SIGTERM, original_sigterm)
            signal.signal(signal.SIGINT, original_sigint)

    except Exception as e:
        emit("error", message=str(e))
        return 1

    finally:
        await SandboxManager.reset()


async def main() -> int:
    """Entry point for the runner subprocess."""
    # Read config from stdin (first line only)
    try:
        config_line = sys.stdin.readline()
        if not config_line.strip():
            emit("error", message="No config provided on stdin")
            return 1

        config_dict = json.loads(config_line)

        # Extract only known fields
        known_fields = set(RunnerConfig.__dataclass_fields__)
        filtered_config = {k: v for k, v in config_dict.items() if k in known_fields}

        config = RunnerConfig(**filtered_config)

    except json.JSONDecodeError as e:
        emit("error", message=f"Invalid JSON config: {e}")
        return 1
    except TypeError as e:
        emit("error", message=f"Invalid config fields: {e}")
        return 1

    return await run(config)


def cli_main() -> None:
    """CLI entry point."""
    exit_code = asyncio.run(main())
    sys.exit(exit_code)


if __name__ == "__main__":
    cli_main()
