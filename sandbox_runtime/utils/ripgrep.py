"""Ripgrep wrapper for file scanning."""

import asyncio
import shutil
from dataclasses import dataclass


@dataclass
class RipgrepConfig:
    """Configuration for ripgrep execution."""

    command: str = "rg"
    args: list[str] | None = None


def has_ripgrep_sync() -> bool:
    """
    Check if ripgrep (rg) is available synchronously.

    Returns:
        True if rg is installed, False otherwise
    """
    return shutil.which("rg") is not None


async def ripgrep(
    args: list[str],
    target: str,
    config: RipgrepConfig | None = None,
    timeout: float = 10.0,
) -> list[str]:
    """
    Execute ripgrep with the given arguments.

    Args:
        args: Command-line arguments to pass to rg
        target: Target directory or file to search
        config: Ripgrep configuration (command and optional args)
        timeout: Timeout in seconds (default: 10)

    Returns:
        Array of matching lines (one per line of output)

    Raises:
        RuntimeError: If ripgrep exits with non-zero status (except exit code 1 which means no matches)
        asyncio.TimeoutError: If the operation times out
    """
    if config is None:
        config = RipgrepConfig()

    cmd = [config.command]
    if config.args:
        cmd.extend(config.args)
    cmd.extend(args)
    cmd.append(target)

    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except TimeoutError:
            proc.kill()
            await proc.wait()
            raise

        # Exit code 0: success with matches
        if proc.returncode == 0:
            return [line for line in stdout.decode().strip().split("\n") if line]

        # Exit code 1: no matches found - this is normal, return empty array
        if proc.returncode == 1:
            return []

        # All other exit codes are errors
        error_msg = stderr.decode() if stderr else f"exit code {proc.returncode}"
        raise RuntimeError(f"ripgrep failed: {error_msg}")

    except FileNotFoundError:
        raise RuntimeError(f"ripgrep command not found: {config.command}")
