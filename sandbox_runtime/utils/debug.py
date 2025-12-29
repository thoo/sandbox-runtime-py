"""Simple debug logging for standalone sandbox."""

import os
import sys
from typing import Literal


def log_for_debugging(
    message: str,
    *,
    level: Literal["info", "error", "warn"] = "info",
) -> None:
    """
    Log a debug message if SRT_DEBUG environment variable is set.

    Uses SRT_DEBUG instead of DEBUG to avoid conflicts with other tools
    (DEBUG is commonly used by various debug libraries).

    Args:
        message: The message to log
        level: The log level (info, error, warn)
    """
    if not os.environ.get("SRT_DEBUG"):
        return

    prefix = "[SandboxDebug]"

    # Always use stderr to avoid corrupting stdout JSON streams
    if level == "error":
        print(f"{prefix} {message}", file=sys.stderr)
    elif level == "warn":
        print(f"{prefix} {message}", file=sys.stderr)
    else:
        print(f"{prefix} {message}", file=sys.stderr)
