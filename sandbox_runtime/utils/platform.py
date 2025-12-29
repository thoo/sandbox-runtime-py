"""Platform detection utilities."""

import sys
from typing import Literal

Platform = Literal["macos", "linux", "windows", "unknown"]


def get_platform() -> Platform:
    """
    Detect the current platform.

    Returns:
        The platform identifier: 'macos', 'linux', 'windows', or 'unknown'
    """
    if sys.platform == "darwin":
        return "macos"
    elif sys.platform == "linux":
        return "linux"
    elif sys.platform == "win32":
        return "windows"
    else:
        return "unknown"
