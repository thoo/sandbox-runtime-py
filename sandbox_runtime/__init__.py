"""Anthropic Sandbox Runtime - Python implementation.

A lightweight sandboxing tool for enforcing filesystem and network restrictions
on arbitrary processes at the OS level, without requiring a container.
"""

from .config import (
    FilesystemConfig,
    IgnoreViolationsConfig,
    NetworkConfig,
    RipgrepConfig,
    SandboxRuntimeConfig,
)
from .macos_sandbox import SandboxViolationEvent
from .manager import SandboxManager
from .runner import RunnerConfig
from .sandbox_utils import get_default_write_paths
from .schemas import (
    FsReadRestrictionConfig,
    FsWriteRestrictionConfig,
    NetworkHostPattern,
    NetworkRestrictionConfig,
    SandboxAskCallback,
)
from .violation_store import SandboxViolationStore

__version__ = "0.1.0"

__all__ = [
    # Main manager
    "SandboxManager",
    # Runner
    "RunnerConfig",
    # Configuration
    "SandboxRuntimeConfig",
    "NetworkConfig",
    "FilesystemConfig",
    "RipgrepConfig",
    "IgnoreViolationsConfig",
    # Schemas
    "FsReadRestrictionConfig",
    "FsWriteRestrictionConfig",
    "NetworkRestrictionConfig",
    "NetworkHostPattern",
    "SandboxAskCallback",
    # Violation tracking
    "SandboxViolationStore",
    "SandboxViolationEvent",
    # Utilities
    "get_default_write_paths",
    # Version
    "__version__",
]
