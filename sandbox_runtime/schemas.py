"""Type definitions for sandbox runtime.

These are internal structures built from permission rules.
"""

from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from typing import Protocol


@dataclass
class FsReadRestrictionConfig:
    """
    Read restriction config using a "deny-only" pattern.

    Semantics:
    - None = no restrictions (allow all reads)
    - FsReadRestrictionConfig(deny_only=[]) = no restrictions (empty deny list = allow all reads)
    - FsReadRestrictionConfig(deny_only=[...paths]) = deny reads from these paths, allow all others

    This is maximally permissive by default - only explicitly denied paths are blocked.
    """

    deny_only: list[str] = field(default_factory=list)


@dataclass
class FsWriteRestrictionConfig:
    """
    Write restriction config using an "allow-only" pattern.

    Semantics:
    - None = no restrictions (allow all writes)
    - FsWriteRestrictionConfig(allow_only=[], deny_within_allow=[]) = maximally restrictive (deny ALL writes)
    - FsWriteRestrictionConfig(allow_only=[...paths], deny_within_allow=[...]) = allow writes only to these paths,
      with exceptions for deny_within_allow

    This is maximally restrictive by default - only explicitly allowed paths are writable.
    Note: Empty `allow_only` means NO paths are writable (unlike read's empty deny_only).
    """

    allow_only: list[str] = field(default_factory=list)
    deny_within_allow: list[str] = field(default_factory=list)


@dataclass
class NetworkRestrictionConfig:
    """
    Network restriction config (internal structure built from permission rules).

    This uses an "allow-only" pattern (like write restrictions):
    - `allowed_hosts` = hosts that are explicitly allowed
    - `denied_hosts` = hosts that are explicitly denied (checked first, before allowed_hosts)

    Semantics:
    - None = maximally restrictive (deny all network)
    - NetworkRestrictionConfig(allowed_hosts=[], denied_hosts=[]) = maximally restrictive (nothing allowed)
    - NetworkRestrictionConfig(allowed_hosts=[...], denied_hosts=[...]) = apply allow/deny rules

    Note: Empty `allowed_hosts` means NO hosts are allowed (unlike read's empty deny_only).
    """

    allowed_hosts: list[str] | None = None
    denied_hosts: list[str] | None = None


@dataclass
class NetworkHostPattern:
    """A host pattern for network filtering."""

    host: str
    port: int | None = None


class SandboxAskCallback(Protocol):
    """Protocol for the sandbox ask callback function."""

    def __call__(self, params: NetworkHostPattern) -> Awaitable[bool]:
        """
        Called when a network request is made to an unknown host.

        Args:
            params: The host pattern to check

        Returns:
            True if the request should be allowed, False otherwise
        """
        ...


# Type alias for the callback
SandboxAskCallbackType = Callable[[NetworkHostPattern], Awaitable[bool]]
