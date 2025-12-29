"""Configuration for Sandbox Runtime.

This is the main configuration interface that consumers pass to SandboxManager.initialize()
"""

from typing import Annotated

from pydantic import BaseModel, Field, field_validator


def _validate_domain_pattern(value: str) -> str:
    """
    Validate a domain pattern.

    Valid patterns:
    - 'localhost'
    - Regular domains like 'example.com'
    - Wildcard domains like '*.example.com' (but not '*.com' - too broad)

    Invalid patterns:
    - URLs with protocols, paths, or ports
    - Overly broad wildcards like '*' or '*.com'
    """
    # Reject protocols, paths, ports
    if "://" in value or "/" in value or ":" in value:
        raise ValueError(f"Invalid domain pattern '{value}': must not contain protocols, paths, or ports")

    # Allow localhost
    if value == "localhost":
        return value

    # Allow wildcard domains like *.example.com
    if value.startswith("*."):
        domain = value[2:]  # Remove '*.'
        # After the *. there must be a valid domain with at least one more dot
        # e.g., *.example.com is valid, *.com is not (too broad)
        if not domain or "." not in domain or domain.startswith(".") or domain.endswith("."):
            raise ValueError(
                f"Invalid wildcard domain '{value}': must have at least two parts after *. (e.g., '*.example.com')"
            )
        parts = domain.split(".")
        if len(parts) < 2 or not all(p for p in parts):
            raise ValueError(f"Invalid wildcard domain '{value}': must have at least two parts after *.")
        return value

    # Reject any other use of wildcards
    if "*" in value:
        raise ValueError(
            f"Invalid domain pattern '{value}': wildcards are only allowed at the start (e.g., '*.example.com')"
        )

    # Regular domains must have at least one dot and valid characters
    if "." not in value or value.startswith(".") or value.endswith("."):
        raise ValueError(f"Invalid domain pattern '{value}': must be a valid domain (e.g., 'example.com')")

    return value


class NetworkConfig(BaseModel):
    """Network configuration for sandbox restrictions."""

    allowed_domains: Annotated[
        list[str],
        Field(description="List of allowed domains (e.g., ['github.com', '*.npmjs.org'])"),
    ] = []

    denied_domains: Annotated[
        list[str],
        Field(description="List of denied domains"),
    ] = []

    allow_unix_sockets: Annotated[
        list[str] | None,
        Field(description="Unix socket paths that are allowed (macOS only)"),
    ] = None

    allow_all_unix_sockets: Annotated[
        bool | None,
        Field(description="Allow ALL Unix sockets (Linux only - disables Unix socket blocking)"),
    ] = None

    allow_local_binding: Annotated[
        bool | None,
        Field(description="Whether to allow binding to local ports (default: false)"),
    ] = None

    http_proxy_port: Annotated[
        int | None,
        Field(
            ge=1,
            le=65535,
            description=(
                "Port of an external HTTP proxy to use instead of starting a local one. "
                "When provided, the library will skip starting its own HTTP proxy and use this port."
            ),
        ),
    ] = None

    socks_proxy_port: Annotated[
        int | None,
        Field(
            ge=1,
            le=65535,
            description=(
                "Port of an external SOCKS proxy to use instead of starting a local one. "
                "When provided, the library will skip starting its own SOCKS proxy and use this port."
            ),
        ),
    ] = None

    @field_validator("allowed_domains", "denied_domains", mode="before")
    @classmethod
    def validate_domains(cls, v: list[str]) -> list[str]:
        """Validate all domain patterns in the list."""
        if v is None:
            return []
        return [_validate_domain_pattern(domain) for domain in v]


class FilesystemConfig(BaseModel):
    """Filesystem configuration for sandbox restrictions."""

    deny_read: Annotated[
        list[str],
        Field(description="Paths denied for reading"),
    ] = []

    allow_write: Annotated[
        list[str],
        Field(description="Paths allowed for writing"),
    ] = []

    deny_write: Annotated[
        list[str],
        Field(description="Paths denied for writing (takes precedence over allow_write)"),
    ] = []

    allow_git_config: Annotated[
        bool | None,
        Field(
            description=(
                "Allow writes to .git/config files (default: false). "
                "Enables git remote URL updates while keeping .git/hooks protected."
            )
        ),
    ] = None

    @field_validator("deny_read", "allow_write", "deny_write", mode="before")
    @classmethod
    def validate_paths(cls, v: list[str]) -> list[str]:
        """Ensure paths are non-empty strings."""
        if v is None:
            return []
        for path in v:
            if not path or not isinstance(path, str):
                raise ValueError("Path cannot be empty")
        return v


class RipgrepConfig(BaseModel):
    """Ripgrep configuration."""

    command: Annotated[
        str,
        Field(description="The ripgrep command to execute (e.g., 'rg', 'claude')"),
    ] = "rg"

    args: Annotated[
        list[str] | None,
        Field(description="Additional arguments to pass before ripgrep args"),
    ] = None


# Type alias for ignore violations config
IgnoreViolationsConfig = dict[str, list[str]]


class SandboxRuntimeConfig(BaseModel):
    """Main configuration for Sandbox Runtime."""

    network: Annotated[
        NetworkConfig,
        Field(description="Network restrictions configuration"),
    ]

    filesystem: Annotated[
        FilesystemConfig,
        Field(description="Filesystem restrictions configuration"),
    ]

    ignore_violations: Annotated[
        IgnoreViolationsConfig | None,
        Field(
            description=(
                "Map of command patterns to filesystem paths to ignore violations for. Use '*' to match all commands"
            )
        ),
    ] = None

    enable_weaker_nested_sandbox: Annotated[
        bool | None,
        Field(description="Enable weaker nested sandbox mode (for Docker environments)"),
    ] = None

    ripgrep: Annotated[
        RipgrepConfig | None,
        Field(description="Custom ripgrep configuration (default: { command: 'rg' })"),
    ] = None

    mandatory_deny_search_depth: Annotated[
        int | None,
        Field(
            ge=1,
            le=10,
            description=(
                "Maximum directory depth to search for dangerous files on Linux (default: 3). "
                "Higher values provide more protection but slower performance."
            ),
        ),
    ] = None

    allow_pty: Annotated[
        bool | None,
        Field(description="Allow pseudo-terminal (pty) operations (macOS only)"),
    ] = None

    model_config = {"extra": "forbid"}
