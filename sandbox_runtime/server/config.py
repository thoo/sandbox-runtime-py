"""Configuration for the MCP sandbox server."""

from dataclasses import dataclass, field

from ..config import SandboxRuntimeConfig


@dataclass
class ServerConfig:
    """Configuration for the MCP sandbox server."""

    host: str = "127.0.0.1"
    port: int = 8080
    max_concurrent_executions: int = 10
    max_executions_per_session: int = 5
    execution_timeout_seconds: int = 300
    output_buffer_size: int = 10000  # lines to buffer for reconnection
    default_sandbox_config: SandboxRuntimeConfig | None = field(default=None)
    auth_token: str | None = None  # Bearer token for authorization (disabled if None)

    def __post_init__(self) -> None:
        if self.default_sandbox_config is None:
            self.default_sandbox_config = SandboxRuntimeConfig(
                network={"allowed_domains": [], "denied_domains": []},
                filesystem={"deny_read": [], "allow_write": [], "deny_write": []},
            )
