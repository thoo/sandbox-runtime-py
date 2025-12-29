"""Shared fixtures for sandbox_runtime tests."""

import tempfile
from collections.abc import AsyncGenerator, Generator
from pathlib import Path

import pytest

from sandbox_runtime.config import (
    FilesystemConfig,
    NetworkConfig,
    SandboxRuntimeConfig,
)
from sandbox_runtime.manager import SandboxManager
from sandbox_runtime.violation_store import SandboxViolationStore


@pytest.fixture
def temp_dir() -> Generator[Path, None, None]:
    """Create a temporary directory for tests."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_network_config() -> NetworkConfig:
    """Create a sample network configuration."""
    return NetworkConfig(
        allowed_domains=["example.com", "*.github.com", "api.anthropic.com"],
        denied_domains=["malicious.com", "*.bad-domain.org"],
    )


@pytest.fixture
def sample_filesystem_config(temp_dir: Path) -> FilesystemConfig:
    """Create a sample filesystem configuration."""
    return FilesystemConfig(
        deny_read=["~/.ssh", "~/.aws/credentials"],
        allow_write=[str(temp_dir), "/tmp"],
        deny_write=[".env", "*.secret"],
    )


@pytest.fixture
def sample_config(
    sample_network_config: NetworkConfig,
    sample_filesystem_config: FilesystemConfig,
) -> SandboxRuntimeConfig:
    """Create a sample sandbox runtime configuration."""
    return SandboxRuntimeConfig(
        network=sample_network_config.model_dump(),
        filesystem=sample_filesystem_config.model_dump(),
    )


@pytest.fixture
def minimal_config() -> SandboxRuntimeConfig:
    """Create a minimal sandbox runtime configuration."""
    return SandboxRuntimeConfig(
        network={"allowed_domains": [], "denied_domains": []},
        filesystem={"deny_read": [], "allow_write": [], "deny_write": []},
    )


@pytest.fixture
def violation_store() -> SandboxViolationStore:
    """Create a fresh violation store."""
    return SandboxViolationStore(max_size=100)


@pytest.fixture
async def initialized_manager(
    minimal_config: SandboxRuntimeConfig,
) -> AsyncGenerator[type[SandboxManager], None]:
    """Initialize and yield SandboxManager, then reset."""
    await SandboxManager.initialize(minimal_config)
    try:
        yield SandboxManager
    finally:
        await SandboxManager.reset()


@pytest.fixture
def sample_settings_json(temp_dir: Path) -> Path:
    """Create a sample settings JSON file."""
    settings_path = temp_dir / "srt-settings.json"
    settings_path.write_text(
        """{
  "network": {
    "allowedDomains": ["example.com", "*.github.com"],
    "deniedDomains": ["malicious.com"]
  },
  "filesystem": {
    "denyRead": ["~/.ssh"],
    "allowWrite": [".", "/tmp"],
    "denyWrite": [".env"]
  }
}"""
    )
    return settings_path
