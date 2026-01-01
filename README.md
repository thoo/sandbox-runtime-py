# Sandbox Runtime (Python)

This repo mirrors Anthropic's TypeScript implementation at https://github.com/anthropic-experimental/sandbox-runtime.

A Python implementation of the Sandbox Runtime - a lightweight sandboxing tool for enforcing filesystem and network restrictions on arbitrary processes at the OS level, without requiring a container.

`srt-py` uses native OS sandboxing primitives (`sandbox-exec` on macOS, `bubblewrap` on Linux) and proxy-based network filtering. It can be used to sandbox the behaviour of agents, local MCP servers, bash commands and arbitrary processes.

> **Beta Research Preview**
>
> The Sandbox Runtime is a research preview developed for [Claude Code](https://www.claude.com/product/claude-code) to enable safer AI agents. It's being made available as an early open source preview to help the broader ecosystem build more secure agentic systems.

## Installation

Install from PyPI:

```bash
# Using pip
pip install sandbox-runtime

# Using uv
uv add sandbox-runtime
```

Or install directly from GitHub:

```bash
# Using pip
pip install "sandbox-runtime @ git+https://github.com/thoo/sandbox-runtime-py.git"

# Using uv
uv add "sandbox-runtime @ git+https://github.com/thoo/sandbox-runtime-py.git"
```

For development:

```bash
git clone https://github.com/thoo/sandbox-runtime-py.git
cd sandbox-runtime-py
uv sync --all-extras
```

## Basic Usage

### CLI

#### Command Modes

- Args mode: `srt-py <cmd> [args...]` (unknown flags are passed through)
- String mode: `srt-py -c "<shell command>"`
- Invalid config files now fail fast instead of silently falling back to defaults.
- HTTPS proxying uses CONNECT tunneling; direct `https://` requests without CONNECT are rejected.

#### macOS Verification (sandbox-exec)

```bash
# Confirm sandbox-exec is available
which sandbox-exec

# Create a simple settings file
cat > /tmp/srt-settings.json <<'JSON'
{
  "network": {
    "allowedDomains": ["example.com"],
    "deniedDomains": []
  },
  "filesystem": {
    "denyRead": ["~/.ssh"],
    "allowWrite": ["."],
    "denyWrite": []
  }
}
JSON

# Network allowlist (HTTP)
srt-py --debug --settings /tmp/srt-settings.json curl -I -m 5 http://example.com

# Network allowlist (HTTPS via CONNECT)
srt-py --debug --settings /tmp/srt-settings.json curl -I -m 5 https://example.com

# Filesystem deny
srt-py --settings /tmp/srt-settings.json cat ~/.ssh/id_rsa
```

```bash
# Network restrictions
$ srt-py "curl anthropic.com"
Running: curl anthropic.com
<html>...</html>  # Request succeeds

$ srt-py "curl example.com"
Running: curl example.com
Connection blocked by network allowlist  # Request blocked

# Filesystem restrictions
$ srt-py "cat README.md"
Running: cat README.md
# Anthropic Sandb...  # Current directory access allowed

$ srt-py "cat ~/.ssh/id_rsa"
Running: cat ~/.ssh/id_rsa
cat: /Users/.../.ssh/id_rsa: Operation not permitted  # Specific file blocked

# With debug logging
$ srt-py --debug curl https://example.com

# With custom settings file
$ srt-py --settings /path/to/srt-settings.json npm install

# Flags are passed through to the command (no `--` needed)
$ srt-py curl -I https://example.com
```

### As a Library

The sandbox runtime can be used as a Python library for programmatic control over sandboxing:

```python
import asyncio
import subprocess
from sandbox_runtime import SandboxManager, SandboxRuntimeConfig

async def main():
    # Define your sandbox configuration
    config = SandboxRuntimeConfig(
        network={
            "allowed_domains": ["example.com", "api.github.com"],
            "denied_domains": [],
        },
        filesystem={
            "deny_read": ["~/.ssh"],
            "allow_write": [".", "/tmp"],
            "deny_write": [".env"],
        },
    )

    # Initialize the sandbox (starts proxy servers, etc.)
    await SandboxManager.initialize(config)

    # Wrap a command with sandbox restrictions
    sandboxed_command = await SandboxManager.wrap_with_sandbox(
        "curl https://example.com"
    )

    # Execute the sandboxed command
    process = subprocess.Popen(
        sandboxed_command,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    stdout, stderr = process.communicate()
    print(f"Exit code: {process.returncode}")
    print(f"Output: {stdout.decode()}")

    # Cleanup when done (optional, happens automatically on process exit)
    await SandboxManager.reset()

asyncio.run(main())
```

#### Advanced Library Usage

##### Custom Permission Callback

You can provide a callback to handle permission requests for domains not in the allowlist:

```python
from sandbox_runtime import SandboxManager, SandboxRuntimeConfig
from sandbox_runtime.schemas import NetworkHostPattern

async def permission_callback(request: NetworkHostPattern) -> bool:
    """Called when a request is made to a domain not in the allowlist."""
    print(f"Permission requested for {request.host}:{request.port}")
    # Implement your own logic (prompt user, check database, etc.)
    return request.host.endswith(".trusted.com")

async def main():
    config = SandboxRuntimeConfig(
        network={
            "allowed_domains": ["api.example.com"],
            "denied_domains": ["malicious.com"],
        },
        filesystem={
            "deny_read": [],
            "allow_write": ["."],
            "deny_write": [],
        },
    )

    # Pass the callback to initialize
    await SandboxManager.initialize(
        config,
        sandbox_ask_callback=permission_callback,
    )

    # ... rest of your code
```

##### Violation Tracking

Monitor sandbox violations in real-time:

```python
from sandbox_runtime import SandboxManager, SandboxViolationStore

# Get the violation store
store = SandboxManager.get_sandbox_violation_store()

# Subscribe to violation updates
def on_violation(violations):
    for v in violations:
        print(f"Violation: {v.line}")

unsubscribe = store.subscribe(on_violation)

# Get violations for a specific command
violations = store.get_violations_for_command("cat /etc/passwd")

# Get all recent violations
all_violations = store.get_violations(limit=10)

# Unsubscribe when done
unsubscribe()
```

##### Checking Dependencies

```python
from sandbox_runtime import SandboxManager

# Check if all sandbox dependencies are available
if SandboxManager.check_dependencies():
    print("Sandbox is ready")
else:
    print("Missing dependencies")

# Check platform support
from sandbox_runtime.utils.platform import get_platform

platform = get_platform()
if SandboxManager.is_supported_platform(platform):
    print(f"Platform {platform} is supported")
```

##### Getting Configuration Details

```python
from sandbox_runtime import SandboxManager

# Get filesystem configurations
read_config = SandboxManager.get_fs_read_config()
write_config = SandboxManager.get_fs_write_config()

print(f"Denied read paths: {read_config.deny_only}")
print(f"Allowed write paths: {write_config.allow_only}")
print(f"Denied write paths: {write_config.deny_within_allow}")

# Get network configuration
network_config = SandboxManager.get_network_restriction_config()
print(f"Allowed hosts: {network_config.allowed_hosts}")
print(f"Denied hosts: {network_config.denied_hosts}")

# Get proxy ports (after initialization)
http_port = SandboxManager.get_proxy_port()
socks_port = SandboxManager.get_socks_proxy_port()
```

#### Available Exports

```python
from sandbox_runtime import (
    # Main manager
    SandboxManager,

    # Configuration models (Pydantic)
    SandboxRuntimeConfig,
    NetworkConfig,
    FilesystemConfig,
    RipgrepConfig,
    IgnoreViolationsConfig,

    # Schema types
    FsReadRestrictionConfig,
    FsWriteRestrictionConfig,
    NetworkRestrictionConfig,
    NetworkHostPattern,
    SandboxAskCallback,

    # Violation tracking
    SandboxViolationStore,
    SandboxViolationEvent,

    # Utilities
    get_default_write_paths,
)
```

## Overview

This package provides a standalone sandbox implementation that can be used as both a CLI tool and a library. It's designed with a **secure-by-default** philosophy tailored for common developer use cases: processes start with minimal access, and you explicitly poke only the holes you need.

**Key capabilities:**

- **Network restrictions**: Control which hosts/domains can be accessed via HTTP/HTTPS and other protocols
- **Filesystem restrictions**: Control which files/directories can be read/written
- **Unix socket restrictions**: Control access to local IPC sockets
- **Violation monitoring**: On macOS, tap into the system's sandbox violation log store for real-time alerts

### MCP Server for Sandboxed Code Execution

This package includes a built-in MCP server (`srt-mcp-server`) that provides sandboxed code execution capabilities. It allows AI agents to execute commands in isolated environments with configurable restrictions.

#### Installing the MCP Server

The MCP server requires additional dependencies. Install with the `server` extra:

```bash
# For development (run commands with uv run)
uv sync --extra server

# For global installation (command available everywhere)
uv tool install -e ".[server]"
# Note: Add ~/.local/bin to your PATH if prompted
```

#### Starting the MCP Server

```bash
# Using uv run (recommended for development)
uv run srt-mcp-server --token mysecrettoken --port 8080

# Or if installed globally via uv tool install
srt-mcp-server --token mysecrettoken --port 8080

# Start with default settings (no auth, localhost:8080)
uv run srt-mcp-server

# Start on custom host/port with auth
uv run srt-mcp-server --host 0.0.0.0 --port 9000 --token mytoken

# Using environment variables
SANDBOX_AUTH_TOKEN=mytoken SANDBOX_PORT=9000 uv run srt-mcp-server

# View all options
uv run srt-mcp-server --help
```

#### CLI Options

| Option | Env Variable | Default | Description |
|--------|--------------|---------|-------------|
| `--token`, `-t` | `SANDBOX_AUTH_TOKEN` | None | Bearer token for authentication |
| `--host` | `SANDBOX_HOST` | `127.0.0.1` | Host to bind the server to |
| `--port`, `-p` | `SANDBOX_PORT` | `8080` | Port to bind the server to |
| `--max-concurrent` | `SANDBOX_MAX_CONCURRENT` | `10` | Max concurrent executions |
| `--max-per-session` | `SANDBOX_MAX_PER_SESSION` | `5` | Max executions per session |
| `--timeout` | `SANDBOX_TIMEOUT` | `300` | Default execution timeout (seconds) |
| `--log-file` | `SANDBOX_LOG_FILE` | None | Log file path |

#### Configuring with Claude Code

Add the server to your `.mcp.json` configuration:

```json
{
  "mcpServers": {
    "sandbox": {
      "type": "streamable-http",
      "url": "http://localhost:8080/mcp",
      "headers": {
        "Authorization": "Bearer your-secret-token"
      }
    }
  }
}
```

Or have Claude Code start the server automatically:

```json
{
  "mcpServers": {
    "sandbox": {
      "command": "uv",
      "args": ["run", "--directory", "/path/to/sandbox_runtime_py", "srt-mcp-server", "--token", "your-secret-token"]
    }
  }
}
```

If installed globally via `uv tool install`:

```json
{
  "mcpServers": {
    "sandbox": {
      "command": "srt-mcp-server",
      "args": ["--token", "your-secret-token", "--port", "8080"]
    }
  }
}
```

#### Available MCP Tools

The server exposes these tools via MCP:

- **execute_code** - Execute a command in the sandbox (sync, waits for completion)
- **execute_code_async** - Start a command without waiting (returns execution_id)
- **get_execution_output** - Get output from an execution
- **get_execution_status** - Get current status of an execution
- **send_stdin** - Send input to an interactive execution
- **cancel_execution** - Cancel a running execution
- **list_executions** - List all executions for the current session

#### Health Check

The server exposes a health check endpoint at `/health`:

```bash
curl http://localhost:8080/health
# {"status": "healthy"}
```

## How It Works

The sandbox uses OS-level primitives to enforce restrictions that apply to the entire process tree:

- **macOS**: Uses `sandbox-exec` with dynamically generated [Seatbelt profiles](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v1.0.pdf)
- **Linux**: Uses [bubblewrap](https://github.com/containers/bubblewrap) for containerization with network namespace isolation

### Dual Isolation Model

Both filesystem and network isolation are required for effective sandboxing.

**Filesystem Isolation** enforces read and write restrictions:

- **Read** (deny-only pattern): By default, read access is allowed everywhere. You can deny specific paths (e.g., `~/.ssh`). An empty deny list means full read access.
- **Write** (allow-only pattern): By default, write access is denied everywhere. You must explicitly allow paths (e.g., `.`, `/tmp`). An empty allow list means no write access.

**Network Isolation** (allow-only pattern): By default, all network access is denied. You must explicitly allow domains. An empty allowedDomains list means no network access.

## Configuration

### Settings File Location

By default, the sandbox runtime looks for configuration at `~/.srt-settings.json`. You can specify a custom path using the `--settings` flag:

```bash
srt-py --settings /path/to/srt-settings.json <command>
```

### Complete Configuration Example

```json
{
  "network": {
    "allowedDomains": [
      "github.com",
      "*.github.com",
      "api.github.com",
      "pypi.org",
      "*.pypi.org"
    ],
    "deniedDomains": ["malicious.com"],
    "allowUnixSockets": ["/var/run/docker.sock"],
    "allowLocalBinding": false
  },
  "filesystem": {
    "denyRead": ["~/.ssh"],
    "allowWrite": [".", "src/", "tests/", "/tmp"],
    "denyWrite": [".env", "config/production.json"],
    "allowGitConfig": false
  },
  "ignoreViolations": {
    "*": ["/usr/bin", "/System"],
    "git push": ["/usr/bin/nc"]
  },
  "enableWeakerNestedSandbox": false,
  "mandatoryDenySearchDepth": 3
}
```

### Configuration Options

#### Network Configuration

Uses an **allow-only pattern** - all network access is denied by default.

| Option | Type | Description |
|--------|------|-------------|
| `allowedDomains` | `list[str]` | Allowed domains (supports wildcards like `*.example.com`). Empty = no network access. |
| `deniedDomains` | `list[str]` | Denied domains (checked first, takes precedence) |
| `allowUnixSockets` | `list[str]` | Unix socket paths that can be accessed (macOS only) |
| `allowLocalBinding` | `bool` | Allow binding to local ports (default: false) |
| `httpProxyPort` | `int` | Use external HTTP proxy instead of built-in |
| `socksProxyPort` | `int` | Use external SOCKS proxy instead of built-in |

#### Filesystem Configuration

| Option | Type | Description |
|--------|------|-------------|
| `denyRead` | `list[str]` | Paths to deny read access (deny-only pattern) |
| `allowWrite` | `list[str]` | Paths to allow write access (allow-only pattern) |
| `denyWrite` | `list[str]` | Paths to deny write within allowed paths |
| `allowGitConfig` | `bool` | Allow writes to `.git/config` (default: false) |

#### Path Syntax

**macOS** supports git-style glob patterns:

- `*` - Matches any characters except `/`
- `**` - Matches any characters including `/`
- `?` - Matches any single character except `/`
- `[abc]` - Matches any character in the set

**Linux** currently does not support glob matching. Use literal paths only.

**All platforms:**

- Paths can be absolute or relative to the current working directory
- `~` expands to the user's home directory

#### Other Configuration

| Option | Type | Description |
|--------|------|-------------|
| `ignoreViolations` | `dict[str, list[str]]` | Command patterns → paths where violations are ignored |
| `enableWeakerNestedSandbox` | `bool` | Enable weaker sandbox for Docker environments |
| `mandatoryDenySearchDepth` | `int` | Search depth for dangerous files (1-10, default: 3) |
| `allowPty` | `bool` | Allow pseudo-terminal operations |

## Platform Support

| Platform | Status | Mechanism |
|----------|--------|-----------|
| macOS | Supported | `sandbox-exec` with Seatbelt profiles |
| Linux | Supported | `bubblewrap` (bwrap) |
| Windows | Not supported | - |

### Platform-Specific Dependencies

**Linux requires:**

```bash
# Ubuntu/Debian
apt-get install bubblewrap socat ripgrep

# Fedora
dnf install bubblewrap socat ripgrep

# Arch
pacman -S bubblewrap socat ripgrep
```

**macOS requires:**

```bash
# Install via Homebrew
brew install ripgrep
```

## API Reference

### SandboxManager

The main class for managing sandbox restrictions. All methods are static.

```python
class SandboxManager:
    # Initialization
    @staticmethod
    async def initialize(
        runtime_config: SandboxRuntimeConfig,
        sandbox_ask_callback: SandboxAskCallbackType | None = None,
        enable_log_monitor: bool = False,
    ) -> None: ...

    # State checking
    @staticmethod
    def is_sandboxing_enabled() -> bool: ...

    @staticmethod
    def is_supported_platform(platform: Platform) -> bool: ...

    @staticmethod
    def check_dependencies(ripgrep_config: RipgrepConfig | None = None) -> bool: ...

    # Command wrapping
    @staticmethod
    async def wrap_with_sandbox(
        command: str,
        bin_shell: str | None = None,
        custom_config: SandboxRuntimeConfig | None = None,
    ) -> str: ...

    # Configuration access
    @staticmethod
    def get_config() -> SandboxRuntimeConfig | None: ...

    @staticmethod
    def update_config(new_config: SandboxRuntimeConfig) -> None: ...

    @staticmethod
    def get_fs_read_config() -> FsReadRestrictionConfig: ...

    @staticmethod
    def get_fs_write_config() -> FsWriteRestrictionConfig: ...

    @staticmethod
    def get_network_restriction_config() -> NetworkRestrictionConfig: ...

    # Proxy information
    @staticmethod
    def get_proxy_port() -> int | None: ...

    @staticmethod
    def get_socks_proxy_port() -> int | None: ...

    # Violation tracking
    @staticmethod
    def get_sandbox_violation_store() -> SandboxViolationStore: ...

    @staticmethod
    def annotate_stderr_with_sandbox_failures(command: str, stderr: str) -> str: ...

    # Cleanup
    @staticmethod
    async def reset() -> None: ...
```

### SandboxRuntimeConfig

Pydantic model for configuration:

```python
from sandbox_runtime import SandboxRuntimeConfig, NetworkConfig, FilesystemConfig

config = SandboxRuntimeConfig(
    network=NetworkConfig(
        allowed_domains=["example.com"],
        denied_domains=[],
    ),
    # Or use dict (auto-converted)
    filesystem={
        "deny_read": ["~/.ssh"],
        "allow_write": ["."],
        "deny_write": [".env"],
    },
)

# Serialize to dict
config_dict = config.model_dump()

# Generate JSON schema
schema = SandboxRuntimeConfig.model_json_schema()
```

### SandboxViolationStore

```python
class SandboxViolationStore:
    def add_violation(self, violation: SandboxViolationEvent) -> None: ...
    def get_violations(self, limit: int | None = None) -> list[SandboxViolationEvent]: ...
    def get_violations_for_command(self, command: str) -> list[SandboxViolationEvent]: ...
    def get_count(self) -> int: ...
    def get_total_count(self) -> int: ...
    def clear(self) -> None: ...
    def subscribe(self, listener: ViolationListener) -> Callable[[], None]: ...
```

## Architecture

```
sandbox_runtime/
├── __init__.py              # Public API exports
├── cli.py                   # CLI entrypoint (srt-py command)
├── config.py                # Pydantic configuration models
├── schemas.py               # Type definitions
├── manager.py               # Main sandbox manager
├── http_proxy.py            # HTTP/HTTPS proxy (aiohttp)
├── socks_proxy.py           # SOCKS5 proxy (asyncio)
├── macos_sandbox.py         # macOS sandbox-exec utilities
├── linux_sandbox.py         # Linux bubblewrap utilities
├── seccomp.py               # Seccomp filter handling
├── sandbox_utils.py         # Shared utilities
├── violation_store.py       # Violation tracking
└── utils/
    ├── debug.py             # Debug logging
    ├── platform.py          # Platform detection
    └── ripgrep.py           # Ripgrep wrapper
```

## Development

```bash
# Install with dev dependencies
uv sync --all-extras

# Run tests
uv run pytest

# Run tests with coverage
uv run pytest --cov=sandbox_runtime

# Type checking
uv run pyright

# Linting
uv run ruff check

# Formatting
uv run ruff format

# Run all pre-commit hooks
uvx pre-commit run --all-files
```

### Building Seccomp Binaries

The pre-generated BPF filters are included in the repository, but you can rebuild them if needed. This requires Docker:

```bash
# From the parent sandbox-runtime directory
cd ..
./scripts/build-seccomp-binaries.sh
```

This script uses Docker to cross-compile seccomp binaries for multiple architectures:

- x64 (x86-64)
- arm64 (aarch64)

The script builds static generator binaries, generates the BPF filters (~104 bytes each), and stores them in `vendor/seccomp/x64/` and `vendor/seccomp/arm64/`. The generator binaries are removed to keep the package size small.

**What gets built:**

- `unix-block.bpf` - Pre-compiled BPF filter that blocks Unix domain socket creation
- `apply-seccomp` - Static binary that applies the seccomp filter and execs the user command

**Source files** (in `vendor/seccomp-src/`):

- `seccomp-unix-block.c` - Generates the BPF filter using libseccomp
- `apply-seccomp.c` - Applies the filter via `prctl(PR_SET_SECCOMP)`

**Architecture support:** x64 and arm64 are fully supported with pre-built binaries. Other architectures are not currently supported.

For more details, see the [original TypeScript implementation README](https://github.com/anthropic-experimental/sandbox-runtime/blob/main/README.md).

## Security Limitations

- **Network Sandboxing**: The network filtering operates by restricting domains. It does not inspect traffic content. Users should be aware of potential data exfiltration through allowed domains.

- **Privilege Escalation via Unix Sockets**: The `allowUnixSockets` configuration can grant access to powerful system services (e.g., Docker socket).

- **Filesystem Permission Escalation**: Overly broad write permissions can enable privilege escalation.

- **Linux Sandbox Strength**: The `enableWeakerNestedSandbox` mode considerably weakens security and should only be used in Docker environments.

## License

MIT
