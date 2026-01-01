# Sandbox MCP Server

An MCP (Model Context Protocol) server that provides sandboxed code execution with streaming output. Built on FastMCP with Streamable HTTP transport.

## Architecture

```mermaid
flowchart TB
    subgraph Client["MCP Client (Claude Agent SDK)"]
        A[Agent]
    end

    subgraph Server["Sandbox MCP Server"]
        B[FastMCP<br/>Streamable HTTP]
        C[ExecutionManager]

        subgraph Sessions["Session Management"]
            S1[Session 1<br/>UUID: abc-123]
            S2[Session 2<br/>UUID: def-456]
        end
    end

    subgraph Runners["Runner Subprocesses"]
        R1[Runner 1<br/>SandboxManager]
        R2[Runner 2<br/>SandboxManager]
        R3[Runner N<br/>SandboxManager]
    end

    subgraph Sandbox["OS-Level Sandbox"]
        direction LR
        M1[macOS: sandbox-exec]
        M2[Linux: bubblewrap]
    end

    A <-->|MCP Streamable HTTP| B
    B --> C
    C --> S1
    C --> S2
    S1 --> R1
    S1 --> R2
    S2 --> R3
    R1 --> Sandbox
    R2 --> Sandbox
    R3 --> Sandbox
```

## Key Components

```mermaid
classDiagram
    class FastMCP {
        +tool() decorator
        +streamable_http_app()
        +lifespan context
    }

    class ExecutionManager {
        +create_execution()
        +send_stdin()
        +cancel_execution()
        +list_executions()
        +cleanup_session()
    }

    class Execution {
        +info: ExecutionInfo
        +runner: RunnerProcess
        +output_buffer: list
        +stream() AsyncIterator
    }

    class RunnerProcess {
        +spawn() classmethod
        +read_events() AsyncIterator
        +send_stdin()
        +terminate()
    }

    class ServerConfig {
        +host: str
        +port: int
        +max_concurrent_executions: int
        +execution_timeout_seconds: int
    }

    FastMCP --> ExecutionManager : lifespan context
    ExecutionManager --> Execution : manages
    Execution --> RunnerProcess : spawns
    ExecutionManager --> ServerConfig : uses
```

## Installation

```bash
# Install with server dependencies
uv sync --extra server

# Or with pip
pip install sandbox-runtime[server]
```

## Quick Start

### Start the Server

```bash
# Default: localhost:8080
srt-mcp-server

# Custom port
SANDBOX_PORT=9000 srt-mcp-server

# All options via environment
SANDBOX_HOST=0.0.0.0 \
SANDBOX_PORT=8080 \
SANDBOX_MAX_CONCURRENT=20 \
SANDBOX_MAX_PER_SESSION=10 \
SANDBOX_TIMEOUT=300 \
srt-mcp-server
```

### Connect with MCP Client

```python
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async with streamablehttp_client("http://localhost:8080/mcp") as (read, write, _):
    async with ClientSession(read, write) as session:
        await session.initialize()

        # Execute code
        result = await session.call_tool(
            "execute_code",
            arguments={"command": "echo hello world"}
        )
        print(result)
```

## Tools

### execute_code

Execute a command and wait for completion.

```json
{
  "name": "execute_code",
  "arguments": {
    "command": "echo hello && sleep 1 && echo done",
    "timeout_seconds": 60,
    "interactive": false,
    "working_directory": "/tmp",
    "environment": {"FOO": "bar"},
    "sandbox_config": {
      "network": {"allowed_domains": ["example.com"]},
      "filesystem": {"allow_write": ["/tmp"]}
    },
    "wait_for_completion": true
  }
}
```

**Response:**
```json
{
  "execution_id": "f878c87e-d3e4-4afe-b9fd-996b3c4f8d12",
  "status": "completed",
  "exit_code": 0,
  "output": [
    {"type": "ready", "ts": 1735550000.1},
    {"type": "stdout", "data": "hello", "ts": 1735550000.2},
    {"type": "stdout", "data": "done", "ts": 1735550001.2},
    {"type": "exit", "code": 0, "duration_ms": 1100, "ts": 1735550001.3}
  ]
}
```

### execute_code_async

Start a command without waiting (for long-running tasks).

```json
{
  "name": "execute_code_async",
  "arguments": {
    "command": "sleep 60 && echo finished"
  }
}
```

**Response:**
```json
{
  "execution_id": "abc-123",
  "status": "running"
}
```

### get_execution_output

Retrieve output from an execution.

```json
{
  "name": "get_execution_output",
  "arguments": {
    "execution_id": "abc-123",
    "wait": true
  }
}
```

### send_stdin

Send input to an interactive execution.

```json
{
  "name": "send_stdin",
  "arguments": {
    "execution_id": "abc-123",
    "input_data": "user input\n"
  }
}
```

### cancel_execution

Cancel a running execution.

```json
{
  "name": "cancel_execution",
  "arguments": {
    "execution_id": "abc-123",
    "force": false
  }
}
```

### list_executions

List all executions for the current session.

```json
{
  "name": "list_executions",
  "arguments": {}
}
```

### get_execution_status

Get detailed status of an execution.

```json
{
  "name": "get_execution_status",
  "arguments": {
    "execution_id": "abc-123"
  }
}
```

## Execution Flow

```mermaid
sequenceDiagram
    participant C as MCP Client
    participant S as MCP Server
    participant E as ExecutionManager
    participant R as Runner Process
    participant B as Sandboxed Command<br/>(subprocess)

    C->>S: POST /mcp (initialize)
    S->>C: capabilities, session_id

    C->>S: tools/call: execute_code
    S->>E: create_execution()
    E->>R: spawn Runner subprocess
    Note over R: Runner Process (runner.py)
    R->>R: SandboxManager.initialize()
    R->>R: wrap_with_sandbox(cmd)
    R->>B: spawn sandboxed subprocess
    Note over B: sandbox-exec [user command]

    loop Stream Output
        B-->>R: process.stdout/stderr<br/>(subprocess pipes)
        Note over R: stream_output() reads<br/>from subprocess pipes
        R-->>E: JSON events<br/>(via Runner's stdout)
        Note over E: read_events() reads<br/>JSON from Runner stdout
        E-->>E: buffer output
    end

    B-->>R: subprocess exit
    R-->>E: exit event (JSON)
    E-->>S: execution complete
    S-->>C: result with output
```

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `SANDBOX_HOST` | `127.0.0.1` | Server bind address |
| `SANDBOX_PORT` | `8080` | Server port |
| `SANDBOX_MAX_CONCURRENT` | `10` | Max concurrent executions (global) |
| `SANDBOX_MAX_PER_SESSION` | `5` | Max concurrent executions per session |
| `SANDBOX_TIMEOUT` | `300` | Default execution timeout (seconds) |
| `SANDBOX_AUTH_TOKEN` | *(none)* | Bearer token for authorization (disabled if not set) |
| `SANDBOX_LOG_FILE` | `sandbox_server.log` | Log file path (set empty to disable file logging) |

### Sandbox Configuration

Each execution can override sandbox settings:

```python
sandbox_config = {
    "network": {
        "allowed_domains": ["api.github.com", "*.example.com"],
        "denied_domains": ["evil.com"],
    },
    "filesystem": {
        "deny_read": ["~/.ssh", "~/.aws"],
        "allow_write": ["/tmp", "."],
        "deny_write": [".env", "*.key"],
    },
    "resource_limits": {
        "max_memory_mb": 512,        # Max 512MB memory
        "max_cpu_seconds": 30,       # Max 30 seconds CPU time
        "max_file_size_mb": 100,     # Max 100MB file size
        "max_processes": 10,         # Max 10 child processes
    },
}
```

### Resource Limits

Resource limits enforce constraints on sandboxed processes:

| Limit | Description | Signal on Violation |
|-------|-------------|---------------------|
| `max_memory_mb` | Virtual address space limit | SIGKILL (OOM) |
| `max_cpu_seconds` | CPU time limit | SIGXCPU |
| `max_file_size_mb` | Maximum file size | SIGXFSZ |
| `max_processes` | Maximum child processes | Fork fails |

When a resource limit is exceeded, a `resource_limit` event is emitted before the `exit` event:

```json
{"type": "resource_limit", "reason": "CPU time limit exceeded", "ts": 1735550000.5}
{"type": "exit", "code": -24, "duration_ms": 30500, "ts": 1735550000.5}
```

## Session Management

```mermaid
stateDiagram-v2
    [*] --> Connected: MCP Initialize
    Connected --> Active: First tool call
    Active --> Active: Tool calls
    Active --> Cleanup: Session timeout
    Active --> Cleanup: DELETE /mcp
    Cleanup --> [*]: Executions terminated

    state Active {
        [*] --> Idle
        Idle --> Running: execute_code
        Running --> Idle: completed
        Running --> Cancelled: cancel_execution
        Cancelled --> Idle
    }
```

- Each MCP session gets a unique UUID
- Executions are isolated per session
- Session cleanup terminates all running executions
- Output is buffered for reconnection scenarios

## Output Events

| Event Type | Description | Fields |
|------------|-------------|--------|
| `ready` | Sandbox initialized | `ts` |
| `stdout` | Standard output line | `data`, `ts` |
| `stderr` | Standard error line | `data`, `ts` |
| `exit` | Command completed | `code`, `duration_ms`, `ts` |
| `timeout` | Execution timed out | `timeout_seconds`, `ts` |
| `error` | Runner error | `message`, `ts` |
| `cancelled` | Execution cancelled | `ts` |

## Authentication

The server supports optional Bearer token authentication via the `SANDBOX_AUTH_TOKEN` environment variable.

### Enable Authentication

```bash
# Generate a secure token
export SANDBOX_AUTH_TOKEN=$(openssl rand -hex 32)

# Start server with auth enabled
srt-mcp-server
```

### Client Configuration

When authentication is enabled, clients must include the `Authorization` header:

```python
from mcp.client.streamable_http import streamablehttp_client

headers = {"Authorization": f"Bearer {auth_token}"}
async with streamablehttp_client("http://localhost:8080/mcp", headers=headers) as (read, write, _):
    # ...
```

### Health Check Endpoint

The `/health` endpoint is always accessible without authentication for load balancer health checks:

```bash
curl http://localhost:8080/health
# {"status": "healthy"}
```

## Security Considerations

1. **Enable authentication** in production (`SANDBOX_AUTH_TOKEN`)
2. **Bind to localhost** in development (`SANDBOX_HOST=127.0.0.1`)
3. **Use TLS** in production (reverse proxy recommended)
4. **Validate working_directory** against allowlist if exposing externally
5. **Rate limit** via `SANDBOX_MAX_PER_SESSION`
6. **Timeout protection** via `SANDBOX_TIMEOUT`

## Example: Claude Agent Integration

```python
import asyncio
from anthropic import Anthropic
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client

async def run_agent():
    async with streamablehttp_client("http://localhost:8080/mcp") as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # List available tools
            tools = await session.list_tools()
            print(f"Available: {[t.name for t in tools.tools]}")

            # Run Python code
            result = await session.call_tool(
                "execute_code",
                arguments={
                    "command": "python -c 'print(sum(range(100)))'",
                    "timeout_seconds": 30,
                }
            )

            # Parse output
            import json
            output = json.loads(result.content[0].text)
            for event in output.get("output", []):
                if event["type"] == "stdout":
                    print(f"Output: {event['data']}")

asyncio.run(run_agent())
```

## Claude Code Integration

Connect the Sandbox MCP Server to [Claude Code](https://claude.ai/code) for sandboxed code execution directly from the CLI.

### Quick Setup (Recommended)

Use the `/setup-sandbox-mcp` slash command in Claude Code:

```
/setup-sandbox-mcp
```

This interactive command will:
- Ask whether to enable or disable the connection
- Choose between local (project) or user (global) scope
- Auto-generate or manually set an authentication token
- Configure everything automatically

### Manual Setup

#### 1. Start the MCP Server

```bash
# Generate and set auth token
export SANDBOX_AUTH_TOKEN=$(uv run python -c "import secrets; print(secrets.token_urlsafe(32))")
echo "Token: $SANDBOX_AUTH_TOKEN"

# Start server
uv run python -m sandbox_runtime.server.mcp_server
```

#### 2. Add to Claude Code

```bash
# Local scope (current project only)
claude mcp add --transport http sandbox http://127.0.0.1:8080/mcp \
  --header "Authorization: Bearer YOUR_TOKEN_HERE"

# User scope (all projects)
claude mcp add --transport http sandbox http://127.0.0.1:8080/mcp \
  --header "Authorization: Bearer YOUR_TOKEN_HERE" \
  --scope user
```

#### 3. Restart Claude Code

```bash
claude
```

#### 4. Verify Connection

```
/mcp
```

You should see `sandbox` listed as a connected server.

### Available Tools in Claude Code

Once connected, Claude Code can use these sandbox tools:

| Tool | Description |
|------|-------------|
| `mcp__sandbox__execute_code` | Execute commands and wait for completion |
| `mcp__sandbox__execute_code_async` | Start long-running commands without waiting |
| `mcp__sandbox__list_executions` | List all executions in the session |
| `mcp__sandbox__get_execution_status` | Check status of an execution |
| `mcp__sandbox__get_execution_output` | Retrieve output from an execution |
| `mcp__sandbox__send_stdin` | Send input to interactive processes |
| `mcp__sandbox__cancel_execution` | Cancel a running execution |

### Example Usage in Claude Code

Ask Claude Code to use the sandbox:

```
Use the sandbox to run: python -c "print('Hello from sandbox!')"
```

Or for more complex tasks:

```
Use the sandbox MCP to:
1. Create a Python script that fetches weather data
2. Run it and show me the output
```

### Managing the Connection

```bash
# List configured MCP servers
claude mcp list

# Remove the sandbox server
claude mcp remove sandbox

# View server details
claude mcp get sandbox
```

### Debugging

Monitor the MCP server logs to see all requests from Claude Code:

```bash
# Server shows detailed request/response logging
uv run python -m sandbox_runtime.server.mcp_server
```

Example log output:
```
2024-12-31 12:00:00 | INFO | [abc123] ▶ POST /mcp
    Headers: {'authorization': 'Bearer ...', ...}
    Body: {"jsonrpc": "2.0", "method": "tools/call", ...}
2024-12-31 12:00:00 | INFO | [abc123] ◀ 200 (28.5ms)
```

## Troubleshooting

### Server won't start
- Check if port is already in use: `lsof -i :8080`
- Ensure dependencies are installed: `uv sync --extra server`

### Executions timeout immediately
- Check sandbox dependencies: `srt-py --help`
- On Linux: ensure `bubblewrap` and `socat` are installed
- On macOS: `sandbox-exec` should be available by default

### Session isolation not working
- Each MCP connection gets a unique session UUID
- Verify `Mcp-Session-Id` header is being sent by client
