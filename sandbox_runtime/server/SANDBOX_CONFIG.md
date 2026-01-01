# Sandbox Configuration Guide

## Overview

The MCP Sandbox Server uses a "deny by default" security model on macOS. This means **all operations are blocked unless explicitly allowed** in the configuration.

## Why Operations Are Blocked by Default

### The Default Behavior

When no `sandbox_config` is provided, the runner creates a minimal default configuration:

```python
{
  "network": {"allowed_domains": [], "denied_domains": []},
  "filesystem": {"deny_read": [], "allow_write": [], "deny_write": []}
}
```

This default configuration:
- **Blocks all network connections** (empty `allowed_domains`)
- **Restricts filesystem writes** to only essential system paths:
  - `/dev/stdout`, `/dev/stderr`, `/dev/null`, `/dev/tty`
  - `/tmp/claude`, `/private/tmp/claude`
  - `~/.npm/_logs`, `~/.claude/debug`
- **Does NOT include**:
  - Current working directory (`.`)
  - General `/tmp` directory
  - User home directory

### macOS Sandbox Architecture

The macOS sandbox (Seatbelt) uses a strict security profile:

1. **Deny by default**: `(deny default ...)` in the sandbox profile
2. **Explicit allow rules**: Only operations explicitly permitted are allowed
3. **Order matters**: Deny rules can override allow rules

This is visible in `macos_sandbox.py:397`:
```python
f'(deny default (with message "{log_tag}"))'
```

## Configuration Format

The configuration supports **both camelCase and snake_case** formats for compatibility:

### Recommended Format (snake_case)
```json
{
  "network": {
    "allowed_domains": ["pypi.org", "*.npmjs.org"],
    "denied_domains": []
  },
  "filesystem": {
    "deny_read": ["~/.ssh"],
    "allow_write": [".", "/tmp", "~/.cache/uv"],
    "deny_write": []
  }
}
```

### Alternative Format (camelCase)
```json
{
  "network": {
    "allowedDomains": ["pypi.org", "*.npmjs.org"],
    "deniedDomains": []
  },
  "filesystem": {
    "denyRead": ["~/.ssh"],
    "allowWrite": [".", "/tmp", "~/.cache/uv"],
    "denyWrite": []
  }
}
```

## Common Use Cases

### Allow Current Directory Writes

**Problem**: Commands fail with "Operation not permitted" when writing files

**Solution**: Add `"."` to `allow_write`:
```json
{
  "filesystem": {
    "allow_write": ["."]
  }
}
```

### Allow Network Access to Specific Domains

**Problem**: Network connections fail with DNS resolution errors

**Solution**: Add domains to `allowed_domains`:
```json
{
  "network": {
    "allowed_domains": [
      "pypi.org",
      "*.pypi.org",
      "files.pythonhosted.org",
      "github.com",
      "*.github.com"
    ]
  }
}
```

**Note**: Network filtering on macOS currently blocks all connections. This is a known limitation under investigation.

### Allow Temp Directory Access

**Problem**: Commands need to write to `/tmp`

**Solution**: Add `/private/tmp` to `allow_write` (macOS):
```json
{
  "filesystem": {
    "allow_write": ["/private/tmp", "."]
  }
}
```

**Important**: On macOS, `/tmp` is a symlink to `private/tmp`. The sandbox requires the **actual path** (`/private/tmp`), not the symlink (`/tmp`).

### Protect Sensitive Files

**Problem**: Want to prevent access to SSH keys or credentials

**Solution**: Add paths to `deny_read`:
```json
{
  "filesystem": {
    "deny_read": ["~/.ssh", "~/.aws", ".env"],
    "allow_write": ["."]
  }
}
```

## Configuration Fields

### Network Configuration

| Field (snake_case) | Field (camelCase) | Type | Description |
|-------------------|-------------------|------|-------------|
| `allowed_domains` | `allowedDomains` | `list[str]` | Domains to allow (supports wildcards like `*.example.com`) |
| `denied_domains` | `deniedDomains` | `list[str]` | Domains to explicitly deny |

### Filesystem Configuration

| Field (snake_case) | Field (camelCase) | Type | Description |
|-------------------|-------------------|------|-------------|
| `deny_read` | `denyRead` | `list[str]` | Paths to deny reading from |
| `allow_write` | `allowWrite` | `list[str]` | Paths to allow writing to (merged with defaults) |
| `deny_write` | `denyWrite` | `list[str]` | Paths to deny writing to (overrides allow) |

## Default Write Paths

The following paths are **always** added to `allow_write` (see `sandbox_utils.py:get_default_write_paths()`):

- `/dev/stdout`, `/dev/stderr`, `/dev/null`, `/dev/tty`
- `/dev/dtracehelper`, `/dev/autofs_nowait`
- `/tmp/claude`, `/private/tmp/claude`
- `~/.npm/_logs`
- `~/.claude/debug`

## Path Patterns

Paths support glob patterns:
- `*.txt` - matches files ending in .txt
- `**/*.log` - matches .log files in any subdirectory
- `~/.ssh` - expands to user home directory

### macOS Symlink Resolution

On macOS, certain system paths are symlinks that need to be specified using their actual paths:
- `/tmp` → Use `/private/tmp` instead
- `/var` → Use `/private/var` instead
- `/etc` → Use `/private/etc` instead

The sandbox does not automatically resolve symlinks, so you must use the actual path.

## Example Configurations

### Minimal (Allow Current Directory)
```json
{
  "network": {"allowed_domains": [], "denied_domains": []},
  "filesystem": {
    "deny_read": [],
    "allow_write": ["."],
    "deny_write": []
  }
}
```

### Python Development
```json
{
  "network": {
    "allowed_domains": [
      "pypi.org",
      "*.pypi.org",
      "files.pythonhosted.org"
    ]
  },
  "filesystem": {
    "deny_read": ["~/.ssh", ".env"],
    "allow_write": [".", "/private/tmp", "~/.cache/pip", "~/.cache/uv"],
    "deny_write": []
  }
}
```

### Node.js Development
```json
{
  "network": {
    "allowed_domains": [
      "registry.npmjs.org",
      "*.npmjs.org",
      "github.com"
    ]
  },
  "filesystem": {
    "deny_read": ["~/.ssh", ".env"],
    "allow_write": [".", "/private/tmp", "~/.npm"],
    "deny_write": []
  }
}
```

## Troubleshooting

### "Operation not permitted" errors

**Cause**: Filesystem restrictions are blocking the operation

**Fix**: Add the required path to `allow_write`:
```json
{
  "filesystem": {
    "allow_write": [".", "/tmp"]
  }
}
```

### Network connections fail

**Cause**: Empty or missing `allowed_domains`

**Fix**: Add required domains:
```json
{
  "network": {
    "allowed_domains": ["your-domain.com"]
  }
}
```

**Note**: macOS network filtering is currently very restrictive and may block all connections. This is under investigation.

### Configuration not taking effect

**Cause**: The `sandbox_config` parameter must be passed with each execution

**Fix**: Ensure you're passing the config in the MCP tool call:
```python
execute_code(
    command="echo test",
    sandbox_config=your_config
)
```

**Note**: You do NOT need to restart the MCP server. Each execution gets its own config.

## Implementation Details

- **Config parsing**: `runner.py:180-188`
- **Sandbox initialization**: `manager.py:408-509`
- **macOS profile generation**: `macos_sandbox.py:381-603`
- **Default paths**: `sandbox_utils.py:223-243`
- **Pydantic models**: `config.py:59-140`

## Security Considerations

The default restrictive behavior is intentional for security:

1. **Prevent data exfiltration**: Network is blocked by default
2. **Protect credentials**: Sensitive files can be denied
3. **Isolation**: Each execution runs in its own sandbox
4. **Least privilege**: Only explicitly allowed operations are permitted

Always use the minimal set of permissions needed for your use case.
