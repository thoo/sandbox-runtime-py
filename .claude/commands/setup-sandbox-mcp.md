# Setup Sandbox MCP Server Connection

Configure the Sandbox MCP server connection for Claude Code using the `claude mcp` CLI.

## Instructions

Use the AskUserQuestion tool to gather user preferences with the following questions:

### Question 1: Enable or Disable
- Header: "MCP Status"
- Question: "Do you want to enable or disable the Sandbox MCP server connection?"
- Options:
  - Enable: Add or update the sandbox MCP server configuration
  - Disable: Remove the sandbox MCP server from configuration

### Question 2: Configuration Scope (only if enabling)
- Header: "Config Scope"
- Question: "Where should the MCP configuration be stored?"
- Options:
  - Local (Recommended): Store in local project config (current project only)
  - User: Store in user config (applies to all your projects)

### Question 3: Authentication Token (only if enabling)
- Header: "Auth Token"
- Question: "How would you like to configure the authentication token?"
- Options:
  - Auto-generate (Recommended): Generate a secure random token automatically
  - Manual: Enter your own token
  - No auth: Run without authentication (not recommended for production)

### Question 4: Manual Token Input (only if "Manual" selected)
If the user selects "Manual" for the token, ask them to provide their token using AskUserQuestion with a text input.

## After gathering preferences

### If Enabling:

1. **Generate token** (if auto-generate selected):
   ```bash
   uv run python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

2. **Remove existing sandbox server** (if exists):
   ```bash
   claude mcp remove sandbox 2>/dev/null || true
   ```

3. **Add MCP server using CLI**:

   With authentication (local scope):
   ```bash
   claude mcp add --transport http sandbox http://127.0.0.1:8080/mcp --header "Authorization: Bearer <TOKEN>"
   ```

   With authentication (user scope):
   ```bash
   claude mcp add --transport http sandbox http://127.0.0.1:8080/mcp --header "Authorization: Bearer <TOKEN>" --scope user
   ```

   Without authentication (local scope):
   ```bash
   claude mcp add --transport http sandbox http://127.0.0.1:8080/mcp
   ```

   Without authentication (user scope):
   ```bash
   claude mcp add --transport http sandbox http://127.0.0.1:8080/mcp --scope user
   ```

4. **Update .env file** with the token (if auth enabled):
   - Check if `.env` exists and read it
   - Add or update `SANDBOX_AUTH_TOKEN=<TOKEN>`
   - Preserve existing entries

5. **Verify configuration**:
   ```bash
   claude mcp list
   ```

6. **Output instructions** for the user:
   - Show the generated token (if auto-generated) so they can note it
   - Show how to start the server:
     ```bash
     uv run python -m sandbox_runtime.server.mcp_server
     ```
   - Remind them to restart Claude Code to pick up the new MCP configuration

### If Disabling:

1. **Remove MCP server**:
   ```bash
   claude mcp remove sandbox
   ```

2. **Optionally remove SANDBOX_AUTH_TOKEN from .env**:
   - Ask user if they want to remove the token from .env
   - If yes, edit .env to remove the SANDBOX_AUTH_TOKEN line

3. **Verify removal**:
   ```bash
   claude mcp list
   ```

## Example Output

After successful setup, display:

```
Sandbox MCP Server configured successfully!

Scope: local (project-specific)
Token: <displayed-token>
Server URL: http://127.0.0.1:8080/mcp

To start the server:
  uv run python -m sandbox_runtime.server.mcp_server

Restart Claude Code to pick up the new MCP configuration.
Then run /mcp to verify the connection.
```

After successful removal, display:

```
Sandbox MCP Server removed.

Restart Claude Code to apply changes.
```
