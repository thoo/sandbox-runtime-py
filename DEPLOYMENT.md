# Sandbox MCP Server - Deployment Guide

## Architecture Overview

### Module-Level State Pattern

This server uses a **module-level state pattern** inspired by the MCP Python SDK's event store design:

```python
# Global state persists across requests (similar to MCP SDK's event_store)
_execution_manager: ExecutionManager | None = None
_redis_store: RedisStateStore | None = None
```

**Why this matters:**
- ✅ ExecutionManager is initialized **once** on first request, then reused
- ✅ Long-running subprocess executions survive across HTTP requests
- ✅ Async executions can be started in one request, polled in subsequent requests
- ✅ Redis mirrors state in real-time for multi-replica deployments

**How it works:**
```
Request 1 (initialize) → Creates ExecutionManager (module-level)
Request 2 (execute_code_async) → Reuses ExecutionManager, starts subprocess
Request 3 (get_output) → Reuses ExecutionManager, reads from running subprocess
...
Server shutdown → Signal handler cleans up ExecutionManager
```

**Contrast with per-request lifespan:**
- ❌ Per-request: Lifespan creates/destroys ExecutionManager on every request
- ❌ Result: Subprocesses killed, async executions fail, "Execution not found" errors
- ✅ Module-level: State persists, processes keep running

---

## Deployment Modes

### 1. Single Instance (Default)
**Best for**: Development, testing, small-scale deployments

**Configuration:**
```bash
# No Redis required
uv run srt-mcp-server --token YOUR_TOKEN --port 8080
```

**Features:**
- ✅ Module-level ExecutionManager (persists across requests)
- ✅ In-memory state management (no external dependencies)
- ✅ Full async execution support
- ✅ Incremental streaming with real-time polling
- ✅ Real-time error capture
- ❌ No horizontal scaling (single server instance)

---

### 2. Multi-Replica with Sticky Sessions (Recommended for Production)
**Best for**: Production deployments requiring redundancy and scaling

**Architecture:**
```
Load Balancer (with session affinity)
    ├─> Server Instance 1 (port 8080)
    ├─> Server Instance 2 (port 8081)
    └─> Server Instance 3 (port 8082)
          ↓
      Redis (shared state)
```

**Configuration:**

1. **Start Redis:**
```bash
redis-server
```

2. **Start multiple server instances:**
```bash
# Instance 1
REDIS_URL="redis://localhost:6379/0" \
  uv run srt-mcp-server --token YOUR_TOKEN --port 8080

# Instance 2
REDIS_URL="redis://localhost:6379/0" \
  uv run srt-mcp-server --token YOUR_TOKEN --port 8081

# Instance 3
REDIS_URL="redis://localhost:6379/0" \
  uv run srt-mcp-server --token YOUR_TOKEN --port 8082
```

3. **Configure load balancer with session affinity:**
```nginx
# nginx example with sticky sessions
upstream sandbox_servers {
    ip_hash;  # Session affinity based on client IP
    server localhost:8080;
    server localhost:8081;
    server localhost:8082;
}

server {
    listen 80;
    location /mcp {
        proxy_pass http://sandbox_servers;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

**Features:**
- ✅ Horizontal scaling
- ✅ Redundancy and failover
- ✅ Shared execution state via Redis
- ✅ Full async execution support
- ✅ Incremental streaming
- ⚠️ Requires session affinity (sticky sessions)

**How it works:**
- Each server instance maintains a **module-level ExecutionManager** that initializes once and persists
- ExecutionManager lifespan pattern:
  ```
  First request → Initialize ExecutionManager + Redis (logged as "🚀 First-time initialization")
  All subsequent requests → Reuse existing ExecutionManager (logged as "♻️ Reusing existing")
  ```
- Each instance runs its own execution processes locally (as subprocesses)
- Execution metadata and output are mirrored to Redis in real-time via background tasks
- Session affinity (sticky sessions) ensures subsequent requests hit the same server where the process is running
- If a server dies, its executions are terminated, but metadata persists in Redis (TTL: 1 hour)
- **Cannot use `stateless_http=True`** because it would recreate ExecutionManager per-request, killing processes

---

### 3. Fully Stateless with Separate Workers (Advanced)
**Best for**: Large-scale deployments, microservices architecture

**Architecture:**
```
Load Balancer (no sticky sessions needed)
    ├─> API Server 1
    ├─> API Server 2
    └─> API Server 3
          ↓
      Message Queue (Redis/RabbitMQ)
          ↓
    Worker Pool
    ├─> Worker 1
    ├─> Worker 2
    └─> Worker 3
          ↓
      Redis (shared state)
```

**This requires:**
1. Separate worker service to execute commands
2. Message queue for job distribution
3. Workers write output directly to Redis
4. API servers only handle requests (fully stateless)

**Status:** Not yet implemented. Contributions welcome!

---

## Redis State Store

When `REDIS_URL` is configured, the server automatically:

### Stores in Redis:
- Execution metadata (status, command, timestamps)
- Incremental output events
- Session-to-execution mappings

### Redis Keys:
```
execution:{execution_id}           - Execution metadata (JSON)
execution:{execution_id}:output    - Output events (List)
session:{session_id}:executions    - Set of execution IDs
```

### TTL:
- Default: 1 hour (3600 seconds)
- Automatically refreshed on access
- Prevents Redis from growing unbounded

---

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `REDIS_URL` | Redis connection URL | None (disabled) |
| `SANDBOX_AUTH_TOKEN` | Bearer token for auth | None (no auth) |
| `SANDBOX_HOST` | Server bind address | 127.0.0.1 |
| `SANDBOX_PORT` | Server port | 8080 |
| `SANDBOX_MAX_CONCURRENT` | Max concurrent executions | 10 |
| `SANDBOX_MAX_PER_SESSION` | Max per session | 5 |
| `SANDBOX_TIMEOUT` | Execution timeout (seconds) | 300 |
| `SANDBOX_LOG_FILE` | Log file path | sandbox_server.log |

---

## Testing Multi-Replica Setup

```bash
# Terminal 1: Start Redis
redis-server

# Terminal 2: Start Instance 1
REDIS_URL="redis://localhost:6379/0" \
  uv run srt-mcp-server --token test123 --port 8080

# Terminal 3: Start Instance 2
REDIS_URL="redis://localhost:6379/0" \
  uv run srt-mcp-server --token test123 --port 8081

# Terminal 4: Test both instances
# Create execution on instance 1
curl -X POST http://localhost:8080/mcp \
  -H "Authorization: Bearer test123" \
  -H "Content-Type: application/json" \
  -H "Accept: application/json" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize",...}'

# Query from instance 2 (should see shared state in Redis)
redis-cli keys "execution:*"
```

---

## Monitoring

### Check Redis Connection:
```bash
redis-cli ping
# Should return: PONG
```

### View Execution Data:
```bash
# List all executions
redis-cli keys "execution:*"

# View execution metadata
redis-cli get "execution:{execution_id}"

# View output events
redis-cli lrange "execution:{execution_id}:output" 0 -1
```

### Monitor Server Logs:
```bash
tail -f sandbox_server.log | grep -E "Redis|ExecutionManager|distributed"
```

---

## Best Practices

1. **Use Redis for production** - Enables redundancy and shared state across replicas
2. **Configure session affinity** - Required for async executions (sticky sessions)
3. **Set reasonable timeouts** - Prevent runaway executions (`SANDBOX_TIMEOUT`)
4. **Monitor Redis memory** - Use TTLs (default: 1 hour) and maxmemory policies
5. **Use strong auth tokens** - Protect your execution environment (`SANDBOX_AUTH_TOKEN`)
6. **Log rotation** - Configure loguru rotation settings (default: 10 MB, 7 days)
7. **Health checks** - Use `/health` endpoint for load balancer checks
8. **Monitor initialization logs** - Watch for "🚀 First-time initialization" (should happen once per server) vs "♻️ Reusing existing" (subsequent requests)

---

## Troubleshooting

### "Execution not found" errors
**Possible causes:**
1. **Session affinity not configured** - Subsequent requests hitting different server instance
   - Solution: Configure sticky sessions in load balancer (see nginx example above)

2. **Redis not connected** - Check if Redis is running and accessible
   - Test: `redis-cli ping` should return `PONG`
   - Verify: `REDIS_URL` environment variable is set correctly
   - Check logs for: "✅ Redis connected - distributed mode enabled"

3. **Execution TTL expired** - Default 1 hour TTL on Redis keys
   - Check: `redis-cli ttl execution:{execution_id}`
   - Solution: Increase TTL or complete executions faster

4. **Module-level state reset** - Server restarted between requests
   - Check logs: Should see "🚀 First-time initialization" only on server start
   - If you see it repeatedly: Server is restarting, check for crashes

### Output not appearing
- Verify incremental streaming is working locally first
- Check Redis output list: `redis-cli lrange execution:{id}:output 0 -1`
- Ensure server process isn't being killed during execution

### Connection refused
- Check server is bound to correct host (not just localhost)
- Verify firewall allows connections
- Check `SANDBOX_HOST` environment variable

---

## Performance Tuning

### Redis
```bash
# Increase max memory
redis-server --maxmemory 2gb --maxmemory-policy allkeys-lru
```

### Server
```bash
# Increase concurrent executions
SANDBOX_MAX_CONCURRENT=50 uv run srt-mcp-server
```

### Load Balancer
- Use least-connections algorithm with session affinity
- Configure health check intervals
- Set appropriate timeouts for long-running executions

---

## Security Considerations

1. **Always use auth tokens in production** - Set `SANDBOX_AUTH_TOKEN` or `--token` flag
2. **Run servers in sandboxed environments** - Use containers, VMs, or dedicated hosts
3. **Restrict network access** - Use firewall rules to limit exposure
4. **Use Redis AUTH** - Configure Redis with `requirepass` for authentication
5. **Enable TLS** - Use HTTPS in production with reverse proxy (nginx/Caddy)
6. **Limit execution resources** - Use system controls (cgroups, ulimit)
7. **Regular security updates** - Keep dependencies updated with `uv pip upgrade`
8. **Validate execution commands** - Sanitize user input before executing
9. **Monitor execution patterns** - Watch for suspicious activity in logs

---

## Architecture Deep Dive

### Module-Level State Pattern (Inspired by MCP SDK)

The server follows the same pattern as the MCP Python SDK's `InMemoryEventStore`:

**MCP SDK Pattern:**
```python
# examples/servers/simple-streamablehttp/server.py
event_store = InMemoryEventStore()  # Module-level, persists for server lifetime

session_manager = StreamableHTTPSessionManager(
    app=app,
    event_store=event_store,  # Passed to session manager
)
```

**Our Pattern:**
```python
# sandbox_runtime/server/mcp_server.py
_execution_manager: ExecutionManager | None = None  # Module-level
_redis_store: RedisStateStore | None = None

@asynccontextmanager
async def lifespan(server: FastMCP):
    global _execution_manager, _redis_store

    # Only initialize once
    if _execution_manager is None:
        logger.info("🚀 First-time initialization of ExecutionManager")
        _execution_manager = ExecutionManager(config, redis_store=_redis_store)
    else:
        logger.debug("♻️ Reusing existing ExecutionManager")

    yield {"execution_manager": _execution_manager}
    # No cleanup here - handled by signal handlers on server shutdown
```

**Benefits:**
- Long-running subprocesses survive across HTTP requests
- Async executions can be started in one request, polled in another
- State persists naturally without complex session management
- Clean separation: MCP handles session routing, ExecutionManager handles process lifecycle

**Cleanup:**
- Signal handlers (SIGINT/SIGTERM) trigger graceful shutdown
- Shutdown routine kills all running executions, closes Redis connection
- Module-level state prevents accidental premature cleanup
