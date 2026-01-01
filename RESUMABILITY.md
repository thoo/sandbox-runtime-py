# Event Resumability Feature

## Overview

The Sandbox MCP Server implements event resumability, inspired by the MCP Python SDK's `InMemoryEventStore` pattern. This allows clients to resume from where they left off after disconnection, similar to SSE's `Last-Event-ID` functionality.

## How It Works

### Event IDs

Every output event is automatically assigned a unique `event_id` (UUID) when it's generated:

```python
{
    "type": "stdout",
    "data": "Hello World\n",
    "ts": 1234567890.123,
    "event_id": "c4db0417-8a2e-4f3d-9b1c-5e6f7a8b9c0d"  # ← Automatically added
}
```

### Resumability API

The `get_execution_output` tool supports a `last_event_id` parameter:

```python
# First poll - get all events
result1 = get_execution_output(execution_id, wait=False)
# Returns: {"output": [
#   {"event_id": "abc-123", "type": "stdout", "data": "Line 1"},
#   {"event_id": "def-456", "type": "stdout", "data": "Line 2"},
# ]}

# Client processes events, saves last_event_id = "def-456"

# ... client disconnects and reconnects ...

# Second poll - resume from last event
result2 = get_execution_output(
    execution_id,
    wait=False,
    last_event_id="def-456"  # ← Only get events after this one
)
# Returns: {"output": [
#   {"event_id": "ghi-789", "type": "stdout", "data": "Line 3"},  # ← Only new events
# ]}
```

## Use Cases

### 1. Network Interruptions

Client can resume without re-fetching events they've already processed:

```
Time 0: Client polls, gets events 1-10, saves last_event_id="event-10"
Time 1: Client disconnects (network issue)
Time 2: Client reconnects
Time 3: Client polls with last_event_id="event-10", gets only events 11-15
```

### 2. Incremental Processing

Process large execution outputs in chunks:

```python
last_event_id = None

while execution_running:
    result = get_execution_output(exec_id, last_event_id=last_event_id)

    for event in result["output"]:
        process_event(event)
        last_event_id = event["event_id"]  # Save for next iteration

    time.sleep(1)  # Poll interval
```

### 3. Multi-Replica Deployments

With Redis backend, event_ids enable resumability across server instances:

```
Request 1 → Server A: Start execution, get events 1-5
Request 2 → Server B (via load balancer): Resume from event-5, get events 6-10
```

## Implementation Details

### In-Memory Mode (No Redis)

```python
class ExecutionManager:
    async def _read_runner_output(self, execution):
        async for event in execution.runner.read_events():
            # Add unique event_id
            if "event_id" not in event:
                event["event_id"] = str(uuid.uuid4())

            execution.output_buffer.append(event)
            await execution.output_queue.put(event)
```

**Characteristics:**
- ✅ Event IDs assigned on generation
- ✅ Resumability works within single server instance
- ⚠️ Limited by buffer size (default: 10,000 events)
- ❌ Event IDs lost if server restarts

### Redis Mode (Distributed)

```python
class RedisStateStore:
    async def append_output(self, execution_id, event):
        # Add event_id if not present
        if "event_id" not in event:
            event["event_id"] = str(uuid.uuid4())

        # Store in Redis list
        await self._client.rpush(f"execution:{execution_id}:output", json.dumps(event))
```

**Characteristics:**
- ✅ Event IDs persisted in Redis
- ✅ Resumability works across server instances
- ✅ Survives server restarts (within TTL window)
- ⚠️ Limited by Redis memory and TTL (default: 1 hour)

### Resumability Algorithm

```python
async def replay_events_after(self, execution_id, last_event_id):
    """Find event with last_event_id and return all events after it."""

    # Get all events (from buffer or Redis)
    all_events = await self.get_output(execution_id)

    # Find the last event index
    last_index = None
    for i, event in enumerate(all_events):
        if event.get("event_id") == last_event_id:
            last_index = i
            break

    if last_index is None:
        return None  # Event not found (may have been evicted)

    # Return events after the last one
    return all_events[last_index + 1:]
```

## Error Handling

### Event Not Found

If `last_event_id` isn't found in the buffer/Redis:

```json
{
    "error": "Event ID 'abc-123' not found (may have been evicted from buffer)",
    "output": []
}
```

**Causes:**
1. **Buffer overflow** - Event was evicted (in-memory mode with 10k limit)
2. **TTL expiration** - Event expired from Redis (> 1 hour old)
3. **Invalid event_id** - Client sent wrong/corrupted ID

**Recovery:** Client should fall back to fetching all events without `last_event_id`.

## Testing

### Unit Test

```python
import asyncio
from sandbox_runtime.server.execution_manager import ExecutionManager
from sandbox_runtime.server.config import ServerConfig

async def test_resumability():
    manager = ExecutionManager(ServerConfig())
    session_id = "test"

    # Start execution
    exec = await manager.create_execution(
        session_id, 'python3 -c "print(\'A\'); print(\'B\')"'
    )

    await asyncio.sleep(0.5)  # Let it run

    # Get first batch
    output1 = await manager.get_buffered_output(session_id, exec.info.id)
    last_event_id = output1[1]["event_id"]  # Second event

    # Replay from that point
    output2 = await manager.replay_events_after(
        session_id, exec.info.id, last_event_id
    )

    assert len(output2) < len(output1)  # Fewer events
    assert output2[0]["event_id"] != last_event_id  # Starts after

asyncio.run(test_resumability())
```

### Integration Test

See `/tmp/test_event_ids.py` for full integration test with Redis.

## Performance Considerations

### Memory Usage

Each event_id adds ~36 bytes (UUID string):
- 10,000 events × 36 bytes = ~350 KB overhead
- Negligible compared to event data

### Lookup Performance

- **In-memory**: O(n) linear scan through buffer
- **Redis**: O(n) linear scan (LRANGE + parse)
- Optimized for small-to-medium event counts (< 10k)

For very large executions (> 100k events), consider:
- Increasing buffer size: `ServerConfig(output_buffer_size=100000)`
- Using cursor-based pagination instead of event_id lookups

### Redis Network

Each `replay_events_after` call:
1. LRANGE to get all events
2. Parse JSON
3. Linear scan for event_id

**Optimization opportunity**: Store event_id → index mapping in Redis hash for O(1) lookup.

## Comparison with MCP SDK Event Store

| Feature | MCP SDK `InMemoryEventStore` | Our Implementation |
|---------|------------------------------|-------------------|
| **Purpose** | SSE stream resumability | Execution output resumability |
| **Scope** | All MCP protocol messages | Only execution output events |
| **Storage** | In-memory deque (max 100) | In-memory buffer (10k) + Redis |
| **Event IDs** | UUID on store | UUID on generation |
| **Persistence** | None (in-memory only) | Optional (Redis with TTL) |
| **Eviction** | Automatic (deque maxlen) | Manual trim + Redis TTL |
| **Distributed** | No | Yes (with Redis) |

## Future Enhancements

### 1. Cursor-Based Pagination

Instead of `last_event_id`, use offset cursors:

```python
get_execution_output(exec_id, cursor=10, limit=100)
# Returns events 10-109 and next_cursor=110
```

**Pros**: O(1) lookup, predictable memory usage
**Cons**: Less robust to insertions (rare in our case)

### 2. Event Index in Redis

Store mapping for O(1) lookup:

```python
# Instead of scanning entire list
event_index = await redis.hget(f"execution:{exec_id}:index", last_event_id)
new_events = await redis.lrange(f"execution:{exec_id}:output", event_index+1, -1)
```

**Pros**: Constant-time lookup
**Cons**: 2x Redis memory usage

### 3. Compressed Event Storage

For long-running executions with many events:

```python
# Store events in compressed chunks
await redis.set(
    f"execution:{exec_id}:chunk:0",
    gzip.compress(json.dumps(events_0_to_999))
)
```

**Pros**: Reduced Redis memory
**Cons**: Must decompress entire chunk to read

## Related Documentation

- [DEPLOYMENT.md](./DEPLOYMENT.md) - Production deployment guide
- [MCP SDK Event Store](https://github.com/modelcontextprotocol/python-sdk/blob/main/examples/servers/simple-streamablehttp/mcp_simple_streamablehttp/event_store.py) - Original inspiration
- [Server-Sent Events Spec](https://html.spec.whatwg.org/multipage/server-sent-events.html#the-last-event-id-header) - Last-Event-ID pattern
