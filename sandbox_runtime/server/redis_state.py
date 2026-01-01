"""Redis-backed state store for distributed execution management."""

import json
import os

import redis.asyncio as redis
from loguru import logger


class RedisStateStore:
    """Redis-backed state store for execution data and session management."""

    def __init__(self, redis_url: str | None = None):
        """Initialize Redis connection.

        Args:
            redis_url: Redis connection URL. If None, reads from REDIS_URL env var.
                      Defaults to redis://localhost:6379/0
        """
        self.redis_url = redis_url or os.getenv("REDIS_URL", "redis://localhost:6379/0")
        self._client: redis.Redis | None = None
        self._pubsub: redis.client.PubSub | None = None

    async def connect(self):
        """Connect to Redis."""
        if self._client is None:
            self._client = await redis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
            logger.info(f"Connected to Redis at {self.redis_url}")

    async def close(self):
        """Close Redis connection."""
        if self._client:
            await self._client.aclose()
            self._client = None
            logger.info("Closed Redis connection")

    async def set_execution(self, execution_id: str, session_id: str, data: dict, ttl: int = 3600):
        """Store execution data in Redis.

        Args:
            execution_id: Unique execution identifier
            session_id: Session this execution belongs to
            data: Execution data to store
            ttl: Time-to-live in seconds (default: 1 hour)
        """
        if not self._client:
            await self.connect()

        key = f"execution:{execution_id}"
        session_key = f"session:{session_id}:executions"

        # Store execution data with TTL
        await self._client.set(key, json.dumps(data), ex=ttl)

        # Add to session's execution set
        await self._client.sadd(session_key, execution_id)
        await self._client.expire(session_key, ttl)

        logger.debug(f"Stored execution {execution_id[:8]}... for session {session_id[:8]}...")

    async def get_execution(self, execution_id: str) -> dict | None:
        """Retrieve execution data from Redis.

        Args:
            execution_id: Execution identifier

        Returns:
            Execution data dict or None if not found
        """
        if not self._client:
            await self.connect()

        key = f"execution:{execution_id}"
        data = await self._client.get(key)

        if data:
            return json.loads(data)
        return None

    async def delete_execution(self, execution_id: str, session_id: str):
        """Delete execution data from Redis.

        Args:
            execution_id: Execution identifier
            session_id: Session this execution belongs to
        """
        if not self._client:
            await self.connect()

        key = f"execution:{execution_id}"
        session_key = f"session:{session_id}:executions"

        # Remove from Redis
        await self._client.delete(key)
        await self._client.srem(session_key, execution_id)

        logger.debug(f"Deleted execution {execution_id[:8]}...")

    async def get_session_executions(self, session_id: str) -> list[str]:
        """Get all execution IDs for a session.

        Args:
            session_id: Session identifier

        Returns:
            List of execution IDs
        """
        if not self._client:
            await self.connect()

        session_key = f"session:{session_id}:executions"
        execution_ids = await self._client.smembers(session_key)
        return list(execution_ids)

    async def append_output(self, execution_id: str, event: dict):
        """Append an output event to execution's output buffer with event ID.

        Args:
            execution_id: Execution identifier
            event: Output event to append (will be enriched with event_id)
        """
        if not self._client:
            await self.connect()

        import uuid

        output_key = f"execution:{execution_id}:output"

        # Add unique event_id for resumability (if not already present)
        if "event_id" not in event:
            event["event_id"] = str(uuid.uuid4())

        # Append event to list
        await self._client.rpush(output_key, json.dumps(event))

        # Set TTL if not already set
        ttl = await self._client.ttl(output_key)
        if ttl == -1:  # No expiration set
            await self._client.expire(output_key, 3600)

    async def get_output(self, execution_id: str, start: int = 0, end: int = -1) -> list[dict]:
        """Get output events for an execution.

        Args:
            execution_id: Execution identifier
            start: Start index (default: 0)
            end: End index (default: -1 for all)

        Returns:
            List of output events
        """
        if not self._client:
            await self.connect()

        output_key = f"execution:{execution_id}:output"
        events = await self._client.lrange(output_key, start, end)

        return [json.loads(event) for event in events]

    async def get_output_count(self, execution_id: str) -> int:
        """Get count of output events for an execution.

        Args:
            execution_id: Execution identifier

        Returns:
            Number of output events
        """
        if not self._client:
            await self.connect()

        output_key = f"execution:{execution_id}:output"
        return await self._client.llen(output_key)

    async def replay_events_after(self, execution_id: str, last_event_id: str) -> list[dict] | None:
        """Replay output events after a specific event ID (resumability).

        This enables clients to resume from where they left off after disconnection,
        similar to SSE's Last-Event-ID functionality.

        Args:
            execution_id: Execution identifier
            last_event_id: Last event ID the client received

        Returns:
            List of events after last_event_id, or None if event not found

        Example:
            # Client previously received events up to event_id="abc-123"
            # After reconnecting, get only new events:
            new_events = await replay_events_after(exec_id, "abc-123")
        """
        if not self._client:
            await self.connect()

        output_key = f"execution:{execution_id}:output"
        all_events_json = await self._client.lrange(output_key, 0, -1)

        if not all_events_json:
            return []

        # Parse all events
        all_events = [json.loads(event) for event in all_events_json]

        # Find the last event index
        last_event_index = None
        for i, event in enumerate(all_events):
            if event.get("event_id") == last_event_id:
                last_event_index = i
                break

        if last_event_index is None:
            logger.warning(f"Event ID {last_event_id} not found in execution {execution_id}")
            return None

        # Return events after the last one
        return all_events[last_event_index + 1 :]

    async def cleanup_session(self, session_id: str):
        """Clean up all data for a session.

        Args:
            session_id: Session identifier
        """
        if not self._client:
            await self.connect()

        # Get all executions for this session
        execution_ids = await self.get_session_executions(session_id)

        # Delete each execution and its output
        for execution_id in execution_ids:
            await self._client.delete(f"execution:{execution_id}")
            await self._client.delete(f"execution:{execution_id}:output")

        # Delete session set
        await self._client.delete(f"session:{session_id}:executions")

        logger.info(f"Cleaned up session {session_id[:8]}... ({len(execution_ids)} executions)")
