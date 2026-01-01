"""Redis-backed event store for MCP session persistence."""

import json
from collections.abc import Callable

import redis.asyncio as redis
from loguru import logger
from mcp.server.streamable_http import EventId, EventStore, StreamId
from mcp.types import JSONRPCMessage


class RedisEventStore(EventStore):
    """Redis-backed event store for persistent MCP sessions.

    Stores SSE events in Redis so they survive server restarts, enabling
    clients to reconnect and resume from where they left off.
    """

    def __init__(self, redis_url: str, ttl: int = 3600):
        """Initialize Redis event store.

        Args:
            redis_url: Redis connection URL
            ttl: Time-to-live for events in seconds (default: 1 hour)
        """
        self.redis_url = redis_url
        self.ttl = ttl
        self._client: redis.Redis | None = None

    async def connect(self):
        """Connect to Redis."""
        if self._client is None:
            self._client = await redis.from_url(
                self.redis_url,
                encoding="utf-8",
                decode_responses=True,
            )
            logger.info(f"RedisEventStore connected to {self.redis_url}")

    async def close(self):
        """Close Redis connection."""
        if self._client:
            await self._client.aclose()
            self._client = None
            logger.info("RedisEventStore connection closed")

    async def store_event(self, stream_id: StreamId, message: JSONRPCMessage | None) -> EventId:
        """Store an SSE event in Redis.

        Args:
            stream_id: ID of the stream (typically session ID)
            message: JSON-RPC message to store

        Returns:
            Generated event ID
        """
        if self._client is None:
            await self.connect()

        # Generate unique event ID
        import uuid

        event_id = str(uuid.uuid4())

        # Store event data
        event_key = f"mcp:event:{event_id}"
        stream_key = f"mcp:stream:{stream_id}:events"

        event_data = {
            "event_id": event_id,
            "stream_id": stream_id,
            "message": message.model_dump() if message else None,
        }

        # Store event details with TTL
        await self._client.set(event_key, json.dumps(event_data), ex=self.ttl)

        # Add event ID to stream's event list (sorted by timestamp)
        await self._client.rpush(stream_key, event_id)  # type: ignore[misc]
        await self._client.expire(stream_key, self.ttl)

        logger.debug(f"Stored event {event_id[:8]}... for stream {stream_id}")
        return event_id

    async def replay_events_after(
        self,
        last_event_id: EventId,
        send_callback: Callable[[JSONRPCMessage | None, EventId], None],
    ) -> StreamId | None:
        """Replay events after a specific event ID.

        Args:
            last_event_id: Last event ID the client received
            send_callback: Callback to send events to client

        Returns:
            Stream ID if event found, None otherwise
        """
        if self._client is None:
            await self.connect()

        # Find the event to get its stream ID
        event_key = f"mcp:event:{last_event_id}"
        event_data_json = await self._client.get(event_key)

        if not event_data_json:
            logger.warning(f"Event {last_event_id} not found in Redis")
            return None

        event_data = json.loads(event_data_json)
        stream_id = event_data["stream_id"]

        # Get all events for this stream
        stream_key = f"mcp:stream:{stream_id}:events"
        all_event_ids = await self._client.lrange(stream_key, 0, -1)  # type: ignore[misc]

        if not all_event_ids:
            return stream_id

        # Find index of last_event_id
        try:
            last_index = all_event_ids.index(last_event_id)
        except ValueError:
            logger.warning(f"Event {last_event_id} not in stream {stream_id}")
            return None

        # Replay events after last_event_id
        events_to_replay = all_event_ids[last_index + 1 :]
        logger.info(f"Replaying {len(events_to_replay)} events after {last_event_id[:8]}...")

        for event_id in events_to_replay:
            event_key = f"mcp:event:{event_id}"
            event_json = await self._client.get(event_key)

            if event_json:
                event_data = json.loads(event_json)
                message_dict = event_data.get("message")

                # Reconstruct JSONRPCMessage if it exists
                message = None
                if message_dict:
                    # JSONRPCMessage is a union type, we need to handle it properly
                    # For now, we'll pass the dict and let the caller handle it
                    message = message_dict

                # Send event to client
                send_callback(message, event_id)

        return stream_id

    async def cleanup_stream(self, stream_id: StreamId):
        """Clean up all events for a stream.

        Args:
            stream_id: Stream ID to clean up
        """
        if self._client is None:
            await self.connect()

        stream_key = f"mcp:stream:{stream_id}:events"
        event_ids = await self._client.lrange(stream_key, 0, -1)  # type: ignore[misc]

        # Delete all events
        for event_id in event_ids:
            event_key = f"mcp:event:{event_id}"
            await self._client.delete(event_key)

        # Delete stream list
        await self._client.delete(stream_key)

        logger.info(f"Cleaned up {len(event_ids)} events for stream {stream_id}")
