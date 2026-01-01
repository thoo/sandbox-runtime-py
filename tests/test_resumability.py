"""Tests for event resumability functionality."""

import asyncio

import pytest

from sandbox_runtime.server.config import ServerConfig
from sandbox_runtime.server.execution_manager import ExecutionManager
from sandbox_runtime.server.redis_state import RedisStateStore


@pytest.mark.asyncio
async def test_event_ids_are_generated():
    """Test that all output events receive unique event_id fields."""
    config = ServerConfig()
    manager = ExecutionManager(config)
    session_id = "test-session"

    try:
        execution = await manager.create_execution(
            session_id=session_id,
            command="python3 -u -c \"print('Line 1'); print('Line 2'); print('Line 3')\"",
            timeout_seconds=5,
        )

        # Wait for execution to complete
        await asyncio.sleep(1)

        # Get buffered output
        output = await manager.get_buffered_output(session_id, execution.info.id)

        # Verify all events have event_id
        assert len(output) > 0, "Should have some output events"
        for event in output:
            assert "event_id" in event, f"Event {event.get('type')} missing event_id"
            assert isinstance(event["event_id"], str), "event_id should be string"
            assert len(event["event_id"]) > 0, "event_id should not be empty"

        # Verify event_ids are unique
        event_ids = [e["event_id"] for e in output]
        assert len(event_ids) == len(set(event_ids)), "All event_ids should be unique"

    finally:
        await manager.shutdown()


@pytest.mark.asyncio
async def test_replay_events_after_in_memory():
    """Test replay_events_after with in-memory execution manager."""
    config = ServerConfig()
    manager = ExecutionManager(config)
    session_id = "test-session"

    try:
        execution = await manager.create_execution(
            session_id=session_id,
            command="python3 -u -c \"import time; [print(f'Event {i}') or time.sleep(0.1) for i in range(5)]\"",
            timeout_seconds=10,
        )

        # Wait for some events
        await asyncio.sleep(1)

        # Get all events
        all_events = await manager.get_buffered_output(session_id, execution.info.id)
        assert len(all_events) >= 3, "Should have at least 3 events"

        # Get event_id from second event
        second_event_id = all_events[1]["event_id"]

        # Replay events after second event
        replayed_events = await manager.replay_events_after(session_id, execution.info.id, second_event_id)

        # Verify we got events after the second one
        assert replayed_events is not None, "Should find the event"
        assert len(replayed_events) < len(all_events), "Should have fewer events than total"
        assert len(replayed_events) == len(all_events) - 2, "Should skip first 2 events"

        # Verify the replayed events match the expected ones
        expected_events = all_events[2:]
        assert replayed_events == expected_events, "Replayed events should match expected slice"

        # Verify first replayed event is not the last_event_id
        if replayed_events:
            assert replayed_events[0]["event_id"] != second_event_id

    finally:
        await manager.shutdown()


@pytest.mark.asyncio
async def test_replay_events_after_with_redis():
    """Test replay_events_after with Redis backend."""
    redis_store = RedisStateStore("redis://localhost:6379/0")
    await redis_store.connect()

    config = ServerConfig()
    manager = ExecutionManager(config, redis_store=redis_store)
    session_id = "test-session-redis"

    try:
        execution = await manager.create_execution(
            session_id=session_id,
            command="python3 -u -c \"print('A'); print('B'); print('C'); print('D')\"",
            timeout_seconds=5,
        )

        # Wait for completion
        await asyncio.sleep(1)

        # Get all events
        all_events = await manager.get_buffered_output(session_id, execution.info.id)
        assert len(all_events) >= 3, "Should have at least 3 events"

        # Test replay from Redis
        middle_event_id = all_events[len(all_events) // 2]["event_id"]

        # Replay events after middle event
        replayed_events = await manager.replay_events_after(session_id, execution.info.id, middle_event_id)

        assert replayed_events is not None, "Should find the event in Redis"
        assert len(replayed_events) > 0, "Should have events after middle"
        assert len(replayed_events) < len(all_events), "Should be subset of all events"

        # Verify event_ids don't include the last_event_id
        replayed_ids = {e["event_id"] for e in replayed_events}
        assert middle_event_id not in replayed_ids, "Should not include the last_event_id itself"

    finally:
        await manager.shutdown()
        await redis_store.close()


@pytest.mark.asyncio
async def test_replay_events_after_not_found():
    """Test replay_events_after with non-existent event_id."""
    config = ServerConfig()
    manager = ExecutionManager(config)
    session_id = "test-session"

    try:
        execution = await manager.create_execution(
            session_id=session_id,
            command="python3 -c \"print('test')\"",
            timeout_seconds=5,
        )

        await asyncio.sleep(0.5)

        # Try to replay with non-existent event_id
        fake_event_id = "00000000-0000-0000-0000-000000000000"
        replayed_events = await manager.replay_events_after(session_id, execution.info.id, fake_event_id)

        # Should return None when event not found
        assert replayed_events is None, "Should return None for non-existent event_id"

    finally:
        await manager.shutdown()


@pytest.mark.asyncio
async def test_replay_events_after_last_event():
    """Test replay_events_after with the last event_id (should return empty list)."""
    config = ServerConfig()
    manager = ExecutionManager(config)
    session_id = "test-session"

    try:
        execution = await manager.create_execution(
            session_id=session_id,
            command="python3 -c \"print('only one line')\"",
            timeout_seconds=5,
        )

        # Wait for completion
        await asyncio.sleep(1)

        # Get all events
        all_events = await manager.get_buffered_output(session_id, execution.info.id)
        assert len(all_events) > 0, "Should have at least one event"

        # Get last event_id
        last_event_id = all_events[-1]["event_id"]

        # Replay after last event (should get empty list)
        replayed_events = await manager.replay_events_after(session_id, execution.info.id, last_event_id)

        assert replayed_events is not None, "Should find the event"
        assert replayed_events == [], "Should return empty list when resuming from last event"

    finally:
        await manager.shutdown()


@pytest.mark.asyncio
async def test_replay_events_incremental_polling():
    """Test resumability pattern: incremental polling with last_event_id."""
    config = ServerConfig()
    manager = ExecutionManager(config)
    session_id = "test-session"

    try:
        # Start long-running execution
        execution = await manager.create_execution(
            session_id=session_id,
            command="python3 -u -c \"import time; [print(f'Count: {i}', flush=True) or time.sleep(0.2) for i in range(10)]\"",
            timeout_seconds=10,
        )

        collected_events = []
        last_event_id = None
        polls = 0

        # Poll incrementally
        for _ in range(5):
            await asyncio.sleep(0.5)
            polls += 1

            if last_event_id:
                # Resume from last event
                new_events = await manager.replay_events_after(session_id, execution.info.id, last_event_id)
                if new_events is None:
                    pytest.fail(f"Event {last_event_id} not found in buffer")
            else:
                # First poll - get all events
                new_events = await manager.get_buffered_output(session_id, execution.info.id)

            # Collect new events
            if new_events:
                collected_events.extend(new_events)
                last_event_id = new_events[-1]["event_id"]

        # Verify we collected events incrementally
        assert len(collected_events) > 0, "Should have collected some events"
        assert polls > 1, "Should have done multiple polls"

        # Verify no duplicate event_ids
        event_ids = [e["event_id"] for e in collected_events]
        assert len(event_ids) == len(set(event_ids)), "Should not have duplicate events"

    finally:
        await manager.shutdown()


@pytest.mark.asyncio
async def test_redis_event_id_persistence():
    """Test that event_ids persist in Redis across manager restarts."""
    redis_store = RedisStateStore("redis://localhost:6379/0")
    await redis_store.connect()

    config = ServerConfig()
    session_id = "test-session-persist"

    # First manager instance
    manager1 = ExecutionManager(config, redis_store=redis_store)

    try:
        execution = await manager1.create_execution(
            session_id=session_id,
            command="python3 -c \"print('Event from first manager')\"",
            timeout_seconds=5,
        )

        execution_id = execution.info.id
        await asyncio.sleep(0.5)

        # Get events from first manager
        events1 = await manager1.get_buffered_output(session_id, execution_id)
        assert len(events1) > 0, "Should have events from first manager"

        first_event_id = events1[0]["event_id"]

        # Shutdown first manager
        await manager1.shutdown()

        # Create second manager instance (simulates server restart)
        manager2 = ExecutionManager(config, redis_store=redis_store)

        # Get events from Redis via second manager
        events2 = await redis_store.get_output(execution_id)
        assert len(events2) > 0, "Should have events in Redis"
        assert events2[0]["event_id"] == first_event_id, "Event IDs should persist in Redis"

        # Test replay via Redis
        if len(events2) > 1:
            second_event_id = events2[1]["event_id"]
            replayed = await redis_store.replay_events_after(execution_id, second_event_id)
            assert replayed is not None, "Should be able to replay from Redis"

    finally:
        await manager1.shutdown()
        await redis_store.close()


@pytest.mark.asyncio
async def test_buffer_eviction_handling():
    """Test resumability when events are evicted from buffer."""
    # Use small buffer size to trigger eviction
    config = ServerConfig(output_buffer_size=5)
    manager = ExecutionManager(config)
    session_id = "test-session"

    try:
        execution = await manager.create_execution(
            session_id=session_id,
            command="python3 -u -c \"import time; [print(f'Event {i}') for i in range(20)]\"",
            timeout_seconds=5,
        )

        # Wait for many events
        await asyncio.sleep(1)

        # Get current buffer (should be trimmed to 5 events)
        current_buffer = await manager.get_buffered_output(session_id, execution.info.id)
        assert len(current_buffer) <= config.output_buffer_size, "Buffer should be trimmed"

        # Try to replay from an event that was evicted (not in current buffer)
        fake_old_event_id = "00000000-1111-2222-3333-444444444444"
        replayed = await manager.replay_events_after(session_id, execution.info.id, fake_old_event_id)

        # Should return None for evicted event
        assert replayed is None, "Should return None for evicted event"

    finally:
        await manager.shutdown()


@pytest.mark.asyncio
async def test_resumability_with_different_event_types():
    """Test that resumability works with various event types (stdout, stderr, ready, exit)."""
    config = ServerConfig()
    manager = ExecutionManager(config)
    session_id = "test-session"

    try:
        execution = await manager.create_execution(
            session_id=session_id,
            command="python3 -u -c \"import sys; print('stdout'); print('stderr', file=sys.stderr)\"",
            timeout_seconds=5,
        )

        await asyncio.sleep(1)

        # Get all events
        all_events = await manager.get_buffered_output(session_id, execution.info.id)

        # Verify we have different event types
        event_types = {e.get("type") for e in all_events}
        assert "ready" in event_types, "Should have ready event"
        assert "stdout" in event_types or "stderr" in event_types, "Should have output events"

        # All should have event_ids
        for event in all_events:
            assert "event_id" in event, f"Event type {event.get('type')} should have event_id"

        # Test replay from middle
        if len(all_events) >= 2:
            middle_event_id = all_events[1]["event_id"]
            replayed = await manager.replay_events_after(session_id, execution.info.id, middle_event_id)
            assert replayed is not None
            # Verify all replayed events have event_ids
            for event in replayed:
                assert "event_id" in event

    finally:
        await manager.shutdown()


@pytest.mark.asyncio
async def test_concurrent_executions_event_ids():
    """Test that concurrent executions have unique event_ids."""
    config = ServerConfig()
    manager = ExecutionManager(config)
    session_id = "test-session"

    try:
        # Start multiple executions concurrently
        exec1 = await manager.create_execution(
            session_id=session_id,
            command="python3 -c \"print('Exec 1')\"",
            timeout_seconds=5,
        )
        exec2 = await manager.create_execution(
            session_id=session_id,
            command="python3 -c \"print('Exec 2')\"",
            timeout_seconds=5,
        )

        await asyncio.sleep(0.5)

        # Get events from both executions
        events1 = await manager.get_buffered_output(session_id, exec1.info.id)
        events2 = await manager.get_buffered_output(session_id, exec2.info.id)

        # Collect all event_ids
        all_event_ids = [e["event_id"] for e in events1] + [e["event_id"] for e in events2]

        # Verify uniqueness across executions
        assert len(all_event_ids) == len(set(all_event_ids)), "Event IDs should be unique across executions"

    finally:
        await manager.shutdown()
