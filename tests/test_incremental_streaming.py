"""Test incremental streaming of execution output."""

import asyncio

import pytest

from sandbox_runtime.server.config import ServerConfig
from sandbox_runtime.server.execution_manager import ExecutionManager


@pytest.mark.asyncio
async def test_incremental_output_buffering():
    """Test that output is buffered incrementally even without active stream consumption."""
    config = ServerConfig(
        host="127.0.0.1",
        port=8080,
        max_concurrent_executions=10,
        max_executions_per_session=5,
        execution_timeout_seconds=30,
    )
    manager = ExecutionManager(config)
    session_id = "test-session"

    try:
        # Start a command that produces output over time
        execution = await manager.create_execution(
            session_id=session_id,
            command="python -u -c \"import time; [print(f'Count: {i}') or time.sleep(0.1) for i in range(1, 6)]\"",
            timeout_seconds=10,
        )

        # Poll for output multiple times without calling stream()
        output_snapshots = []

        for _ in range(3):
            await asyncio.sleep(0.15)  # Wait a bit for some output
            output = await manager.get_buffered_output(session_id, execution.info.id)
            output_snapshots.append(len(output))

        # Wait for completion
        await asyncio.sleep(1)
        final_output = await manager.get_buffered_output(session_id, execution.info.id)

        # Verify incremental growth
        print(f"Output snapshots: {output_snapshots}")
        print(f"Final output length: {len(final_output)}")

        # At least one snapshot should show incremental growth
        # (not all empty, and not just the final one having data)
        assert any(count > 0 for count in output_snapshots), "Output should appear incrementally"

        # Final output should have all events
        assert len(final_output) > 0, "Final output should not be empty"

        # Verify we got the expected output events
        stdout_events = [e for e in final_output if e["type"] == "stdout"]
        assert len(stdout_events) >= 5, f"Should have at least 5 stdout events, got {len(stdout_events)}"

    finally:
        await manager.shutdown()


@pytest.mark.asyncio
async def test_polling_without_wait_returns_incremental_output():
    """Test that get_execution_output with wait=False returns incremental output."""
    config = ServerConfig(
        host="127.0.0.1",
        port=8080,
        max_concurrent_executions=10,
        max_executions_per_session=5,
        execution_timeout_seconds=30,
    )
    manager = ExecutionManager(config)
    session_id = "test-session"

    try:
        # Start a long-running command
        execution = await manager.create_execution(
            session_id=session_id,
            command="python -u -c \"import time; [print(f'Line {i}', flush=True) or time.sleep(0.2) for i in range(5)]\"",
            timeout_seconds=10,
        )

        # Poll multiple times
        poll_results = []
        for i in range(5):
            await asyncio.sleep(0.25)
            output = await manager.get_buffered_output(session_id, execution.info.id)
            poll_results.append(
                {
                    "poll": i + 1,
                    "event_count": len(output),
                    "has_stdout": any(e["type"] == "stdout" for e in output),
                }
            )

        print(f"Poll results: {poll_results}")

        # Verify that we saw output during polling
        has_incremental_output = any(r["has_stdout"] for r in poll_results[:-1])  # Check all but last
        assert has_incremental_output, "Should see stdout events during polling, not just at the end"

        # Verify final output has all events
        final_output = await manager.get_buffered_output(session_id, execution.info.id)
        stdout_count = sum(1 for e in final_output if e["type"] == "stdout")
        assert stdout_count >= 5, f"Expected at least 5 stdout events, got {stdout_count}"

    finally:
        await manager.shutdown()


@pytest.mark.asyncio
async def test_stream_still_works_with_new_buffering():
    """Test that stream() still works correctly with the new buffering approach."""
    config = ServerConfig(
        host="127.0.0.1",
        port=8080,
        max_concurrent_executions=10,
        max_executions_per_session=5,
        execution_timeout_seconds=30,
    )
    manager = ExecutionManager(config)
    session_id = "test-session"

    try:
        execution = await manager.create_execution(
            session_id=session_id,
            command="python -u -c \"print('Hello'); print('World')\"",
            timeout_seconds=10,
        )

        # Consume via stream
        events = []
        async for event in execution.stream():
            events.append(event)

        # Verify events were received
        stdout_events = [e for e in events if e["type"] == "stdout"]
        assert len(stdout_events) >= 2, f"Expected at least 2 stdout events, got {len(stdout_events)}"

        # Verify buffer also has the events
        buffered = await manager.get_buffered_output(session_id, execution.info.id)
        buffered_stdout = [e for e in buffered if e["type"] == "stdout"]
        assert len(buffered_stdout) >= 2, f"Buffer should also have events, got {len(buffered_stdout)}"

    finally:
        await manager.shutdown()
