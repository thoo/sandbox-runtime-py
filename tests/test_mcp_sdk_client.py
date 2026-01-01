"""Tests for MCP SDK client connectivity and resumability."""

import asyncio
import json
import subprocess
import time

import httpx
import pytest
from mcp import ClientSession, types
from mcp.client.streamable_http import streamable_http_client

# Module-level server for all tests
_server_proc = None
_server_url = "http://localhost:8081/mcp"


def setup_module():
    """Start MCP server once for all tests."""
    global _server_proc
    _server_proc = subprocess.Popen(
        [
            "uv",
            "run",
            "srt-mcp-server",
            "--port",
            "8081",
            "--log-file",
            "/tmp/mcp_test_server.log",
        ],
        env={
            **subprocess.os.environ,
            "SANDBOX_AUTH_TOKEN": "test-token-123",
            "REDIS_URL": "redis://localhost:6379/1",
        },
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    time.sleep(4)  # Wait for server to start


def teardown_module():
    """Stop MCP server after all tests."""
    global _server_proc
    if _server_proc:
        _server_proc.terminate()
        _server_proc.wait(timeout=5)


async def create_mcp_session():
    """Create an MCP client session."""
    http_client = httpx.AsyncClient(
        headers={"Authorization": "Bearer test-token-123"},
        timeout=60.0,
    )

    client_ctx = streamable_http_client(_server_url, http_client=http_client)
    read_stream, write_stream, _ = await client_ctx.__aenter__()

    session = ClientSession(read_stream, write_stream)
    await session.__aenter__()
    await session.initialize()

    return session, client_ctx


@pytest.mark.asyncio
async def test_mcp_client_initialization():
    """Test MCP client can initialize and connect."""
    session, client_ctx = await create_mcp_session()

    try:
        # List tools
        result = await session.list_tools()
        assert result.tools is not None
        assert len(result.tools) > 0

        # Verify expected tools
        tool_names = {tool.name for tool in result.tools}
        assert "execute_code" in tool_names
        assert "get_execution_output" in tool_names
    finally:
        await session.__aexit__(None, None, None)
        await client_ctx.__aexit__(None, None, None)


@pytest.mark.asyncio
async def test_mcp_client_execute_code():
    """Test executing code via MCP SDK client."""
    session, client_ctx = await create_mcp_session()

    try:
        result = await session.call_tool(
            "execute_code",
            {
                "command": "python3 -c \"print('Hello from MCP SDK test')\"",
                "wait_for_completion": True,
                "timeout_seconds": 10,
            },
        )

        assert not result.isError
        assert len(result.content) > 0

        for content in result.content:
            if isinstance(content, types.TextContent):
                data = json.loads(content.text)
                assert data["status"] == "completed"
                assert data["exit_code"] == 0
                assert len(data["output"]) > 0

                # Verify event IDs
                for event in data["output"]:
                    assert "event_id" in event
                    assert len(event["event_id"]) > 0
    finally:
        await session.__aexit__(None, None, None)
        await client_ctx.__aexit__(None, None, None)


@pytest.mark.asyncio
async def test_mcp_client_streaming_output():
    """Test streaming output via MCP SDK client."""
    session, client_ctx = await create_mcp_session()

    try:
        # Start long-running execution
        result = await session.call_tool(
            "execute_code",
            {
                "command": "python3 -u -c \"import time; [print(f'Line {i}', flush=True) or time.sleep(0.2) for i in range(5)]\"",  # noqa: E501
                "wait_for_completion": False,
                "timeout_seconds": 10,
            },
        )

        execution_id = None
        for content in result.content:
            if isinstance(content, types.TextContent):
                data = json.loads(content.text)
                execution_id = data["execution_id"]

        assert execution_id is not None

        # Poll for output
        await asyncio.sleep(0.5)

        result = await session.call_tool(
            "get_execution_output",
            {"execution_id": execution_id, "wait": False},
        )

        for content in result.content:
            if isinstance(content, types.TextContent):
                data = json.loads(content.text)
                output = data["output"]
                assert len(output) > 0

                # Verify event IDs
                for event in output:
                    assert "event_id" in event
    finally:
        await session.__aexit__(None, None, None)
        await client_ctx.__aexit__(None, None, None)


@pytest.mark.asyncio
async def test_mcp_client_resumability():
    """Test resumability using last_event_id via MCP SDK client."""
    session, client_ctx = await create_mcp_session()

    try:
        # Start execution
        result = await session.call_tool(
            "execute_code",
            {
                "command": "python3 -u -c \"import time; [print(f'Event {i}', flush=True) or time.sleep(0.3) for i in range(7)]\"",  # noqa: E501
                "wait_for_completion": False,
                "timeout_seconds": 10,
            },
        )

        execution_id = None
        for content in result.content:
            if isinstance(content, types.TextContent):
                data = json.loads(content.text)
                execution_id = data["execution_id"]

        assert execution_id is not None

        # Wait and get initial output
        await asyncio.sleep(1.0)

        result = await session.call_tool(
            "get_execution_output",
            {"execution_id": execution_id, "wait": False},
        )

        initial_output = []
        for content in result.content:
            if isinstance(content, types.TextContent):
                data = json.loads(content.text)
                initial_output = data["output"]

        assert len(initial_output) >= 2

        # Save last event ID
        last_event_id = initial_output[1]["event_id"]

        # Wait for more events
        await asyncio.sleep(1.0)

        # Resume from last event ID
        result = await session.call_tool(
            "get_execution_output",
            {
                "execution_id": execution_id,
                "wait": False,
                "last_event_id": last_event_id,
            },
        )

        resumed_output = []
        for content in result.content:
            if isinstance(content, types.TextContent):
                data = json.loads(content.text)
                resumed_output = data["output"]

        # Verify we got new events
        assert len(resumed_output) > 0

        # Verify no duplicates
        initial_ids = {e["event_id"] for e in initial_output[:2]}
        resumed_ids = {e["event_id"] for e in resumed_output}
        duplicates = initial_ids & resumed_ids

        assert len(duplicates) == 0, "Should not return duplicate events"
    finally:
        await session.__aexit__(None, None, None)
        await client_ctx.__aexit__(None, None, None)


@pytest.mark.asyncio
async def test_mcp_client_resume_from_last_event():
    """Test resuming from the last event returns empty list."""
    session, client_ctx = await create_mcp_session()

    try:
        result = await session.call_tool(
            "execute_code",
            {
                "command": "python3 -c \"print('single line')\"",
                "wait_for_completion": True,
                "timeout_seconds": 10,
            },
        )

        execution_id = None
        all_output = []
        for content in result.content:
            if isinstance(content, types.TextContent):
                data = json.loads(content.text)
                execution_id = data["execution_id"]
                all_output = data["output"]

        assert len(all_output) > 0

        last_event_id = all_output[-1]["event_id"]

        # Resume from last event
        result = await session.call_tool(
            "get_execution_output",
            {
                "execution_id": execution_id,
                "wait": False,
                "last_event_id": last_event_id,
            },
        )

        resumed_output = []
        for content in result.content:
            if isinstance(content, types.TextContent):
                data = json.loads(content.text)
                resumed_output = data["output"]

        assert resumed_output == [], "Should return empty list"
    finally:
        await session.__aexit__(None, None, None)
        await client_ctx.__aexit__(None, None, None)


@pytest.mark.asyncio
async def test_mcp_client_resume_with_invalid_event_id():
    """Test resuming with non-existent event ID returns error."""
    session, client_ctx = await create_mcp_session()

    try:
        result = await session.call_tool(
            "execute_code",
            {
                "command": "python3 -c \"print('test')\"",
                "wait_for_completion": True,
                "timeout_seconds": 10,
            },
        )

        execution_id = None
        for content in result.content:
            if isinstance(content, types.TextContent):
                data = json.loads(content.text)
                execution_id = data["execution_id"]

        # Try with fake event ID
        fake_event_id = "00000000-0000-0000-0000-000000000000"

        result = await session.call_tool(
            "get_execution_output",
            {
                "execution_id": execution_id,
                "wait": False,
                "last_event_id": fake_event_id,
            },
        )

        for content in result.content:
            if isinstance(content, types.TextContent):
                data = json.loads(content.text)
                assert "error" in data
                assert "not found" in data["error"].lower() or "evicted" in data["error"].lower()
    finally:
        await session.__aexit__(None, None, None)
        await client_ctx.__aexit__(None, None, None)
