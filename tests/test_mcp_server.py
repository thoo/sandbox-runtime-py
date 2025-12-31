"""Tests for sandbox_runtime.server.mcp_server module."""

from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import sandbox_runtime.server.mcp_server as mcp_server_module
from sandbox_runtime.server.execution_manager import (
    ExecutionCompletedError,
    ExecutionNotFoundError,
    ExecutionNotInteractiveError,
    ExecutionStatus,
    TooManyExecutionsError,
)
from sandbox_runtime.server.mcp_server import (
    BearerAuthMiddleware,
    _get_int_env,
    _session_id_map,
    cancel_execution,
    execute_code,
    execute_code_async,
    get_execution_output,
    get_execution_status,
    get_session_id,
    list_executions,
    send_stdin,
)


def test_get_int_env_uses_default_on_missing(monkeypatch):
    """Missing env vars should return the default."""
    monkeypatch.delenv("SANDBOX_PORT", raising=False)
    assert _get_int_env("SANDBOX_PORT", 8080) == 8080


def test_get_int_env_uses_default_on_invalid(monkeypatch):
    """Invalid int env vars should return the default."""
    monkeypatch.setenv("SANDBOX_PORT", "nope")
    assert _get_int_env("SANDBOX_PORT", 8080) == 8080


def test_get_int_env_parses_valid_int(monkeypatch):
    """Valid int env vars should be parsed."""
    monkeypatch.setenv("SANDBOX_PORT", "9090")
    assert _get_int_env("SANDBOX_PORT", 8080) == 9090


async def test_execute_code_missing_context_returns_error():
    """execute_code should return an error if ctx is missing."""
    result = await execute_code(command="echo hi", ctx=None)
    assert result["status"] == "failed"
    assert "Missing request context" in result["error"]


async def test_list_executions_missing_context_returns_error():
    """list_executions should return an error if ctx is missing."""
    result = await list_executions(ctx=None)
    assert result["error"] == "Missing request context"


async def test_get_execution_status_missing_context_returns_error():
    """get_execution_status should return an error if ctx is missing."""
    result = await get_execution_status(execution_id="x", ctx=None)
    assert result["error"] == "Missing request context"


async def test_get_execution_output_missing_context_returns_error():
    """get_execution_output should return an error if ctx is missing."""
    result = await get_execution_output(execution_id="x", ctx=None)
    assert result["error"] == "Missing request context"
    assert result["output"] == []


async def test_execute_code_no_wait_returns_running():
    """execute_code should return running status when not waiting."""
    manager = Mock()
    manager.create_execution = AsyncMock(return_value=SimpleNamespace(info=SimpleNamespace(id="exec-1")))
    with patch("sandbox_runtime.server.mcp_server._get_manager_and_session", return_value=(manager, "sess-1")):
        result = await execute_code(command="echo hi", wait_for_completion=False, ctx=Mock())

    assert result["status"] == "running"
    assert result["execution_id"] == "exec-1"
    manager.create_execution.assert_awaited_once()


async def test_send_stdin_appends_newline():
    """send_stdin should append a newline if missing."""
    manager = Mock()
    manager.send_stdin = AsyncMock()
    with patch("sandbox_runtime.server.mcp_server._get_manager_and_session", return_value=(manager, "sess-1")):
        result = await send_stdin(execution_id="exec-1", input_data="hello", ctx=Mock())

    assert result["success"] is True
    manager.send_stdin.assert_awaited_once_with("sess-1", "exec-1", "hello\n")


async def test_get_execution_output_uses_public_get_execution():
    """get_execution_output should use get_execution and return buffered output."""
    execution = SimpleNamespace(info=SimpleNamespace(status=ExecutionStatus.COMPLETED, exit_code=0))
    manager = Mock(spec=["get_execution", "get_buffered_output"])
    manager.get_execution = Mock(return_value=execution)
    manager.get_buffered_output = AsyncMock(return_value=[{"type": "stdout", "data": "ok"}])

    with patch("sandbox_runtime.server.mcp_server._get_manager_and_session", return_value=(manager, "sess-1")):
        result = await get_execution_output(execution_id="exec-1", wait=False, ctx=Mock())

    assert result["status"] == ExecutionStatus.COMPLETED.value
    assert result["exit_code"] == 0
    assert result["output"] == [{"type": "stdout", "data": "ok"}]


# --- execute_code_async tests ---


async def test_execute_code_async_missing_context_returns_error():
    """execute_code_async should return an error if ctx is missing."""
    result = await execute_code_async(command="echo hi", ctx=None)
    assert result["status"] == "failed"
    assert "Missing request context" in result["error"]


async def test_execute_code_async_returns_running():
    """execute_code_async should return running status."""
    manager = Mock()
    manager.create_execution = AsyncMock(return_value=SimpleNamespace(info=SimpleNamespace(id="exec-1")))
    with patch("sandbox_runtime.server.mcp_server._get_manager_and_session", return_value=(manager, "sess-1")):
        result = await execute_code_async(command="sleep 10", ctx=Mock())

    assert result["status"] == "running"
    assert result["execution_id"] == "exec-1"


async def test_execute_code_async_too_many_executions():
    """execute_code_async should return error on TooManyExecutionsError."""
    manager = Mock()
    manager.create_execution = AsyncMock(side_effect=TooManyExecutionsError("limit reached"))
    with patch("sandbox_runtime.server.mcp_server._get_manager_and_session", return_value=(manager, "sess-1")):
        result = await execute_code_async(command="echo hi", ctx=Mock())

    assert result["status"] == "failed"
    assert "limit reached" in result["error"]


# --- execute_code additional tests ---


async def test_execute_code_wait_for_completion():
    """execute_code with wait_for_completion=True should return all output."""

    async def mock_stream():
        yield {"type": "stdout", "data": "hello"}
        yield {"type": "exit", "code": 0}

    execution = SimpleNamespace(
        info=SimpleNamespace(id="exec-1", status=ExecutionStatus.COMPLETED, exit_code=0),
        stream=mock_stream,
    )
    manager = Mock()
    manager.create_execution = AsyncMock(return_value=execution)

    with patch("sandbox_runtime.server.mcp_server._get_manager_and_session", return_value=(manager, "sess-1")):
        result = await execute_code(command="echo hello", wait_for_completion=True, ctx=Mock())

    assert result["status"] == ExecutionStatus.COMPLETED.value
    assert result["exit_code"] == 0
    assert result["output"] == [{"type": "stdout", "data": "hello"}, {"type": "exit", "code": 0}]


async def test_execute_code_too_many_executions():
    """execute_code should return error on TooManyExecutionsError."""
    manager = Mock()
    manager.create_execution = AsyncMock(side_effect=TooManyExecutionsError("limit reached"))
    with patch("sandbox_runtime.server.mcp_server._get_manager_and_session", return_value=(manager, "sess-1")):
        result = await execute_code(command="echo hi", ctx=Mock())

    assert result["status"] == "failed"
    assert "limit reached" in result["error"]


# --- cancel_execution tests ---


async def test_cancel_execution_missing_context_returns_error():
    """cancel_execution should return an error if ctx is missing."""
    result = await cancel_execution(execution_id="x", ctx=None)
    assert result["success"] is False
    assert result["error"] == "Missing request context"


async def test_cancel_execution_success():
    """cancel_execution should return success with was_running flag."""
    manager = Mock()
    manager.cancel_execution = AsyncMock(return_value=True)
    with patch("sandbox_runtime.server.mcp_server._get_manager_and_session", return_value=(manager, "sess-1")):
        result = await cancel_execution(execution_id="exec-1", ctx=Mock())

    assert result["success"] is True
    assert result["was_running"] is True
    manager.cancel_execution.assert_awaited_once_with("sess-1", "exec-1", force=False)


async def test_cancel_execution_with_force():
    """cancel_execution with force=True should pass force to manager."""
    manager = Mock()
    manager.cancel_execution = AsyncMock(return_value=True)
    with patch("sandbox_runtime.server.mcp_server._get_manager_and_session", return_value=(manager, "sess-1")):
        result = await cancel_execution(execution_id="exec-1", force=True, ctx=Mock())

    assert result["success"] is True
    manager.cancel_execution.assert_awaited_once_with("sess-1", "exec-1", force=True)


async def test_cancel_execution_not_found():
    """cancel_execution should return error when execution not found."""
    manager = Mock()
    manager.cancel_execution = AsyncMock(side_effect=ExecutionNotFoundError("not found"))
    with patch("sandbox_runtime.server.mcp_server._get_manager_and_session", return_value=(manager, "sess-1")):
        result = await cancel_execution(execution_id="exec-1", ctx=Mock())

    assert result["success"] is False
    assert result["error"] == "Execution not found"


# --- send_stdin additional error tests ---


async def test_send_stdin_execution_not_found():
    """send_stdin should return error when execution not found."""
    manager = Mock()
    manager.send_stdin = AsyncMock(side_effect=ExecutionNotFoundError("not found"))
    with patch("sandbox_runtime.server.mcp_server._get_manager_and_session", return_value=(manager, "sess-1")):
        result = await send_stdin(execution_id="exec-1", input_data="hello", ctx=Mock())

    assert result["success"] is False
    assert result["error"] == "Execution not found"


async def test_send_stdin_not_interactive():
    """send_stdin should return error when execution is not interactive."""
    manager = Mock()
    manager.send_stdin = AsyncMock(side_effect=ExecutionNotInteractiveError("not interactive"))
    with patch("sandbox_runtime.server.mcp_server._get_manager_and_session", return_value=(manager, "sess-1")):
        result = await send_stdin(execution_id="exec-1", input_data="hello", ctx=Mock())

    assert result["success"] is False
    assert result["error"] == "Execution is not interactive"


async def test_send_stdin_already_completed():
    """send_stdin should return error when execution already completed."""
    manager = Mock()
    manager.send_stdin = AsyncMock(side_effect=ExecutionCompletedError("already completed"))
    with patch("sandbox_runtime.server.mcp_server._get_manager_and_session", return_value=(manager, "sess-1")):
        result = await send_stdin(execution_id="exec-1", input_data="hello", ctx=Mock())

    assert result["success"] is False
    assert result["error"] == "Execution already completed"


async def test_send_stdin_missing_context_returns_error():
    """send_stdin should return an error if ctx is missing."""
    result = await send_stdin(execution_id="x", input_data="hello", ctx=None)
    assert result["success"] is False
    assert result["error"] == "Missing request context"


# --- get_execution_status additional tests ---


async def test_get_execution_status_success():
    """get_execution_status should return status from manager."""
    manager = Mock()
    manager.get_status = AsyncMock(return_value={"status": "completed", "exit_code": 0})
    with patch("sandbox_runtime.server.mcp_server._get_manager_and_session", return_value=(manager, "sess-1")):
        result = await get_execution_status(execution_id="exec-1", ctx=Mock())

    assert result["status"] == "completed"
    assert result["exit_code"] == 0


async def test_get_execution_status_not_found():
    """get_execution_status should return error when execution not found."""
    manager = Mock()
    manager.get_status = AsyncMock(side_effect=ExecutionNotFoundError("not found"))
    with patch("sandbox_runtime.server.mcp_server._get_manager_and_session", return_value=(manager, "sess-1")):
        result = await get_execution_status(execution_id="exec-1", ctx=Mock())

    assert result["error"] == "Execution not found"


# --- get_execution_output additional tests ---


async def test_get_execution_output_not_found():
    """get_execution_output should return error when execution not found."""
    manager = Mock()
    manager.get_execution = Mock(side_effect=ExecutionNotFoundError("not found"))
    with patch("sandbox_runtime.server.mcp_server._get_manager_and_session", return_value=(manager, "sess-1")):
        result = await get_execution_output(execution_id="exec-1", ctx=Mock())

    assert result["error"] == "Execution not found"
    assert result["output"] == []


async def test_get_execution_output_wait_for_running():
    """get_execution_output with wait=True should wait for completion."""

    async def mock_stream():
        yield {"type": "stdout", "data": "output"}
        yield {"type": "exit", "code": 0}
        # Update status after stream completes
        execution.info.status = ExecutionStatus.COMPLETED
        execution.info.exit_code = 0

    execution = SimpleNamespace(
        info=SimpleNamespace(status=ExecutionStatus.RUNNING, exit_code=None),
        stream=mock_stream,
    )

    manager = Mock()
    manager.get_execution = Mock(return_value=execution)

    with patch("sandbox_runtime.server.mcp_server._get_manager_and_session", return_value=(manager, "sess-1")):
        result = await get_execution_output(execution_id="exec-1", wait=True, ctx=Mock())

    assert result["output"] == [{"type": "stdout", "data": "output"}, {"type": "exit", "code": 0}]


# --- list_executions tests ---


async def test_list_executions_success():
    """list_executions should return list from manager."""
    manager = Mock()
    manager.list_executions = AsyncMock(return_value=[{"id": "exec-1", "status": "running"}])
    with patch("sandbox_runtime.server.mcp_server._get_manager_and_session", return_value=(manager, "sess-1")):
        result = await list_executions(ctx=Mock())

    assert result == [{"id": "exec-1", "status": "running"}]


# --- get_session_id tests ---


def test_get_session_id_uses_session_object_id():
    """get_session_id should use session object id to generate consistent UUID."""
    _session_id_map.clear()
    session = SimpleNamespace()
    ctx = Mock()
    ctx.request_context = SimpleNamespace(session=session)
    ctx.client_id = None

    session_id_1 = get_session_id(ctx)
    session_id_2 = get_session_id(ctx)

    # Same session should return same UUID
    assert session_id_1 == session_id_2
    # Should be a valid UUID format
    assert len(session_id_1) == 36
    assert session_id_1.count("-") == 4

    _session_id_map.clear()


def test_get_session_id_different_sessions_get_different_ids():
    """Different sessions should get different UUIDs."""
    _session_id_map.clear()
    session1 = SimpleNamespace()
    session2 = SimpleNamespace()

    ctx1 = Mock()
    ctx1.request_context = SimpleNamespace(session=session1)
    ctx1.client_id = None

    ctx2 = Mock()
    ctx2.request_context = SimpleNamespace(session=session2)
    ctx2.client_id = None

    session_id_1 = get_session_id(ctx1)
    session_id_2 = get_session_id(ctx2)

    assert session_id_1 != session_id_2

    _session_id_map.clear()


def test_get_session_id_falls_back_to_client_id():
    """get_session_id should fall back to client_id if no session."""
    ctx = Mock()
    ctx.request_context = SimpleNamespace(session=None)
    ctx.client_id = "client-123"

    session_id = get_session_id(ctx)
    assert session_id == "client-123"


def test_get_session_id_generates_uuid_as_last_resort():
    """get_session_id should generate UUID if no session and no client_id."""
    ctx = Mock()
    ctx.request_context = None
    ctx.client_id = None

    session_id = get_session_id(ctx)
    # Should be a valid UUID format
    assert len(session_id) == 36
    assert session_id.count("-") == 4


# --- BearerAuthMiddleware tests ---


async def test_auth_middleware_allows_request_when_auth_disabled():
    """Middleware should allow requests when auth token is not set."""
    original_token = mcp_server_module._auth_token
    try:
        mcp_server_module._auth_token = None

        call_next = AsyncMock(return_value="response")
        middleware = BearerAuthMiddleware(app=Mock())

        request = Mock()
        request.url.path = "/mcp"

        result = await middleware.dispatch(request, call_next)

        assert result == "response"
        call_next.assert_awaited_once_with(request)
    finally:
        mcp_server_module._auth_token = original_token


async def test_auth_middleware_allows_health_endpoint_without_auth():
    """Middleware should allow /health endpoint without auth."""
    original_token = mcp_server_module._auth_token
    try:
        mcp_server_module._auth_token = "secret-token"

        call_next = AsyncMock(return_value="response")
        middleware = BearerAuthMiddleware(app=Mock())

        request = Mock()
        request.url.path = "/health"

        result = await middleware.dispatch(request, call_next)

        assert result == "response"
        call_next.assert_awaited_once_with(request)
    finally:
        mcp_server_module._auth_token = original_token


async def test_auth_middleware_rejects_missing_auth_header():
    """Middleware should reject requests without Authorization header."""
    original_token = mcp_server_module._auth_token
    try:
        mcp_server_module._auth_token = "secret-token"

        middleware = BearerAuthMiddleware(app=Mock())

        request = Mock()
        request.url.path = "/mcp"
        request.headers.get = Mock(return_value=None)

        result = await middleware.dispatch(request, AsyncMock())

        assert result.status_code == 401
        assert b"Missing Authorization header" in result.body
    finally:
        mcp_server_module._auth_token = original_token


async def test_auth_middleware_rejects_invalid_auth_format():
    """Middleware should reject requests with invalid Authorization format."""
    original_token = mcp_server_module._auth_token
    try:
        mcp_server_module._auth_token = "secret-token"

        middleware = BearerAuthMiddleware(app=Mock())

        request = Mock()
        request.url.path = "/mcp"
        request.headers.get = Mock(return_value="Basic dXNlcjpwYXNz")

        result = await middleware.dispatch(request, AsyncMock())

        assert result.status_code == 401
        assert b"Invalid Authorization header format" in result.body
    finally:
        mcp_server_module._auth_token = original_token


async def test_auth_middleware_rejects_invalid_token():
    """Middleware should reject requests with wrong token."""
    original_token = mcp_server_module._auth_token
    try:
        mcp_server_module._auth_token = "secret-token"

        middleware = BearerAuthMiddleware(app=Mock())

        request = Mock()
        request.url.path = "/mcp"
        request.headers.get = Mock(return_value="Bearer wrong-token")

        result = await middleware.dispatch(request, AsyncMock())

        assert result.status_code == 401
        assert b"Invalid token" in result.body
    finally:
        mcp_server_module._auth_token = original_token


async def test_auth_middleware_allows_valid_token():
    """Middleware should allow requests with valid token."""
    original_token = mcp_server_module._auth_token
    try:
        mcp_server_module._auth_token = "secret-token"

        call_next = AsyncMock(return_value="response")
        middleware = BearerAuthMiddleware(app=Mock())

        request = Mock()
        request.url.path = "/mcp"
        request.headers.get = Mock(return_value="Bearer secret-token")

        result = await middleware.dispatch(request, call_next)

        assert result == "response"
        call_next.assert_awaited_once_with(request)
    finally:
        mcp_server_module._auth_token = original_token


# --- Additional auth edge case tests ---


async def test_auth_middleware_rejects_empty_token():
    """Middleware should reject requests with empty Bearer token."""
    original_token = mcp_server_module._auth_token
    try:
        mcp_server_module._auth_token = "secret-token"

        middleware = BearerAuthMiddleware(app=Mock())

        request = Mock()
        request.url.path = "/mcp"
        request.headers.get = Mock(return_value="Bearer ")

        result = await middleware.dispatch(request, AsyncMock())

        assert result.status_code == 401
        assert b"Invalid token" in result.body
    finally:
        mcp_server_module._auth_token = original_token


async def test_auth_middleware_case_sensitive_bearer():
    """Middleware should be case-sensitive for 'Bearer' prefix."""
    original_token = mcp_server_module._auth_token
    try:
        mcp_server_module._auth_token = "secret-token"

        middleware = BearerAuthMiddleware(app=Mock())

        request = Mock()
        request.url.path = "/mcp"
        request.headers.get = Mock(return_value="bearer secret-token")  # lowercase

        result = await middleware.dispatch(request, AsyncMock())

        assert result.status_code == 401
        assert b"Invalid Authorization header format" in result.body
    finally:
        mcp_server_module._auth_token = original_token


async def test_auth_middleware_timing_safe_comparison():
    """Middleware should use timing-safe comparison (test that wrong tokens are rejected)."""
    original_token = mcp_server_module._auth_token
    try:
        mcp_server_module._auth_token = "correct-token-12345"

        middleware = BearerAuthMiddleware(app=Mock())

        request = Mock()
        request.url.path = "/mcp"
        # Token with same length but different content
        request.headers.get = Mock(return_value="Bearer correct-token-12346")

        result = await middleware.dispatch(request, AsyncMock())

        assert result.status_code == 401
        assert b"Invalid token" in result.body
    finally:
        mcp_server_module._auth_token = original_token


async def test_auth_middleware_allows_multiple_endpoints_without_auth():
    """Middleware should allow /health without auth but require auth for other endpoints."""
    original_token = mcp_server_module._auth_token
    try:
        mcp_server_module._auth_token = "secret-token"

        middleware = BearerAuthMiddleware(app=Mock())

        # /health should work without auth
        health_request = Mock()
        health_request.url.path = "/health"
        call_next = AsyncMock(return_value="health-response")
        result = await middleware.dispatch(health_request, call_next)
        assert result == "health-response"

        # /mcp should require auth
        mcp_request = Mock()
        mcp_request.url.path = "/mcp"
        mcp_request.headers.get = Mock(return_value=None)
        result = await middleware.dispatch(mcp_request, AsyncMock())
        assert result.status_code == 401
    finally:
        mcp_server_module._auth_token = original_token
