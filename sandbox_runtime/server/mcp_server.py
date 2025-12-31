"""MCP server for sandbox execution with streaming output."""

import os
import secrets
import uuid
from contextlib import asynccontextmanager
from typing import Annotated

from dotenv import load_dotenv
from mcp.server.fastmcp import Context, FastMCP
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

from .config import ServerConfig
from .execution_manager import (
    ExecutionCompletedError,
    ExecutionManager,
    ExecutionNotFoundError,
    ExecutionNotInteractiveError,
    ExecutionStatus,
    TooManyExecutionsError,
)

load_dotenv()

# Store auth token globally for middleware access
_auth_token: str | None = None


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Middleware to validate Bearer token authorization."""

    async def dispatch(self, request: Request, call_next):
        if _auth_token is None:
            # Auth disabled
            return await call_next(request)

        # Allow health check endpoint without auth
        if request.url.path == "/health":
            return await call_next(request)

        auth_header = request.headers.get("Authorization")
        if not auth_header:
            return JSONResponse(
                {"error": "Missing Authorization header"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not auth_header.startswith("Bearer "):
            return JSONResponse(
                {"error": "Invalid Authorization header format. Expected: Bearer <token>"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = auth_header[7:]  # Strip "Bearer " prefix
        if not secrets.compare_digest(token, _auth_token):
            return JSONResponse(
                {"error": "Invalid token"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        return await call_next(request)


# Map session object id to UUID for consistent session identification
_session_id_map: dict[int, str] = {}


def _get_int_env(name: str, default: int) -> int:
    """Parse an int env var, falling back to default on errors."""
    value = os.getenv(name)
    if value is None:
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _get_manager_and_session(ctx: Context | None) -> tuple[ExecutionManager, str] | None:
    """Fetch the execution manager and session id from context."""
    if ctx is None or ctx.request_context is None:
        return None
    lifespan_context = ctx.request_context.lifespan_context or {}
    execution_manager = lifespan_context.get("execution_manager")
    if execution_manager is None:
        return None
    return execution_manager, get_session_id(ctx)


@asynccontextmanager
async def lifespan(server: FastMCP):
    """Initialize execution manager on startup, cleanup on shutdown."""
    global _auth_token
    _auth_token = os.getenv("SANDBOX_AUTH_TOKEN")

    config = ServerConfig(
        host=os.getenv("SANDBOX_HOST", "127.0.0.1"),
        port=_get_int_env("SANDBOX_PORT", 8080),
        max_concurrent_executions=_get_int_env("SANDBOX_MAX_CONCURRENT", 10),
        max_executions_per_session=_get_int_env("SANDBOX_MAX_PER_SESSION", 5),
        execution_timeout_seconds=_get_int_env("SANDBOX_TIMEOUT", 300),
        auth_token=_auth_token,
    )
    execution_manager = ExecutionManager(config)
    try:
        yield {"execution_manager": execution_manager, "config": config}
    finally:
        await execution_manager.shutdown()
        _session_id_map.clear()
        _auth_token = None


mcp = FastMCP("Sandbox Execution Server", lifespan=lifespan)


def get_session_id(ctx: Context) -> str:
    """Get a unique session ID from the context using UUID."""
    # Use the session object's id as a key to get a consistent UUID
    if ctx.request_context and ctx.request_context.session:
        session_obj_id = id(ctx.request_context.session)
        if session_obj_id not in _session_id_map:
            _session_id_map[session_obj_id] = str(uuid.uuid4())
        return _session_id_map[session_obj_id]

    # Fall back to client_id if available
    if ctx.client_id:
        return ctx.client_id

    # Last resort: generate a new UUID (stateless mode)
    return str(uuid.uuid4())


@mcp.tool()
async def execute_code(
    command: Annotated[str, "The shell command to execute in the sandbox"],
    timeout_seconds: Annotated[int, "Maximum execution time in seconds"] = 60,
    interactive: Annotated[bool, "Enable stdin input via send_stdin tool"] = False,
    working_directory: Annotated[str | None, "Working directory for execution"] = None,
    environment: Annotated[dict[str, str] | None, "Additional environment variables"] = None,
    sandbox_config: Annotated[dict | None, "Override default sandbox configuration"] = None,
    wait_for_completion: Annotated[bool, "If True, wait for execution to complete and return all output"] = True,
    ctx: Context = None,
) -> dict:
    """
    Execute a command in an isolated sandbox.

    The command runs in a sandboxed environment with configurable network and
    filesystem restrictions.

    If wait_for_completion=True (default), blocks until execution completes and
    returns all output. If False, returns immediately with the execution_id for
    polling via get_execution_output.

    Returns:
        {
            "execution_id": "...",
            "status": "completed|running|failed|timeout",
            "exit_code": 0,  # if completed
            "output": [...],  # list of output events if wait_for_completion=True
            "error": "..."  # if failed
        }
    """
    context = _get_manager_and_session(ctx)
    if context is None:
        return {"error": "Missing request context", "status": "failed"}
    execution_manager, session_id = context

    try:
        execution = await execution_manager.create_execution(
            session_id=session_id,
            command=command,
            timeout_seconds=timeout_seconds,
            interactive=interactive,
            working_directory=working_directory,
            environment=environment,
            sandbox_config=sandbox_config,
        )

        if not wait_for_completion:
            return {
                "execution_id": execution.info.id,
                "status": "running",
                "message": "Execution started. Use get_execution_output to retrieve results.",
            }

        # Wait for completion by consuming the stream
        output = [event async for event in execution.stream()]

        return {
            "execution_id": execution.info.id,
            "status": execution.info.status.value,
            "exit_code": execution.info.exit_code,
            "output": output,
        }

    except TooManyExecutionsError as e:
        return {"error": str(e), "status": "failed"}


@mcp.tool()
async def execute_code_async(
    command: Annotated[str, "The shell command to execute in the sandbox"],
    timeout_seconds: Annotated[int, "Maximum execution time in seconds"] = 60,
    interactive: Annotated[bool, "Enable stdin input via send_stdin tool"] = False,
    working_directory: Annotated[str | None, "Working directory for execution"] = None,
    environment: Annotated[dict[str, str] | None, "Additional environment variables"] = None,
    sandbox_config: Annotated[dict | None, "Override default sandbox configuration"] = None,
    ctx: Context = None,
) -> dict:
    """
    Start a command in an isolated sandbox without waiting for completion.

    Returns immediately with an execution_id. Use get_execution_output or
    get_execution_status to check progress and retrieve output.

    This is useful for long-running commands where you want to do other work
    while the command runs.
    """
    context = _get_manager_and_session(ctx)
    if context is None:
        return {"error": "Missing request context", "status": "failed"}
    execution_manager, session_id = context

    try:
        execution = await execution_manager.create_execution(
            session_id=session_id,
            command=command,
            timeout_seconds=timeout_seconds,
            interactive=interactive,
            working_directory=working_directory,
            environment=environment,
            sandbox_config=sandbox_config,
        )

        return {
            "execution_id": execution.info.id,
            "status": "running",
        }

    except TooManyExecutionsError as e:
        return {"error": str(e), "status": "failed"}


@mcp.tool()
async def send_stdin(
    execution_id: Annotated[str, "The execution ID to send input to"],
    input_data: Annotated[str, "The input string to send (newline appended if not present)"],
    ctx: Context = None,
) -> dict:
    """
    Send input to a running interactive execution.

    Only works for executions started with interactive=True.
    """
    context = _get_manager_and_session(ctx)
    if context is None:
        return {"success": False, "error": "Missing request context"}
    execution_manager, session_id = context

    try:
        if not input_data.endswith("\n"):
            input_data += "\n"
        await execution_manager.send_stdin(session_id, execution_id, input_data)
        return {"success": True}
    except ExecutionNotFoundError:
        return {"success": False, "error": "Execution not found"}
    except ExecutionNotInteractiveError:
        return {"success": False, "error": "Execution is not interactive"}
    except ExecutionCompletedError:
        return {"success": False, "error": "Execution already completed"}


@mcp.tool()
async def cancel_execution(
    execution_id: Annotated[str, "The execution ID to cancel"],
    force: Annotated[bool, "If True, send SIGKILL instead of SIGTERM"] = False,
    ctx: Context = None,
) -> dict:
    """
    Cancel a running execution.

    Returns whether the execution was actually running when cancelled.
    """
    context = _get_manager_and_session(ctx)
    if context is None:
        return {"success": False, "error": "Missing request context"}
    execution_manager, session_id = context

    try:
        was_running = await execution_manager.cancel_execution(session_id, execution_id, force=force)
        return {"success": True, "was_running": was_running}
    except ExecutionNotFoundError:
        return {"success": False, "error": "Execution not found"}


@mcp.tool()
async def list_executions(ctx: Context = None) -> list[dict] | dict:
    """
    List all executions for the current session.

    Returns execution info including id, status, command, and timing info.
    """
    context = _get_manager_and_session(ctx)
    if context is None:
        return {"error": "Missing request context"}
    execution_manager, session_id = context

    return await execution_manager.list_executions(session_id)


@mcp.tool()
async def get_execution_status(
    execution_id: Annotated[str, "The execution ID to get status for"],
    ctx: Context = None,
) -> dict:
    """
    Get the current status of an execution.

    Returns detailed info including exit code, error message, and timing.
    """
    context = _get_manager_and_session(ctx)
    if context is None:
        return {"error": "Missing request context"}
    execution_manager, session_id = context

    try:
        return await execution_manager.get_status(session_id, execution_id)
    except ExecutionNotFoundError:
        return {"error": "Execution not found"}


@mcp.tool()
async def get_execution_output(
    execution_id: Annotated[str, "The execution ID to get output for"],
    wait: Annotated[bool, "If True and execution is running, wait for completion"] = False,
    ctx: Context = None,
) -> dict:
    """
    Get output from an execution.

    If wait=True and the execution is still running, blocks until completion.
    Otherwise returns the buffered output so far.

    Returns:
        {
            "status": "completed|running|...",
            "output": [...],  # list of output events
            "exit_code": 0  # if completed
        }
    """
    context = _get_manager_and_session(ctx)
    if context is None:
        return {"error": "Missing request context", "output": []}
    execution_manager, session_id = context

    try:
        execution = execution_manager.get_execution(session_id, execution_id)

        if wait and execution.info.status == ExecutionStatus.RUNNING:
            # Wait for completion by consuming the stream
            output = [event async for event in execution.stream()]
            return {
                "status": execution.info.status.value,
                "exit_code": execution.info.exit_code,
                "output": output,
            }
        else:
            output = await execution_manager.get_buffered_output(session_id, execution_id)
            return {
                "status": execution.info.status.value,
                "exit_code": execution.info.exit_code,
                "output": output,
            }
    except ExecutionNotFoundError:
        return {"error": "Execution not found", "output": []}


def main() -> None:
    """Run the MCP server."""
    global _auth_token
    import uvicorn
    from starlette.routing import Route

    host = os.getenv("SANDBOX_HOST", "127.0.0.1")
    port = _get_int_env("SANDBOX_PORT", 8080)
    _auth_token = os.getenv("SANDBOX_AUTH_TOKEN")

    # Get the ASGI app from FastMCP
    app = mcp.streamable_http_app()

    # Add health check endpoint
    async def health_check(request: Request) -> JSONResponse:
        return JSONResponse({"status": "healthy"})

    app.routes.append(Route("/health", health_check, methods=["GET"]))

    # Add authentication middleware
    app.add_middleware(BearerAuthMiddleware)

    print(f"Starting Sandbox MCP Server on {host}:{port}")
    if _auth_token:
        print("Authorization: enabled (SANDBOX_AUTH_TOKEN set)")
    else:
        print("Authorization: disabled (set SANDBOX_AUTH_TOKEN to enable)")
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
