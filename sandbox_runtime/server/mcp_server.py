"""MCP server for sandbox execution with streaming output."""

import json
import os
import secrets
import time
import uuid
from collections.abc import Callable
from contextlib import asynccontextmanager
from functools import wraps
from typing import Annotated, Any

from dotenv import load_dotenv
from loguru import logger
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

# Configure loguru file logging
_log_file = os.getenv("SANDBOX_LOG_FILE", "sandbox_server.log")
if _log_file:
    logger.add(
        _log_file,
        rotation="10 MB",
        retention="7 days",
        compression="gz",
        format="{time:YYYY-MM-DD HH:mm:ss} | {level:<8} | {message}",
    )

# Store auth token globally for middleware access
_auth_token: str | None = None


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Middleware to log all HTTP requests and responses."""

    async def dispatch(self, request: Request, call_next):
        request_id = str(uuid.uuid4())[:8]
        start_time = time.time()

        # Log request
        body = None
        if request.method in ("POST", "PUT", "PATCH"):
            try:
                body = await request.body()
                # Store body for later use since it can only be read once
                request._body = body
                body_str = body.decode("utf-8")
                # Try to parse and pretty-print JSON
                try:
                    body_json = json.loads(body_str)
                    body_str = json.dumps(body_json, indent=2)
                except json.JSONDecodeError:
                    pass
                logger.info(
                    f"[{request_id}] ▶ {request.method} {request.url.path}\n"
                    f"    Headers: {dict(request.headers)}\n"
                    f"    Body:\n{_indent(body_str, 8)}"
                )
            except Exception as e:
                logger.info(
                    f"[{request_id}] ▶ {request.method} {request.url.path}\n"
                    f"    Headers: {dict(request.headers)}\n"
                    f"    Body: <error reading: {e}>"
                )
        else:
            logger.info(f"[{request_id}] ▶ {request.method} {request.url.path}\n    Headers: {dict(request.headers)}")

        response = await call_next(request)
        duration_ms = (time.time() - start_time) * 1000

        # Log response
        logger.info(f"[{request_id}] ◀ {response.status_code} ({duration_ms:.1f}ms)")

        return response


def _indent(text: str, spaces: int) -> str:
    """Indent each line of text by the specified number of spaces."""
    prefix = " " * spaces
    return "\n".join(prefix + line for line in text.split("\n"))


def _format_value(value: Any, max_length: int = 500) -> str:
    """Format a value for logging, truncating if necessary."""
    if value is None:
        return "None"
    try:
        if isinstance(value, (dict, list)):
            formatted = json.dumps(value, indent=2, default=str)
        else:
            formatted = str(value)
        if len(formatted) > max_length:
            return formatted[:max_length] + f"... (truncated, {len(formatted)} chars)"
        return formatted
    except Exception:
        return f"<unformattable: {type(value).__name__}>"


def log_tool_call(func: Callable) -> Callable:
    """Decorator to log tool calls with their arguments and results."""

    @wraps(func)
    async def wrapper(*args, **kwargs):
        tool_name = func.__name__
        call_id = str(uuid.uuid4())[:8]

        # Filter out ctx from logged kwargs
        logged_kwargs = {k: v for k, v in kwargs.items() if k != "ctx"}

        logger.info(f"[{call_id}] 🔧 TOOL CALL: {tool_name}\n    Args: {_format_value(logged_kwargs)}")

        start_time = time.time()
        try:
            result = await func(*args, **kwargs)
            duration_ms = (time.time() - start_time) * 1000

            logger.info(
                f"[{call_id}] ✅ TOOL RESULT: {tool_name} ({duration_ms:.1f}ms)\n    Result: {_format_value(result)}"
            )
            return result
        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error(
                f"[{call_id}] ❌ TOOL ERROR: {tool_name} ({duration_ms:.1f}ms)\n    Error: {type(e).__name__}: {e}"
            )
            raise

    return wrapper


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
            logger.warning("Auth failed: Missing Authorization header")
            return JSONResponse(
                {"error": "Missing Authorization header"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        if not auth_header.startswith("Bearer "):
            logger.warning("Auth failed: Invalid header format")
            return JSONResponse(
                {"error": "Invalid Authorization header format. Expected: Bearer <token>"},
                status_code=401,
                headers={"WWW-Authenticate": "Bearer"},
            )

        token = auth_header[7:]  # Strip "Bearer " prefix
        if not secrets.compare_digest(token, _auth_token):
            logger.warning("Auth failed: Invalid token")
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
    logger.info("Initializing ExecutionManager")
    logger.info(f"  max_concurrent_executions: {config.max_concurrent_executions}")
    logger.info(f"  max_executions_per_session: {config.max_executions_per_session}")
    logger.info(f"  execution_timeout_seconds: {config.execution_timeout_seconds}")
    execution_manager = ExecutionManager(config)
    try:
        logger.info("Server ready to accept connections")
        yield {"execution_manager": execution_manager, "config": config}
    finally:
        logger.info("Shutting down ExecutionManager...")
        await execution_manager.shutdown()
        _session_id_map.clear()
        _auth_token = None
        logger.info("Shutdown complete")


mcp = FastMCP("Sandbox Execution Server", lifespan=lifespan)


def get_session_id(ctx: Context) -> str:
    """Get a unique session ID from the context using UUID."""
    # Use the session object's id as a key to get a consistent UUID
    if ctx.request_context and ctx.request_context.session:
        session_obj_id = id(ctx.request_context.session)
        if session_obj_id not in _session_id_map:
            new_session_id = str(uuid.uuid4())
            _session_id_map[session_obj_id] = new_session_id
            logger.info(f"🔗 New session connected: {new_session_id[:8]}...")
        return _session_id_map[session_obj_id]

    # Fall back to client_id if available
    if ctx.client_id:
        logger.debug(f"Using client_id as session: {ctx.client_id}")
        return ctx.client_id

    # Last resort: generate a new UUID (stateless mode)
    stateless_id = str(uuid.uuid4())
    logger.debug(f"Stateless session: {stateless_id[:8]}...")
    return stateless_id


@mcp.tool()
@log_tool_call
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
@log_tool_call
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
@log_tool_call
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
@log_tool_call
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
@log_tool_call
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
@log_tool_call
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
@log_tool_call
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

    # Add middleware (order matters: auth first, then logging)
    app.add_middleware(BearerAuthMiddleware)
    app.add_middleware(RequestLoggingMiddleware)

    logger.info("=" * 60)
    logger.info("Starting Sandbox MCP Server")
    logger.info(f"  Host: {host}")
    logger.info(f"  Port: {port}")
    logger.info(f"  Auth: {'enabled' if _auth_token else 'disabled'}")
    logger.info("=" * 60)

    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
