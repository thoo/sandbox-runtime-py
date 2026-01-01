"""MCP server for sandbox execution with streaming output."""

import json
import os
import secrets
import sys
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
from .redis_event_store import RedisEventStore
from .redis_state import RedisStateStore

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

# Global state - persists across requests (module-level like MCP SDK example)
_auth_token: str | None = None
_execution_manager: ExecutionManager | None = None
_redis_store: RedisStateStore | None = None
_redis_event_store: RedisEventStore | None = None
_server_config: ServerConfig | None = None
_session_id_map: dict[int, str] = {}


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
    logger.info(f"🔍 _get_manager_and_session: ctx={type(ctx).__name__ if ctx else 'None'}")
    if ctx is None:
        logger.warning("❌ Context is None")
        return None

    logger.info(f"🔍 request_context={type(ctx.request_context).__name__ if ctx.request_context else 'None'}")
    if ctx.request_context is None:
        logger.warning("❌ ctx.request_context is None - this is the problem!")
        return None

    lifespan_context = ctx.request_context.lifespan_context or {}
    logger.info(f"🔍 lifespan_context keys: {list(lifespan_context.keys())}")

    execution_manager = lifespan_context.get("execution_manager")
    if execution_manager is None:
        logger.warning("❌ execution_manager not found in lifespan_context")
        return None

    session_id = get_session_id(ctx)
    logger.info(f"✅ Got session_id: {session_id[:8]}...")
    return execution_manager, session_id


@asynccontextmanager
async def lifespan(server: FastMCP):
    """Initialize execution manager once on first request, cleanup on shutdown.

    Note: Uses global state (module-level) to persist across requests, similar to
    MCP SDK's event_store pattern. This prevents re-initialization on every request.
    """
    global _auth_token, _execution_manager, _redis_store, _redis_event_store, _server_config

    # Only initialize once (first request)
    if _execution_manager is None:
        logger.info("🚀 First-time initialization of ExecutionManager")

        _auth_token = os.getenv("SANDBOX_AUTH_TOKEN")

        _server_config = ServerConfig(
            host=os.getenv("SANDBOX_HOST", "127.0.0.1"),
            port=_get_int_env("SANDBOX_PORT", 8080),
            max_concurrent_executions=_get_int_env("SANDBOX_MAX_CONCURRENT", 10),
            max_executions_per_session=_get_int_env("SANDBOX_MAX_PER_SESSION", 5),
            execution_timeout_seconds=_get_int_env("SANDBOX_TIMEOUT", 300),
            auth_token=_auth_token,
        )

        # Initialize Redis if URL is provided
        redis_url = os.getenv("REDIS_URL")
        if redis_url:
            logger.info(f"Initializing Redis state store at {redis_url}")
            _redis_store = RedisStateStore(redis_url)
            await _redis_store.connect()
            logger.info("✅ Redis state store connected")

            # Initialize Redis event store for session persistence
            logger.info("Initializing Redis event store for MCP session persistence")
            _redis_event_store = RedisEventStore(redis_url, ttl=3600)
            await _redis_event_store.connect()
            logger.info("✅ Redis event store connected - MCP sessions will persist across restarts")

        logger.info("Initializing ExecutionManager")
        logger.info(f"  max_concurrent_executions: {_server_config.max_concurrent_executions}")
        logger.info(f"  max_executions_per_session: {_server_config.max_executions_per_session}")
        logger.info(f"  execution_timeout_seconds: {_server_config.execution_timeout_seconds}")
        logger.info(f"  distributed_mode: {_redis_store is not None}")

        _execution_manager = ExecutionManager(_server_config, redis_store=_redis_store)
        logger.info("✅ ExecutionManager initialized and ready")
    else:
        logger.debug("♻️  Reusing existing ExecutionManager (stateful mode)")

    try:
        yield {"execution_manager": _execution_manager, "config": _server_config}
    finally:
        # Only cleanup on actual server shutdown (not per-request)
        pass  # Cleanup handled in _run_server shutdown


mcp = FastMCP(
    "Sandbox Execution Server",
    lifespan=lifespan,
    json_response=True,
    stateless_http=False,  # Must be False to keep ExecutionManager alive across requests
    event_store=_redis_event_store,  # Redis-backed event store for session persistence
    # IMPORTANT: We cannot use stateless_http=True because:
    # - Lifespan runs per-request in stateless mode, shutting down ExecutionManager
    # - This kills all running subprocess executions
    # - For multi-replica deployments, use Redis + sticky sessions instead
    # - Redis shares execution metadata/output across replicas
    # - Sticky sessions ensure subsequent requests hit the server where process is running
    # - Redis event store enables session persistence across server restarts
)


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
    last_event_id: Annotated[
        str | None, "Last event ID received (for resumability - only get events after this one)"
    ] = None,
    ctx: Context = None,
) -> dict:
    """
    Get output from an execution.

    If wait=True and the execution is still running, blocks until completion.
    Otherwise returns the buffered output so far.

    Supports resumability: If last_event_id is provided, only returns events after that ID.
    This allows clients to reconnect and resume from where they left off, similar to SSE
    Last-Event-ID functionality.

    Returns:
        {
            "status": "completed|running|...",
            "output": [...],  # list of output events (each with event_id field)
            "exit_code": 0  # if completed
        }

    Example with resumability:
        # First poll - get all events
        result1 = get_execution_output(exec_id, wait=False)
        # result1 = {"output": [{"event_id": "abc", ...}, {"event_id": "def", ...}]}

        # Client disconnects, reconnects later
        # Second poll - only get new events after "def"
        result2 = get_execution_output(exec_id, wait=False, last_event_id="def")
        # result2 = {"output": [{"event_id": "ghi", ...}, ...]}  # only new events
    """
    context = _get_manager_and_session(ctx)
    if context is None:
        return {"error": "Missing request context", "output": []}
    execution_manager, session_id = context

    try:
        execution = execution_manager.get_execution(session_id, execution_id)

        # Handle resumability - get events after last_event_id
        if last_event_id:
            replayed_events = await execution_manager.replay_events_after(session_id, execution_id, last_event_id)
            if replayed_events is None:
                return {
                    "error": f"Event ID '{last_event_id}' not found (may have been evicted from buffer)",
                    "output": [],
                }
            return {
                "status": execution.info.status.value,
                "exit_code": execution.info.exit_code,
                "output": replayed_events,
            }

        # Normal mode - get all buffered output or wait for completion
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


async def _cleanup_global_state():
    """Cleanup global execution manager and Redis on shutdown."""
    global _execution_manager, _redis_store, _redis_event_store, _session_id_map, _auth_token

    if _execution_manager:
        logger.info("Shutting down ExecutionManager...")
        await _execution_manager.shutdown()
        _execution_manager = None

    if _redis_store:
        await _redis_store.close()
        logger.info("Redis state store closed")
        _redis_store = None

    if _redis_event_store:
        await _redis_event_store.close()
        logger.info("Redis event store closed")
        _redis_event_store = None

    _session_id_map.clear()
    _auth_token = None
    logger.info("Global state cleanup complete")


def _run_server(
    host: str,
    port: int,
    token: str | None,
    max_concurrent: int,
    max_per_session: int,
    timeout: int,
    log_file: str | None,
) -> None:
    """Internal function to run the MCP server with given configuration."""
    global _auth_token
    import signal

    import uvicorn
    from starlette.middleware.cors import CORSMiddleware
    from starlette.routing import Route

    _auth_token = token

    # Register cleanup handler for graceful shutdown
    def signal_handler(signum, frame):
        import asyncio

        logger.info("Received shutdown signal, cleaning up...")
        asyncio.run(_cleanup_global_state())
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Configure log file if specified (in addition to default from load_dotenv)
    if log_file:
        logger.add(
            log_file,
            rotation="10 MB",
            retention="7 days",
            compression="gz",
            format="{time:YYYY-MM-DD HH:mm:ss} | {level:<8} | {message}",
        )

    # Set environment variables for lifespan to pick up
    os.environ["SANDBOX_MAX_CONCURRENT"] = str(max_concurrent)
    os.environ["SANDBOX_MAX_PER_SESSION"] = str(max_per_session)
    os.environ["SANDBOX_TIMEOUT"] = str(timeout)
    if token:
        os.environ["SANDBOX_AUTH_TOKEN"] = token

    # Get the MCP app (which already has /mcp as its path)
    app = mcp.streamable_http_app()

    # Add health check endpoint
    async def health_check(request: Request) -> JSONResponse:
        return JSONResponse({"status": "healthy"})

    app.routes.insert(0, Route("/health", health_check, methods=["GET"]))

    # Add CORS middleware to expose MCP session header
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=["Mcp-Session-Id"],
    )

    # Add our custom middleware (order matters: auth first, then logging)
    app.add_middleware(BearerAuthMiddleware)
    app.add_middleware(RequestLoggingMiddleware)

    logger.info("=" * 60)
    logger.info("Starting Sandbox MCP Server")
    logger.info(f"  Host: {host}")
    logger.info(f"  Port: {port}")
    logger.info(f"  Auth: {'enabled' if _auth_token else 'disabled'}")
    logger.info(f"  Max concurrent: {max_concurrent}")
    logger.info(f"  Max per session: {max_per_session}")
    logger.info(f"  Timeout: {timeout}s")
    logger.info("=" * 60)

    uvicorn.run(app, host=host, port=port, log_level="info")


def _create_cli():
    """Create and return the CLI command (for testing)."""
    import click

    @click.command()
    @click.option(
        "--token",
        "-t",
        envvar="SANDBOX_AUTH_TOKEN",
        default=None,
        help="Bearer token for authentication. If not set, auth is disabled.",
    )
    @click.option(
        "--host",
        envvar="SANDBOX_HOST",
        default="127.0.0.1",
        show_default=True,
        help="Host to bind the server to.",
    )
    @click.option(
        "--port",
        "-p",
        envvar="SANDBOX_PORT",
        default=8080,
        show_default=True,
        type=int,
        help="Port to bind the server to.",
    )
    @click.option(
        "--max-concurrent",
        envvar="SANDBOX_MAX_CONCURRENT",
        default=10,
        show_default=True,
        type=int,
        help="Maximum number of concurrent executions.",
    )
    @click.option(
        "--max-per-session",
        envvar="SANDBOX_MAX_PER_SESSION",
        default=5,
        show_default=True,
        type=int,
        help="Maximum executions per session.",
    )
    @click.option(
        "--timeout",
        envvar="SANDBOX_TIMEOUT",
        default=300,
        show_default=True,
        type=int,
        help="Default execution timeout in seconds.",
    )
    @click.option(
        "--log-file",
        envvar="SANDBOX_LOG_FILE",
        default=None,
        help="Log file path. Defaults to sandbox_server.log.",
    )
    def cli(
        token: str | None,
        host: str,
        port: int,
        max_concurrent: int,
        max_per_session: int,
        timeout: int,
        log_file: str | None,
    ) -> None:
        """Start the Sandbox MCP Server.

        This server provides sandboxed code execution capabilities via the
        Model Context Protocol (MCP). It can execute commands in isolated
        environments with configurable restrictions.

        Examples:

            # Start with default settings (no auth)
            srt-mcp-server

            # Start with authentication
            srt-mcp-server --token mysecrettoken

            # Start on custom host/port
            srt-mcp-server --host 0.0.0.0 --port 9000 --token mytoken

            # Using environment variables
            SANDBOX_AUTH_TOKEN=mytoken srt-mcp-server
        """
        _run_server(
            host=host,
            port=port,
            token=token,
            max_concurrent=max_concurrent,
            max_per_session=max_per_session,
            timeout=timeout,
            log_file=log_file,
        )

    return cli


def main() -> None:
    """Run the MCP server with CLI argument support."""
    cli = _create_cli()
    cli()


if __name__ == "__main__":
    main()
