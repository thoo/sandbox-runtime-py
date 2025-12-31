"""Execution manager for tracking sandbox executions."""

import asyncio
import json
import sys
import time
import uuid
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from enum import Enum

from .config import ServerConfig


class ExecutionStatus(Enum):
    """Status of an execution."""

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    CANCELLED = "cancelled"
    FAILED = "failed"
    TIMEOUT = "timeout"


@dataclass
class ExecutionInfo:
    """Information about an execution."""

    id: str
    session_id: str
    status: ExecutionStatus
    command: str
    interactive: bool
    started_at: float
    completed_at: float | None = None
    exit_code: int | None = None
    error_message: str | None = None


class RunnerProcess:
    """Manages a subprocess that runs code in a sandbox."""

    def __init__(self, process: asyncio.subprocess.Process, output_buffer_size: int = 10000):
        self.process = process
        self.output_buffer_size = output_buffer_size
        self._stdin_lock = asyncio.Lock()

    @classmethod
    async def spawn(
        cls,
        command: str,
        timeout_seconds: int,
        interactive: bool,
        working_directory: str | None,
        environment: dict[str, str] | None,
        sandbox_config: dict | None,
        output_buffer_size: int = 10000,
    ) -> "RunnerProcess":
        """Spawn a new runner subprocess."""
        # Spawn the runner script as a subprocess
        process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-m",
            "sandbox_runtime.runner",
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )

        # Build config
        config = {
            "command": command,
            "timeout_seconds": timeout_seconds,
            "interactive": interactive,
        }
        if working_directory:
            config["working_directory"] = working_directory
        if environment:
            config["environment"] = environment
        if sandbox_config:
            config["sandbox_config"] = sandbox_config

        # Send config as first line
        config_json = json.dumps(config) + "\n"
        process.stdin.write(config_json.encode())
        await process.stdin.drain()

        return cls(process, output_buffer_size)

    async def read_events(self) -> AsyncIterator[dict]:
        """Read JSON events from runner stdout."""
        while True:
            line = await self.process.stdout.readline()
            if not line:
                break

            try:
                event = json.loads(line.decode().strip())
                yield event
            except json.JSONDecodeError:
                # Non-JSON output, wrap it as stderr
                yield {
                    "type": "stderr",
                    "data": f"[runner] {line.decode().rstrip()}",
                    "ts": time.time(),
                }

    async def send_stdin(self, input_data: str) -> None:
        """Send input to the runner's stdin."""
        async with self._stdin_lock:
            if not input_data.endswith("\n"):
                input_data += "\n"

            # Send as JSON command
            cmd = json.dumps({"type": "stdin", "data": input_data}) + "\n"
            self.process.stdin.write(cmd.encode())
            await self.process.stdin.drain()

    async def terminate(self, force: bool = False) -> None:
        """Terminate the runner process."""
        if force:
            self.process.kill()
        else:
            self.process.terminate()

        try:
            await asyncio.wait_for(self.process.wait(), timeout=5.0)
        except TimeoutError:
            self.process.kill()
            await self.process.wait()


@dataclass
class Execution:
    """An active execution with its runner and output buffer."""

    info: ExecutionInfo
    runner: RunnerProcess
    output_buffer: list[dict] = field(default_factory=list)
    output_queue: asyncio.Queue = field(default_factory=asyncio.Queue)

    async def stream(self) -> AsyncIterator[dict]:
        """Stream output events from this execution."""
        while True:
            event = await self.output_queue.get()
            self.output_buffer.append(event)

            # Trim buffer if too large
            if len(self.output_buffer) > self.runner.output_buffer_size:
                self.output_buffer = self.output_buffer[-self.runner.output_buffer_size :]

            yield event

            if event["type"] in ("exit", "error", "timeout", "cancelled"):
                break


class TooManyExecutionsError(Exception):
    """Raised when session has too many concurrent executions."""


class ExecutionNotFoundError(Exception):
    """Raised when execution is not found."""


class ExecutionNotInteractiveError(Exception):
    """Raised when trying to send stdin to non-interactive execution."""


class ExecutionCompletedError(Exception):
    """Raised when trying to interact with completed execution."""


class ExecutionManager:
    """Manages the lifecycle of all executions across sessions."""

    def __init__(self, config: ServerConfig | None = None):
        self.config = config or ServerConfig()
        self.executions: dict[str, Execution] = {}  # execution_id -> Execution
        self.session_executions: dict[str, set[str]] = {}  # session_id -> set of execution_ids
        self._lock = asyncio.Lock()
        self._background_tasks: set[asyncio.Task] = set()

    async def create_execution(
        self,
        session_id: str,
        command: str,
        timeout_seconds: int | None = None,
        interactive: bool = False,
        working_directory: str | None = None,
        environment: dict[str, str] | None = None,
        sandbox_config: dict | None = None,
    ) -> Execution:
        """Create and start a new execution."""
        async with self._lock:
            # Check session limits
            session_execs = self.session_executions.get(session_id, set())
            active_count = sum(
                1
                for eid in session_execs
                if eid in self.executions and self.executions[eid].info.status == ExecutionStatus.RUNNING
            )
            if active_count >= self.config.max_executions_per_session:
                raise TooManyExecutionsError(
                    f"Maximum {self.config.max_executions_per_session} concurrent executions per session"
                )

            # Create execution
            execution_id = str(uuid.uuid4())
            info = ExecutionInfo(
                id=execution_id,
                session_id=session_id,
                status=ExecutionStatus.PENDING,
                command=command,
                interactive=interactive,
                started_at=time.time(),
            )

            # Use default timeout if not specified
            if timeout_seconds is None:
                timeout_seconds = self.config.execution_timeout_seconds

            # Spawn runner process
            runner = await RunnerProcess.spawn(
                command=command,
                timeout_seconds=timeout_seconds,
                interactive=interactive,
                working_directory=working_directory,
                environment=environment,
                sandbox_config=sandbox_config,
                output_buffer_size=self.config.output_buffer_size,
            )

            execution = Execution(info=info, runner=runner)
            self.executions[execution_id] = execution

            if session_id not in self.session_executions:
                self.session_executions[session_id] = set()
            self.session_executions[session_id].add(execution_id)

            # Start background task to read runner output
            task = asyncio.create_task(self._read_runner_output(execution))
            self._background_tasks.add(task)
            task.add_done_callback(self._background_tasks.discard)

            info.status = ExecutionStatus.RUNNING
            return execution

    async def _read_runner_output(self, execution: Execution) -> None:
        """Background task to read output from runner and queue it."""
        try:
            async for event in execution.runner.read_events():
                await execution.output_queue.put(event)

                if event["type"] in ("exit", "error", "timeout", "cancelled"):
                    if event["type"] == "exit":
                        execution.info.status = ExecutionStatus.COMPLETED
                        execution.info.exit_code = event.get("code")
                    elif event["type"] == "timeout":
                        execution.info.status = ExecutionStatus.TIMEOUT
                    elif event["type"] == "cancelled":
                        execution.info.status = ExecutionStatus.CANCELLED
                    else:
                        execution.info.status = ExecutionStatus.FAILED
                        execution.info.error_message = event.get("message")

                    execution.info.completed_at = time.time()
                    break
        except asyncio.CancelledError:
            execution.info.status = ExecutionStatus.CANCELLED
            execution.info.completed_at = time.time()
            await execution.output_queue.put({"type": "cancelled", "ts": time.time()})
        except Exception as e:
            execution.info.status = ExecutionStatus.FAILED
            execution.info.error_message = str(e)
            execution.info.completed_at = time.time()
            await execution.output_queue.put({"type": "error", "message": str(e), "ts": time.time()})

    async def send_stdin(self, session_id: str, execution_id: str, input_data: str) -> None:
        """Send stdin to an execution."""
        execution = self._get_execution(session_id, execution_id)

        if not execution.info.interactive:
            raise ExecutionNotInteractiveError("Execution is not interactive")
        if execution.info.status != ExecutionStatus.RUNNING:
            raise ExecutionCompletedError("Execution is not running")

        await execution.runner.send_stdin(input_data)

    async def cancel_execution(self, session_id: str, execution_id: str, force: bool = False) -> bool:
        """Cancel an execution. Returns True if it was running."""
        execution = self._get_execution(session_id, execution_id)

        if execution.info.status != ExecutionStatus.RUNNING:
            return False

        await execution.runner.terminate(force=force)
        return True

    async def get_status(self, session_id: str, execution_id: str) -> dict:
        """Get the status of an execution."""
        execution = self._get_execution(session_id, execution_id)
        return {
            "id": execution.info.id,
            "status": execution.info.status.value,
            "command": execution.info.command,
            "interactive": execution.info.interactive,
            "started_at": execution.info.started_at,
            "completed_at": execution.info.completed_at,
            "exit_code": execution.info.exit_code,
            "error_message": execution.info.error_message,
        }

    async def get_buffered_output(self, session_id: str, execution_id: str) -> list[dict]:
        """Get buffered output from an execution."""
        execution = self._get_execution(session_id, execution_id)
        return execution.output_buffer.copy()

    async def list_executions(self, session_id: str) -> list[dict]:
        """List all executions for a session."""
        execution_ids = self.session_executions.get(session_id, set())
        result = []
        for eid in execution_ids:
            if eid in self.executions:
                execution = self.executions[eid]
                result.append(
                    {
                        "id": execution.info.id,
                        "status": execution.info.status.value,
                        "command": execution.info.command,
                        "interactive": execution.info.interactive,
                        "started_at": execution.info.started_at,
                        "completed_at": execution.info.completed_at,
                    }
                )
        return result

    async def cleanup_session(self, session_id: str) -> None:
        """Clean up all executions for a session."""
        async with self._lock:
            execution_ids = self.session_executions.pop(session_id, set())
            for eid in execution_ids:
                execution = self.executions.pop(eid, None)
                if execution and execution.info.status == ExecutionStatus.RUNNING:
                    await execution.runner.terminate(force=True)

    async def shutdown(self) -> None:
        """Shutdown all executions."""
        async with self._lock:
            for execution in self.executions.values():
                if execution.info.status == ExecutionStatus.RUNNING:
                    await execution.runner.terminate(force=True)
            self.executions.clear()
            self.session_executions.clear()

            # Cancel all background tasks
            for task in self._background_tasks:
                task.cancel()

    def _get_execution(self, session_id: str, execution_id: str) -> Execution:
        """Get an execution, validating session ownership."""
        if execution_id not in self.executions:
            raise ExecutionNotFoundError(f"Execution {execution_id} not found")

        execution = self.executions[execution_id]
        if execution.info.session_id != session_id:
            raise ExecutionNotFoundError(f"Execution {execution_id} not found")

        return execution
