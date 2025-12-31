"""Tests for sandbox_runtime.runner module."""

import io
from unittest.mock import AsyncMock, Mock, patch

from sandbox_runtime.runner import RunnerConfig, get_default_sandbox_config, main, run


def test_get_default_sandbox_config_has_empty_lists():
    """Default sandbox config should be minimal with empty lists."""
    config = get_default_sandbox_config()
    assert config.network.allowed_domains == []
    assert config.network.denied_domains == []
    assert config.filesystem.deny_read == []
    assert config.filesystem.allow_write == []
    assert config.filesystem.deny_write == []


async def test_run_invalid_sandbox_config_emits_error():
    """Invalid sandbox config should emit an error and exit."""
    config = RunnerConfig(
        command="echo hi",
        sandbox_config={
            "network": {"allowed_domains": ["*"], "denied_domains": []},
            "filesystem": {"deny_read": [], "allow_write": [], "deny_write": []},
        },
    )

    with patch("sandbox_runtime.runner.emit") as mock_emit:
        with patch("sandbox_runtime.runner.SandboxManager.initialize", new_callable=AsyncMock) as mock_init:
            exit_code = await run(config)

    assert exit_code == 1
    assert mock_emit.call_args[0][0] == "error"
    assert "Invalid sandbox config" in mock_emit.call_args[1]["message"]
    mock_init.assert_not_called()


async def test_run_initialize_failure_emits_error():
    """Sandbox initialization errors should emit an error event."""
    config = RunnerConfig(command="echo hi")

    with patch("sandbox_runtime.runner.emit") as mock_emit:
        with patch(
            "sandbox_runtime.runner.SandboxManager.initialize",
            new_callable=AsyncMock,
            side_effect=RuntimeError("boom"),
        ):
            exit_code = await run(config)

    assert exit_code == 1
    assert mock_emit.call_args[0][0] == "error"
    assert "Failed to initialize sandbox: boom" in mock_emit.call_args[1]["message"]


async def test_run_success_emits_ready_and_exit():
    """Successful runs should emit ready and exit events."""
    config = RunnerConfig(command="echo hi")
    mock_proc = AsyncMock()
    mock_proc.wait = AsyncMock(return_value=0)
    mock_proc.returncode = 0
    mock_proc.stdin = None
    mock_proc.stdout = object()
    mock_proc.stderr = object()
    mock_proc.terminate = Mock()
    mock_proc.kill = Mock()

    with patch("sandbox_runtime.runner.emit") as mock_emit:
        with patch("sandbox_runtime.runner.SandboxManager.initialize", new_callable=AsyncMock):
            with patch(
                "sandbox_runtime.runner.SandboxManager.wrap_with_sandbox",
                new_callable=AsyncMock,
                return_value="echo hi",
            ):
                with patch("sandbox_runtime.runner.SandboxManager.reset", new_callable=AsyncMock):
                    with patch(
                        "sandbox_runtime.runner.asyncio.create_subprocess_shell",
                        new_callable=AsyncMock,
                        return_value=mock_proc,
                    ):
                        with patch("sandbox_runtime.runner.stream_output", new_callable=AsyncMock):
                            exit_code = await run(config)

    assert exit_code == 0
    event_types = [call_args[0][0] for call_args in mock_emit.call_args_list]
    assert "ready" in event_types
    assert "exit" in event_types


async def test_main_no_input_emits_error():
    """Missing config on stdin should emit an error."""
    with patch("sandbox_runtime.runner.emit") as mock_emit:
        with patch("sandbox_runtime.runner.run", new_callable=AsyncMock) as mock_run:
            with patch("sys.stdin", io.StringIO("")):
                exit_code = await main()

    assert exit_code == 1
    assert mock_emit.call_args[0][0] == "error"
    assert "No config provided" in mock_emit.call_args[1]["message"]
    mock_run.assert_not_called()


async def test_main_invalid_json_emits_error():
    """Invalid JSON on stdin should emit an error."""
    with patch("sandbox_runtime.runner.emit") as mock_emit:
        with patch("sandbox_runtime.runner.run", new_callable=AsyncMock) as mock_run:
            with patch("sys.stdin", io.StringIO("{invalid}\n")):
                exit_code = await main()

    assert exit_code == 1
    assert mock_emit.call_args[0][0] == "error"
    assert "Invalid JSON config" in mock_emit.call_args[1]["message"]
    mock_run.assert_not_called()


async def test_main_missing_required_fields_emits_error():
    """Missing required fields should emit an error."""
    with patch("sandbox_runtime.runner.emit") as mock_emit:
        with patch("sandbox_runtime.runner.run", new_callable=AsyncMock) as mock_run:
            with patch("sys.stdin", io.StringIO("{}\n")):
                exit_code = await main()

    assert exit_code == 1
    assert mock_emit.call_args[0][0] == "error"
    assert "Invalid config fields" in mock_emit.call_args[1]["message"]
    mock_run.assert_not_called()


async def test_main_filters_unknown_fields():
    """Unknown fields should be ignored when building RunnerConfig."""
    with patch("sandbox_runtime.runner.run", new_callable=AsyncMock, return_value=0) as mock_run:
        with patch(
            "sys.stdin",
            io.StringIO('{"command": "echo hi", "timeout_seconds": 5, "unknown": "x"}\n'),
        ):
            exit_code = await main()

    assert exit_code == 0
    assert mock_run.call_count == 1
    config = mock_run.call_args[0][0]
    assert config.command == "echo hi"
    assert config.timeout_seconds == 5
