"""Tests for resource limits configuration and enforcement."""

from unittest.mock import patch

from sandbox_runtime.config import ResourceLimitsConfig, SandboxRuntimeConfig
from sandbox_runtime.runner import (
    create_resource_limiter,
    get_resource_violation_reason,
)

# --- ResourceLimitsConfig validation tests ---


def test_resource_limits_config_defaults():
    """ResourceLimitsConfig should have None as default for all fields."""
    config = ResourceLimitsConfig()
    assert config.max_memory_mb is None
    assert config.max_cpu_seconds is None
    assert config.max_file_size_mb is None
    assert config.max_processes is None


def test_resource_limits_config_with_values():
    """ResourceLimitsConfig should accept valid values."""
    config = ResourceLimitsConfig(
        max_memory_mb=512,
        max_cpu_seconds=30,
        max_file_size_mb=100,
        max_processes=10,
    )
    assert config.max_memory_mb == 512
    assert config.max_cpu_seconds == 30
    assert config.max_file_size_mb == 100
    assert config.max_processes == 10


def test_resource_limits_config_min_values():
    """ResourceLimitsConfig should accept minimum valid values."""
    config = ResourceLimitsConfig(
        max_memory_mb=1,
        max_cpu_seconds=1,
        max_file_size_mb=1,
        max_processes=1,
    )
    assert config.max_memory_mb == 1
    assert config.max_cpu_seconds == 1
    assert config.max_file_size_mb == 1
    assert config.max_processes == 1


def test_resource_limits_config_max_values():
    """ResourceLimitsConfig should accept maximum valid values."""
    config = ResourceLimitsConfig(
        max_memory_mb=65536,
        max_cpu_seconds=86400,
        max_file_size_mb=10240,
        max_processes=1024,
    )
    assert config.max_memory_mb == 65536
    assert config.max_cpu_seconds == 86400
    assert config.max_file_size_mb == 10240
    assert config.max_processes == 1024


def test_sandbox_config_with_resource_limits():
    """SandboxRuntimeConfig should accept resource_limits field."""
    config = SandboxRuntimeConfig(
        network={"allowed_domains": [], "denied_domains": []},
        filesystem={"deny_read": [], "allow_write": [], "deny_write": []},
        resource_limits=ResourceLimitsConfig(
            max_memory_mb=256,
            max_cpu_seconds=60,
        ),
    )
    assert config.resource_limits is not None
    assert config.resource_limits.max_memory_mb == 256
    assert config.resource_limits.max_cpu_seconds == 60


def test_sandbox_config_resource_limits_from_dict():
    """SandboxRuntimeConfig should accept resource_limits as a dict."""
    config = SandboxRuntimeConfig(
        network={"allowed_domains": [], "denied_domains": []},
        filesystem={"deny_read": [], "allow_write": [], "deny_write": []},
        resource_limits={
            "max_memory_mb": 1024,
            "max_cpu_seconds": 120,
            "max_file_size_mb": 50,
        },
    )
    assert config.resource_limits is not None
    assert config.resource_limits.max_memory_mb == 1024
    assert config.resource_limits.max_cpu_seconds == 120
    assert config.resource_limits.max_file_size_mb == 50
    assert config.resource_limits.max_processes is None


# --- create_resource_limiter tests ---


def test_create_resource_limiter_returns_none_when_no_limits():
    """create_resource_limiter should return None when limits is None."""
    result = create_resource_limiter(None)
    assert result is None


def test_create_resource_limiter_returns_callable_with_limits():
    """create_resource_limiter should return a callable when limits are provided."""
    limits = ResourceLimitsConfig(max_memory_mb=512)
    result = create_resource_limiter(limits)
    assert callable(result)


def test_create_resource_limiter_sets_memory_limit():
    """create_resource_limiter should call setrlimit for RLIMIT_AS when max_memory_mb is set."""
    import resource

    limits = ResourceLimitsConfig(max_memory_mb=512)
    limiter = create_resource_limiter(limits)
    assert limiter is not None

    with patch("sandbox_runtime.runner.resource.setrlimit") as mock_setrlimit:
        limiter()

        expected_bytes = 512 * 1024 * 1024
        mock_setrlimit.assert_called_once_with(resource.RLIMIT_AS, (expected_bytes, expected_bytes))


def test_create_resource_limiter_sets_cpu_limit():
    """create_resource_limiter should call setrlimit for RLIMIT_CPU when max_cpu_seconds is set."""
    import resource

    limits = ResourceLimitsConfig(max_cpu_seconds=30)
    limiter = create_resource_limiter(limits)
    assert limiter is not None

    with patch("sandbox_runtime.runner.resource.setrlimit") as mock_setrlimit:
        limiter()

        mock_setrlimit.assert_called_once_with(resource.RLIMIT_CPU, (30, 30))


def test_create_resource_limiter_sets_file_size_limit():
    """create_resource_limiter should call setrlimit for RLIMIT_FSIZE when max_file_size_mb is set."""
    import resource

    limits = ResourceLimitsConfig(max_file_size_mb=100)
    limiter = create_resource_limiter(limits)
    assert limiter is not None

    with patch("sandbox_runtime.runner.resource.setrlimit") as mock_setrlimit:
        limiter()

        expected_bytes = 100 * 1024 * 1024
        mock_setrlimit.assert_called_once_with(resource.RLIMIT_FSIZE, (expected_bytes, expected_bytes))


def test_create_resource_limiter_sets_process_limit():
    """create_resource_limiter should call setrlimit for RLIMIT_NPROC when max_processes is set."""
    import resource

    limits = ResourceLimitsConfig(max_processes=10)
    limiter = create_resource_limiter(limits)
    assert limiter is not None

    with patch("sandbox_runtime.runner.resource.setrlimit") as mock_setrlimit:
        limiter()

        mock_setrlimit.assert_called_once_with(resource.RLIMIT_NPROC, (10, 10))


def test_create_resource_limiter_sets_multiple_limits():
    """create_resource_limiter should call setrlimit for all configured limits."""
    import resource

    limits = ResourceLimitsConfig(
        max_memory_mb=256,
        max_cpu_seconds=60,
        max_file_size_mb=50,
        max_processes=5,
    )
    limiter = create_resource_limiter(limits)
    assert limiter is not None

    with patch("sandbox_runtime.runner.resource.setrlimit") as mock_setrlimit:
        limiter()

        # Should be called 4 times for 4 different limits
        assert mock_setrlimit.call_count == 4

        # Verify all calls were made with correct arguments
        calls = mock_setrlimit.call_args_list
        call_args = {c[0][0]: c[0][1] for c in calls}

        assert call_args[resource.RLIMIT_AS] == (256 * 1024 * 1024, 256 * 1024 * 1024)
        assert call_args[resource.RLIMIT_CPU] == (60, 60)
        assert call_args[resource.RLIMIT_FSIZE] == (50 * 1024 * 1024, 50 * 1024 * 1024)
        assert call_args[resource.RLIMIT_NPROC] == (5, 5)


# --- get_resource_violation_reason tests ---


def test_get_resource_violation_reason_returns_none_for_success():
    """get_resource_violation_reason should return None for successful exit."""
    assert get_resource_violation_reason(0) is None
    assert get_resource_violation_reason(1) is None
    assert get_resource_violation_reason(127) is None


def test_get_resource_violation_reason_returns_none_for_none():
    """get_resource_violation_reason should return None for None input."""
    assert get_resource_violation_reason(None) is None


def test_get_resource_violation_reason_detects_sigxcpu_negative():
    """get_resource_violation_reason should detect SIGXCPU from negative exit code."""
    # SIGXCPU = 24
    result = get_resource_violation_reason(-24)
    assert result == "CPU time limit exceeded"


def test_get_resource_violation_reason_detects_sigxcpu_128_offset():
    """get_resource_violation_reason should detect SIGXCPU from 128+signal exit code."""
    # SIGXCPU = 24, so 128 + 24 = 152
    result = get_resource_violation_reason(152)
    assert result == "CPU time limit exceeded"


def test_get_resource_violation_reason_detects_sigxfsz_negative():
    """get_resource_violation_reason should detect SIGXFSZ from negative exit code."""
    # SIGXFSZ = 25
    result = get_resource_violation_reason(-25)
    assert result == "File size limit exceeded"


def test_get_resource_violation_reason_detects_sigxfsz_128_offset():
    """get_resource_violation_reason should detect SIGXFSZ from 128+signal exit code."""
    # SIGXFSZ = 25, so 128 + 25 = 153
    result = get_resource_violation_reason(153)
    assert result == "File size limit exceeded"


def test_get_resource_violation_reason_detects_sigkill():
    """get_resource_violation_reason should detect SIGKILL (possible OOM)."""
    # SIGKILL = 9
    result = get_resource_violation_reason(-9)
    assert result == "Process killed (possibly memory limit exceeded)"


def test_get_resource_violation_reason_other_signals():
    """get_resource_violation_reason should return None for other signals."""
    # SIGTERM = 15
    assert get_resource_violation_reason(-15) is None
    # SIGINT = 2
    assert get_resource_violation_reason(-2) is None
    # SIGSEGV = 11
    assert get_resource_violation_reason(-11) is None
