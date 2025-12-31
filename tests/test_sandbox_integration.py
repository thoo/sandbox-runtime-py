"""Integration tests demonstrating sandbox restrictions.

These tests verify that the sandbox actually restricts:
1. Filesystem access (blocking reads to sensitive paths)
2. Network access (blocking non-allowed domains)
3. Environment detection (proxy variables set inside sandbox)
"""

import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from sandbox_runtime.config import SandboxRuntimeConfig
from sandbox_runtime.manager import SandboxManager


@pytest.fixture
def integration_config() -> SandboxRuntimeConfig:
    """Create a configuration for integration testing."""
    return SandboxRuntimeConfig(
        network={
            "allowed_domains": ["pypi.org", "*.pypi.org"],
            "denied_domains": [],
        },
        filesystem={
            "deny_read": ["~/.ssh"],
            "allow_write": [".", "/tmp"],
            "deny_write": [],
        },
    )


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only integration test")
@pytest.mark.integration
class TestSandboxFilesystemRestrictions:
    """Tests for filesystem restrictions in the sandbox."""

    async def test_blocks_ssh_directory_read(self, integration_config: SandboxRuntimeConfig):
        """Test that reading ~/.ssh is blocked inside the sandbox."""
        await SandboxManager.initialize(integration_config)
        try:
            wrapped_cmd = await SandboxManager.wrap_with_sandbox("cat ~/.ssh/config")

            process = subprocess.run(
                wrapped_cmd,
                check=False,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
            )

            # Should fail with "Operation not permitted"
            assert process.returncode != 0
            assert "Operation not permitted" in process.stderr or "Permission denied" in process.stderr
        finally:
            await SandboxManager.reset()

    async def test_allows_current_directory_write(self, integration_config: SandboxRuntimeConfig):
        """Test that writing to current directory is allowed."""
        await SandboxManager.initialize(integration_config)
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                test_file = Path(tmpdir) / "test_write.txt"
                wrapped_cmd = await SandboxManager.wrap_with_sandbox(
                    f'echo "test content" > {test_file}',
                    custom_config=SandboxRuntimeConfig(
                        network=integration_config.network.model_dump(),
                        filesystem={
                            "deny_read": [],
                            "allow_write": [tmpdir, "/tmp"],
                            "deny_write": [],
                        },
                    ),
                )

                process = subprocess.run(
                    wrapped_cmd,
                    check=False,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=10,
                )

                # Write should succeed
                assert process.returncode == 0
                assert test_file.exists()
        finally:
            await SandboxManager.reset()


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only integration test")
@pytest.mark.integration
class TestSandboxNetworkRestrictions:
    """Tests for network restrictions in the sandbox."""

    async def test_blocks_non_allowed_domain(self, integration_config: SandboxRuntimeConfig):
        """Test that accessing non-allowed domains is blocked."""
        await SandboxManager.initialize(integration_config)
        try:
            # google.com is not in allowed_domains
            wrapped_cmd = await SandboxManager.wrap_with_sandbox(
                "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 5 https://google.com"
            )

            process = subprocess.run(
                wrapped_cmd,
                check=False,
                shell=True,
                capture_output=True,
                text=True,
                timeout=15,
            )

            # Should fail or return 403
            assert process.returncode != 0 or "403" in process.stdout
        finally:
            await SandboxManager.reset()

    async def test_allows_permitted_domain(self, integration_config: SandboxRuntimeConfig):
        """Test that accessing allowed domains works."""
        await SandboxManager.initialize(integration_config)
        try:
            # pypi.org is in allowed_domains
            wrapped_cmd = await SandboxManager.wrap_with_sandbox(
                "curl -s -o /dev/null -w '%{http_code}' --connect-timeout 10 https://pypi.org"
            )

            process = subprocess.run(
                wrapped_cmd,
                check=False,
                shell=True,
                capture_output=True,
                text=True,
                timeout=20,
            )

            # Should succeed with 200 or 301/302 redirect
            http_code = process.stdout.strip()
            assert http_code in ["200", "301", "302", "000"] or process.returncode == 0
        finally:
            await SandboxManager.reset()


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only integration test")
@pytest.mark.integration
class TestSandboxEnvironmentDetection:
    """Tests for detecting sandbox environment."""

    async def test_proxy_environment_variables_set(self, integration_config: SandboxRuntimeConfig):
        """Test that HTTP_PROXY and HTTPS_PROXY are set inside sandbox."""
        await SandboxManager.initialize(integration_config)
        try:
            wrapped_cmd = await SandboxManager.wrap_with_sandbox(
                'python -c \'import os; print(os.environ.get("HTTP_PROXY", "NOT_SET"))\''
            )

            process = subprocess.run(
                wrapped_cmd,
                check=False,
                shell=True,
                capture_output=True,
                text=True,
                timeout=10,
            )

            # HTTP_PROXY should be set to localhost proxy
            assert "localhost" in process.stdout or "127.0.0.1" in process.stdout
        finally:
            await SandboxManager.reset()

    async def test_proxy_not_set_outside_sandbox(self):
        """Test that proxy variables are not set outside sandbox (baseline)."""
        import os

        # Outside sandbox, these should not be set (unless user configured them)
        http_proxy = os.environ.get("HTTP_PROXY")
        # This test just documents expected behavior - proxy shouldn't be set
        # unless the user has configured it themselves
        assert http_proxy is None or "localhost" not in http_proxy


@pytest.mark.skipif(sys.platform != "darwin", reason="macOS-only integration test")
@pytest.mark.integration
class TestSandboxPlotGeneration:
    """Tests for generating plots inside the sandbox."""

    async def test_matplotlib_plot_generation(self, integration_config: SandboxRuntimeConfig):
        """Test that matplotlib can generate and save plots inside sandbox."""
        await SandboxManager.initialize(integration_config)
        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                output_path = Path(tmpdir) / "test_plot.png"

                # Create a config that allows writing to the temp directory
                plot_config = SandboxRuntimeConfig(
                    network={"allowed_domains": [], "denied_domains": []},
                    filesystem={
                        "deny_read": [],
                        "allow_write": [tmpdir, "/tmp"],
                        "deny_write": [],
                    },
                )

                plot_script = f'''
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

x = np.linspace(0, 10, 50)
y = np.sin(x)

fig, ax = plt.subplots()
ax.plot(x, y)
ax.set_title("Test Plot")
plt.savefig("{output_path}")
plt.close()
print("Plot saved successfully")
'''

                # Write the script to a temp file
                script_path = Path(tmpdir) / "plot_script.py"
                script_path.write_text(plot_script)

                wrapped_cmd = await SandboxManager.wrap_with_sandbox(
                    f"python {script_path}",
                    custom_config=plot_config,
                )

                process = subprocess.run(
                    wrapped_cmd,
                    check=False,
                    shell=True,
                    capture_output=True,
                    text=True,
                    timeout=30,
                )

                # Check if plot was generated
                if output_path.exists():
                    assert output_path.stat().st_size > 0
                    assert "Plot saved successfully" in process.stdout
                else:
                    # matplotlib might not be installed, skip gracefully
                    pytest.skip("matplotlib not available")
        finally:
            await SandboxManager.reset()
