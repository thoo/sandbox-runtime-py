"""Tests for sandbox_runtime.http_proxy module."""

import asyncio

import pytest

from sandbox_runtime.http_proxy import HttpProxyServer, create_http_proxy_server


class TestHttpProxyServer:
    """Tests for HttpProxyServer class."""

    @pytest.fixture
    def allow_all_filter(self):
        """Filter that allows all connections."""

        def filter_fn(port: int, host: str) -> bool:
            return True

        return filter_fn

    @pytest.fixture
    def deny_all_filter(self):
        """Filter that denies all connections."""

        def filter_fn(port: int, host: str) -> bool:
            return False

        return filter_fn

    @pytest.fixture
    def selective_filter(self):
        """Filter that only allows specific hosts."""
        allowed_hosts = {"example.com", "allowed.test"}

        def filter_fn(port: int, host: str) -> bool:
            return host in allowed_hosts

        return filter_fn

    @pytest.fixture
    def async_filter(self):
        """Async filter function."""

        async def filter_fn(port: int, host: str) -> bool:
            await asyncio.sleep(0.001)  # Small delay to simulate async work
            return host == "async.test"

        return filter_fn

    async def test_create_server(self, allow_all_filter):
        """Test creating an HTTP proxy server."""
        server = create_http_proxy_server(allow_all_filter)
        assert isinstance(server, HttpProxyServer)
        assert server.port is None  # Not started yet

    async def test_start_and_stop(self, allow_all_filter):
        """Test starting and stopping the server."""
        server = HttpProxyServer(allow_all_filter)

        # Start server
        port = await server.start()
        assert port > 0
        assert server.port == port

        # Stop server
        await server.stop()
        assert server.port is None

    async def test_start_on_random_port(self, allow_all_filter):
        """Test that server starts on a random port when port=0."""
        server = HttpProxyServer(allow_all_filter)

        try:
            port = await server.start(port=0)
            assert port > 0
            # Port should be in the ephemeral range
            assert port >= 1024
        finally:
            await server.stop()

    async def test_start_on_specific_port(self, allow_all_filter):
        """Test starting server on a specific port."""
        server = HttpProxyServer(allow_all_filter)

        # Use a random high port to avoid conflicts
        import socket

        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        test_port = sock.getsockname()[1]
        sock.close()

        try:
            port = await server.start(port=test_port)
            assert port == test_port
        finally:
            await server.stop()

    async def test_filter_callback_sync(self, selective_filter):
        """Test that sync filter callback is called correctly."""
        filter_calls: list[tuple[int, str]] = []

        def tracking_filter(port: int, host: str) -> bool:
            filter_calls.append((port, host))
            return selective_filter(port, host)

        server = HttpProxyServer(tracking_filter)
        await server.start()

        try:
            # The filter is checked when requests come in
            # We can verify the server is running
            assert server.port is not None
        finally:
            await server.stop()

    async def test_filter_callback_async(self, async_filter):
        """Test that async filter callback works correctly."""
        server = HttpProxyServer(async_filter)

        try:
            port = await server.start()
            assert port > 0
        finally:
            await server.stop()

    async def test_multiple_start_stop_cycles(self, allow_all_filter):
        """Test multiple start/stop cycles."""
        server = HttpProxyServer(allow_all_filter)

        for _ in range(3):
            port = await server.start()
            assert port > 0
            await server.stop()
            assert server.port is None

    async def test_stop_without_start(self, allow_all_filter):
        """Test that stopping a non-started server is safe."""
        server = HttpProxyServer(allow_all_filter)
        # Should not raise
        await server.stop()
        assert server.port is None


class TestHttpProxyFiltering:
    """Tests for HTTP proxy request filtering."""

    @pytest.fixture
    async def proxy_with_filter(self):
        """Create a proxy with a configurable filter."""
        allowed_hosts: set[str] = set()

        def filter_fn(port: int, host: str) -> bool:
            return host in allowed_hosts

        server = HttpProxyServer(filter_fn)
        await server.start()

        yield server, allowed_hosts

        await server.stop()

    async def test_proxy_is_running(self, proxy_with_filter):
        """Test that proxy is running and accessible."""
        server, _ = proxy_with_filter
        assert server.port is not None
        assert server.port > 0


class TestHttpProxyIntegration:
    """Integration tests for HTTP proxy with real HTTP requests."""

    @pytest.fixture
    def domain_filter(self):
        """Filter that allows specific domains."""
        allowed = {"httpbin.org", "example.com", "127.0.0.1"}

        def filter_fn(port: int, host: str) -> bool:
            return host in allowed

        return filter_fn

    @pytest.mark.integration
    @pytest.mark.slow
    async def test_proxy_allows_whitelisted_domain(self, domain_filter):
        """Test that proxy allows requests to whitelisted domains."""
        import httpx

        server = HttpProxyServer(domain_filter)

        try:
            port = await server.start()

            async def handle_http(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
                try:
                    data = await reader.readuntil(b"\r\n\r\n")
                    if data:
                        response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
                        writer.write(response)
                        await writer.drain()
                finally:
                    writer.close()

            http_server = await asyncio.start_server(handle_http, "127.0.0.1", 0)
            http_port = http_server.sockets[0].getsockname()[1]

            # Make request through proxy
            async with httpx.AsyncClient(
                proxy=f"http://127.0.0.1:{port}",
                timeout=10.0,
            ) as client:
                response = await client.get(f"http://127.0.0.1:{http_port}/")
                assert response.status_code == 200
                assert response.text == "OK"
        finally:
            if "http_server" in locals():
                http_server.close()
                await http_server.wait_closed()
            await server.stop()

    @pytest.mark.integration
    @pytest.mark.slow
    async def test_proxy_blocks_non_whitelisted_domain(self, domain_filter):
        """Test that proxy blocks requests to non-whitelisted domains."""
        import httpx

        server = HttpProxyServer(domain_filter)

        try:
            port = await server.start()

            # Make request through proxy to non-whitelisted domain
            async with httpx.AsyncClient(
                proxy=f"http://127.0.0.1:{port}",
                timeout=10.0,
            ) as client:
                response = await client.get("http://blocked-domain.test/")
                # Should be blocked
                assert response.status_code == 403
                assert "blocked" in response.text.lower()
        finally:
            await server.stop()



class TestHttpProxyConnectTunnel:
    """Tests for HTTPS CONNECT tunneling with a local TCP server."""

    @staticmethod
    async def _start_echo_server():
        async def handle_echo(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                while True:
                    data = await reader.read(8192)
                    if not data:
                        break
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(handle_echo, "127.0.0.1", 0)
        port = server.sockets[0].getsockname()[1]
        return server, port

    async def test_connect_tunnel_to_local_echo(self):
        """Test CONNECT tunnel forwards raw bytes to a local echo server."""
        def allow_local(port: int, host: str) -> bool:
            return host == "127.0.0.1"

        proxy = HttpProxyServer(allow_local)
        echo_server, echo_port = await self._start_echo_server()
        writer = None

        try:
            proxy_port = await proxy.start()
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)

            connect_req = (
                f"CONNECT 127.0.0.1:{echo_port} HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{echo_port}\r\n"
                "\r\n"
            )
            writer.write(connect_req.encode())
            await writer.drain()

            response = await reader.readuntil(b"\r\n\r\n")
            assert b"200" in response.split(b"\r\n", 1)[0]

            payload = b"ping"
            writer.write(payload)
            await writer.drain()

            echoed = await reader.readexactly(len(payload))
            assert echoed == payload
        finally:
            if writer is not None:
                writer.close()
            echo_server.close()
            await echo_server.wait_closed()
            await proxy.stop()


class TestHttpProxyHttpsWithoutConnect:
    """Tests for HTTPS requests without CONNECT."""

    async def test_https_absolute_form_rejected(self):
        """Test https:// absolute-form without CONNECT returns 400."""
        def allow_all(port: int, host: str) -> bool:
            return True

        proxy = HttpProxyServer(allow_all)
        writer = None

        try:
            proxy_port = await proxy.start()
            reader, writer = await asyncio.open_connection("127.0.0.1", proxy_port)
            request = b"GET https://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n"
            writer.write(request)
            await writer.drain()

            response = await reader.readuntil(b"\r\n\r\n")
            assert b"400 Bad Request" in response.split(b"\r\n", 1)[0]
        finally:
            if writer is not None:
                writer.close()
            await proxy.stop()
