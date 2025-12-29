"""Tests for sandbox_runtime.socks_proxy module."""

import asyncio
import socket
import struct

import pytest

from sandbox_runtime.socks_proxy import (
    ATYP_DOMAIN,
    ATYP_IPV4,
    AUTH_NO_AUTH,
    CMD_CONNECT,
    REP_CONNECTION_NOT_ALLOWED,
    REP_SUCCESS,
    SOCKS_VERSION,
    Socks5ProxyServer,
    create_socks_proxy_server,
)


class TestSocks5ProxyServer:
    """Tests for Socks5ProxyServer class."""

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
        allowed_hosts = {"example.com", "allowed.test", "127.0.0.1"}

        def filter_fn(port: int, host: str) -> bool:
            return host in allowed_hosts

        return filter_fn

    @pytest.fixture
    def async_filter(self):
        """Async filter function."""

        async def filter_fn(port: int, host: str) -> bool:
            await asyncio.sleep(0.001)
            return host == "async.test"

        return filter_fn

    async def test_create_server(self, allow_all_filter):
        """Test creating a SOCKS5 proxy server."""
        server = create_socks_proxy_server(allow_all_filter)
        assert isinstance(server, Socks5ProxyServer)
        assert server.port is None

    async def test_start_and_stop(self, allow_all_filter):
        """Test starting and stopping the server."""
        server = Socks5ProxyServer(allow_all_filter)

        port = await server.start()
        assert port > 0
        assert server.port == port

        await server.stop()
        assert server.port is None

    async def test_start_on_random_port(self, allow_all_filter):
        """Test that server starts on a random port when port=0."""
        server = Socks5ProxyServer(allow_all_filter)

        try:
            port = await server.start(port=0)
            assert port > 0
            assert port >= 1024
        finally:
            await server.stop()

    async def test_multiple_start_stop_cycles(self, allow_all_filter):
        """Test multiple start/stop cycles."""
        server = Socks5ProxyServer(allow_all_filter)

        for _ in range(3):
            port = await server.start()
            assert port > 0
            await server.stop()
            assert server.port is None

    async def test_stop_without_start(self, allow_all_filter):
        """Test that stopping a non-started server is safe."""
        server = Socks5ProxyServer(allow_all_filter)
        await server.stop()
        assert server.port is None

    async def test_unref(self, allow_all_filter):
        """Test unref method (no-op in Python)."""
        server = Socks5ProxyServer(allow_all_filter)
        # Should not raise
        server.unref()


class TestSocks5Protocol:
    """Tests for SOCKS5 protocol implementation."""

    @pytest.fixture
    async def running_proxy(self, request):
        """Create a running proxy with configurable filter."""

        def default_filter(port: int, host: str) -> bool:
            return host in {"allowed.test", "127.0.0.1"}

        filter_fn = getattr(request, "param", default_filter)
        server = Socks5ProxyServer(filter_fn)
        port = await server.start()

        yield server, port

        await server.stop()

    async def test_authentication_handshake(self, running_proxy):
        """Test SOCKS5 authentication handshake."""
        server, port = running_proxy

        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        try:
            # Send auth request: version + 1 method + no auth
            writer.write(struct.pack("!BBB", SOCKS_VERSION, 1, AUTH_NO_AUTH))
            await writer.drain()

            # Read auth response
            response = await reader.readexactly(2)
            version, method = struct.unpack("!BB", response)

            assert version == SOCKS_VERSION
            assert method == AUTH_NO_AUTH
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_connect_allowed_domain(self, running_proxy):
        """Test CONNECT to allowed domain."""
        server, port = running_proxy

        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        try:
            # Auth handshake
            writer.write(struct.pack("!BBB", SOCKS_VERSION, 1, AUTH_NO_AUTH))
            await writer.drain()
            await reader.readexactly(2)

            # Connect request to allowed.test:80
            domain = b"allowed.test"
            writer.write(
                struct.pack("!BBBBB", SOCKS_VERSION, CMD_CONNECT, 0, ATYP_DOMAIN, len(domain))
                + domain
                + struct.pack("!H", 80)
            )
            await writer.drain()

            # Read reply (at least first 4 bytes)
            reply = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
            version, rep, _, atyp = struct.unpack("!BBBB", reply)

            assert version == SOCKS_VERSION
            # Rep could be success or failure depending on if allowed.test resolves
            # Just check we got a valid SOCKS response
            assert rep in (
                REP_SUCCESS,
                0x03,
                0x04,
                0x05,
                0x01,
            )  # Various error codes
        except TimeoutError:
            # Connection might hang if allowed.test doesn't resolve
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_connect_blocked_domain(self, running_proxy):
        """Test CONNECT to blocked domain returns REP_CONNECTION_NOT_ALLOWED."""
        server, port = running_proxy

        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        try:
            # Auth handshake
            writer.write(struct.pack("!BBB", SOCKS_VERSION, 1, AUTH_NO_AUTH))
            await writer.drain()
            await reader.readexactly(2)

            # Connect request to blocked.test:80
            domain = b"blocked.test"
            writer.write(
                struct.pack("!BBBBB", SOCKS_VERSION, CMD_CONNECT, 0, ATYP_DOMAIN, len(domain))
                + domain
                + struct.pack("!H", 80)
            )
            await writer.drain()

            # Read full reply
            reply = await reader.readexactly(10)  # Standard reply size
            version, rep, _, atyp = struct.unpack("!BBBB", reply[:4])

            assert version == SOCKS_VERSION
            assert rep == REP_CONNECTION_NOT_ALLOWED
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_connect_ipv4(self, running_proxy):
        """Test CONNECT with IPv4 address."""
        server, port = running_proxy

        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        try:
            # Auth handshake
            writer.write(struct.pack("!BBB", SOCKS_VERSION, 1, AUTH_NO_AUTH))
            await writer.drain()
            await reader.readexactly(2)

            # Connect request to 127.0.0.1:80 (allowed in filter)
            addr = socket.inet_aton("127.0.0.1")
            writer.write(struct.pack("!BBBB", SOCKS_VERSION, CMD_CONNECT, 0, ATYP_IPV4) + addr + struct.pack("!H", 80))
            await writer.drain()

            # Read reply header
            reply = await asyncio.wait_for(reader.readexactly(4), timeout=5.0)
            version, rep, _, _ = struct.unpack("!BBBB", reply)

            assert version == SOCKS_VERSION
            # Could be success or connection refused (no server on 127.0.0.1:80)
            assert rep in (REP_SUCCESS, 0x01, 0x05)
        except TimeoutError:
            pass
        finally:
            writer.close()
            await writer.wait_closed()

    async def test_invalid_version(self, running_proxy):
        """Test that invalid SOCKS version closes connection."""
        server, port = running_proxy

        reader, writer = await asyncio.open_connection("127.0.0.1", port)

        try:
            # Send invalid version
            writer.write(struct.pack("!BBB", 0x04, 1, AUTH_NO_AUTH))  # SOCKS4
            await writer.drain()

            # Connection should be closed
            data = await asyncio.wait_for(reader.read(1024), timeout=1.0)
            # Empty read means connection closed
            assert data == b""
        except TimeoutError:
            # Also acceptable
            pass
        finally:
            writer.close()
            await writer.wait_closed()


class TestSocks5ProxyWithAsyncFilter:
    """Tests for SOCKS5 proxy with async filter function."""

    async def test_async_filter(self):
        """Test that async filter function works correctly."""
        filter_calls: list[str] = []

        async def async_filter(port: int, host: str) -> bool:
            filter_calls.append(host)
            await asyncio.sleep(0.001)
            return host == "async.allowed.test"

        server = Socks5ProxyServer(async_filter)

        try:
            port = await server.start()

            reader, writer = await asyncio.open_connection("127.0.0.1", port)

            try:
                # Auth handshake
                writer.write(struct.pack("!BBB", SOCKS_VERSION, 1, AUTH_NO_AUTH))
                await writer.drain()
                await reader.readexactly(2)

                # Connect request
                domain = b"async.test"
                writer.write(
                    struct.pack("!BBBBB", SOCKS_VERSION, CMD_CONNECT, 0, ATYP_DOMAIN, len(domain))
                    + domain
                    + struct.pack("!H", 80)
                )
                await writer.drain()

                # Read reply
                reply = await reader.readexactly(10)
                _, rep, _, _ = struct.unpack("!BBBB", reply[:4])

                # Should be blocked (async.test != async.allowed.test)
                assert rep == REP_CONNECTION_NOT_ALLOWED
                assert "async.test" in filter_calls
            finally:
                writer.close()
                await writer.wait_closed()
        finally:
            await server.stop()
