"""SOCKS5 proxy server for network filtering."""

import asyncio
import socket
import struct
from collections.abc import Awaitable, Callable

from .utils.debug import log_for_debugging

# Type for the filter callback
FilterCallback = Callable[[int, str], Awaitable[bool] | bool]

# SOCKS5 protocol constants
SOCKS_VERSION = 0x05

# Authentication methods
AUTH_NO_AUTH = 0x00
AUTH_NO_ACCEPTABLE = 0xFF

# Commands
CMD_CONNECT = 0x01

# Address types
ATYP_IPV4 = 0x01
ATYP_DOMAIN = 0x03
ATYP_IPV6 = 0x04

# Reply codes
REP_SUCCESS = 0x00
REP_GENERAL_FAILURE = 0x01
REP_CONNECTION_NOT_ALLOWED = 0x02
REP_NETWORK_UNREACHABLE = 0x03
REP_HOST_UNREACHABLE = 0x04
REP_CONNECTION_REFUSED = 0x05
REP_TTL_EXPIRED = 0x06
REP_COMMAND_NOT_SUPPORTED = 0x07
REP_ADDRESS_TYPE_NOT_SUPPORTED = 0x08


class Socks5ProxyServer:
    """
    Minimal SOCKS5 proxy server that filters connections based on domain allowlist.

    Only supports the CONNECT command (sufficient for most use cases).
    """

    def __init__(self, filter_fn: FilterCallback) -> None:
        """
        Initialize the SOCKS5 proxy server.

        Args:
            filter_fn: Callback function that takes (port, host) and returns True if allowed
        """
        self._filter_fn = filter_fn
        self._server: asyncio.Server | None = None
        self._port: int | None = None

    @property
    def port(self) -> int | None:
        """Get the port the server is listening on."""
        return self._port

    async def _check_filter(self, port: int, host: str) -> bool:
        """Check if a connection should be allowed."""
        result = self._filter_fn(port, host)
        if asyncio.iscoroutine(result):
            return await result
        return result

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single client connection."""
        try:
            # === Authentication negotiation ===
            # Client sends: VER | NMETHODS | METHODS
            header = await reader.readexactly(2)
            version, nmethods = struct.unpack("!BB", header)

            if version != SOCKS_VERSION:
                writer.close()
                await writer.wait_closed()
                return

            # Read authentication methods
            methods = await reader.readexactly(nmethods)

            # We only support no authentication
            if AUTH_NO_AUTH not in methods:
                writer.write(struct.pack("!BB", SOCKS_VERSION, AUTH_NO_ACCEPTABLE))
                await writer.drain()
                writer.close()
                await writer.wait_closed()
                return

            # Send: VER | METHOD (no auth required)
            writer.write(struct.pack("!BB", SOCKS_VERSION, AUTH_NO_AUTH))
            await writer.drain()

            # === Request handling ===
            # Client sends: VER | CMD | RSV | ATYP | DST.ADDR | DST.PORT
            request_header = await reader.readexactly(4)
            version, cmd, _, atyp = struct.unpack("!BBBB", request_header)

            if version != SOCKS_VERSION:
                writer.close()
                await writer.wait_closed()
                return

            # Only support CONNECT command
            if cmd != CMD_CONNECT:
                await self._send_reply(writer, REP_COMMAND_NOT_SUPPORTED, atyp)
                return

            # Parse destination address
            if atyp == ATYP_IPV4:
                addr_data = await reader.readexactly(4)
                dest_addr = socket.inet_ntoa(addr_data)
            elif atyp == ATYP_DOMAIN:
                addr_len = (await reader.readexactly(1))[0]
                dest_addr = (await reader.readexactly(addr_len)).decode()
            elif atyp == ATYP_IPV6:
                addr_data = await reader.readexactly(16)
                dest_addr = socket.inet_ntop(socket.AF_INET6, addr_data)
            else:
                await self._send_reply(writer, REP_ADDRESS_TYPE_NOT_SUPPORTED, atyp)
                return

            # Read destination port
            port_data = await reader.readexactly(2)
            dest_port = struct.unpack("!H", port_data)[0]

            log_for_debugging(f"Connection request to {dest_addr}:{dest_port}")

            # Check filter
            allowed = await self._check_filter(dest_port, dest_addr)
            if not allowed:
                log_for_debugging(
                    f"Connection blocked to {dest_addr}:{dest_port}",
                    level="error",
                )
                await self._send_reply(writer, REP_CONNECTION_NOT_ALLOWED, atyp)
                return

            log_for_debugging(f"Connection allowed to {dest_addr}:{dest_port}")

            # Connect to destination
            try:
                remote_reader, remote_writer = await asyncio.open_connection(
                    dest_addr,
                    dest_port,
                )
            except OSError as e:
                log_for_debugging(f"Connection failed to {dest_addr}:{dest_port}: {e}", level="error")
                if "refused" in str(e).lower():
                    await self._send_reply(writer, REP_CONNECTION_REFUSED, atyp)
                elif "unreachable" in str(e).lower():
                    await self._send_reply(writer, REP_HOST_UNREACHABLE, atyp)
                else:
                    await self._send_reply(writer, REP_GENERAL_FAILURE, atyp)
                return

            # Send success reply
            await self._send_reply(writer, REP_SUCCESS, ATYP_IPV4)

            # Pipe data between client and remote
            async def pipe(
                src: asyncio.StreamReader,
                dst: asyncio.StreamWriter,
            ) -> None:
                try:
                    while True:
                        data = await src.read(8192)
                        if not data:
                            break
                        dst.write(data)
                        await dst.drain()
                except Exception:
                    pass
                finally:
                    try:
                        dst.close()
                    except Exception:
                        pass

            await asyncio.gather(
                pipe(reader, remote_writer),
                pipe(remote_reader, writer),
                return_exceptions=True,
            )

        except asyncio.IncompleteReadError:
            pass
        except Exception as e:
            log_for_debugging(f"Error handling SOCKS client: {e}", level="error")
        finally:
            try:
                writer.close()
                await writer.wait_closed()
            except Exception:
                pass

    async def _send_reply(
        self,
        writer: asyncio.StreamWriter,
        reply_code: int,
        atyp: int = ATYP_IPV4,
    ) -> None:
        """Send a SOCKS5 reply to the client."""
        # Reply: VER | REP | RSV | ATYP | BND.ADDR | BND.PORT
        # For simplicity, we always send 0.0.0.0:0 as bound address
        reply = struct.pack(
            "!BBBB4sH",
            SOCKS_VERSION,
            reply_code,
            0x00,  # Reserved
            ATYP_IPV4,
            b"\x00\x00\x00\x00",  # Bound address (0.0.0.0)
            0,  # Bound port
        )
        writer.write(reply)
        await writer.drain()

        if reply_code != REP_SUCCESS:
            writer.close()
            await writer.wait_closed()

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> int:
        """
        Start the SOCKS5 proxy server.

        Args:
            host: Host to bind to (default: 127.0.0.1)
            port: Port to bind to (default: 0 for random available port)

        Returns:
            The actual port the server is listening on
        """
        self._server = await asyncio.start_server(
            self._handle_client,
            host,
            port,
        )

        # Get the actual port
        if self._server.sockets:
            self._port = self._server.sockets[0].getsockname()[1]
            log_for_debugging(f"SOCKS proxy listening on {host}:{self._port}")
            return self._port

        raise RuntimeError("Failed to get SOCKS proxy server address")

    async def stop(self) -> None:
        """Stop the SOCKS5 proxy server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        self._port = None

    def unref(self) -> None:
        """Unref the server (allow process to exit even if server is running)."""
        # In Python, we don't have the same concept as Node.js unref
        # The asyncio event loop will keep running as long as there are tasks
        pass


def create_socks_proxy_server(filter_fn: FilterCallback) -> Socks5ProxyServer:
    """
    Create a SOCKS5 proxy server with the given filter function.

    Args:
        filter_fn: Callback function that takes (port, host) and returns True if allowed

    Returns:
        A Socks5ProxyServer instance (not yet started)
    """
    return Socks5ProxyServer(filter_fn)
