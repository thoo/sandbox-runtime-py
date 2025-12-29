"""HTTP/HTTPS proxy server for network filtering."""

import asyncio
from collections.abc import Awaitable, Callable
from urllib.parse import urlparse

from aiohttp import ClientSession, TCPConnector

from .utils.debug import log_for_debugging

# Type for the filter callback
FilterCallback = Callable[[int, str], Awaitable[bool] | bool]

_HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "proxy-connection",
    "te",
    "trailer",
    "upgrade",
}


class HttpProxyServer:
    """
    HTTP/HTTPS proxy server that filters requests based on domain allowlist.

    Handles regular HTTP requests and HTTPS CONNECT tunnels.
    """

    def __init__(self, filter_fn: FilterCallback) -> None:
        """
        Initialize the HTTP proxy server.

        Args:
            filter_fn: Callback function that takes (port, host) and returns True if allowed
        """
        self._filter_fn = filter_fn
        self._server: asyncio.AbstractServer | None = None
        self._port: int | None = None

    @property
    def port(self) -> int | None:
        """Get the port the server is listening on."""
        return self._port

    async def _check_filter(self, port: int, host: str) -> bool:
        """Check if a request should be allowed."""
        result = self._filter_fn(port, host)
        if asyncio.iscoroutine(result):
            return await result
        return result

    async def _read_headers(
        self,
        reader: asyncio.StreamReader,
        max_size: int = 65536,
    ) -> tuple[bytes, bytes]:
        """Read request headers and return (header_bytes, remaining_bytes)."""
        buffer = b""
        while b"\r\n\r\n" not in buffer:
            chunk = await reader.read(4096)
            if not chunk:
                break
            buffer += chunk
            if len(buffer) > max_size:
                raise ValueError("Request headers too large")
        if b"\r\n\r\n" not in buffer:
            raise ValueError("Incomplete HTTP headers")
        header_bytes, remaining = buffer.split(b"\r\n\r\n", 1)
        return header_bytes, remaining

    def _parse_headers(self, header_bytes: bytes) -> tuple[str, str, str, list[tuple[str, str]], dict[str, str]]:
        """Parse HTTP headers into request line parts and header lists."""
        lines = header_bytes.split(b"\r\n")
        request_line = lines[0].decode("latin-1")
        parts = request_line.split()
        if len(parts) != 3:
            raise ValueError("Invalid request line")
        method, target, version = parts

        headers: list[tuple[str, str]] = []
        header_map: dict[str, str] = {}
        for line in lines[1:]:
            if not line:
                continue
            if b":" not in line:
                continue
            name, value = line.split(b":", 1)
            name_str = name.decode("latin-1").strip()
            value_str = value.decode("latin-1").strip()
            headers.append((name_str, value_str))
            header_map[name_str.lower()] = value_str

        return method, target, version, headers, header_map

    async def _send_error(self, writer: asyncio.StreamWriter, status: str, message: str) -> None:
        """Send an HTTP error response and close the connection."""
        response = f"HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{message}"
        writer.write(response.encode("latin-1"))
        await writer.drain()
        writer.close()

    async def _read_exactly(
        self,
        reader: asyncio.StreamReader,
        length: int,
        buffer: bytes,
    ) -> bytes:
        """Read exactly length bytes, using buffer first."""
        if length <= 0:
            return b""
        data = buffer
        if len(data) >= length:
            return data[:length]
        remaining = length - len(data)
        more = await reader.readexactly(remaining)
        return data + more

    async def _read_chunked(
        self,
        reader: asyncio.StreamReader,
        buffer: bytes,
    ) -> bytes:
        """Decode HTTP chunked transfer encoding."""
        data = buffer
        body_parts: list[bytes] = []

        async def read_more() -> None:
            nonlocal data
            chunk = await reader.read(4096)
            if not chunk:
                raise ValueError("Unexpected EOF in chunked body")
            data += chunk

        while True:
            while b"\r\n" not in data:
                await read_more()
            line, data = data.split(b"\r\n", 1)
            chunk_size_str = line.split(b";", 1)[0].strip()
            if not chunk_size_str:
                raise ValueError("Invalid chunked encoding")
            try:
                chunk_size = int(chunk_size_str, 16)
            except ValueError as exc:
                raise ValueError("Invalid chunk size") from exc

            if chunk_size == 0:
                # Read and discard trailers until CRLF CRLF
                while b"\r\n\r\n" not in data:
                    await read_more()
                _, data = data.split(b"\r\n\r\n", 1)
                break

            while len(data) < chunk_size + 2:
                await read_more()
            body_parts.append(data[:chunk_size])
            data = data[chunk_size + 2 :]

        return b"".join(body_parts)

    async def _read_request_body(
        self,
        reader: asyncio.StreamReader,
        header_map: dict[str, str],
        body_prefix: bytes,
    ) -> bytes:
        """Read request body based on headers."""
        transfer_encoding = header_map.get("transfer-encoding", "").lower()
        content_length = header_map.get("content-length")

        if "chunked" in transfer_encoding:
            return await self._read_chunked(reader, body_prefix)

        if content_length is None:
            return body_prefix

        try:
            length = int(content_length)
        except ValueError:
            raise ValueError("Invalid Content-Length")

        return await self._read_exactly(reader, length, body_prefix)

    async def _handle_connect(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        target: str,
    ) -> None:
        """Handle HTTPS CONNECT requests for tunneling."""
        if ":" in target:
            host, port_str = target.rsplit(":", 1)
            try:
                port = int(port_str)
            except ValueError:
                await self._send_error(writer, "400 Bad Request", "Invalid CONNECT port")
                return
        else:
            host = target
            port = 443

        allowed = await self._check_filter(port, host)
        if not allowed:
            log_for_debugging(f"Connection blocked to {host}:{port}", level="error")
            await self._send_error(writer, "403 Forbidden", "Connection blocked by network allowlist")
            return

        try:
            remote_reader, remote_writer = await asyncio.open_connection(host, port)
        except OSError as e:
            log_for_debugging(f"CONNECT tunnel failed: {e}", level="error")
            await self._send_error(writer, "502 Bad Gateway", "Bad Gateway")
            return

        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()

        async def pipe(src: asyncio.StreamReader, dst: asyncio.StreamWriter) -> None:
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

    async def _handle_http_request(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        method: str,
        target: str,
        version: str,
        headers: list[tuple[str, str]],
        header_map: dict[str, str],
        body_prefix: bytes,
    ) -> None:
        """Handle regular HTTP requests by forwarding them."""
        parsed = urlparse(target)
        if parsed.scheme in ("http", "https"):
            scheme = parsed.scheme
            host = parsed.hostname
            port = parsed.port or (443 if scheme == "https" else 80)
            path = parsed.path or "/"
            if parsed.query:
                path += "?" + parsed.query
        else:
            scheme = "http"
            host_header = header_map.get("host")
            if not host_header:
                await self._send_error(writer, "400 Bad Request", "Missing Host header")
                return
            if ":" in host_header:
                host, port_str = host_header.rsplit(":", 1)
                try:
                    port = int(port_str)
                except ValueError:
                    await self._send_error(writer, "400 Bad Request", "Invalid Host header")
                    return
            else:
                host = host_header
                port = 80
            path = target if target.startswith("/") else f"/{target}"

        if scheme == "https":
            await self._send_error(writer, "400 Bad Request", "HTTPS requests require CONNECT")
            return

        if not host:
            await self._send_error(writer, "400 Bad Request", "Invalid request target")
            return

        allowed = await self._check_filter(port, host)
        if not allowed:
            log_for_debugging(f"HTTP request blocked to {host}:{port}", level="error")
            await self._send_error(writer, "403 Forbidden", "Connection blocked by network allowlist")
            return

        try:
            body = await self._read_request_body(reader, header_map, body_prefix)
        except ValueError as exc:
            await self._send_error(writer, "400 Bad Request", str(exc))
            return

        host_header = host if port in (80, 443) else f"{host}:{port}"

        filtered_headers: dict[str, str] = {}
        for name, value in headers:
            lower = name.lower()
            if lower in _HOP_BY_HOP_HEADERS:
                continue
            if lower == "host":
                continue
            if lower == "transfer-encoding":
                continue
            filtered_headers[name] = value

        filtered_headers["Host"] = host_header
        filtered_headers["Connection"] = "close"

        connector = TCPConnector(force_close=True)
        async with ClientSession(connector=connector) as session:
            url = f"http://{host_header}{path}"
            try:
                async with session.request(
                    method=method,
                    url=url,
                    headers=filtered_headers,
                    data=body if body else None,
                    allow_redirects=False,
                ) as resp:
                    response_body = await resp.read()
                    status_line = f"HTTP/1.1 {resp.status} {resp.reason}\r\n"
                    writer.write(status_line.encode("latin-1"))

                    response_headers = dict(resp.headers)
                    for header in list(response_headers.keys()):
                        if header.lower() in _HOP_BY_HOP_HEADERS:
                            response_headers.pop(header, None)
                    response_headers["Content-Length"] = str(len(response_body))
                    response_headers["Connection"] = "close"

                    for name, value in response_headers.items():
                        writer.write(f"{name}: {value}\r\n".encode("latin-1"))
                    writer.write(b"\r\n")
                    writer.write(response_body)
                    await writer.drain()
            except Exception as e:
                log_for_debugging(f"Proxy request failed: {e}", level="error")
                await self._send_error(writer, "502 Bad Gateway", "Bad Gateway")

    async def _handle_client(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle a single client connection."""
        try:
            header_bytes, remaining = await self._read_headers(reader)
            method, target, version, headers, header_map = self._parse_headers(header_bytes)
        except ValueError as e:
            await self._send_error(writer, "400 Bad Request", str(e))
            return
        except Exception as e:
            log_for_debugging(f"Error handling request: {e}", level="error")
            await self._send_error(writer, "500 Internal Server Error", "Internal Server Error")
            return

        if method.upper() == "CONNECT":
            await self._handle_connect(reader, writer, target)
            return

        await self._handle_http_request(
            reader,
            writer,
            method,
            target,
            version,
            headers,
            header_map,
            remaining,
        )

    async def start(self, host: str = "127.0.0.1", port: int = 0) -> int:
        """
        Start the proxy server.

        Args:
            host: Host to bind to (default: 127.0.0.1)
            port: Port to bind to (default: 0 for random available port)

        Returns:
            The actual port the server is listening on
        """
        self._server = await asyncio.start_server(self._handle_client, host, port)
        if self._server.sockets:
            self._port = self._server.sockets[0].getsockname()[1]
            log_for_debugging(f"HTTP proxy listening on {host}:{self._port}")
            return self._port
        raise RuntimeError("Failed to get proxy server address")

    async def stop(self) -> None:
        """Stop the proxy server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
        self._port = None


def create_http_proxy_server(filter_fn: FilterCallback) -> HttpProxyServer:
    """
    Create an HTTP proxy server with the given filter function.

    Args:
        filter_fn: Callback function that takes (port, host) and returns True if allowed

    Returns:
        An HttpProxyServer instance (not yet started)
    """
    return HttpProxyServer(filter_fn)
