"""Fast health probe for MCP servers.

Supports both StreamableHTTP and stdio transports.
Connects, performs MCP initialize + ping, and captures timing at each phase.
"""

from __future__ import annotations

import asyncio
import logging
import time

import httpx
from mcp import ClientSession, Implementation
from mcp.client.streamable_http import streamable_http_client

from ..types import FastProbeResult

logger = logging.getLogger(__name__)

PROBE_TIMEOUT = 10  # seconds total per probe
USER_AGENT = "MCPScoringEngine/1.0"


async def _probe_server_http(url: str) -> FastProbeResult:
    """Run a fast probe against a single MCP server endpoint via HTTP."""
    result = FastProbeResult()

    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(PROBE_TIMEOUT, read=PROBE_TIMEOUT),
        headers={"User-Agent": USER_AGENT},
    )

    try:
        t_connect_start = time.monotonic()

        async with http_client:
            async with streamable_http_client(url, http_client=http_client) as (
                read_stream,
                write_stream,
                _get_session_id,
            ):
                t_connect_end = time.monotonic()
                result.connection_ms = int((t_connect_end - t_connect_start) * 1000)

                async with ClientSession(
                    read_stream,
                    write_stream,
                    client_info=Implementation(name="MCPScoringEngine", version="1.0"),
                ) as session:
                    t_init_start = time.monotonic()
                    await session.initialize()
                    t_init_end = time.monotonic()
                    result.initialize_ms = int((t_init_end - t_init_start) * 1000)

                    t_ping_start = time.monotonic()
                    await session.send_ping()
                    t_ping_end = time.monotonic()
                    result.ping_ms = int((t_ping_end - t_ping_start) * 1000)

                    result.is_reachable = True

    except BaseException as e:
        real = _unwrap_exception(e)
        if isinstance(real, asyncio.TimeoutError):
            result.error_message = "timeout"
        elif isinstance(real, httpx.ConnectError):
            msg = str(real)[:200]
            result.error_message = f"connect_error: {msg}"
        elif isinstance(real, httpx.HTTPStatusError):
            result.error_message = f"http_{real.response.status_code}"
        elif isinstance(real, httpx.InvalidURL):
            result.error_message = f"invalid_url: {real}"
        else:
            result.error_message = f"{type(real).__name__}: {real}"

    return result


async def _probe_server_stdio(command: list[str]) -> FastProbeResult:
    """Run a fast probe via stdio transport.

    Spawns the server process, connects via MCP stdio client,
    runs initialize + ping, then terminates.
    """
    from mcp.client.stdio import StdioServerParameters, stdio_client

    result = FastProbeResult()

    try:
        params = StdioServerParameters(command=command[0], args=command[1:])

        t_connect_start = time.monotonic()

        async with stdio_client(params) as (read_stream, write_stream):
            t_connect_end = time.monotonic()
            result.connection_ms = int((t_connect_end - t_connect_start) * 1000)

            async with ClientSession(
                read_stream,
                write_stream,
                client_info=Implementation(name="MCPScoringEngine", version="1.0"),
            ) as session:
                t_init_start = time.monotonic()
                await session.initialize()
                t_init_end = time.monotonic()
                result.initialize_ms = int((t_init_end - t_init_start) * 1000)

                t_ping_start = time.monotonic()
                await session.send_ping()
                t_ping_end = time.monotonic()
                result.ping_ms = int((t_ping_end - t_ping_start) * 1000)

                result.is_reachable = True

    except BaseException as e:
        real = _unwrap_exception(e)
        if isinstance(real, asyncio.TimeoutError):
            result.error_message = "timeout"
        else:
            result.error_message = f"{type(real).__name__}: {real}"

    return result


def _unwrap_exception(exc: BaseException) -> BaseException:
    """Unwrap ExceptionGroup / BaseExceptionGroup to get the root cause."""
    while hasattr(exc, "exceptions") and exc.exceptions:
        exc = exc.exceptions[0]
    return exc


def probe_server(url: str) -> FastProbeResult:
    """Synchronous wrapper for the HTTP fast probe."""
    try:
        return asyncio.run(_probe_server_http(url))
    except BaseException as e:
        real = _unwrap_exception(e)
        return FastProbeResult(
            is_reachable=False,
            error_message=f"runner_error: {real}",
        )


def probe_server_stdio(command: list[str]) -> FastProbeResult:
    """Synchronous wrapper for the stdio fast probe."""
    try:
        return asyncio.run(_probe_server_stdio(command))
    except BaseException as e:
        real = _unwrap_exception(e)
        return FastProbeResult(
            is_reachable=False,
            error_message=f"runner_error: {real}",
        )
