"""Deep protocol compliance probe for MCP servers.

Extends the fast probe with:
- tools/list validation and schema checks
- Error handling tests (bad inputs, wrong types, unknown tools)
- Fuzz testing for adversarial inputs
- Auth discovery check (.well-known/oauth-protected-resource)

Supports both StreamableHTTP and stdio transports.
"""

from __future__ import annotations

import asyncio
import logging
import time

import httpx
from mcp import ClientSession, Implementation
from mcp.client.streamable_http import streamable_http_client

from ..types import DeepProbeResult
from .health import USER_AGENT, _unwrap_exception

logger = logging.getLogger(__name__)

DEEP_PROBE_TIMEOUT = 30


def _validate_tool_schema(tool) -> list[str]:
    """Validate a single tool's schema against MCP spec expectations."""
    issues = []
    name = getattr(tool, "name", None) or str(tool)

    if not getattr(tool, "name", None):
        issues.append("tool missing name")
        return issues

    if not getattr(tool, "description", None):
        issues.append(f"{name}: missing description")

    input_schema = getattr(tool, "inputSchema", None)
    if not input_schema:
        return issues

    schema = input_schema if isinstance(input_schema, dict) else {}

    if schema.get("type") != "object":
        issues.append(
            f"{name}: inputSchema.type should be 'object', got '{schema.get('type')}'"
        )

    properties = schema.get("properties", {})
    if properties:
        for prop_name, prop_def in properties.items():
            if not isinstance(prop_def, dict):
                issues.append(f"{name}.{prop_name}: property definition is not a dict")
                continue
            if "type" not in prop_def and "$ref" not in prop_def and "anyOf" not in prop_def:
                issues.append(f"{name}.{prop_name}: missing type definition")
            if "description" not in prop_def:
                issues.append(f"{name}.{prop_name}: missing description")

    return issues


async def _test_error_handling(session: ClientSession, tools: list) -> tuple[int, dict]:
    """Test server's error handling by sending malformed requests."""
    tests_passed = 0
    tests_total = 0
    details = {}

    # Test 1: Call with unknown tool name
    tests_total += 1
    try:
        result = await session.call_tool("__nonexistent_tool_scoreboard_test__", {})
        if result and getattr(result, "isError", False):
            tests_passed += 1
            details["unknown_tool"] = "proper_error"
        else:
            details["unknown_tool"] = "no_error_returned"
    except BaseException as e:
        real = _unwrap_exception(e)
        error_str = str(real)
        if any(kw in error_str.lower() for kw in ("not found", "unknown", "error")):
            tests_passed += 1
            details["unknown_tool"] = "proper_error"
        else:
            details["unknown_tool"] = f"error: {type(real).__name__}"
            tests_passed += 0.5

    # Test 2: Call tool with empty params when it requires params
    if tools:
        tool_with_required = None
        for t in tools:
            schema = getattr(t, "inputSchema", None)
            if isinstance(schema, dict) and schema.get("required"):
                tool_with_required = t
                break

        if tool_with_required:
            tests_total += 1
            try:
                result = await session.call_tool(tool_with_required.name, {})
                if result and getattr(result, "isError", False):
                    tests_passed += 1
                    details["missing_required_params"] = "proper_error"
                else:
                    details["missing_required_params"] = "no_error_returned"
            except BaseException:
                tests_passed += 1
                details["missing_required_params"] = "proper_error"

    # Test 3: Call tool with wrong param types
    if tools:
        tool_with_props = None
        for t in tools:
            schema = getattr(t, "inputSchema", None)
            if isinstance(schema, dict) and schema.get("properties"):
                tool_with_props = t
                break

        if tool_with_props:
            tests_total += 1
            schema = tool_with_props.inputSchema
            bad_args = {}
            for prop_name, prop_def in schema.get("properties", {}).items():
                prop_type = prop_def.get("type", "") if isinstance(prop_def, dict) else ""
                if prop_type == "string":
                    bad_args[prop_name] = 99999
                elif prop_type in ("number", "integer"):
                    bad_args[prop_name] = "not_a_number"
                elif prop_type == "boolean":
                    bad_args[prop_name] = "not_a_bool"
                else:
                    bad_args[prop_name] = None
                break

            if bad_args:
                try:
                    result = await session.call_tool(tool_with_props.name, bad_args)
                    if result and getattr(result, "isError", False):
                        tests_passed += 1
                        details["wrong_param_type"] = "proper_error"
                    else:
                        details["wrong_param_type"] = "accepted_bad_input"
                except BaseException:
                    tests_passed += 1
                    details["wrong_param_type"] = "proper_error"

    if tests_total == 0:
        return 50, {"note": "no_testable_tools"}

    score = int((tests_passed / tests_total) * 100)
    details["tests_passed"] = tests_passed
    details["tests_total"] = tests_total
    return score, details


async def _test_fuzz_inputs(session: ClientSession, tools: list) -> tuple[int, dict]:
    """Test server resilience to adversarial/boundary inputs."""
    fuzzable_tool = None
    fuzzable_param = None
    param_type = None

    for t in tools:
        schema = getattr(t, "inputSchema", None)
        if not isinstance(schema, dict):
            continue
        for pname, pdef in schema.get("properties", {}).items():
            if not isinstance(pdef, dict):
                continue
            ptype = pdef.get("type", "")
            if ptype in ("string", "number", "integer"):
                fuzzable_tool = t
                fuzzable_param = pname
                param_type = ptype
                break
        if fuzzable_tool:
            break

    if not fuzzable_tool:
        return 50, {"note": "no_fuzzable_tools"}

    if param_type == "string":
        payloads = [
            ("long_string", "A" * 100_000),
            ("unicode_special", "\u0000\uffff\U0001f4a9\u200b\u200e"),
            ("empty_string", ""),
            ("null", None),
            ("nested_object", {"a": {"b": {"c": "deep"}}}),
            ("empty_object", {}),
            ("sql_injection", "'; DROP TABLE users; --"),
            ("empty_array", []),
        ]
    else:
        payloads = [
            ("very_large_number", 10**18),
            ("negative", -999999),
            ("float_overflow", 1.7976931348623157e308),
            ("zero", 0),
            ("wrong_type_string", "not_a_number"),
            ("boolean", True),
            ("tiny_float", 1e-300),
            ("negative_zero", -0.0),
        ]

    tests_passed = 0
    tests_total = len(payloads)
    details = {}

    for label, value in payloads:
        try:
            args = {fuzzable_param: value}
            result = await session.call_tool(fuzzable_tool.name, args)
            if result and getattr(result, "isError", False):
                details[label] = "proper_error"
            else:
                details[label] = "accepted"
            tests_passed += 1
        except BaseException as e:
            real = _unwrap_exception(e)
            if isinstance(real, (ConnectionError, asyncio.TimeoutError)):
                details[label] = f"crash: {type(real).__name__}"
            else:
                details[label] = f"error: {type(real).__name__}"
                tests_passed += 1

    score = int((tests_passed / tests_total) * 100) if tests_total else 50
    details["tests_passed"] = tests_passed
    details["tests_total"] = tests_total
    details["tool_tested"] = fuzzable_tool.name
    details["param_tested"] = fuzzable_param
    return score, details


async def _check_auth_discovery(url: str) -> bool | None:
    """Check if the server implements OAuth discovery per MCP auth spec."""
    from urllib.parse import urlparse

    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    well_known_url = f"{base}/.well-known/oauth-protected-resource"

    try:
        async with httpx.AsyncClient(
            timeout=5, headers={"User-Agent": USER_AGENT}
        ) as client:
            resp = await client.get(well_known_url)
            if resp.status_code == 200:
                data = resp.json()
                if "resource" in data:
                    return True
                return False
            elif resp.status_code == 404:
                return None
            else:
                return False
    except Exception:
        return None


async def _run_deep_probe_session(session: ClientSession, result: DeepProbeResult) -> None:
    """Run all deep probe checks on an established MCP session."""
    # Phase 1: Initialize
    t_init_start = time.monotonic()
    await session.initialize()
    t_init_end = time.monotonic()
    result.initialize_ms = int((t_init_end - t_init_start) * 1000)

    # Phase 2: Ping
    t_ping_start = time.monotonic()
    await session.send_ping()
    t_ping_end = time.monotonic()
    result.ping_ms = int((t_ping_end - t_ping_start) * 1000)

    result.is_reachable = True

    # Phase 3: tools/list
    t_tools_start = time.monotonic()
    tools_result = await session.list_tools()
    t_tools_end = time.monotonic()
    result.tools_list_ms = int((t_tools_end - t_tools_start) * 1000)

    tools = tools_result.tools if tools_result else []
    result.tools_count = len(tools)
    result.tools = list(tools)

    # Phase 4: Schema validation
    all_issues = []
    for tool in tools:
        all_issues.extend(_validate_tool_schema(tool))
    result.schema_issues = all_issues
    result.schema_valid = len(all_issues) == 0

    # Phase 5: Error handling tests
    try:
        eh_score, eh_details = await _test_error_handling(session, tools)
        result.error_handling_score = eh_score
        result.error_handling_details = eh_details
    except BaseException as e:
        real = _unwrap_exception(e)
        result.error_handling_score = 0
        result.error_handling_details = {"error": f"{type(real).__name__}: {real}"}

    # Phase 6: Fuzz testing
    try:
        fz_score, fz_details = await _test_fuzz_inputs(session, tools)
        result.fuzz_score = fz_score
        result.fuzz_details = fz_details
    except BaseException as e:
        real = _unwrap_exception(e)
        result.fuzz_score = 0
        result.fuzz_details = {"error": f"{type(real).__name__}: {real}"}


async def _deep_probe_server_http(url: str) -> DeepProbeResult:
    """Run a deep protocol compliance probe via HTTP."""
    result = DeepProbeResult()

    http_client = httpx.AsyncClient(
        timeout=httpx.Timeout(DEEP_PROBE_TIMEOUT, read=DEEP_PROBE_TIMEOUT),
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
                    await _run_deep_probe_session(session, result)

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

    # Auth discovery (independent of MCP connection)
    if not result.error_message or "401" in result.error_message:
        try:
            result.auth_discovery_valid = await _check_auth_discovery(url)
        except Exception:
            pass

    return result


async def _deep_probe_server_stdio(command: list[str]) -> DeepProbeResult:
    """Run a deep protocol compliance probe via stdio transport."""
    from mcp.client.stdio import StdioServerParameters, stdio_client

    result = DeepProbeResult()

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
                await _run_deep_probe_session(session, result)

    except BaseException as e:
        real = _unwrap_exception(e)
        if isinstance(real, asyncio.TimeoutError):
            result.error_message = "timeout"
        else:
            result.error_message = f"{type(real).__name__}: {real}"

    return result


def deep_probe_server(url: str) -> DeepProbeResult:
    """Synchronous wrapper for the HTTP deep probe."""
    try:
        return asyncio.run(_deep_probe_server_http(url))
    except BaseException as e:
        real = _unwrap_exception(e)
        return DeepProbeResult(
            is_reachable=False,
            error_message=f"runner_error: {real}",
        )


def deep_probe_server_stdio(command: list[str]) -> DeepProbeResult:
    """Synchronous wrapper for the stdio deep probe."""
    try:
        return asyncio.run(_deep_probe_server_stdio(command))
    except BaseException as e:
        real = _unwrap_exception(e)
        return DeepProbeResult(
            is_reachable=False,
            error_message=f"runner_error: {real}",
        )
