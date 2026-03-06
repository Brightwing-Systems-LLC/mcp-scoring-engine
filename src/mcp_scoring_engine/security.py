"""Deterministic security scanners for MCP tool descriptions.

Lightweight regex-based scanning that runs without LLM calls.
Catches obvious prompt injection attempts in tool descriptions.
"""

from __future__ import annotations

import re

INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?previous\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+a", re.IGNORECASE),
    re.compile(r"disregard\s+(all\s+)?prior", re.IGNORECASE),
    re.compile(r"system\s*:\s*", re.IGNORECASE),
    re.compile(r"<\s*system\s*>", re.IGNORECASE),
    re.compile(r"IMPORTANT:\s*always", re.IGNORECASE),
    re.compile(r"\u200b"),  # zero-width space
    re.compile(r"\u200e"),  # left-to-right mark
    re.compile(r"\u2060"),  # word joiner
    re.compile(r"<!--.*?-->"),  # HTML comments in descriptions
]


def scan_tool_descriptions(tools: list) -> dict:
    """Scan tool descriptions for prompt injection patterns.

    Args:
        tools: List of tool objects with 'name' and 'description' attributes,
               or dicts with 'name' and 'description' keys.

    Returns:
        {
            "injection_found": bool,
            "matches": [{"tool": str, "pattern": str, "snippet": str}, ...],
        }
    """
    matches = []

    for tool in tools:
        name = (
            getattr(tool, "name", None)
            or (tool.get("name") if isinstance(tool, dict) else None)
            or str(tool)
        )
        desc = (
            getattr(tool, "description", None)
            or (tool.get("description") if isinstance(tool, dict) else None)
            or ""
        )
        if not desc:
            continue

        for pattern in INJECTION_PATTERNS:
            m = pattern.search(desc)
            if m:
                # Extract a snippet around the match for reporting
                start = max(0, m.start() - 20)
                end = min(len(desc), m.end() + 20)
                snippet = desc[start:end]
                matches.append({
                    "tool": name,
                    "pattern": pattern.pattern,
                    "snippet": snippet,
                })

    return {
        "injection_found": len(matches) > 0,
        "matches": matches,
    }
