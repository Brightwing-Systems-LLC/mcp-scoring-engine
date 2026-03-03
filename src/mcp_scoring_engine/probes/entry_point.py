"""Detect how to run an MCP server from its repository contents.

Uses the GitHub file tree and file-reading API (already available from
static analysis) to parse build metadata and infer a run command.

Returns a dict like::

    {
        "language": "python",
        "install_cmd": "uv pip install -e .",
        "run_cmd": ["python", "-m", "my_server"],
        "source": "pyproject.toml [project.scripts]",
        "confidence": "high",
    }

Or ``None`` if no entry point could be detected.
"""

from __future__ import annotations

import base64
import json
import logging
import re
from typing import Callable

logger = logging.getLogger(__name__)


def detect_entry_point(
    file_tree: list[dict],
    file_reader: Callable[[str], str | None],
) -> dict | None:
    """Detect how to run an MCP server from repo metadata.

    Args:
        file_tree: List of tree entries from GitHub ``get_tree()``.
                   Each entry has ``path``, ``type``, ``sha``, ``size``.
        file_reader: Callable that takes a file path and returns the
                     decoded text content, or None on failure.

    Returns:
        Detection result dict or None.
    """
    paths = {e["path"] for e in file_tree if e.get("type") == "blob"}

    # Try Python detection first, then Node
    result = _detect_python(paths, file_reader)
    if result:
        return result

    result = _detect_node(paths, file_reader)
    if result:
        return result

    return None


def make_github_file_reader(
    client,  # GitHubPublicClient instance
) -> Callable[[str], str | None]:
    """Create a file_reader callable that fetches content via GitHub API.

    The GitHub contents API returns base64-encoded content for files.
    """

    def reader(path: str) -> str | None:
        result = client.get_contents(path)
        if result is None or isinstance(result, list):
            return None
        content = result.get("content")
        encoding = result.get("encoding", "")
        if content and encoding == "base64":
            try:
                return base64.b64decode(content).decode("utf-8", errors="replace")
            except Exception:
                return None
        return content

    return reader


# ---------------------------------------------------------------------------
# Python detection
# ---------------------------------------------------------------------------


def _detect_python(
    paths: set[str], file_reader: Callable[[str], str | None]
) -> dict | None:
    # 1) pyproject.toml — highest confidence
    if "pyproject.toml" in paths:
        result = _parse_pyproject_toml(file_reader)
        if result:
            return result

    # 2) setup.cfg console_scripts
    if "setup.cfg" in paths:
        result = _parse_setup_cfg(file_reader)
        if result:
            return result

    # 3) setup.py console_scripts (regex-based, medium confidence)
    if "setup.py" in paths:
        result = _parse_setup_py(file_reader)
        if result:
            return result

    # 4) __main__.py pattern — look for src/<pkg>/__main__.py or <pkg>/__main__.py
    main_modules = _find_main_modules(paths)
    if main_modules:
        module = main_modules[0]
        return {
            "language": "python",
            "install_cmd": _python_install_cmd(paths),
            "run_cmd": ["python", "-m", module],
            "source": f"__main__.py ({module})",
            "confidence": "medium",
        }

    return None


def _parse_pyproject_toml(file_reader: Callable[[str], str | None]) -> dict | None:
    content = file_reader("pyproject.toml")
    if not content:
        return None

    try:
        import tomllib
    except ImportError:
        import tomli as tomllib  # type: ignore[no-redef]

    try:
        data = tomllib.loads(content)
    except Exception:
        logger.debug("Failed to parse pyproject.toml")
        return None

    # [project.scripts] — PEP 621
    scripts = data.get("project", {}).get("scripts", {})
    if scripts:
        name, entry = next(iter(scripts.items()))
        module = _entry_point_to_module(entry)
        if module:
            return {
                "language": "python",
                "install_cmd": "uv pip install -e .",
                "run_cmd": ["python", "-m", module],
                "source": "pyproject.toml [project.scripts]",
                "confidence": "high",
            }
        return {
            "language": "python",
            "install_cmd": "uv pip install -e .",
            "run_cmd": [name],
            "source": "pyproject.toml [project.scripts]",
            "confidence": "high",
        }

    # [tool.poetry.scripts]
    poetry_scripts = data.get("tool", {}).get("poetry", {}).get("scripts", {})
    if poetry_scripts:
        name, entry = next(iter(poetry_scripts.items()))
        module = _entry_point_to_module(entry)
        if module:
            return {
                "language": "python",
                "install_cmd": "uv pip install -e .",
                "run_cmd": ["python", "-m", module],
                "source": "pyproject.toml [tool.poetry.scripts]",
                "confidence": "high",
            }
        return {
            "language": "python",
            "install_cmd": "uv pip install -e .",
            "run_cmd": [name],
            "source": "pyproject.toml [tool.poetry.scripts]",
            "confidence": "high",
        }

    return None


def _parse_setup_cfg(file_reader: Callable[[str], str | None]) -> dict | None:
    content = file_reader("setup.cfg")
    if not content:
        return None

    # Look for console_scripts in [options.entry_points]
    in_section = False
    in_console = False
    for line in content.splitlines():
        stripped = line.strip()
        if stripped.startswith("["):
            in_section = stripped == "[options.entry_points]"
            in_console = False
            continue
        if in_section and stripped.lower().startswith("console_scripts"):
            in_console = True
            continue
        if in_console and "=" in stripped and not stripped.startswith("["):
            name, _, entry = stripped.partition("=")
            name = name.strip()
            entry = entry.strip()
            module = _entry_point_to_module(entry)
            if module:
                return {
                    "language": "python",
                    "install_cmd": "pip install -e .",
                    "run_cmd": ["python", "-m", module],
                    "source": "setup.cfg console_scripts",
                    "confidence": "high",
                }
            return {
                "language": "python",
                "install_cmd": "pip install -e .",
                "run_cmd": [name],
                "source": "setup.cfg console_scripts",
                "confidence": "high",
            }
        if in_console and stripped.startswith("["):
            break

    return None


def _parse_setup_py(file_reader: Callable[[str], str | None]) -> dict | None:
    content = file_reader("setup.py")
    if not content:
        return None

    # Regex: look for console_scripts=['name=module:func']
    match = re.search(
        r"console_scripts\s*=\s*\[([^\]]+)\]",
        content,
        re.DOTALL,
    )
    if not match:
        return None

    entries_str = match.group(1)
    entry_match = re.search(r"['\"](\S+?)\s*=\s*(\S+?)['\"]", entries_str)
    if not entry_match:
        return None

    name = entry_match.group(1)
    entry = entry_match.group(2)
    module = _entry_point_to_module(entry)
    if module:
        return {
            "language": "python",
            "install_cmd": "pip install -e .",
            "run_cmd": ["python", "-m", module],
            "source": "setup.py console_scripts",
            "confidence": "medium",
        }
    return {
        "language": "python",
        "install_cmd": "pip install -e .",
        "run_cmd": [name],
        "source": "setup.py console_scripts",
        "confidence": "medium",
    }


def _find_main_modules(paths: set[str]) -> list[str]:
    """Find packages with __main__.py, returning module names."""
    modules = []
    for p in sorted(paths):
        if p.endswith("/__main__.py"):
            parts = p.split("/")
            # e.g. src/my_server/__main__.py -> my_server
            # e.g. my_server/__main__.py -> my_server
            idx = parts.index("__main__.py")
            if idx >= 1:
                # Skip 'src' prefix if present
                start = 1 if parts[0] == "src" else 0
                module = ".".join(parts[start:idx])
                if module:
                    modules.append(module)
    return modules


def _python_install_cmd(paths: set[str]) -> str:
    """Choose the best install command for a Python project."""
    if "pyproject.toml" in paths:
        return "uv pip install -e ."
    if "setup.py" in paths or "setup.cfg" in paths:
        return "pip install -e ."
    if "requirements.txt" in paths:
        return "pip install -r requirements.txt"
    return "pip install -e ."


def _entry_point_to_module(entry: str) -> str | None:
    """Convert 'my_package.module:func' to 'my_package.module'.

    Returns just the module portion (before the colon), which can be
    used with ``python -m``.
    """
    if ":" not in entry:
        return None
    module_part = entry.split(":")[0].strip()
    return module_part if module_part else None


# ---------------------------------------------------------------------------
# Node detection
# ---------------------------------------------------------------------------


def _detect_node(
    paths: set[str], file_reader: Callable[[str], str | None]
) -> dict | None:
    if "package.json" not in paths:
        return None

    content = file_reader("package.json")
    if not content:
        return None

    try:
        pkg = json.loads(content)
    except json.JSONDecodeError:
        return None

    # 1) bin field — highest confidence
    bin_field = pkg.get("bin")
    if bin_field:
        if isinstance(bin_field, str):
            return {
                "language": "node",
                "install_cmd": "npm install",
                "run_cmd": ["node", bin_field],
                "source": "package.json bin",
                "confidence": "high",
            }
        if isinstance(bin_field, dict):
            first_bin = next(iter(bin_field.values()))
            return {
                "language": "node",
                "install_cmd": "npm install",
                "run_cmd": ["node", first_bin],
                "source": "package.json bin",
                "confidence": "high",
            }

    # 2) scripts.start
    start_script = pkg.get("scripts", {}).get("start")
    if start_script:
        return {
            "language": "node",
            "install_cmd": "npm install",
            "run_cmd": ["npm", "start"],
            "source": "package.json scripts.start",
            "confidence": "medium",
        }

    # 3) main field
    main = pkg.get("main")
    if main:
        return {
            "language": "node",
            "install_cmd": "npm install",
            "run_cmd": ["node", main],
            "source": "package.json main",
            "confidence": "low",
        }

    return None
