# mcp-scoring-engine

A standalone scoring engine for evaluating the quality of [Model Context Protocol (MCP)](https://modelcontextprotocol.io) servers. Pure Python, no framework dependencies — just dataclasses, scoring logic, and network probes.

Used in production by [MCP Scoreboard](https://mcpscoreboard.com) to grade thousands of MCP servers.

## Installation

```bash
pip install mcp-scoring-engine
```

## Quick Start

### Score a server from its GitHub repo (static analysis)

```python
from mcp_scoring_engine import ServerInfo, analyze_repo, compute_score

server = ServerInfo(
    name="my-mcp-server",
    description="A tool server for doing useful things",
    repo_url="https://github.com/owner/my-mcp-server",
)

static = analyze_repo(server.repo_url)
result = compute_score(server, static_result=static)

print(result.composite_score)  # 0–100
print(result.grade)            # "A+", "B", "D", etc.
print(result.score_type)       # "partial" (1 tier) or "full" (2+ tiers)
```

### Probe a running server

```python
from mcp_scoring_engine import (
    ServerInfo, probe_server, deep_probe_server, compute_score
)

# Fast health check (~10s) — connection, initialize, ping
fast = probe_server("https://my-server.example.com/mcp")
print(fast.is_reachable, fast.connection_ms)

# Deep protocol probe (~30s) — schema validation, error handling, fuzz testing
deep = deep_probe_server("https://my-server.example.com/mcp")
print(deep.tools_count, deep.schema_valid, deep.fuzz_score)

# Score with the probe results
server = ServerInfo(name="my-server", description="...", repo_url="...")
static = analyze_repo(server.repo_url)
result = compute_score(server, static_result=static, deep_probe=deep)
print(result.grade)
```

### Probe a stdio server

```python
from mcp_scoring_engine import probe_server_stdio, deep_probe_server_stdio

fast = probe_server_stdio(["npx", "-y", "@modelcontextprotocol/server-memory"])
deep = deep_probe_server_stdio(["python", "-m", "my_mcp_server"])
```

### Classify a server

```python
from mcp_scoring_engine import classify_server, ServerInfo

server = ServerInfo(
    name="stripe-mcp",
    description="MCP server for Stripe payment processing",
    repo_url="https://github.com/stripe/stripe-mcp",
)

category, targets = classify_server(server)
print(category)  # "finance"
print(targets)   # ["Stripe"]
```

### Detect entry points for stdio servers

```python
from mcp_scoring_engine import detect_entry_point, make_github_file_reader

# With a GitHubPublicClient (from your own GitHub API code)
file_reader = make_github_file_reader(client)
tree = client.get_tree()

result = detect_entry_point(tree, file_reader)
# {"language": "python", "run_cmd": ["python", "-m", "my_server"],
#  "install_cmd": "uv pip install -e .",
#  "source": "pyproject.toml [project.scripts]", "confidence": "high"}
```

Entry point detection parses build metadata to infer how to run an MCP server:

- **Python**: `pyproject.toml` scripts, `setup.cfg`/`setup.py` console_scripts, `__main__.py`
- **Node**: `package.json` bin field, `scripts.start`, `main` field

When called via `analyze_repo()`, detection piggybacks on the already-fetched file tree at zero extra API cost. The result is stored in `StaticAnalysis.details["entry_point"]`.

### Detect red flags

```python
from mcp_scoring_engine import detect_flags, ServerInfo

server = ServerInfo(
    name="sketchy-server",
    description="A MCP server",
    repo_url="",
    remote_endpoint_url="http://localhost:3000/mcp",
)

flags = detect_flags(server)
for flag in flags:
    print(f"[{flag.severity}] {flag.label}: {flag.description}")
    # [critical] No Source Code: No repository URL or source link provided
    # [warning] Staging Artifact: Endpoint URL contains localhost or staging reference
```

## Architecture

The engine evaluates servers across **three data tiers**:

| Tier | Source | What it measures |
|------|--------|-----------------|
| **Tier 1 — Static Analysis** | GitHub repo | Schema completeness, description quality, documentation, maintenance pulse, dependency health, license clarity, version hygiene |
| **Tier 2 — Protocol Probe** | Live server | Connection health, tool schema validation, error handling, fuzz resilience, auth discovery |
| **Tier 3 — Reliability** | Rolling window | Uptime percentage, p50/p95 latency |

The composite score is a weighted blend of five categories:

| Category | Weight |
|----------|--------|
| Schema & Docs | 25% |
| Protocol Compliance | 20% |
| Reliability | 20% |
| Maintenance | 15% |
| Security | 20% |

**Score types:**
- `partial` — Only 1 data tier available. Numeric score but no letter grade.
- `full` — 2+ data tiers. Graded A+ through F.

## API Reference

### Core

| Function | Description |
|----------|-------------|
| `compute_score(server, static_result?, deep_probe?, reliability?)` | Compute weighted composite score → `ScoreResult` |
| `score_to_grade(score)` | Convert 0–100 → letter grade (A+, A, B, C, D, F) |
| `classify_server(server)` | Categorize a server → `(category, target_platforms)` |
| `detect_flags(server, context?)` | Detect red flags → `list[Flag]` |
| `generate_badges(server, static_result?, deep_probe?, reliability?, flags?)` | Generate display badges → `dict` |

### Probes

| Function | Description |
|----------|-------------|
| `probe_server(url)` | Fast health check over HTTP → `FastProbeResult` |
| `probe_server_stdio(command)` | Fast health check over stdio → `FastProbeResult` |
| `deep_probe_server(url)` | Full protocol probe over HTTP → `DeepProbeResult` |
| `deep_probe_server_stdio(command)` | Full protocol probe over stdio → `DeepProbeResult` |
| `analyze_repo(repo_url)` | Static analysis of GitHub repo → `StaticAnalysis` |
| `detect_entry_point(file_tree, file_reader)` | Detect how to run a server from repo metadata → `dict \| None` |
| `make_github_file_reader(client)` | Create a file_reader callable from a GitHub API client → `Callable` |
| `compute_reliability_score(data)` | Score from uptime + latency → `int` |

### Types

All inputs and outputs are plain dataclasses:

- **`ServerInfo`** — Input server metadata (name, description, repo_url, etc.)
- **`ScoreResult`** — Complete scoring output (composite_score, grade, category scores, flags, badges)
- **`FastProbeResult`** — Health check results (is_reachable, timing)
- **`DeepProbeResult`** — Protocol compliance results (schema, error handling, fuzz)
- **`StaticAnalysis`** — Repo analysis results (7 metric scores + GitHub metadata)
- **`ReliabilityData`** — Pre-computed reliability metrics (uptime, latency)
- **`Flag`** — Red flag (key, severity, label, description)
- **`Badge`** — Display badge (key, label, level)

## License

MIT
