# mcp-scoring-engine

Scoring engine for MCP server quality assessment, published to PyPI as `mcp-scoring-engine`.

## Project structure

- `src/mcp_scoring_engine/` — package source
- `tests/` — pytest test suite (109 tests)
- Version is defined in `pyproject.toml` only (no `__version__` in code)

## Development

```bash
source .venv/bin/activate
python -m pytest tests/ -v
```

## Publishing to PyPI

Publishing is automated via GitHub Actions. The workflow (`.github/workflows/publish.yml`) triggers on version tags.

### Steps to release a new version

1. **Bump the version** in `pyproject.toml`
2. **Commit** the version bump
3. **Tag the commit** with `v` prefix matching the version:
   ```bash
   git tag v0.1.2
   ```
4. **Push the commit and tag**:
   ```bash
   git push origin main --tags
   ```
5. The GitHub Action will automatically build and publish to PyPI

### Requirements

- The repo must have a `PYPI_API_TOKEN` secret configured in GitHub Settings > Secrets and variables > Actions
- The token must have upload permissions for the `mcp-scoring-engine` project on PyPI

### Manual publish (fallback)

If the GitHub Action is not set up yet or fails:
```bash
uv build
uv publish --token pypi-YOUR_TOKEN_HERE
```
