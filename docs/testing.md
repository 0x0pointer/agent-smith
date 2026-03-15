# Testing

---

## Quick start

```bash
# Install dev dependencies (first time only)
poetry install --with dev

# Run all tests
poetry run pytest

# Run with coverage report
poetry run pytest --cov=core --cov=tools --cov=mcp_server --cov-report=term-missing
```

---

## Test layout

```
tests/
  conftest.py           Shared fixtures — isolation for module-level globals
  test_clip.py          _clip() output truncation helper
  test_cost.py          core/cost.py — token estimation and weighted cost
  test_session.py       core/session.py — scan lifecycle and limit enforcement
  test_findings.py      core/findings.py — async findings/diagram store
  test_logger.py        core/logger.py — structured session logging
  test_docker_runner.py tools/docker_runner.py — Docker subprocess wrapper
  test_kali_runner.py   tools/kali_runner.py — Kali container HTTP API client
  test_parsers.py       tools/semgrep.py + tools/trufflehog.py — output parsers
  test_dotenv.py        mcp_server/_app._load_dotenv()
```

No Docker daemon or running containers are needed — Docker calls and HTTP requests are fully mocked.

---

## What is and isn't tested

| Layer | Covered | Not covered |
|-------|---------|-------------|
| `core/` | cost, session, findings, logger | api_server (FastAPI — needs a running server) |
| `tools/` | docker_runner, kali_runner, semgrep parser, trufflehog parser, base, REGISTRY | arg builders for individual tools (nmap, nuclei, …) |
| `mcp_server/` | `_clip()`, `_load_dotenv()` | Tool handler functions — they wire MCP → Docker and require a live environment |

The mcp_server tool handlers (`scan_tools.py`, `kali_tools.py`, etc.) intentionally have no unit tests. They are thin glue between the MCP protocol and Docker runners; their behaviour is better validated by integration/E2E tests against a real target.

---

## Global state isolation

Three modules use module-level mutable globals. `conftest.py` resets them automatically before every test via `monkeypatch` + `autouse=True` fixtures:

| Module | Global | Reset to |
|--------|--------|----------|
| `core.cost` | `_calls` (list) | `[]` |
| `core.session` | `_current` (dict\|None) | `None` |
| `core.findings` | `_lock` (asyncio.Lock) | fresh `asyncio.Lock()` |

File outputs (`session_cost.json`, `session.json`, `findings.json`) are redirected to `tmp_path` so the repo root stays clean.

The findings lock specifically must be recreated per test because `asyncio.Lock()` attaches to the running event loop on first use — pytest-asyncio creates a new event loop per test, so reusing the same lock object would cause "Future attached to different loop" errors.

---

## Adding a new test file

1. Create `tests/test_<module>.py`
2. Import the module under test directly — no special setup needed for `core/` and `tools/` modules
3. Use `pytest.mark.asyncio` (or just `async def` — asyncio mode is `auto`) for async tests
4. Use the `findings_file` fixture when your test writes to `findings.json`

Minimal example:

```python
import pytest
from core.cost import start, finish, get_summary


def test_finish_records_tokens():
    call_id = start("my_tool")
    finish(call_id, "x" * 400)
    assert get_summary()["total_output_tokens"] == 100


@pytest.mark.asyncio
async def test_async_example(findings_file):
    import core.findings
    entry = await core.findings.add_finding(
        title="Test", severity="low", target="localhost",
        description="desc", evidence="proof",
    )
    assert entry["title"] == "Test"
```

---

## Adding tests for a new tool parser

Each tool in `tools/` has a `_parse(stdout, stderr) -> list[dict]` function. Tests go in `tests/test_parsers.py` alongside the existing semgrep and trufflehog tests.

Pattern:

```python
from tools.my_tool import _parse

def test_my_tool_parse_extracts_severity():
    stdout = '...'  # raw tool output
    findings = _parse(stdout, "")
    assert findings[0]["severity"] == "high"

def test_my_tool_parse_invalid_input_returns_empty():
    assert _parse("not valid output", "") == []
```

Keep the test data inline as string literals — avoid loading fixture files unless the output format is genuinely too large to read inline.

---

## CI

Tests run automatically on every push and pull request via `.github/workflows/ci.yml`. The workflow:

1. Installs Python 3.11 and Poetry
2. Runs `pytest --cov` and writes `coverage.xml`
3. Uploads results to SonarCloud for quality gate analysis

To see coverage locally in HTML:

```bash
poetry run pytest --cov=core --cov=tools --cov=mcp_server --cov-report=html
open htmlcov/index.html
```
