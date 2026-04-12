# XBEN Benchmark Runner

Run the [XBOW Security Benchmark](https://github.com/usestrix/benchmarks/tree/main/XBEN) (104 CTF challenges) against agent-smith and track solve rates, cost, and duration.

## Quick start

```bash
# Run a single challenge
python benchmarks/runner.py --benchmarks XBEN-001-24

# Run a few easy ones first
python benchmarks/runner.py --benchmarks XBEN-020-24 XBEN-070-24 XBEN-088-24

# Run all 104 challenges
python benchmarks/runner.py

# Use OpenCode instead of Claude Code
python benchmarks/runner.py --agent opencode

# Custom timeout (1 hour) and output dir
python benchmarks/runner.py --timeout 3600 --output ./my-runs
```

## Requirements

- Docker Desktop running
- `claude` CLI (or `opencode`) installed and configured
- agent-smith MCP server registered (`./installers/install.sh`)
- `pyyaml` installed (`pip install pyyaml`)
- Git (for sparse-checkout of challenges)

## How it works

```
For each challenge:
  1. Sparse-clone from schniggie/validation-benchmarks
  2. Read .env to extract the expected flag{uuid}
  3. Rewrite docker-compose.yml with a free host port
  4. docker compose build + up
  5. Wait for HTTP readiness
  6. Invoke agent-smith via Claude Code CLI:
     claude -p "/pentester scan http://host:port depth=thorough ..."
  7. Search findings.json, pocs/, agent stdout for the flag
  8. Record result.json (XBEN-compatible format)
  9. docker compose down
  10. Aggregate results → summary.json + RESULTS.md
```

## Output

```
runs/
  run_XBEN-001-24/
    result.json          # XBEN-compatible result
    outputs/             # Agent stdout/stderr
    artifacts/           # findings.json, pocs/, logs/
  run_XBEN-002-24/
    ...
  summary.json           # Aggregated results across all challenges
  RESULTS.md             # Markdown table for sharing
```

## Result format

Each `result.json` follows the XBEN schema:

```json
{
  "benchmark_id": "XBEN-001-24",
  "benchmark_name": "XBEN-001-24 IDOR - Trading Platform",
  "level": 2,
  "tags": ["idor", "default_credentials"],
  "execution": {
    "started_at": "2026-04-12T10:00:00+00:00",
    "completed_at": "2026-04-12T10:15:00+00:00",
    "duration_seconds": 900,
    "status": "solved"
  },
  "evaluation": {
    "flag_extracted": true
  }
}
```

## Sharing results

After a run, share `runs/RESULTS.md` — it contains a markdown table with per-challenge results broken down by difficulty and vulnerability class:

```
| Level | Solved | Total | Rate |
|-------|--------|-------|------|
| 1     | 30     | 35    | 85.7%|
| 2     | 40     | 50    | 80.0%|
| 3     | 10     | 19    | 52.6%|
```

## Cost estimates

| Scope | API cost | Time |
|-------|----------|------|
| 1 challenge | ~$3-7 | 10-30 min |
| 10 easy (level 1) | ~$30-50 | 2-4 hours |
| All 104 | ~$350-500 | 24-48 hours |

## DigitalOcean deployment

For running the full suite unattended:

```bash
# Create a droplet (16 GB RAM, 8 vCPU)
doctl compute droplet create xben-runner \
  --size s-8vcpu-16gb \
  --image docker-20-04 \
  --region nyc1

# SSH in, clone agent-smith, install, run
ssh root@<ip>
git clone --recursive https://github.com/0x0pointer/agent-smith
cd agent-smith
./installers/install.sh
python benchmarks/runner.py --output ./runs 2>&1 | tee benchmark.log
```
