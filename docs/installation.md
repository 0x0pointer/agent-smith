# Installation & Setup

Full setup guide for every supported client, self-hosted local models, Windows, and the
optional Docker images. For a one-line quick start see the [README](../README.md#quick-start).

---

## Requirements

| Dependency | Notes |
|---|---|
| [Docker Desktop](https://www.docker.com/products/docker-desktop/) | Must be running. All scanners are sandboxed. |
| [Poetry](https://python-poetry.org) | `curl -sSL https://install.python-poetry.org \| python3 -` |
| **One LLM client** (pick one) | See below ↓ |
| [Node.js](https://nodejs.org) v18+ | Optional — enables server-side Mermaid pre-rendering. |

> 🛡️ **Production hardening.** Because Smith ingests attacker-controlled data and can run
> commands, run it in an isolated, disposable VM for any real engagement — see
> [production-isolation.md](production-isolation.md).

---

## Pick your LLM client

agent-smith ships an MCP server. Anything that speaks MCP can drive it.

<table>
  <tr>
    <th width="25%">Claude Code</th>
    <th width="25%">Codex</th>
    <th width="25%">OpenCode (BYO LLM)</th>
    <th width="25%">Custom MCP client</th>
  </tr>
  <tr>
    <td>
      Anthropic's official CLI. Best UX, native skill support.
      <pre><code>git clone --recursive &lt;repo&gt;
cd agent-smith
./installers/install.sh</code></pre>
      Requires <a href="https://docs.anthropic.com/en/docs/claude-code">Claude Code</a>. Uses your <strong>Claude subscription by default</strong> — no Anthropic API key needed. The installer only writes <code>ANTHROPIC_API_KEY</code> if you opt in when it asks (<code>SMITH_USE_API_KEY=no</code> by default).
    </td>
    <td>
      OpenAI's coding agent. Installs AGENTS.md instructions, Codex skills, and the stdio MCP server.
      <pre><code>git clone --recursive &lt;repo&gt;
cd agent-smith
./installers/install_codex.sh</code></pre>
      Requires <a href="https://developers.openai.com/codex">Codex</a>. Restart Codex after install so the MCP server and skills reload.
    </td>
    <td>
      Open-source coding agent that supports <strong>any</strong> provider — OpenAI, Anthropic, Google, OpenRouter, Ollama, llama.cpp, vLLM, your own endpoint.
      <pre><code>git clone --recursive &lt;repo&gt;
cd agent-smith
./installers/install_opencode.sh</code></pre>
      Requires <a href="https://opencode.ai">OpenCode</a>. Configure your model in <code>~/.config/opencode/opencode.json</code>.
    </td>
    <td>
      Any MCP-capable client (Cursor, Continue, Zed, custom Agent SDK app, etc.).
      <pre><code>poetry install
poetry run python -m mcp_server</code></pre>
      Wire the stdio MCP server into your client. Skills are plain markdown in <code>skills/</code> — load them however your client expects prompts.
    </td>
  </tr>
</table>

> 🧠 **The LLM is your choice.** agent-smith doesn't care if it's Claude Opus 4.6, GPT-5, Gemini 2.5, Llama-4, or a local Qwen3 — anything strong enough to follow tool-use instructions will work. Bigger / smarter models find more interesting attack paths. On a small / local model Smith auto-scales to a tighter `small` profile so it doesn't overflow a 16–32K context; force it with `SMITH_MODEL_PROFILE=small` in `.env` (the one knob works identically across Claude Code, Codex, and opencode — handy because those clients don't pass their model name to the server).

> ⚠️ **After install, fully restart your client.** The MCP server connects at startup.

---

## Self-hosted local model (DGX Spark + vLLM)

Run Smith **fully local** — no API bills, nothing leaving your network — by serving an open model on your own GPU host with [vLLM](https://docs.vllm.ai) and pointing opencode at it. This is the exact setup we run on an **NVIDIA DGX Spark (GB10, 128 GB unified memory)**; any vLLM-capable box works.

**Model — `Qwen/Qwen3.6-27B-FP8`.** A dense 27B at FP8: strong tool-calling + reasoning, a **native 256K context** (no rope-scaling needed), and small enough that weights (~29 GB) + a large KV cache fit the GB10's unified memory. The big window matters — a *thorough* scan accumulates a lot of context (endpoints, coverage matrix, artifacts), and a cramped 16–32K window forces constant compaction.

**1. Serve it with vLLM (Docker)** — on the GPU host (this is our `model-agent.sh`; `HF_HOME` points at the HF cache, `HF_TOKEN` only needed to download):

```bash
docker run -d --name vllm-agent-smith --gpus all \
  --ipc=host --ulimit memlock=-1 --ulimit stack=67108864 \
  -p 8000:8000 \
  -e HF_TOKEN="$HF_TOKEN" \
  -v "$HF_HOME":/root/.cache/huggingface \
  --restart unless-stopped \
  vllm/vllm-openai:latest \
    --model Qwen/Qwen3.6-27B-FP8 \
    --served-model-name agent-smith \
    --host 0.0.0.0 --port 8000 \
    --tensor-parallel-size 1 \
    --max-model-len 262144 \
    --max-num-seqs 2 \
    --gpu-memory-utilization 0.92 \
    --kv-cache-dtype fp8 \
    --enable-prefix-caching --enable-chunked-prefill \
    --enable-auto-tool-choice \
    --tool-call-parser qwen3_coder \
    --reasoning-parser qwen3 \
    --language-model-only \
    --speculative-config '{"method":"qwen3_next_mtp","num_speculative_tokens":2}'
```

Flags that matter: `--max-model-len 262144` serves the full **256K** window (native — no rope-scaling); `--kv-cache-dtype fp8` roughly halves KV-cache memory; `--tool-call-parser qwen3_coder` + `--enable-auto-tool-choice` make the model emit real tool calls (agent-smith is all tool use); `--reasoning-parser qwen3` keeps thinking tokens out of the output; `--served-model-name agent-smith` is the id opencode targets. The KV cache is the gate, not the weights — at 256K with fp8 KV and `--gpu-memory-utilization 0.92`, vLLM reserves ~79 GB of KV pool (~2.2M tokens, ~8× concurrency), plenty for one Smith. On a smaller host, lower `--max-model-len` (e.g. `131072`) or `--gpu-memory-utilization`.

**2. Point opencode at it** — add the `provider` + `model` to `~/.config/opencode/opencode.json` (`install_opencode.sh` writes the `mcp` / `compaction` / `permission` / `agent` blocks for you and sizes them from the model's reported window):

```json
{
  "provider": {
    "agent-smith-vllm": {
      "npm": "@ai-sdk/openai-compatible",
      "options": { "baseURL": "http://YOUR-GPU-HOST:8000/v1", "apiKey": "dummy" },
      "models": {
        "agent-smith": {
          "name": "Agent Smith (Qwen3.6-27B-FP8 @256k)",
          "tool_call": true,
          "reasoning": true,
          "limit": { "context": 262144, "output": 16384 },
          "options": { "temperature": 0.7, "top_p": 0.8, "top_k": 20, "repetition_penalty": 1.05 }
        }
      }
    }
  },
  "model": "agent-smith-vllm/agent-smith",
  "mcp": {
    "pentest-agent": { "type": "remote", "url": "http://127.0.0.1:7778/sse", "enabled": true, "timeout": 9000000 }
  },
  "compaction": { "auto": true, "prune": true, "reserved": 24384 },
  "permission": { "doom_loop": "allow", "bash": "allow", "edit": "allow", "webfetch": "allow", "external_directory": "allow" },
  "agent": { "build": { "steps": 10000 } }
}
```

Things that bite on a slow local model:

- **`compaction.reserved` must stay greater than `limit.output`.** opencode compacts when `input > context − reserved`, but the server rejects when `input + output > context`. If `reserved ≤ output`, the server rejects *before* opencode compacts and the session dies with `maximum context length…`. `prune: true` evicts already-read file bodies from context.
- **`mcp.timeout` is huge (2.5 h)** because spider / sqlmap / kali runs are long; the 5 s default would cut them off.
- **`external_directory: allow`** lets `/codebase` review paths outside opencode's cwd without an unanswerable permission prompt.
- opencode reads the **served** `max_model_len` from `/v1/models` at runtime, so the effective window follows whatever you launch vLLM with. Local reasoning models are slow on a full window, so the dashboard watchdog tolerates up to **30 min** between tool calls before treating Smith as hung.

---

> 🍎 **macOS: keep the checkout out of `~/Desktop`, `~/Documents` and `~/Downloads`.** macOS privacy
> protection stops background (launchd) jobs from reading those folders, so the MCP auto-start job
> cannot run from there. The installer detects this, skips auto-start, and leaves a self-managed
> server running that you restart by hand (`installers/start-mcp-server.sh restart`) after a reboot.
> Clone to e.g. `~/agent-smith` to get auto-start and crash recovery.

---

## Control plane (`smith`)

The control plane is optional. Driving a single scan from your client needs nothing beyond the
installer. Start the control plane when you want the dashboard to launch and track several runs,
each with its own working directory, containers and Docker network.

Every bash installer (`install.sh`, `install_codex.sh`, `install_opencode.sh`, `install_pi.sh`)
installs a `smith` launcher at `~/.local/bin/smith` (override the directory with `SMITH_BIN_DIR`).
`install.sh` also offers to start the control plane at the end.

```bash
smith start     # Postgres (docker compose) + dashboard/orchestrator on 127.0.0.1:7777
smith status    # database / dashboard / orchestrator / api health, as JSON
smith stop      # stop the dashboard and the Postgres container (data volume is kept)
```

`smith start` prints a `dashboard_url` and an `operator_token`; open `<dashboard_url>/#k=<operator_token>`.

| What | Where | Notes |
|---|---|---|
| Postgres | `127.0.0.1:55432` | `postgres:16-alpine` from `docker-compose.yml`; data in the `smith-postgres-data` volume. The port is fixed, so free it first if something else holds it. |
| Dashboard + orchestrator | `127.0.0.1:7777` | Same dashboard the MCP server opens; `/api/runs` is the control-plane API. |
| Per-run state | `runs/<run-id>/` in the checkout | Session files, logs and artifacts for each run. |

Troubleshooting:

- **`smith: command not found`** — `~/.local/bin` is not on your PATH. Add it, or run
  `poetry run python smith_cli.py start` from the checkout. (`poetry install` does not create the
  command: the project is `package-mode = false`, so the launcher comes from
  `installers/install-smith-cli.sh`.)
- **`"status": "unhealthy"` with the dashboard `failed`** — another process holds port 7777,
  usually a dashboard left running by an older install or a checkout in another directory.
  Re-run the installer (it stops a stale agent-smith dashboard), or find it with
  `lsof -nP -iTCP:7777 -sTCP:LISTEN` and stop it yourself.
- **`smith start` fails with a port error** — port 55432 is already allocated. Stop whatever
  holds it (`docker ps --filter publish=55432`) or point `SMITH_DATABASE_URL` at your own database.
- **Windows** — `install.ps1` installs a `smith.cmd` launcher at `%USERPROFILE%\.local\bin`
  (override with `SMITH_BIN_DIR`; standalone: `installers\install-smith-cli.ps1`), offers to add
  that folder to your user PATH, stops a stale agent-smith dashboard on :7777, and offers to start
  the control plane when Docker Desktop is running. Find what holds a port with
  `Get-NetTCPConnection -LocalPort 7777 -State Listen`.

---

## Source updates and the work queue

A scan started from the dashboard can be bound to a **Source** (Advanced options → Source): a
knowledge base running on this machine, registered in `sources.yaml`. While that scan is open,
agent-smith watches the Source. When notes are added or edited — for example what a PR scanner
learned about a pull request — the change becomes an item in the scan's **work queue**, and an
**idle** Smith is started on it: read the notes, register the new endpoints, domains and features,
and run the pentester workflow against them.

- **One item at a time.** Each item gets its own agent turn, so a burst of updates cannot crowd
  each other out of context or be forgotten. A busy scan is not interrupted; its items wait.
- **Nothing is queued when you bind.** The Source's existing content is the baseline; only changes
  after that are queued.
- **Scope still applies.** Smith is told to treat note contents as data, and to record an
  out-of-scope host as a scope request instead of testing it.
- **Push instead of poll.** `POST /api/runs/<run-id>/work` with `{"title": "...", "text": "..."}`
  (operator token) queues an item directly — the hook for a PR scanner or CI job.
- **See it.** The command panel shows what Smith is working on and how many items wait; the
  Timeline page lists every item and its outcome (`GET /api/runs/<run-id>/work`).

Edited notes are detected through the `sha256` each note reports in the Source's `/list`. A Source
that does not report it only gets new notes (and edits that change a note's section count) noticed.

---

## Environment variables

A handful of env vars (read from your shell or the repo `.env`) tune how Smith runs. None are
required — every one has a working default.

| Variable | Default | What it does |
|---|---|---|
| `SMITH_MODEL_PROFILE` | auto-detected | Force the model profile (`full` \| `medium` \| `small`) instead of auto-detecting from the environment. Smaller profiles tighten tool/output budgets and reduce required thorough passes so a small/local model's context window isn't overflowed. |
| `SMITH_USE_API_KEY` | `no` | Set to `yes` to bill the **Smith agent** against an Anthropic API key instead of your Claude subscription. The installer sets this (and writes `ANTHROPIC_API_KEY`) only if you opt in when prompted; the default keeps you on the subscription with no key written. |
| `SMITH_SPAWN_USE_API_KEY` | unset | When set (`1`), a **spawned/respawned** Smith (Restart button, watchdog) keeps `ANTHROPIC_API_KEY` and bills API credit — for a subscription-less box (e.g. CI). Unset, a spawned Smith strips the key so it never silently bills API credit. |
| `SMITH_SOURCE_DIR` | unset | Where [Source](https://github.com/0x0pointer/Source) is installed, so the Knowledge page can create and start notes vaults. Unset, a `Source` folder next to the agent-smith folder is used. |
| `SMITH_VAULTS_DIR` | `~/smith-vaults` | The folder new notes vaults are created in (**New vault** on the Knowledge page). |
| `SMITH_CODE_ROOTS` | unset | Folders a white-box scan's source-code folder must sit inside, separated like `PATH` (`;` on Windows, `:` elsewhere). Unset, a scan started from the dashboard may use any folder on the machine. Set it on a shared install, e.g. `SMITH_CODE_ROOTS=/srv/code`. |
| `SMITH_WATCHDOG_DISABLED` | unset (watchdog **on**) | Set (`1`) to disable the dashboard auto-respawn watchdog. The watchdog is meant for headless runs; **disable it for interactive-terminal runs** so it doesn't ghost-spawn a second Smith when you're driving `claude` yourself. |
| `SMITH_DATABASE_URL` | `postgresql+psycopg://smith:smith@127.0.0.1:55432/agent_smith` when started via `smith start`; otherwise unset (database **off**) | SQLAlchemy URL for the control-plane database. A `sqlite:///…` URL skips the Docker Postgres entirely. |
| `SMITH_SINGLE_RUN` | unset | Set (`1`) to force classic single-run mode: the database and per-run isolation are ignored even if the variables above are set. |
| `SMITH_WORKER_CLIENT` | `claude` | Which client the control plane spawns for a dashboard-launched run (`claude` \| `opencode` \| `codex`). |
| `SMITH_AUTO_RESUME` | unset (**idle** on stop) | By default, when Smith stops on its own (its turn ended, it exited, or it hung and was shut down) the scan goes **idle** and waits for you: nothing is respawned. Send an instruction or press **Resume** in the dashboard to continue. Set (`1`) to restore automatic respawn for unattended runs. |
| `SMITH_WORK_QUEUE_DISABLED` | unset (queue **on**) | Set (`1`) to stop turning Source updates into queued work for dashboard-started scans (see [Source updates](#source-updates-and-the-work-queue)). |
| `SMITH_WORK_POLL_SECONDS` | `30` | How often bound Sources are checked for new or changed notes, and queued work is handed to idle scans (minimum 10). |
| `SMITH_KEEP_CONTAINERS` | unset (teardown **on**) | Set (`1`) to opt out of the automatic Kali / Metasploit / MobSF container teardown at scan end — e.g. to inspect a container after the scan finishes. |

---

## Running on Windows

> ⚠️ **Experimental — not fully tested.** The native Windows / PowerShell path (the `.ps1` installers) is provided as-is and has not been thoroughly validated. For the most reliable setup, run under **WSL2** with the bash installers above. Bug reports and PRs for the Windows path are welcome.

The installers above are bash-only (macOS / Linux / WSL). For native Windows
PowerShell, use the `.ps1` siblings:

```powershell
# Clone the repo, then from an elevated PowerShell window:
cd agent-smith
.\installers\install.ps1            # Claude Code
.\installers\install_opencode.ps1   # opencode
.\installers\install_codex.ps1      # Codex
```

What's different on Windows:

- **Auto-start:** the bash installer wires the MCP daemon into macOS launchd.
  The PowerShell installer wires it into **Windows Task Scheduler** instead —
  same intent ("run at logon, restart on failure"), different service manager.
  Elevation is required for the Task Scheduler registration; everything else
  runs without admin.
- **Process management:** the dashboard uses `psutil` for cross-platform
  process introspection (PID liveness, client detection). No Unix tools
  (`lsof`, `pgrep`, `ps`) are required at runtime.
- **CLIs on `$PATH`:** the installer looks up `claude` / `opencode` / `codex`
  through `Get-Command` (PATHEXT-aware, handles `.cmd` shims from npm) — no
  hardcoded `/opt/homebrew/`-style fallbacks.
- **Docker:** the Kali and Metasploit images are Linux containers. They run
  via **Docker Desktop's WSL2 backend** with no code changes. See the next
  section for the build commands in each shell.

---

## Optional images

The Kali and Metasploit images are optional but required for most deep
skills. They are full Linux containers that build identically on every
host — only the path syntax of `docker build` differs per shell.

**Kali** — required for `/credential-audit`, `/web-exploit` deep tools,
`/ad-assessment`, `/lateral-movement`, etc. ~10 min build, ~3 GB image.

```bash
# macOS / Linux / WSL / Git Bash
docker build -t pentest-agent/kali-mcp ./tools/kali/
```
```powershell
# Windows PowerShell
docker build -t pentest-agent/kali-mcp .\tools\kali\
```

**Metasploit** — required for `/metasploit`. ~5 min build.

```bash
# macOS / Linux / WSL / Git Bash
docker build -t pentest-agent/metasploit ./tools/metasploit/
```
```powershell
# Windows PowerShell
docker build -t pentest-agent/metasploit .\tools\metasploit\
```

**Prerequisites on Windows:**

1. **Docker Desktop** with the **WSL2 backend enabled**
   (Settings → General → "Use the WSL 2 based engine"). Linux containers
   under Hyper-V's classic backend will not work — WSL2 is required for the
   `ARM64`/`AMD64` multi-arch buildx that the Kali Dockerfile uses, as well
   as for `--device=/dev/net/tun` mounts used by VPN-aware tools.
2. **At least 16 GB free disk space** allocated to Docker Desktop's data
   volume (Settings → Resources → Disk image size). The Kali image alone is
   ~3 GB, the Metasploit image adds ~2 GB, and build caches roughly double
   that during the first build.
3. **Either** `C:\` mounted into WSL (the default) **or** the agent-smith
   checkout placed under your WSL home (`\\wsl$\Ubuntu\home\<you>\…`) for
   noticeably faster volume mounts. Either works; the WSL-home path avoids
   NTFS↔ext4 translation on every scan write.

**One-shot pre-pull** of the lightweight scanner images (nmap, naabu,
httpx, nuclei, subfinder, semgrep, trufflehog) is identical on every host:

```bash
# bash
docker pull instrumentisto/nmap projectdiscovery/naabu projectdiscovery/httpx \
            projectdiscovery/nuclei projectdiscovery/subfinder \
            semgrep/semgrep trufflesecurity/trufflehog
```
```powershell
# PowerShell — same images, different line-continuation
'instrumentisto/nmap', 'projectdiscovery/naabu', 'projectdiscovery/httpx',
'projectdiscovery/nuclei', 'projectdiscovery/subfinder',
'semgrep/semgrep', 'trufflesecurity/trufflehog' | ForEach-Object { docker pull $_ }
```

(The lightweight images also auto-pull on first use; the explicit pull is
just to avoid the wait during your first scan.)
