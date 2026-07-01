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
      Requires <a href="https://docs.anthropic.com/en/docs/claude-code">Claude Code</a> + an Anthropic API key.
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
