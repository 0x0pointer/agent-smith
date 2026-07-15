# Running Smith in Production: Host Isolation

**TL;DR** — Smith is a high-agency agent that, by design, feeds attacker-controlled data
(scan output, HTTP responses, target source) into an LLM that can run commands. Prompt
injection against such a system is *not preventable*, so we don't rely on preventing it.
Instead, Smith is meant to run inside a **disposable, egress-restricted VM that holds no
host credentials**. The worst case of a *total* compromise — a malicious npm/pip package,
an injected `kali()` command, a hijacked agent — is then a throwaway VM, not your machine,
your keys, or your network. This document is the plan for building that environment.

> The one-sentence version you can tell people: *"We treat prompt injection as inevitable,
> so Smith runs in a disposable VM with no host secrets and locked-down egress — a full
> compromise costs you a VM, nothing more."*

---

## 1. Why isolation is the control — not guardrails

Smith has all three legs of the **lethal trifecta**:

1. **Access to sensitive data / credentials** — LLM API keys, notifier tokens, findings,
   and anything else in its environment.
2. **Exposure to untrusted content** — its *entire input* is attacker-controlled: tool
   output, HTTP response bodies, analyzed source code, DNS callbacks.
3. **The ability to act and exfiltrate** — `kali()` runs arbitrary commands, `http()` makes
   arbitrary requests, `exec_sandbox` runs arbitrary code.

Any system with all three is exploitable via indirect prompt injection, and there is **no
known way to make an LLM injection-proof**. You cannot remove leg 2 (untrusted content *is*
the job) and you cannot remove leg 3 (capability *is* the job). The only leg you can break
is the environment: **contain it so a successful injection reaches nothing that matters.**

Guardrails (system-prompt rules, scope reminders, output filters) can raise the attacker's
cost and reduce noise, but they are **defense-in-depth, never the boundary**. Enforce scope
at the *network* layer, not by asking the model to behave. If a design relies on the model
not being tricked, it is not a security boundary.

---

## 2. The containment contract

A production deployment must satisfy **all four** properties. Any one missing and "run it in
a VM" becomes a false comfort:

| # | Property | Why it's necessary | If missing… |
|---|----------|--------------------|-------------|
| 1 | **Host isolation** | A compromise must not reach the real host kernel/filesystem. | Attacker owns your workstation. |
| 2 | **Secret minimization** | The VM boundary only protects what's *outside* it. | Attacker steals every credential you loaded *into* the VM. |
| 3 | **Egress control** | A VM can't touch your disk, but a hijacked agent can still exfiltrate over the wire and pivot into your LAN. | Data theft + lateral movement, just over the network. |
| 4 | **Ephemerality** | A persistent implant must not survive to the next engagement. | One compromised job silently taints all future jobs. |

The rest of this doc is how to achieve each one.

---

## 3. The Docker-socket trapdoor — why "just containerize Smith" fails

The obvious idea is to run the Smith process in a container. **Do not do this naively.**

Smith's job is to orchestrate Docker — it spawns tool containers (`kali`, `metasploit`,
`mobsf`, the sandbox). The way a container does that is by mounting the host's
`/var/run/docker.sock`. But **the Docker socket is root-equivalent on whatever runs that
daemon**: any code-exec in Smith simply runs

```bash
docker run -v /:/host --privileged alpine chroot /host   # instant host root
```

and walks straight out. A Smith container with the host docker socket mounted (or privileged
Docker-in-Docker) is **less safe than a bare install** — it looks sandboxed but the socket is
a trapdoor.

**The fix:** the isolation boundary is a **VM**, and the VM runs **its own Docker daemon**.
Smith orchestrates the VM-local dockerd; that daemon can only reach the VM's own kernel and
filesystem. Nothing crosses back to the real host. Container escape (shared kernel) is far
more plausible than VM escape (hardware-virtualized boundary), which is why the boundary is a
VM, not a container.

---

## 4. Reference architecture

```
┌─ operator laptop (macOS / your workstation) ─────────────────────────────┐
│  · holds NO Smith secrets                                                 │
│  · reaches the dashboard only through an SSH tunnel (localhost:7777)      │
│                                                                           │
│        ssh -L 7777:127.0.0.1:7777  smith@vm                               │
│                         │                                                 │
└─────────────────────────┼─────────────────────────────────────────────────┘
                          │  (control plane only)
┌─ DISPOSABLE VM (Linux, hardware-virtualized) ─── blast radius ═══════════┐
│                                                                           │
│  Layer 1 — the VM                                                         │
│   · Smith MCP server + FastAPI dashboard (run as non-root `smith` user)   │
│   · dashboard bound to 127.0.0.1 only (never 0.0.0.0)                     │
│   · its OWN dockerd (NOT the host's socket)                               │
│   · nftables default-deny egress + allowlist  ◄── property 3             │
│   · only secret present: a SCOPED LLM API key + notifier tokens          │
│                                                                           │
│   Layer 2 — hardened tool containers (spawned by Smith's dockerd)         │
│    ┌ kali ┐ ┌ metasploit ┐ ┌ mobsf ┐ ┌ exec_sandbox ┐                    │
│    │ cap-drop, no-new-privileges, seccomp, ro-rootfs where possible │     │
│    └──────┘ └────────────┘ └───────┘ └──────────────┘                    │
│                                                                           │
│  Rebuilt from a golden image per engagement, destroyed after  ◄─ prop 4  │
└═══════════════════════════════════════════════════════════════════════════┘
                          │  egress ONLY to:
                          ▼
        authorized target scope · LLM API · notifier API · image registry
        (everything else — RFC1918, link-local, metadata — DROPPED)
```

Two nested trust boundaries: the **VM** contains a host compromise (properties 1 & 4), and
**per-container hardening** limits what a single tool can do inside the VM (defense-in-depth).
**Egress rules** (property 3) and **secret minimization** (property 2) tame the fact that
Smith's **lightweight scanner** containers legitimately use `--network=host`
(`tools/docker_runner.py`) — inside the VM, "host" *is* the VM, and the VM's firewall is what
bounds it. (The Kali and Metasploit **command** containers do NOT use host networking — they
publish their APIs to loopback only; see §8.)

---

## 5. Deployment options

| Option | Isolation from host | Isolation from your LAN | Effort | Recommendation |
|--------|---------------------|-------------------------|--------|----------------|
| **Cloud ephemeral VM** (EC2 / GCE / Hetzner) | Strong (separate hardware) | Strong (not on your LAN at all) | Medium | **Best for external targets & regular use** |
| **Local Linux VM on the Mac** (Lima / UTM / Multipass) | Strong (hardware virt) | Weak *unless* egress is locked | Low | Good for getting started / internal targets |
| **Dedicated on-prem box** | Strong | Needs VLAN segmentation | Medium | Good for a permanent lab |

**Recommended default: an ephemeral cloud VM, rebuilt per engagement, with scope-allowlist
egress.** It removes Smith from your LAN entirely, so even a network pivot lands in a
cloud subnet you control, and teardown is a single API call. Use the local Lima variant when
you need to reach internal targets or want a zero-cost start — just don't skip the egress
rules (§10), because a local VM shares your home/office network by default.

> **macOS note:** today the Smith Python process runs *natively on your Mac* — only the tool
> containers live in Docker Desktop's VM. So RCE in the Smith process is code-exec *on your
> Mac*. The whole point of this plan is to move the **Smith process itself** inside the VM.
> When using Lima/UTM, give the guest **its own dockerd** — do **not** reuse Docker Desktop's
> socket from the guest, or you've rebuilt the trapdoor from §3.

---

## 6. Build the golden image

Bake a reusable image so each engagement boots clean and fast. Sketch (Debian/Ubuntu):

```bash
# --- provisioning (run once, then snapshot to a golden image) ---
adduser --disabled-password --gecos "" smith          # non-root runtime user
usermod -aG docker smith                               # can talk to VM-local dockerd only

# VM-local Docker daemon (rootless recommended — see §8)
curl -fsSL https://get.docker.com | sh
# … or rootless: dockerd-rootless-setuptool.sh install  (as the smith user)

# Smith itself
sudo -u smith git clone git@github.com:0x0pointer/agent-smith.git /home/smith/agent-smith
cd /home/smith/agent-smith && sudo -u smith ./installers/install.sh

# Pre-pull tool images INTO the golden image, then block registry egress at runtime
sudo -u smith bash -c 'cd /home/smith/agent-smith && \
  python -m mcp_server &  sleep 5;  # or call session(action="pull_images")
  docker build -t pentest-agent/kali-mcp ./tools/kali/
  docker build -t pentest-agent/metasploit ./tools/metasploit/'

# Harden: no swap to disk of secrets, tighten perms, disable unused services
chmod 700 /home/smith
```

Snapshot the result (cloud AMI/image, or `limactl` disk snapshot). **The `.env` is NOT baked
in** — it's injected at boot per engagement (§9) so images can be shared without leaking keys.

For repeatability, express the above as a Packer template or a cloud-init `user-data` script
checked into your ops repo (not this one).

---

## 7. Layer 1 — the VM

- **Run Smith as a non-root user** (`smith`), never root. Limits damage if a container-escape
  path exists and constrains egress rules by uid (§10).
- **The VM owns its Docker daemon.** Verify Smith is talking to the VM-local socket, not a
  forwarded host socket: `docker context ls` inside the VM must show the local daemon.
- **The dashboard is loopback + token-authed by default — keep it that way.** Smith binds
  uvicorn to `127.0.0.1` by default (`host = os.environ.get("DASHBOARD_HOST", "127.0.0.1")`
  in `core/api_server/serve.py`), and every `/api/*` control-plane call is gated by a
  per-session bearer token (`core/dashboard_auth.py`, enforced by the middleware in
  `core/api_server/__init__.py`). The only action here is **don't** set `DASHBOARD_HOST=0.0.0.0`
  unless you are behind a trusted boundary — reach the dashboard via SSH tunnel instead (§11).
- **Resource caps** so a crypto-miner pulled in by a malicious dependency can't peg the box:
  size the VM modestly (e.g. 4 vCPU / 8 GB) and rely on the VM hypervisor's limits; inside,
  keep the per-container `--memory` / `--cpus` limits the runners already set.
- **No host filesystem mounts into the VM.** If your hypervisor supports shared folders
  (Lima/UTM/VirtualBox), **disable them** — a shared folder is a direct path back to the host.
  Move artifacts out over SSH/SCP instead (§12).

---

## 8. Layer 2 — harden the tool containers (defense-in-depth)

Inside the VM, a single tool container should not be able to compromise the VM either. Smith
already applies some of this (`tools/sandbox_runner.py` uses `--cap-drop=ALL`,
`--security-opt=no-new-privileges`, and `--network=none` for untrusted code). Extend the same
posture broadly:

- **Rootless Docker or Podman** for the VM-local daemon. Even a container breakout then lands
  as an unprivileged user, not VM-root. This is the single highest-leverage Layer-2 upgrade.
- **`--cap-drop=ALL`** and add back only what a tool needs (the kali container legitimately
  needs `NET_RAW`/`NET_ADMIN` for raw-socket scanning — keep those *only* on kali).
- **`--security-opt=no-new-privileges`** on every container.
- **seccomp**: keep Docker's default profile on; use a custom stricter profile for the sandbox.
- **`--read-only` root filesystem** with an explicit `--tmpfs /tmp` where the tool allows it.
- **`--pids-limit`** and per-container `--memory` / `--cpus` (runners already set the latter).
- For genuinely untrusted code analysis, consider a **sandboxed runtime** (gVisor `runsc` or
  Kata Containers) as the exec_sandbox backend — VM-grade isolation per container.

> `--network=host` in `tools/docker_runner.py` (the **lightweight scanner** containers —
> nmap/nuclei/httpx/ffuf/…) is acceptable *inside the VM* because the VM's network namespace is
> itself bounded by the egress firewall (§10). It would be dangerous on a bare host. This is why
> the egress rules are not optional. The Kali/Metasploit **command** containers do *not* use host
> networking — see the next subsection.

### 8.1 The tool command APIs — loopback-only, token + Host-allowlist guarded

Smith's Kali and Metasploit containers each expose a command API (`POST /api/command`) that runs
an arbitrary shell — Kali's kali-server-mcp runs it **as root**. These used to be published on
`0.0.0.0`, i.e. **unauthenticated remote code execution reachable from the LAN**. They are now
hardened at three layers:

- **Loopback-only publish.** `tools/kali_runner.py` publishes with `-p 127.0.0.1:5001:5000` and
  `tools/metasploit_runner.py` with `-p 127.0.0.1:5002:5000`, so only the VM-local MCP process can
  reach the command API — the LAN cannot. (Tunnel / handler ports — chisel, ligolo, meterpreter —
  stay on `0.0.0.0` because targets must reach them for reverse connections; those are not command
  APIs.)
- **Token + Host-allowlist guard in front of each API.** For Kali, `tools/kali/api_guard.py`
  requires a shared-secret token (`KALI_API_TOKEN`) and an allowlisted `Host` header, and forwards
  to the upstream kali-server which is itself bound **loopback-only inside the container on
  `:5555`**. For Metasploit, `tools/metasploit/server.py` enforces a `before_request` Host
  allowlist, an `MSF_API_SECRET` shared secret, and `application/json`-only bodies (anti-CSRF — a
  browser "simple request" in `text/plain`/form-encoded is rejected before it can execute).
  Together these close the **network** vector, the **DNS-rebinding** vector (a rebound request
  carries the attacker's `Host`), and the **local-process** vector (no token → no exec).
- **Auto-teardown on scan end.** `core/session/lifecycle.py:stop_pentest_containers()` stops the
  Kali / Metasploit / MobSF containers the moment a scan reaches a terminal state, so a **finished
  scan leaves no running RCE endpoint**. Opt out with `SMITH_KEEP_CONTAINERS=1` only when you need
  to inspect a container post-run.

---

## 9. Secret minimization (property 2)

The VM boundary protects what's *outside* it. Everything inside is in the blast radius, so put
as little of value inside as possible:

- **No host credentials in the VM.** No personal SSH private keys, no cloud CLI creds
  (`~/.aws`, `~/.config/gcloud`), no corporate VPN configs, no password-manager exports.
- **The LLM API key is the one secret that must live inside** (Smith can't work without it).
  Treat it as sacrificial: use a **dedicated, spend-capped, least-privilege key** for Smith,
  separate from any other workload, so a leak means a bounded bill — not your whole account.
- **Scope notifier tokens** (Telegram/Slack/Discord) to a throwaway channel; a leaked webhook
  should let an attacker post to one channel, nothing more.
- **Block the cloud metadata endpoint.** On a cloud VM, `169.254.169.254` can mint IAM
  credentials. Drop egress to `169.254.0.0/16` (§10), require IMDSv2 with hop-limit 1, and
  attach the *most minimal* instance role possible (ideally none).
- **Inject `.env` at boot, not in the image**, and lock it down: `chmod 600 .env`, owned by
  `smith`. Never commit it (it's already gitignored — keep it that way).
- **Assume artifacts/logs contain secrets.** JWTs and creds harvested during a scan land in
  `artifacts/`, `logs/`, `session.json`. Export them over an encrypted channel and treat the
  export as sensitive.

---

## 10. Egress control (property 3)

Default-deny outbound, allowlist the few things Smith legitimately needs. This is what stops a
hijacked agent from pivoting into your LAN, hitting cloud metadata, or exfiltrating to an
arbitrary host. Filter **both** the `OUTPUT` chain (the Smith host process) **and** the
`FORWARD` chain (masqueraded container traffic), on the external interface only — leave
`docker0`/loopback alone so the VM-local containers still talk to each other and to dockerd.

Example `nftables` skeleton (adapt the target scope and interface name):

```nft
# /etc/nftables.conf  — default-deny egress with an allowlist
table inet smith_egress {
    set allowed_hosts {
        type ipv4_addr; flags interval
        elements = {
            10.20.30.0/24,          # <-- the AUTHORIZED target scope for THIS engagement
            160.79.104.0/23         # <-- LLM API provider range (pin to your provider)
        }
    }

    chain out_common {
        # DNS to a controlled resolver only
        ip daddr 1.1.1.1 udp dport 53 accept
        ip daddr 1.1.1.1 tcp dport 53 accept

        # allowlisted destinations (target scope + LLM + notifiers)
        ip daddr @allowed_hosts accept

        # HARD DROP the dangerous internals (defense against pivot / metadata theft)
        ip daddr 169.254.0.0/16 drop            # link-local + cloud metadata
        ip daddr 10.0.0.0/8      drop            # RFC1918 (unless a /24 above re-allows scope)
        ip daddr 172.16.0.0/12   drop
        ip daddr 192.168.0.0/16  drop

        drop                                     # default deny
    }

    chain output {                               # Smith host process egress
        type filter hook output priority 0;
        oifname "lo" accept
        oifname "docker0" accept                 # let dockerd/containers reach the daemon net
        jump out_common
    }

    chain forward {                              # container (masqueraded) egress
        type filter hook forward priority 0;
        iifname "docker0" oifname "eth0" jump out_common
        ct state established,related accept
    }
}
```

Allow, at most: **(a)** the authorized target scope for the current engagement, **(b)** the
LLM API endpoint, **(c)** notifier endpoints, **(d)** the image registry *only during golden-
image build* — then block it at runtime since images are pre-pulled (§6). Everything else is
dropped. Re-scope `allowed_hosts` per engagement; that set *is* your rules-of-engagement,
enforced in the kernel instead of in a prompt.

---

## 11. Control-plane access (dashboard + MCP)

The dashboard (`:7777`) and MCP SSE (`:7778`) are the control plane — anyone who reaches them
can steer or stop the agent. They must **never** be exposed on the network:

- **It already binds `127.0.0.1` and requires a per-session bearer token.** The uvicorn bind
  defaults to loopback (`DASHBOARD_HOST`, `core/api_server/serve.py`) and the `/api/*` routes
  reject any request that doesn't carry the session token (`core/dashboard_auth.py`, minted
  per scan). Leave `DASHBOARD_HOST` unset — do **not** set it to `0.0.0.0` unless the port is
  behind a trusted boundary.
- **Reach the dashboard from your laptop via SSH tunnel**, not by opening the port:

  ```bash
  ssh -N -L 7777:127.0.0.1:7777 smith@<vm>     # then browse http://localhost:7777
  ```

- If a tunnel isn't possible, put the port behind an authenticating reverse proxy (mTLS or a
  strong bearer token) and firewall it to your source IP. Do **not** rely on "it's only on the
  LAN" — the LAN is exactly the boundary this whole plan assumes is hostile.

---

## 12. Per-engagement runbook

1. **Provision** a fresh VM from the golden image (`terraform apply` / `limactl start` /
   cloud console).
2. **Inject secrets**: copy the scoped `.env` in over SCP; `chmod 600`.
3. **Set the scope**: edit `allowed_hosts` in the nftables set to *this engagement's* targets;
   `nft -f /etc/nftables.conf`; verify with the checklist in §13.
4. **Open the tunnel**: `ssh -N -L 7777:127.0.0.1:7777 smith@<vm>`.
5. **Run** the engagement (start Smith, drive the scan).
6. **Export artifacts**: `scp -r smith@<vm>:~/agent-smith/artifacts ./out/` (treat as
   sensitive — it may contain harvested creds).
7. **Destroy** the VM (`terraform destroy` / `limactl delete`). Do not reuse it.

---

## 13. What this protects — and what it doesn't

**Protected:**
- A malicious dependency, injected command, or full RCE inside Smith → contained to a
  disposable VM; your host, keys, and LAN are untouched.
- A hijacked agent trying to pivot or exfiltrate → blocked by default-deny egress.
- Persistence across engagements → prevented by ephemerality.

**NOT protected (residual risk — be honest about it):**
- **The current engagement's target and data.** Anything Smith can legitimately reach and
  read *this* run is inside the blast radius. Isolation limits spread; it doesn't make the
  agent trustworthy.
- **The LLM API key inside the VM.** Minimized and spend-capped, but present. A leak means a
  bounded bill / that key's access, not your account — *if* you scoped it (§9).
- **Attacks against the target that you're authorized to run anyway** — out of scope for
  *this* control; that's what rules-of-engagement and the egress allowlist bound.
- **VM/hypervisor escape (0-day).** Real but rare; a cloud VM further limits it to a subnet
  you control. This is why the boundary is a VM and not a shared-kernel container.

---

## 14. Verification checklist

Prove the containment holds *before* trusting it — don't assume:

```bash
# 1. Smith runs as non-root
ps -o user= -C python | sort -u                      # expect: smith (not root)

# 2. The dashboard is NOT on the network
ss -tlnp | grep 7777                                 # expect: 127.0.0.1:7777, never 0.0.0.0

# 3. Docker is VM-local, not a forwarded host socket
docker context ls                                    # endpoint must be the local unix socket
readlink -f /var/run/docker.sock                     # must be inside the VM, no host bind-mount

# 4. Egress is default-deny (run as the smith user)
curl -m 5 https://example.com            ; echo $?   # expect: FAIL (7/28) unless allowlisted
curl -m 5 http://169.254.169.254/         ; echo $?  # expect: FAIL — metadata blocked
curl -m 5 http://<an-internal-LAN-host>/  ; echo $?  # expect: FAIL — no LAN pivot
curl -m 5 https://<your-LLM-API-host>/    ; echo $?  # expect: SUCCESS — allowlisted

# 5. No host secrets present
ls ~/.aws ~/.ssh ~/.config/gcloud 2>/dev/null        # expect: nothing sensitive
stat -c '%a' ~/agent-smith/.env                      # expect: 600

# 6. No host filesystem shared into the VM
mount | grep -iE 'virtfs|9p|vboxsf|shared'           # expect: no host shared folders

# 7. The tool command APIs are loopback-only (check while Kali/MSF are running)
ss -tlnp | grep -E ':(5001|5002)\b'                  # expect: 127.0.0.1:5001 / :5002, never 0.0.0.0
```

If any check fails, the corresponding property in §2 is broken — fix it before running an
engagement against a live target.
```

---

*This document describes the deployment posture. The application-level hardening it references
(loopback bind + per-session token on the dashboard; loopback-only + token/Host-allowlisted
container command APIs; auto-teardown of the RCE containers on scan end) is now implemented in
Smith — not pending. Isolation is the boundary; those fixes are defense-in-depth on top of it.*
