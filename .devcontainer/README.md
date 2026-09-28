# agent-smith — Codespaces dev container

The harness (agent-smith, the MCP server, Claude Code, opencode) runs **natively**
in the Codespace, exactly like your local box. **Only the hacking tools run in a
container** (via docker-in-docker). Tailscale joins the Codespace to your lab so
the tools can reach targets and receive callbacks.

## Model backend

Claude only (no local model, no DGX Spark). Pick one credential:

| Credential | How to get it | Billing |
|---|---|---|
| `ANTHROPIC_API_KEY` | Anthropic Console | API, separate from any plan |
| `CLAUDE_CODE_OAUTH_TOKEN` | run `claude setup-token` on your laptop (browser, one time) | your Pro/Max subscription |

Add whichever you choose as a **Codespaces secret**
(Settings → Codespaces → Secrets); it's injected as an env var automatically.
Don't set both.

**No credential set?** Run `claude` in the VS Code integrated terminal and use
`/login`. It prints a `http://localhost:PORT/...` URL; VS Code forwards that
loopback port to your browser so the callback completes. If it doesn't, add the
port in the **Ports** panel and reopen the URL.

## Networking — reach the lab and get callbacks back

A Codespace isn't on your network and has no public inbound path, so raw reverse
shells won't reach it by default. Tailscale fixes this by putting the Codespace
on your lab tailnet.

1. **Auth key:** create a tagged, ephemeral, reusable auth key in the Tailscale
   admin panel and store it as the `TS_AUTH_KEY` Codespaces secret. The daemon
   auto-starts and runs `tailscale up --accept-routes`.
2. **Subnet router:** run one Tailscale subnet router in your lab advertising the
   target subnet(s), e.g. `tailscale up --advertise-routes=10.0.0.0/24`, and
   approve the routes in the admin console. No need to install Tailscale on every
   target.
3. **Tools container on the host network:** run the hacking-tools container with
   `--network=host` (compose: `network_mode: host`) so it shares the Codespace's
   `tailscale0` interface and routes. Then:
   - **Outbound:** tools reach lab IPs directly over the tailnet.
   - **Callbacks:** point reverse shells / handlers (`LHOST`) at the **Codespace
     tailnet IP** (`tailscale ip -4`) — the target routes back over the tailnet
     to the listener in the host-networked container.

Tailscale connects even behind Codespaces egress restrictions (DERP over 443).

**Limitation:** a public-internet target that must call back to a *public*
listener (not on your tailnet) needs a small VPS redirector — Tailscale alone
won't expose a public inbound endpoint. Authorized lab targets on the tailnet
need nothing extra.

## Containers

`setup.sh` waits for the docker-in-docker daemon, then builds/pulls the
hacking-tools container. By default it calls the repo's `install.sh`; if that's
interactive or also installs the CLIs, trim it to the tool-build steps, or switch
to the `docker compose` branch in `setup.sh`.

## opencode

`opencode.json` (repo root) points at Claude's native provider. With the
credential in env it works with no further config — run `/models` to pick the
exact current Claude model.

## Sizing

8 cores / 16 GB / 64 GB storage. Bump cores if the tool container is heavy.
