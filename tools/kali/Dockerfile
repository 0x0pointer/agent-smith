FROM kalilinux/kali-rolling@sha256:287cd5cfa409e258e9ec3661db4dff0bfbb45fc95734e82d3b270a0f749629ca

ENV DEBIAN_FRONTEND=noninteractive

# Core apt tools — split into layers so a single failed package doesn't abort everything

# Layer 1: network scanning
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap masscan hping3 arp-scan nbtscan fping ncat tcpdump tshark \
    && rm -rf /var/lib/apt/lists/*

# Layer 2: DNS / subdomain
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsrecon dnsenum fierce dmitry dnstwist dnsmap whois bind9-dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Layer 3: web scanning + exploit-db + php (for running PHP exploits)
RUN apt-get update && apt-get install -y --no-install-recommends \
    nikto sqlmap whatweb wafw00f wapiti commix xsser davtest skipfish \
    zaproxy exploitdb php-cli \
    && rm -rf /var/lib/apt/lists/*

# Layer 4: web fuzzing / discovery
RUN apt-get update && apt-get install -y --no-install-recommends \
    ffuf gobuster feroxbuster dirb dirsearch wfuzz \
    && rm -rf /var/lib/apt/lists/*

# Layer 5: SSL / TLS
RUN apt-get update && apt-get install -y --no-install-recommends \
    sslscan sslyze testssl.sh openssl \
    && rm -rf /var/lib/apt/lists/*

# Layer 6: credential testing
RUN apt-get update && apt-get install -y --no-install-recommends \
    hydra ncrack john cewl crunch medusa \
    && rm -rf /var/lib/apt/lists/*

# Layer 7: SMB / Windows / AD
# rpcclient is bundled inside smbclient; ldapdomaindump is pip-only
# certipy-ad — ADCS enumeration and exploitation (ESC1-ESC8)
# bloodhound — BloodHound ingestor for AD attack path mapping
RUN apt-get update && apt-get install -y --no-install-recommends \
    smbmap smbclient samba-common-bin impacket-scripts \
    enum4linux-ng netexec ldap-utils python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir ldapdomaindump==0.9.4 certipy-ad==5.0.4 bloodhound==1.9.0 --break-system-packages

# Layer 8: service enumeration
# snmpwalk is bundled in the snmp package; snmp-check not available on arm64
# default-mysql-client — MySQL/MariaDB CLI for database enumeration and credential extraction
RUN apt-get update && apt-get install -y --no-install-recommends \
    ssh-audit redis-tools snmp onesixtyone swaks \
    smtp-user-enum ike-scan finger rpcbind \
    default-mysql-client \
    && rm -rf /var/lib/apt/lists/*

# Layer 9: OSINT / recon
RUN apt-get update && apt-get install -y --no-install-recommends \
    theharvester nfs-common lbd \
    && rm -rf /var/lib/apt/lists/*

# Layer 10: network utilities + wordlists + document tools + cross-compilation
# gcc-mingw-w64 — cross-compile C exploits to Windows EXE/DLL from Kali
RUN apt-get update && apt-get install -y --no-install-recommends \
    socat proxychains4 curl wget \
    seclists wordlists \
    gcc gcc-mingw-w64 unrar p7zip-full \
    poppler-utils \
    && rm -rf /var/lib/apt/lists/*

# Optional: gcc-multilib (amd64 only) + freerdp (xfreerdp for RDP)
RUN apt-get update \
    && apt-get install -y --no-install-recommends gcc-multilib 2>/dev/null || true \
    && apt-get install -y --no-install-recommends freerdp2-x11 2>/dev/null \
    || apt-get install -y --no-install-recommends xfreerdp 2>/dev/null || true \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery tools via apt (katana not in arm64 repo — installed via pre-built binary)
RUN apt-get update && apt-get install -y --no-install-recommends \
    naabu httpx-toolkit subfinder amass dnsx nuclei \
    && rm -rf /var/lib/apt/lists/*

# Install katana from pre-built GitHub release (supports amd64 + arm64)
# Pinned to v1.5.0 — update explicitly when needed
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
    && KATANA_VERSION=1.5.0 \
    && curl -fsSL "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${ARCH}.zip" \
        -o /tmp/katana.zip \
    && unzip /tmp/katana.zip katana -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/katana \
    && rm /tmp/katana.zip

# Official Kali MCP server — provides POST /api/command (and per-tool endpoints)
# on port 5000. Replaces our hand-rolled server.py.
RUN apt-get update && apt-get install -y --no-install-recommends \
    mcp-kali-server \
    && rm -rf /var/lib/apt/lists/*

# AI red-teaming: Microsoft PyRIT + thin CLI runner
# pyrit-runner wraps the PyRIT SDK for scripted multi-turn adversarial attacks.
# base2048 (PyRIT dep) requires Rust to compile — install, build, then clean up.
RUN apt-get update && apt-get install -y --no-install-recommends rustc cargo \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir --ignore-installed pyrit==0.11.0 --break-system-packages \
    && apt-get purge -y rustc cargo \
    && apt-get autoremove -y \
    && rm -rf /root/.cargo /root/.rustup
COPY pyrit_runner.py /usr/local/bin/pyrit-runner
RUN chmod +x /usr/local/bin/pyrit-runner

# AI red-teaming: CyberArk FuzzyAI runs as a separate Docker image (ghcr.io/cyberark/fuzzyai),
# not installed here. See tools/fuzzyai.py for the image definition.

# AI red-teaming: NVIDIA Garak — LLM vulnerability scanner (probe-based)
RUN pip3 install --no-cache-dir garak==0.14.0 --break-system-packages || true

# AI red-teaming: promptfoo — LLM eval + red-team framework (npm)
RUN (apt-get update && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g promptfoo@0.121.2) || true

# Layer 11: container & K8s security
# trivy — container image vulnerability scanner
# kube-bench — CIS Kubernetes Benchmark auditor
# kubectl — Kubernetes CLI (for K8s assessments from inside Kali)
# dive — Docker image layer explorer (installed from GitHub release)
RUN apt-get update && apt-get install -y --no-install-recommends \
    trivy kubectl \
    && rm -rf /var/lib/apt/lists/*

# kube-bench from GitHub release (not in Kali repos)
# Pinned to v0.15.0 — update explicitly when needed
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
    && KB_VERSION=0.15.0 \
    && curl -fsSL "https://github.com/aquasecurity/kube-bench/releases/download/v${KB_VERSION}/kube-bench_${KB_VERSION}_linux_${ARCH}.tar.gz" \
        -o /tmp/kube-bench.tar.gz \
    && tar -xzf /tmp/kube-bench.tar.gz -C /usr/local/bin/ kube-bench \
    && chmod +x /usr/local/bin/kube-bench \
    && rm /tmp/kube-bench.tar.gz

# dive from GitHub release (Docker image layer explorer)
# Pinned to v0.13.1 — update explicitly when needed
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
    && DIVE_VERSION=0.13.1 \
    && curl -fsSL "https://github.com/wagoodman/dive/releases/download/v${DIVE_VERSION}/dive_${DIVE_VERSION}_linux_${ARCH}.tar.gz" \
        -o /tmp/dive.tar.gz \
    && tar -xzf /tmp/dive.tar.gz -C /usr/local/bin/ dive \
    && chmod +x /usr/local/bin/dive \
    && rm /tmp/dive.tar.gz

# Layer 12: cloud security — AWS CLI, Azure CLI, GCP CLI, Prowler, ScoutSuite
# AWS CLI (via pip — kali apt awscli is often outdated)
RUN pip3 install --no-cache-dir awscli==1.44.63 --break-system-packages || true

# Azure CLI
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl apt-transport-https lsb-release gnupg \
    && curl -sL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > /etc/apt/keyrings/microsoft.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ $(lsb_release -cs) main" > /etc/apt/sources.list.d/azure-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends azure-cli \
    && rm -rf /var/lib/apt/lists/* || true

# GCP CLI
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" > /etc/apt/sources.list.d/google-cloud-sdk.list \
    && curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
    && apt-get update && apt-get install -y --no-install-recommends google-cloud-cli \
    && rm -rf /var/lib/apt/lists/* || true

# Prowler (AWS/Azure/GCP security auditor) + ScoutSuite (multi-cloud auditor)
# NOTE: prowler and scoutsuite currently fail to install on kali-rolling arm64.
# Pinned versions for when the build succeeds on compatible platforms.
RUN pip3 install --no-cache-dir prowler==5.22.0 scoutsuite==5.14.0 --break-system-packages || true

# Layer 13: pivoting — ligolo-ng (TUN-based, primary) + chisel (HTTP/WS, fallback)
# ligolo-ng proxy + agent from GitHub release (avoids broken third-party apt repos)
# Pinned to v0.8.2 — update explicitly when needed
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
    && LIGOLO_VERSION=0.8.2 \
    && curl -fsSL "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VERSION}/ligolo-ng_proxy_${LIGOLO_VERSION}_linux_${ARCH}.tar.gz" \
        -o /tmp/ligolo-proxy.tar.gz \
    && tar xzf /tmp/ligolo-proxy.tar.gz -C /usr/local/bin/ ligolo-proxy \
    && chmod +x /usr/local/bin/ligolo-proxy \
    && curl -fsSL "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VERSION}/ligolo-ng_agent_${LIGOLO_VERSION}_linux_${ARCH}.tar.gz" \
        -o /tmp/ligolo-agent.tar.gz \
    && tar xzf /tmp/ligolo-agent.tar.gz -C /usr/local/bin/ ligolo-agent \
    && chmod +x /usr/local/bin/ligolo-agent \
    && rm -f /tmp/ligolo-proxy.tar.gz /tmp/ligolo-agent.tar.gz

# chisel: fallback for HTTP-only egress or when TUN creation fails
# Pinned to v1.10.1 — update explicitly when needed
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
    && CHISEL_VERSION=1.10.1 \
    && curl -fsSL "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VERSION}/chisel_${CHISEL_VERSION}_linux_${ARCH}.gz" \
        -o /tmp/chisel.gz \
    && gunzip /tmp/chisel.gz \
    && mv /tmp/chisel /usr/local/bin/chisel \
    && chmod +x /usr/local/bin/chisel

# Decompress rockyou wordlist (needed by hydra, john, etc.)
RUN gzip -d /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

EXPOSE 5000

# kali-server-mcp is the Flask API component of mcp-kali-server.
# The MCP client bridge (mcp-server) is not needed — we call the HTTP API directly.
CMD ["kali-server-mcp", "--ip", "0.0.0.0"]
