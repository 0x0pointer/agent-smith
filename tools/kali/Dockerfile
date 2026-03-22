FROM kalilinux/kali-rolling

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

# Layer 3: web scanning + exploit-db
RUN apt-get update && apt-get install -y --no-install-recommends \
    nikto sqlmap whatweb wafw00f wapiti commix xsser davtest skipfish \
    zaproxy exploitdb \
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
RUN apt-get update && apt-get install -y --no-install-recommends \
    smbmap smbclient samba-common-bin impacket-scripts \
    enum4linux-ng netexec ldap-utils python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir ldapdomaindump --break-system-packages

# Layer 8: service enumeration
# snmpwalk is bundled in the snmp package; snmp-check not available on arm64
RUN apt-get update && apt-get install -y --no-install-recommends \
    ssh-audit redis-tools snmp onesixtyone swaks \
    smtp-user-enum ike-scan finger rpcbind \
    && rm -rf /var/lib/apt/lists/*

# Layer 9: OSINT / recon
RUN apt-get update && apt-get install -y --no-install-recommends \
    theharvester nfs-common lbd \
    && rm -rf /var/lib/apt/lists/*

# Layer 10: network utilities + wordlists + document tools + RDP
RUN apt-get update && apt-get install -y --no-install-recommends \
    socat proxychains4 curl wget \
    seclists wordlists \
    poppler-utils freerdp3-x11 \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery tools via apt (katana not in arm64 repo — installed via pre-built binary)
RUN apt-get update && apt-get install -y --no-install-recommends \
    naabu httpx-toolkit subfinder amass dnsx nuclei \
    && rm -rf /var/lib/apt/lists/*

# Install katana from pre-built GitHub release (supports amd64 + arm64)
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
    && KATANA_VERSION=$(curl -fsSL "https://api.github.com/repos/projectdiscovery/katana/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/') \
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
    && pip3 install --no-cache-dir --ignore-installed pyrit --break-system-packages \
    && apt-get purge -y rustc cargo \
    && apt-get autoremove -y \
    && rm -rf /root/.cargo /root/.rustup
COPY pyrit_runner.py /usr/local/bin/pyrit-runner
RUN chmod +x /usr/local/bin/pyrit-runner

# AI red-teaming: NVIDIA Garak — LLM vulnerability scanner (probe-based)
RUN pip3 install --no-cache-dir garak --break-system-packages || true

# AI red-teaming: promptfoo — LLM eval + red-team framework (npm)
RUN (apt-get update && apt-get install -y --no-install-recommends nodejs npm \
    && rm -rf /var/lib/apt/lists/* \
    && npm install -g promptfoo) || true

# Layer 11: container & K8s security
# trivy — container image vulnerability scanner
# kube-bench — CIS Kubernetes Benchmark auditor
# kubectl — Kubernetes CLI (for K8s assessments from inside Kali)
# dive — Docker image layer explorer (installed from GitHub release)
RUN apt-get update && apt-get install -y --no-install-recommends \
    trivy kubectl \
    && rm -rf /var/lib/apt/lists/*

# kube-bench from GitHub release (not in Kali repos)
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
    && KB_VERSION=$(curl -fsSL "https://api.github.com/repos/aquasecurity/kube-bench/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/') \
    && curl -fsSL "https://github.com/aquasecurity/kube-bench/releases/download/v${KB_VERSION}/kube-bench_${KB_VERSION}_linux_${ARCH}.tar.gz" \
        -o /tmp/kube-bench.tar.gz \
    && tar -xzf /tmp/kube-bench.tar.gz -C /usr/local/bin/ kube-bench \
    && chmod +x /usr/local/bin/kube-bench \
    && rm /tmp/kube-bench.tar.gz

# dive from GitHub release (Docker image layer explorer)
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
    && DIVE_VERSION=$(curl -fsSL "https://api.github.com/repos/wagoodman/dive/releases/latest" \
        | grep '"tag_name"' | head -1 | sed 's/.*"v\([^"]*\)".*/\1/') \
    && curl -fsSL "https://github.com/wagoodman/dive/releases/download/v${DIVE_VERSION}/dive_${DIVE_VERSION}_linux_${ARCH}.tar.gz" \
        -o /tmp/dive.tar.gz \
    && tar -xzf /tmp/dive.tar.gz -C /usr/local/bin/ dive \
    && chmod +x /usr/local/bin/dive \
    && rm /tmp/dive.tar.gz

# Decompress rockyou wordlist (needed by hydra, john, etc.)
RUN gzip -d /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

EXPOSE 5000

# kali-server-mcp is the Flask API component of mcp-kali-server.
# The MCP client bridge (mcp-server) is not needed — we call the HTTP API directly.
CMD ["kali-server-mcp", "--ip", "0.0.0.0"]
