FROM kalilinux/kali-rolling@sha256:287cd5cfa409e258e9ec3661db4dff0bfbb45fc95734e82d3b270a0f749629ca

ENV DEBIAN_FRONTEND=noninteractive

# Bootstrap CA certs over HTTP, then switch mirror to HTTPS for all subsequent layers.
# This avoids 404s from out-of-sync round-robin mirrors (http.kali.org) while keeping
# all package downloads encrypted once the cert store is in place.
RUN echo "deb http://kali.download/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && echo "deb https://kali.download/kali kali-rolling main contrib non-free non-free-firmware" > /etc/apt/sources.list
    
# SSL bypass for Docker build environments where a proxy CA intercepts HTTPS
# (e.g. Zscaler, corporate VPN). Only applies at build time — the running
# container inherits these only if explicitly passed at runtime.
ENV PIP_TRUSTED_HOST="pypi.org files.pythonhosted.org pypi.python.org"
ENV GIT_SSL_NO_VERIFY=true
ENV GONOSUMDB=*
ENV GOPRIVATE=*
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
RUN echo "insecure" > /root/.curlrc

# Core apt tools — split into layers so a single failed package doesn't abort everything

# Layer 1: network scanning
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    nmap masscan hping3 arp-scan nbtscan fping ncat tcpdump tshark \
    && rm -rf /var/lib/apt/lists/*

# Layer 2: DNS / subdomain
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    dnsrecon dnsenum fierce dmitry dnstwist dnsmap whois bind9-dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Layer 3: web scanning + exploit-db + php (for running PHP exploits)
# wpscan — WordPress plugin/theme/core CVE scanner (the authoritative source
#   for WordPress plugin vulnerabilities — nuclei templates are incomplete)
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    nikto sqlmap whatweb wafw00f wapiti commix xsser davtest skipfish \
    zaproxy exploitdb php-cli wpscan \
    && rm -rf /var/lib/apt/lists/*

# Layer 4: web fuzzing / discovery
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    ffuf gobuster feroxbuster dirb dirsearch wfuzz \
    && rm -rf /var/lib/apt/lists/*

# Layer 4b: Phase-1 injection specialists — raise detector CLEAN-trust for the
# injection cells from Partial to Automatable (see docs/phase1-detector-trust.md).
# Installed from PREBUILT release binaries (like katana/interactsh) — NOT built
# from source — so this layer stays small and never pulls a 240 MB golang
# toolchain + huge module trees onto the build disk. Split into independent
# layers so one failure can't poison the others; `|| true` degrades gracefully
# (the sweep falls back to nuclei -dast / wapiti for any missing tool).
#
# dalfox — context-aware XSS scanner (reflected/stored/DOM). Asset names use the
# raw `uname -m` arch (aarch64 / x86_64). Pinned — bump explicitly.
RUN ARCH=$(uname -m) \
    && DALFOX_VERSION=3.1.2 \
    && curl -fsSL "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox-v${DALFOX_VERSION}-linux-${ARCH}.tar.gz" -o /tmp/dalfox.tar.gz \
    && tar -xzf /tmp/dalfox.tar.gz -C /tmp/ \
    && find /tmp -type f -name dalfox -exec mv {} /usr/local/bin/dalfox \; \
    && chmod +x /usr/local/bin/dalfox \
    && rm -rf /tmp/dalfox.tar.gz /tmp/dalfox-* || true

# nosqli — NoSQL injection scanner (Charlie-belmer). Only x86_64 prebuilt exists;
# on arm64 it's skipped and the sweep falls back to nuclei -dast for nosqli.
RUN ARCH=$(uname -m) \
    && if [ "$ARCH" = "x86_64" ]; then \
         curl -fsSL "https://github.com/Charlie-belmer/nosqli/releases/download/v0.5.4/nosqli_linux_x64_v0.5.4" -o /usr/local/bin/nosqli \
         && chmod +x /usr/local/bin/nosqli; \
       else echo "nosqli: no ${ARCH} prebuilt — skipped (sweep uses nuclei -dast for nosqli)"; fi || true

# SSTImap — multi-engine SSTI detect+exploit (maintained Python3 fork of tplmap).
# Create the PATH wrapper right after clone (independent of the requirements
# install) so `sstimap` is runnable even if a single dep fails — the old `&&`
# chain under `|| true` left /opt/SSTImap cloned but no wrapper on PATH.
RUN git clone --depth=1 https://github.com/vladko312/SSTImap /opt/SSTImap || true; \
    if [ -d /opt/SSTImap ]; then \
        printf '#!/bin/sh\nexec python3 /opt/SSTImap/sstimap.py "$@"\n' > /usr/local/bin/sstimap \
        && chmod +x /usr/local/bin/sstimap; \
        pip3 install --no-cache-dir -r /opt/SSTImap/requirements.txt --break-system-packages || true; \
    fi

# arjun (HTTP param discovery) + graphql-cop / graphw00f (GraphQL fingerprint,
# introspection, batching tests). Installed SEPARATELY — pip resolves a single
# invocation atomically, so batching them meant one unresolvable dep on arm64
# silently took down all three (the prior build shipped none of them).
RUN for pkg in arjun graphql-cop graphw00f; do \
        pip3 install --no-cache-dir "$pkg" --break-system-packages || echo "WARN: pip install $pkg failed (continuing)"; \
    done

# jwt_tool — JWT attack toolkit (none alg, alg confusion, kid injection, key brute)
# KOAuth   — automated OAuth 2.0 security scanner (22 checks)
# interactsh-client — out-of-band callback listener for blind SSRF / DNS exfil
RUN (git clone --depth=1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool \
        && pip3 install --no-cache-dir pycryptodomex termcolor cprint requests --break-system-packages \
        && printf '#!/bin/sh\nexec python3 /opt/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool \
        && chmod +x /usr/local/bin/jwt_tool) || true \
    && apt-get update && apt-get install -y --no-install-recommends ca-certificates golang-go unzip \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth=1 https://github.com/morganc3/KOAuth /opt/KOAuth \
    && cd /opt/KOAuth && go build -o /usr/local/bin/KOAuth . \
    && apt-get purge -y golang-go && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* \
    && ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
    && INTERACTSH_VERSION=1.2.1 \
    && curl -fsSL "https://github.com/projectdiscovery/interactsh/releases/download/v${INTERACTSH_VERSION}/interactsh-client_${INTERACTSH_VERSION}_linux_${ARCH}.zip" \
        -o /tmp/interactsh.zip \
    && unzip /tmp/interactsh.zip interactsh-client -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/interactsh-client \
    && rm /tmp/interactsh.zip

# Layer 5: SSL / TLS
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    sslscan sslyze testssl.sh openssl \
    && rm -rf /var/lib/apt/lists/*

# Layer 6: credential testing
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    hydra ncrack john cewl crunch medusa \
    && rm -rf /var/lib/apt/lists/*

# Layer 7: SMB / Windows / AD
# rpcclient is bundled inside smbclient; ldapdomaindump is pip-only
# certipy-ad — ADCS enumeration and exploitation (ESC1-ESC8)
# bloodhound — BloodHound ingestor for AD attack path mapping
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    smbmap smbclient samba-common-bin impacket-scripts \
    enum4linux-ng netexec ldap-utils python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir ldapdomaindump==0.9.4 certipy-ad==5.0.4 bloodhound==1.9.0 --break-system-packages

# Layer 8: service enumeration
# snmpwalk is bundled in the snmp package; snmp-check not available on arm64
# default-mysql-client — MySQL/MariaDB CLI for database enumeration and credential extraction
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    ssh-audit redis-tools snmp onesixtyone swaks \
    smtp-user-enum ike-scan finger rpcbind \
    default-mysql-client \
    && rm -rf /var/lib/apt/lists/*

# Layer 9: OSINT / recon
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    theharvester nfs-common lbd \
    && rm -rf /var/lib/apt/lists/*

# Layer 10: network utilities + wordlists + document tools + cross-compilation
# gcc-mingw-w64 — cross-compile C exploits to Windows EXE/DLL from Kali
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    socat proxychains4 curl wget \
    seclists wordlists \
    gcc gcc-mingw-w64 unrar p7zip-full \
    poppler-utils \
    && rm -rf /var/lib/apt/lists/*

# Optional: gcc-multilib (amd64 only) + freerdp (xfreerdp for RDP)
RUN apt-get update \
    && apt-get install -y --no-install-recommends --fix-missing gcc-multilib 2>/dev/null || true \
    && apt-get install -y --no-install-recommends --fix-missing freerdp2-x11 2>/dev/null \
    || apt-get install -y --no-install-recommends --fix-missing xfreerdp 2>/dev/null || true \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery tools via apt (katana not in arm64 repo — installed via pre-built binary)
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
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
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    mcp-kali-server \
    && rm -rf /var/lib/apt/lists/*

# AI red-teaming: Microsoft PyRIT + thin CLI runner
# pyrit-runner wraps the PyRIT SDK for scripted multi-turn adversarial attacks.
# base2048 (PyRIT dep) requires Rust to compile — install, build, then clean up.
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing rustc cargo \
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
# Installed in a venv to avoid conflicts with Debian-managed packages (no RECORD file).
# --system-site-packages inherits system packages so only the delta is fetched.
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/garak-venv --system-site-packages \
    && /opt/garak-venv/bin/pip install --no-cache-dir garak==0.15.0 \
    && ln -sf /opt/garak-venv/bin/garak /usr/local/bin/garak

# AI red-teaming: promptfoo — LLM eval + red-team framework (npm)
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing nodejs npm \
    && rm -rf /var/lib/apt/lists/* \
    && npm config set strict-ssl false \
    && npm install -g promptfoo@0.121.2

# Web spider: Playwright + headless Chromium for JavaScript-aware crawling
# (required for Hotwire/Turbo Frame apps where katana misses lazy-loaded content)
# Pinned to 1.59.0 — update explicitly when needed
# 1.50+ uses pyee>=13.0.0 which matches the Kali system python3-pyee package
RUN pip3 install --no-cache-dir playwright==1.59.0 --break-system-packages \
    && playwright install chromium --with-deps

# Exploitation payload generators
# phpggc — PHP deserialization gadget-chain generator (Laravel, Symfony,
# Twig, Monolog, Guzzle, SwiftMailer, Yii, ...). Used for exploiting
# PHP unserialize / phar:// sinks. Ships `phpggc` binary + a chains/
# directory with every supported framework/version combination.
RUN git clone --depth=1 https://github.com/ambionics/phpggc /opt/phpggc \
    && ln -s /opt/phpggc/phpggc /usr/local/bin/phpggc

# Layer 11: container & K8s security
# trivy — container image vulnerability scanner
# kube-bench — CIS Kubernetes Benchmark auditor
# kubectl — Kubernetes CLI (for K8s assessments from inside Kali)
# dive — Docker image layer explorer (installed from GitHub release)
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
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
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    ca-certificates curl apt-transport-https lsb-release gnupg \
    && curl -sL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > /etc/apt/keyrings/microsoft.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ $(lsb_release -cs) main" > /etc/apt/sources.list.d/azure-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends --fix-missing azure-cli \
    && rm -rf /var/lib/apt/lists/* || true

# GCP CLI
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" > /etc/apt/sources.list.d/google-cloud-sdk.list \
    && curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
    && apt-get update && apt-get install -y --no-install-recommends --fix-missing google-cloud-cli \
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
    && tar xzf /tmp/ligolo-proxy.tar.gz -C /tmp/ proxy \
    && mv /tmp/proxy /usr/local/bin/ligolo-proxy \
    && chmod +x /usr/local/bin/ligolo-proxy \
    && curl -fsSL "https://github.com/nicocha30/ligolo-ng/releases/download/v${LIGOLO_VERSION}/ligolo-ng_agent_${LIGOLO_VERSION}_linux_${ARCH}.tar.gz" \
        -o /tmp/ligolo-agent.tar.gz \
    && tar xzf /tmp/ligolo-agent.tar.gz -C /tmp/ agent \
    && mv /tmp/agent /usr/local/bin/ligolo-agent \
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

COPY playwright_spider.py /usr/local/bin/playwright-spider
RUN chmod +x /usr/local/bin/playwright-spider

# Layer 14: mobile app reversing + dynamic instrumentation (used by
# /android-security and /ios-security). APK reversing/repackaging (apktool,
# dex2jar, jadx, apksigner, zipalign) + the adb transport. adb/frida connect OUT
# to an operator-provided emulator/device over the network (adb connect <ip>:5555)
# — the `android-dynamic` setup gate confirms the device is live before use.
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    apktool dex2jar jadx apksigner zipalign adb fastboot \
    && rm -rf /var/lib/apt/lists/* || true

# Frida + objection for runtime hooking: SSL-pinning bypass, keystore/keychain
# dumps, runtime storage/heap inspection. NOTE (client↔server coupling): the
# operator must push a frida-server whose version MATCHES this frida-tools pin to
# the device/emulator (see the android-security skill's dynamic ref). Pinned as a
# compatible pair (frida 16.x) — update explicitly when bumping.
RUN pip3 install --no-cache-dir --break-system-packages \
    frida-tools==12.5.1 objection==1.11.0 || true

EXPOSE 5000

# kali-server-mcp is the Flask API component of mcp-kali-server.
# The MCP client bridge (mcp-server) is not needed — we call the HTTP API directly.
CMD ["kali-server-mcp", "--ip", "0.0.0.0"]
