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

# OPT-IN TLS-interception CA capture — for building BEHIND a MITM proxy only.
# OFF by default. A normal build reaches crates.io / PyPI directly and needs
# none of this; do NOT enable it unless your build network intercepts TLS.
# Enable for a proxied build with:
#     docker build --build-arg TRUST_BUILD_PROXY_CA=1 -t pentest-agent/kali-mcp ./tools/kali/
#
# Why it exists: the env-var bypasses above cover pip/git/npm/curl, but NOT
# cargo (used later to compile PyRIT's base2048 Rust dep). cargo has no
# "insecure" switch and, behind a MITM proxy (e.g. Aikido endpoint proxy,
# Zscaler), hard-fails with "self-signed certificate in certificate chain".
# When enabled, we capture the CA the proxy presents for a couple of stable
# hosts (keeping only the issuer chain, not the per-host leaf) and add it to the
# trust store so cargo accepts it. This deliberately trusts whatever the local
# proxy presents, so it is gated behind an explicit opt-in rather than forced on
# every user of the image.
ARG TRUST_BUILD_PROXY_CA=0
RUN if [ "$TRUST_BUILD_PROXY_CA" != "0" ] && [ "$TRUST_BUILD_PROXY_CA" != "false" ]; then \
        echo "TRUST_BUILD_PROXY_CA set — capturing local proxy CA into the trust store"; \
        apt-get update && apt-get install -y --no-install-recommends openssl \
        && rm -rf /var/lib/apt/lists/* \
        && cd /usr/local/share/ca-certificates \
        && for host in index.crates.io pypi.org; do \
             echo | openssl s_client -showcerts -servername "$host" -connect "$host":443 2>/dev/null \
             | awk -v h="$host" '/-----BEGIN CERTIFICATE-----/{n++} n>1{print > ("mitm-" h "-" n ".crt")}' || true; \
           done \
        && update-ca-certificates || true; \
    else echo "TRUST_BUILD_PROXY_CA not set — skipping proxy CA capture (normal direct build)"; fi

# ============================================================================
# DOMAIN SELECTION (composable tool bundles)
# ----------------------------------------------------------------------------
# The image is split into domains so users install only what they need. `core`
# is ALWAYS installed (the MCP server + universal recon/utility toolchain);
# every other domain is a build-arg toggle (1 = install, anything else = skip).
# Compose any combination in ONE image, e.g. a web+mobile build:
#     docker build --build-arg INSTALL_MOBILE=1 -t pentest-agent/kali-mcp ./tools/kali/
#
# Defaults: web + infra ON (the classic pentest baseline); mobile/cloud/ai are
# heavier/specialized and opt-IN. A bare `docker build ./tools/kali/` therefore
# yields a core+web+infra image. The installer prompts for domains and passes
# the matching --build-arg flags.
#
# Each domain is introduced by exactly one ARG and its layers guard on that ARG
# alone, so toggling one domain only invalidates that domain's cache (and the
# layers after it) — not the whole build.
# ============================================================================
ARG INSTALL_WEB=1
ARG INSTALL_INFRA=1
ARG INSTALL_MOBILE=0
ARG INSTALL_CLOUD=0
ARG INSTALL_AI=0

# ============================================================================
# CORE — always installed. The MCP server, python/pip, universal recon
# (nmap/naabu/httpx/nuclei/subfinder/dnsx/amass), DNS/OSINT enumeration,
# network utilities, wordlists, and the OOB callback client.
# ============================================================================

# Python + pip MUST exist before the first `pip3 install` anywhere below. The
# base kali-rolling image ships no pip, and several domains invoke pip3 — install
# it once here in core so every downstream domain can rely on it.
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    python3 python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Core network + shell tooling (nmap/ncat are used by the scan() dispatchers and
# nearly every skill; openssl backs TLS probing everywhere).
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    nmap ncat fping openssl \
    && rm -rf /var/lib/apt/lists/*

# DNS / subdomain / OSINT recon — the reconnaissance backbone shared by web,
# infra and osint workflows, so it lives in core.
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    dnsrecon dnsenum fierce dmitry dnstwist dnsmap whois bind9-dnsutils \
    theharvester nfs-common lbd \
    && rm -rf /var/lib/apt/lists/*

# Network utilities + wordlists + document/archive tools (universal helpers).
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    socat proxychains4 curl wget \
    seclists wordlists \
    unrar p7zip-full poppler-utils \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery recon suite via apt (katana ships per-domain in web).
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    naabu httpx-toolkit subfinder amass dnsx nuclei \
    && rm -rf /var/lib/apt/lists/*

# interactsh-client — out-of-band callback listener for blind SSRF / RCE / XXE /
# DNS exfil. OOB confirmation is cross-cutting (web injection AND infra blind
# RCE), so it lives in core rather than a single domain. Prebuilt binary.
RUN ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
    && apt-get update && apt-get install -y --no-install-recommends --fix-missing unzip \
    && rm -rf /var/lib/apt/lists/* \
    && INTERACTSH_VERSION=1.2.1 \
    && curl -fsSL "https://github.com/projectdiscovery/interactsh/releases/download/v${INTERACTSH_VERSION}/interactsh-client_${INTERACTSH_VERSION}_linux_${ARCH}.zip" \
        -o /tmp/interactsh.zip \
    && unzip /tmp/interactsh.zip interactsh-client -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/interactsh-client \
    && rm /tmp/interactsh.zip

# Official Kali MCP server — provides POST /api/command (and per-tool endpoints)
# on port 5000. This is what the CMD launches; mandatory in every build.
RUN apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    mcp-kali-server \
    && rm -rf /var/lib/apt/lists/*

# Decompress rockyou wordlist (needed by hydra, john, and web brute-force).
RUN gzip -d /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

# ============================================================================
# WEB (INSTALL_WEB) — web/API exploitation: scanners, fuzzers, injection
# specialists, JWT/OAuth, SSL/TLS, JS-aware crawling, deserialization gadgets.
# Skills: web-exploit, api-security, param-fuzz, business-logic, ssl-tls-audit,
# credential-audit.
# ============================================================================

# Web scanning + exploit-db + php (for running PHP exploits).
# wpscan — WordPress plugin/theme/core CVE scanner.
RUN [ "$INSTALL_WEB" = "1" ] || { echo "[web] skipped"; exit 0; }; \
    apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    nikto sqlmap whatweb wafw00f wapiti commix xsser davtest skipfish \
    zaproxy exploitdb php-cli wpscan \
    && rm -rf /var/lib/apt/lists/*

# Web fuzzing / content discovery.
RUN [ "$INSTALL_WEB" = "1" ] || { echo "[web] skipped"; exit 0; }; \
    apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    ffuf gobuster feroxbuster dirb dirsearch wfuzz \
    && rm -rf /var/lib/apt/lists/*

# SSL / TLS audit tooling.
RUN [ "$INSTALL_WEB" = "1" ] || { echo "[web] skipped"; exit 0; }; \
    apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    sslscan sslyze testssl.sh \
    && rm -rf /var/lib/apt/lists/*

# Injection specialists (prebuilt binaries; fail-soft — the sweep falls back to
# nuclei -dast / wapiti for any missing tool).
# dalfox — context-aware XSS scanner. Pinned — bump explicitly.
RUN [ "$INSTALL_WEB" = "1" ] || { echo "[web] skipped"; exit 0; }; \
    ARCH=$(uname -m) \
    && DALFOX_VERSION=3.1.2 \
    && curl -fsSL "https://github.com/hahwul/dalfox/releases/download/v${DALFOX_VERSION}/dalfox-v${DALFOX_VERSION}-linux-${ARCH}.tar.gz" -o /tmp/dalfox.tar.gz \
    && tar -xzf /tmp/dalfox.tar.gz -C /tmp/ \
    && find /tmp -type f -name dalfox -exec mv {} /usr/local/bin/dalfox \; \
    && chmod +x /usr/local/bin/dalfox \
    && rm -rf /tmp/dalfox.tar.gz /tmp/dalfox-* || true

# nosqli — NoSQL injection scanner (Charlie-belmer). Only x86_64 prebuilt exists;
# on arm64 it's skipped and the sweep falls back to nuclei -dast for nosqli.
RUN [ "$INSTALL_WEB" = "1" ] || { echo "[web] skipped"; exit 0; }; \
    ARCH=$(uname -m) \
    && if [ "$ARCH" = "x86_64" ]; then \
         curl -fsSL "https://github.com/Charlie-belmer/nosqli/releases/download/v0.5.4/nosqli_linux_x64_v0.5.4" -o /usr/local/bin/nosqli \
         && chmod +x /usr/local/bin/nosqli; \
       else echo "nosqli: no ${ARCH} prebuilt — skipped (sweep uses nuclei -dast for nosqli)"; fi || true

# SSTImap — multi-engine SSTI detect+exploit (maintained Python3 fork of tplmap).
# Wrapper is created right after clone (independent of the requirements install)
# so `sstimap` is runnable even if a single dep fails.
RUN [ "$INSTALL_WEB" = "1" ] || { echo "[web] skipped"; exit 0; }; \
    git clone --depth=1 https://github.com/vladko312/SSTImap /opt/SSTImap || true; \
    if [ -d /opt/SSTImap ]; then \
        printf '#!/bin/sh\nexec python3 /opt/SSTImap/sstimap.py "$@"\n' > /usr/local/bin/sstimap \
        && chmod +x /usr/local/bin/sstimap; \
        pip3 install --no-cache-dir -r /opt/SSTImap/requirements.txt --break-system-packages || true; \
    fi

# arjun (HTTP param discovery) is on PyPI. graphql-cop and graphw00f (GraphQL
# fingerprint, introspection, batching tests) are NOT — `pip install` on those
# names returns "No matching distribution found" on every platform; they are
# run-from-source tools, so clone them and drop PATH wrappers.
RUN [ "$INSTALL_WEB" = "1" ] || { echo "[web] skipped"; exit 0; }; \
    pip3 install --no-cache-dir arjun --break-system-packages || echo "WARN: pip install arjun failed (continuing)"
RUN [ "$INSTALL_WEB" = "1" ] || { echo "[web] skipped"; exit 0; }; \
    git clone --depth=1 https://github.com/dolevf/graphql-cop /opt/graphql-cop || true; \
    if [ -f /opt/graphql-cop/graphql-cop.py ]; then \
        printf '#!/bin/sh\nexec python3 /opt/graphql-cop/graphql-cop.py "$@"\n' > /usr/local/bin/graphql-cop \
        && chmod +x /usr/local/bin/graphql-cop; \
        pip3 install --no-cache-dir -r /opt/graphql-cop/requirements.txt --break-system-packages || true; \
    else echo "WARN: graphql-cop clone failed (continuing)"; fi
RUN [ "$INSTALL_WEB" = "1" ] || { echo "[web] skipped"; exit 0; }; \
    git clone --depth=1 https://github.com/dolevf/graphw00f /opt/graphw00f || true; \
    if [ -f /opt/graphw00f/main.py ]; then \
        printf '#!/bin/sh\nexec python3 /opt/graphw00f/main.py "$@"\n' > /usr/local/bin/graphw00f \
        && chmod +x /usr/local/bin/graphw00f; \
        pip3 install --no-cache-dir -r /opt/graphw00f/requirements.txt --break-system-packages || true; \
    else echo "WARN: graphw00f clone failed (continuing)"; fi

# jwt_tool — JWT attack toolkit (none alg, alg confusion, kid injection, key brute)
# KOAuth   — automated OAuth 2.0 security scanner (built from source with golang,
#            which is installed then purged to keep the layer small).
RUN [ "$INSTALL_WEB" = "1" ] || { echo "[web] skipped"; exit 0; }; \
    (git clone --depth=1 https://github.com/ticarpi/jwt_tool /opt/jwt_tool \
        && pip3 install --no-cache-dir pycryptodomex termcolor cprint requests --break-system-packages \
        && printf '#!/bin/sh\nexec python3 /opt/jwt_tool/jwt_tool.py "$@"\n' > /usr/local/bin/jwt_tool \
        && chmod +x /usr/local/bin/jwt_tool) || true \
    && apt-get update && apt-get install -y --no-install-recommends golang-go unzip \
    && rm -rf /var/lib/apt/lists/* \
    && git clone --depth=1 https://github.com/morganc3/KOAuth /opt/KOAuth \
    && cd /opt/KOAuth && go build -o /usr/local/bin/KOAuth . \
    && apt-get purge -y golang-go && apt-get autoremove -y

# katana — JS-aware web crawler (prebuilt release; supports amd64 + arm64).
# Pinned to v1.5.0 — update explicitly when needed.
RUN [ "$INSTALL_WEB" = "1" ] || { echo "[web] skipped"; exit 0; }; \
    ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
    && KATANA_VERSION=1.5.0 \
    && curl -fsSL "https://github.com/projectdiscovery/katana/releases/download/v${KATANA_VERSION}/katana_${KATANA_VERSION}_linux_${ARCH}.zip" \
        -o /tmp/katana.zip \
    && unzip /tmp/katana.zip katana -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/katana \
    && rm /tmp/katana.zip

# Web spider: Playwright + headless Chromium for JavaScript-aware crawling
# (required for Hotwire/Turbo Frame apps where katana misses lazy-loaded content).
# Pinned to 1.59.0 — update explicitly when needed.
RUN [ "$INSTALL_WEB" = "1" ] || { echo "[web] skipped"; exit 0; }; \
    pip3 install --no-cache-dir playwright==1.59.0 --break-system-packages \
    && playwright install chromium --with-deps

# phpggc — PHP deserialization gadget-chain generator (Laravel, Symfony, Twig,
# Monolog, Guzzle, ...). Used for exploiting PHP unserialize / phar:// sinks.
RUN [ "$INSTALL_WEB" = "1" ] || { echo "[web] skipped"; exit 0; }; \
    git clone --depth=1 https://github.com/ambionics/phpggc /opt/phpggc \
    && ln -s /opt/phpggc/phpggc /usr/local/bin/phpggc

COPY playwright_spider.py /usr/local/bin/playwright-spider
RUN chmod +x /usr/local/bin/playwright-spider
# COPY can't be ARG-guarded, so drop the wrapper if web (its playwright runtime) isn't installed.
RUN [ "$INSTALL_WEB" = "1" ] || rm -f /usr/local/bin/playwright-spider

# ============================================================================
# INFRA (INSTALL_INFRA) — internal network, Active Directory, credentials,
# service enumeration, cross-compilation, and pivoting.
# Skills: network-assess, ad-assessment, lateral-movement, post-exploit,
# credential-audit.
# ============================================================================

# Internal-network scanning / packet tooling.
RUN [ "$INSTALL_INFRA" = "1" ] || { echo "[infra] skipped"; exit 0; }; \
    apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    masscan hping3 arp-scan nbtscan tcpdump tshark \
    && rm -rf /var/lib/apt/lists/*

# Credential testing.
RUN [ "$INSTALL_INFRA" = "1" ] || { echo "[infra] skipped"; exit 0; }; \
    apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    hydra ncrack john cewl crunch medusa \
    && rm -rf /var/lib/apt/lists/*

# SMB / Windows / AD. rpcclient is bundled inside smbclient.
# certipy-ad — ADCS enumeration/exploitation (ESC1-ESC8); bloodhound.py — AD
# attack-path ingestor. Installed from apt (not pip) to avoid the dnspython
# uninstall-no-record-file conflict that used to abort the build.
RUN [ "$INSTALL_INFRA" = "1" ] || { echo "[infra] skipped"; exit 0; }; \
    apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    smbmap smbclient samba-common-bin impacket-scripts \
    enum4linux-ng netexec ldap-utils \
    certipy-ad bloodhound.py python3-ldapdomaindump \
    && rm -rf /var/lib/apt/lists/*

# Service enumeration. snmpwalk is bundled in the snmp package.
# default-mysql-client — MySQL/MariaDB CLI for DB enumeration.
RUN [ "$INSTALL_INFRA" = "1" ] || { echo "[infra] skipped"; exit 0; }; \
    apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    ssh-audit redis-tools snmp onesixtyone swaks \
    smtp-user-enum ike-scan finger rpcbind \
    default-mysql-client \
    && rm -rf /var/lib/apt/lists/*

# Cross-compilation for exploit builds. gcc-mingw-w64 — Windows EXE/DLL from Kali.
RUN [ "$INSTALL_INFRA" = "1" ] || { echo "[infra] skipped"; exit 0; }; \
    apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    gcc gcc-mingw-w64 \
    && rm -rf /var/lib/apt/lists/*

# Optional: gcc-multilib (amd64 only) + freerdp (xfreerdp for RDP).
RUN [ "$INSTALL_INFRA" = "1" ] || { echo "[infra] skipped"; exit 0; }; \
    apt-get update \
    && apt-get install -y --no-install-recommends --fix-missing gcc-multilib 2>/dev/null || true \
    && apt-get install -y --no-install-recommends --fix-missing freerdp2-x11 2>/dev/null \
    || apt-get install -y --no-install-recommends --fix-missing xfreerdp 2>/dev/null || true \
    && rm -rf /var/lib/apt/lists/*

# Pivoting — ligolo-ng (TUN-based, primary) + chisel (HTTP/WS, fallback).
# Pinned to v0.8.2 / v1.10.1 — update explicitly when needed.
RUN [ "$INSTALL_INFRA" = "1" ] || { echo "[infra] skipped"; exit 0; }; \
    ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
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
    && CHISEL_VERSION=1.10.1 \
    && curl -fsSL "https://github.com/jpillora/chisel/releases/download/v${CHISEL_VERSION}/chisel_${CHISEL_VERSION}_linux_${ARCH}.gz" \
        -o /tmp/chisel.gz \
    && gunzip /tmp/chisel.gz \
    && mv /tmp/chisel /usr/local/bin/chisel \
    && chmod +x /usr/local/bin/chisel \
    && rm -f /tmp/ligolo-proxy.tar.gz /tmp/ligolo-agent.tar.gz

# ============================================================================
# MOBILE (INSTALL_MOBILE) — Android/iOS app reversing + dynamic instrumentation.
# Skills: android-security, ios-security. (MobSF runs as a separate container.)
# ============================================================================

# APK reversing/repackaging (apktool, dex2jar, jadx, apksigner, zipalign) + adb.
# adb/frida connect OUT to an operator-provided emulator/device over the network
# (adb connect <ip>:5555) — the android-dynamic setup gate confirms it's live.
RUN [ "$INSTALL_MOBILE" = "1" ] || { echo "[mobile] skipped"; exit 0; }; \
    apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    apktool dex2jar jadx apksigner zipalign adb fastboot \
    && rm -rf /var/lib/apt/lists/* || true

# Frida + objection for runtime hooking: SSL-pinning bypass, keystore/keychain
# dumps, runtime storage/heap inspection. The operator must push a frida-server
# whose version MATCHES this frida-tools pin to the device/emulator.
# --ignore-installed: objection pulls a newer `tabulate` than the apt-managed
# one, and pip cannot uninstall the apt copy (no RECORD file). Ignoring
# already-installed deps installs cleanly on top instead of aborting.
RUN [ "$INSTALL_MOBILE" = "1" ] || { echo "[mobile] skipped"; exit 0; }; \
    pip3 install --no-cache-dir --break-system-packages --ignore-installed \
    frida-tools==12.5.1 objection==1.11.0 || true

# ============================================================================
# CLOUD (INSTALL_CLOUD) — cloud posture + container/K8s security.
# Skills: cloud-security, container-k8s-security.
# ============================================================================

# Container & K8s: trivy (image vuln scan) + kubectl.
RUN [ "$INSTALL_CLOUD" = "1" ] || { echo "[cloud] skipped"; exit 0; }; \
    apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    trivy kubectl \
    && rm -rf /var/lib/apt/lists/*

# kube-bench (CIS K8s benchmark) from GitHub release. Pinned v0.15.0.
RUN [ "$INSTALL_CLOUD" = "1" ] || { echo "[cloud] skipped"; exit 0; }; \
    ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
    && KB_VERSION=0.15.0 \
    && curl -fsSL "https://github.com/aquasecurity/kube-bench/releases/download/v${KB_VERSION}/kube-bench_${KB_VERSION}_linux_${ARCH}.tar.gz" \
        -o /tmp/kube-bench.tar.gz \
    && tar -xzf /tmp/kube-bench.tar.gz -C /usr/local/bin/ kube-bench \
    && chmod +x /usr/local/bin/kube-bench \
    && rm /tmp/kube-bench.tar.gz

# dive (Docker image layer explorer) from GitHub release. Pinned v0.13.1.
RUN [ "$INSTALL_CLOUD" = "1" ] || { echo "[cloud] skipped"; exit 0; }; \
    ARCH=$(uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/') \
    && DIVE_VERSION=0.13.1 \
    && curl -fsSL "https://github.com/wagoodman/dive/releases/download/v${DIVE_VERSION}/dive_${DIVE_VERSION}_linux_${ARCH}.tar.gz" \
        -o /tmp/dive.tar.gz \
    && tar -xzf /tmp/dive.tar.gz -C /usr/local/bin/ dive \
    && chmod +x /usr/local/bin/dive \
    && rm /tmp/dive.tar.gz

# AWS CLI (via pip — kali apt awscli is often outdated).
RUN [ "$INSTALL_CLOUD" = "1" ] || { echo "[cloud] skipped"; exit 0; }; \
    pip3 install --no-cache-dir awscli==1.44.63 --break-system-packages || true

# Azure CLI.
RUN [ "$INSTALL_CLOUD" = "1" ] || { echo "[cloud] skipped"; exit 0; }; \
    apt-get update && apt-get install -y --no-install-recommends --fix-missing \
    ca-certificates curl apt-transport-https lsb-release gnupg \
    && curl -sL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > /etc/apt/keyrings/microsoft.gpg \
    && echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ $(lsb_release -cs) main" > /etc/apt/sources.list.d/azure-cli.list \
    && apt-get update && apt-get install -y --no-install-recommends --fix-missing azure-cli \
    && rm -rf /var/lib/apt/lists/* || true

# GCP CLI.
RUN [ "$INSTALL_CLOUD" = "1" ] || { echo "[cloud] skipped"; exit 0; }; \
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" > /etc/apt/sources.list.d/google-cloud-sdk.list \
    && curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
    && apt-get update && apt-get install -y --no-install-recommends --fix-missing google-cloud-cli \
    && rm -rf /var/lib/apt/lists/* || true

# Prowler (AWS/Azure/GCP auditor) + ScoutSuite (multi-cloud auditor), each under
# `|| true` so one uninstallable pin can't take down the other. prowler 5.31.0 is
# the first Python-3.13-compatible release; scoutsuite stays fail-soft.
RUN [ "$INSTALL_CLOUD" = "1" ] || { echo "[cloud] skipped"; exit 0; }; \
    pip3 install --no-cache-dir prowler==5.31.0 --break-system-packages || true
RUN [ "$INSTALL_CLOUD" = "1" ] || { echo "[cloud] skipped"; exit 0; }; \
    pip3 install --no-cache-dir scoutsuite==5.14.0 --break-system-packages || true

# ============================================================================
# AI (INSTALL_AI) — LLM/agent red-teaming. Skill: ai-redteam.
# The heaviest domain (torch/CUDA deps), hence opt-in. FuzzyAI runs as a
# separate container (ghcr.io/cyberark/fuzzyai); see tools/fuzzyai.py.
# ============================================================================

# Microsoft PyRIT + thin CLI runner. base2048 (a PyRIT dep) compiles Rust, so
# rustc/cargo are installed then purged. NOTE: behind a TLS-intercepting proxy,
# cargo needs the CA — build with --build-arg TRUST_BUILD_PROXY_CA=1.
RUN [ "$INSTALL_AI" = "1" ] || { echo "[ai] skipped"; exit 0; }; \
    apt-get update && apt-get install -y --no-install-recommends --fix-missing rustc cargo \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir --ignore-installed pyrit==0.11.0 --break-system-packages \
    && apt-get purge -y rustc cargo \
    && apt-get autoremove -y \
    && rm -rf /root/.cargo /root/.rustup
COPY pyrit_runner.py /usr/local/bin/pyrit-runner
RUN chmod +x /usr/local/bin/pyrit-runner
# COPY can't be ARG-guarded, so drop the wrapper if the ai module (PyRIT) isn't installed.
RUN [ "$INSTALL_AI" = "1" ] || rm -f /usr/local/bin/pyrit-runner

# NVIDIA Garak — LLM vulnerability scanner (probe-based). Installed in a venv
# (--system-site-packages) to avoid conflicts with Debian-managed packages.
RUN [ "$INSTALL_AI" = "1" ] || { echo "[ai] skipped"; exit 0; }; \
    apt-get update && apt-get install -y --no-install-recommends --fix-missing python3-venv \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/garak-venv --system-site-packages \
    && /opt/garak-venv/bin/pip install --no-cache-dir garak==0.15.0 \
    && ln -sf /opt/garak-venv/bin/garak /usr/local/bin/garak

# promptfoo — LLM eval + red-team framework (npm).
RUN [ "$INSTALL_AI" = "1" ] || { echo "[ai] skipped"; exit 0; }; \
    apt-get update && apt-get install -y --no-install-recommends --fix-missing nodejs npm \
    && rm -rf /var/lib/apt/lists/* \
    && npm config set strict-ssl false \
    && npm install -g promptfoo@0.121.2

# Bound curl by DEFAULT so a hung request can never silently block a tool call for
# minutes — a working injection payload (time-based-blind, SSRF-connect) routinely stalls
# the response, and without a cap curl waits ~300s. The agent can still override --max-time
# for deliberate time-based tests. (kali_runner also seeds this at container start, so it
# applies even before a rebuild.)
RUN printf 'connect-timeout = 5\nmax-time = 30\n' > /root/.curlrc

EXPOSE 5000

# kali-server-mcp is the Flask API component of mcp-kali-server.
# The MCP client bridge (mcp-server) is not needed — we call the HTTP API directly.
CMD ["kali-server-mcp", "--ip", "0.0.0.0"]
