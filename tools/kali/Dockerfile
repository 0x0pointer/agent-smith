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

# Layer 3: web scanning
RUN apt-get update && apt-get install -y --no-install-recommends \
    nikto sqlmap whatweb wafw00f wapiti commix xsser davtest skipfish \
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

# Layer 10: network utilities + wordlists
RUN apt-get update && apt-get install -y --no-install-recommends \
    socat proxychains4 curl wget \
    seclists wordlists \
    && rm -rf /var/lib/apt/lists/*

# ProjectDiscovery tools via apt (katana not in arm64 repo — installed via Go below)
RUN apt-get update && apt-get install -y --no-install-recommends \
    naabu httpx-toolkit subfinder amass dnsx nuclei golang-go \
    && rm -rf /var/lib/apt/lists/* \
    && go install github.com/projectdiscovery/katana/cmd/katana@latest \
    && mv /root/go/bin/katana /usr/local/bin/katana 2>/dev/null || true

# Official Kali MCP server — provides POST /api/command (and per-tool endpoints)
# on port 5000. Replaces our hand-rolled server.py.
RUN apt-get update && apt-get install -y --no-install-recommends \
    mcp-kali-server \
    && rm -rf /var/lib/apt/lists/*

# Decompress rockyou wordlist (needed by hydra, john, etc.)
RUN gzip -d /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true

EXPOSE 5000

# kali-server-mcp is the Flask API component of mcp-kali-server.
# The MCP client bridge (mcp-server) is not needed — we call the HTTP API directly.
CMD ["kali-server-mcp", "--ip", "0.0.0.0"]
