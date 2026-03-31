FROM metasploitframework/metasploit-framework@sha256:ba9ecc0172052ea687adb3b3e6356b24dba4497d1bf73a6de0e201f1e25e9777

# Install Python + Flask for the command API server
# The msf image runs as uid 1000 — use --user flag instead of USER directive
RUN apk add --no-cache python3 py3-pip \
    && pip3 install --no-cache-dir flask==3.0.2 --break-system-packages

# Command API server — same pattern as kali-server-mcp
COPY server.py /opt/server.py

EXPOSE 5000

# Start the Flask API server (msfconsole is invoked per-command)
CMD ["python3", "/opt/server.py"]
