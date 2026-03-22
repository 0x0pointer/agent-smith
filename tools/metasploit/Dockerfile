FROM metasploitframework/metasploit-framework:latest

# Install Python + Flask for the command API server
# The msf image runs as uid 1000 — use --user flag instead of USER directive
RUN apk add --no-cache python3 py3-pip \
    && pip3 install --no-cache-dir flask --break-system-packages

# Command API server — same pattern as kali-server-mcp
COPY server.py /opt/server.py

EXPOSE 5000

# Start the Flask API server (msfconsole is invoked per-command)
CMD ["python3", "/opt/server.py"]
