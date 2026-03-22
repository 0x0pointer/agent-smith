FROM metasploitframework/metasploit-framework:latest

USER root

# Install Python + Flask for the command API server
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip \
    && rm -rf /var/lib/apt/lists/* \
    && pip3 install --no-cache-dir flask --break-system-packages

# Command API server — same pattern as kali-server-mcp
COPY server.py /opt/server.py

EXPOSE 5000

# Start the Flask API server (msfconsole is invoked per-command)
CMD ["python3", "/opt/server.py"]
