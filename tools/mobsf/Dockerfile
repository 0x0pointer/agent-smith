# MobSF — Mobile Security Framework (static analysis of APK / IPA / APPX / source).
# Thin wrapper over the official image so we get a stable local tag
# (pentest-agent/mobsf) alongside the other custom images (kali-mcp, metasploit).
#
# The base image already starts the Django app on port 8000. tools/mobsf_runner.py
# injects the API key at run time via `-e MOBSF_API_KEY=` and sends it as the
# Authorization header on every REST call, so nothing else is needed here.
#
# Pinned to v4.4.6 — update explicitly when bumping (and CVE-scan the new tag;
# MobSF processes hostile attacker-authored binaries, so keep it current).
FROM opensecurity/mobile-security-framework-mobsf:v4.4.6

EXPOSE 8000
