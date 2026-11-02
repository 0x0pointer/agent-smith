"""IMPROVEMENT-PLAN 1.3 — lean tunnel v1: a proxychains wrap on kali().

The agent stands up a SOCKS endpoint through a foothold (chisel / ligolo-ng / ssh -D /
msf socks_proxy), then passes proxy= so a scanner reaches cluster-internal hosts Kali can't
route to directly. These unit-test the pure command-building; the container round-trip is not
exercised here.
"""
import shlex

from tools import kali_runner


def test_parse_proxy_forms():
    assert kali_runner._parse_proxy("socks5://10.0.0.1:1080") == ("socks5", "10.0.0.1", 1080)
    assert kali_runner._parse_proxy("socks4://h:9050") == ("socks4", "h", 9050)
    assert kali_runner._parse_proxy("127.0.0.1:1080") == ("socks5", "127.0.0.1", 1080)  # bare → socks5
    assert kali_runner._parse_proxy("127.0.0.1") == ("socks5", "127.0.0.1", 1080)       # default port
    assert kali_runner._parse_proxy("h:not-a-port") == ("socks5", "h", 1080)            # bad port → default
    assert kali_runner._parse_proxy("") == ("socks5", "127.0.0.1", 1080)


def test_wrap_builds_runnable_proxychains_command():
    cmd = kali_runner._wrap_proxychains("nmap -sT -Pn 10.150.0.158", "socks5://127.0.0.1:1080")
    assert "proxychains4 -f" in cmd
    assert "nmap -sT -Pn 10.150.0.158" in cmd
    assert "socks5 127.0.0.1 1080" in cmd        # the proxy line lands in the generated config
    assert "mktemp" in cmd and "rm -f" in cmd     # throwaway config, cleaned up
    assert "exit $_rc" in cmd                     # preserves the wrapped command's exit status


def test_wrap_does_not_rewrite_loopback_through_tunnel():
    """A proxied command's loopback SOCKS listener must survive — exec_command skips the
    host-rewrite when proxy is set, and the wrap itself references 127.0.0.1 verbatim."""
    cmd = kali_runner._wrap_proxychains("curl http://10.1.1.1/", "127.0.0.1:1080")
    assert "127.0.0.1 1080" in cmd
    assert "host.docker.internal" not in cmd      # NOT rewritten


def test_syn_scan_warning_documented():
    # The -sT (connect) vs -sS (SYN) caveat must be surfaced where the wrap is built.
    doc = kali_runner._wrap_proxychains.__doc__ or ""
    assert "-sT" in doc and "-sS" in doc
