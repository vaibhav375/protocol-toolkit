"""Prove that exported captures open and decrypt in Wireshark's tshark.

Runs real requests (HTTP/2 over TLS, HTTP/3 over QUIC, DNS over UDP), exports each as
pcapng with the embedded TLS keys, and asks tshark to decode the application layer.
Exits non-zero if tshark can't see the decrypted traffic.
"""
import os
import subprocess
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from protocol_toolkit.dnsclient import DNSClient  # noqa: E402
from protocol_toolkit.httpclient import HTTPClient  # noqa: E402
from protocol_toolkit.pcap import to_pcapng  # noqa: E402
from protocol_toolkit.wire import WireLog  # noqa: E402


def tshark(path: str, display_filter: str, fields: list) -> list:
    cmd = ["tshark", "-r", path, "-Y", display_filter, "-T", "fields"] + sum((["-e", f] for f in fields), [])
    out = subprocess.run(cmd, capture_output=True, text=True, check=True).stdout
    return [line for line in out.splitlines() if line.strip()]


def check(name: str, wire: WireLog, display_filter: str, fields: list, expect: str) -> bool:
    path = os.path.join(tempfile.mkdtemp(), f"{name}.pcapng")
    with open(path, "wb") as fh:
        fh.write(to_pcapng(wire))
    rows = tshark(path, display_filter, fields)
    ok = any(expect in row for row in rows)
    print(f"{'PASS' if ok else 'FAIL'}  {name}: {len(rows)} matching packets; looking for {expect!r}")
    for row in rows[:3]:
        print("      ", row[:140])
    return ok


def main() -> int:
    client = HTTPClient()
    results = [
        check("http2-over-tls", client.send("https://www.google.com/", http_version="2").wire,
              "http2.type == 1", ["http2.header.name", "http2.header.value"], ":status"),
        check("http11-over-tls", client.send("https://example.com/", http_version="1.1").wire,
              "http.response", ["http.response.code"], "200"),
        check("dns-over-udp", _dns_wire(), "dns.flags.response == 1", ["dns.qry.name"], "example.com"),
    ]
    try:
        h3 = client.send("https://www.cloudflare.com/cdn-cgi/trace", http_version="3", follow_redirects=False).wire
        results.append(check("http3-over-quic", h3, "http3", ["http3.frame_type"], "1"))
    except OSError as e:  # UDP 443 can be blocked on some networks; report but don't hide it
        print(f"SKIP  http3-over-quic: {e}")
    return 0 if all(results) else 1


def _dns_wire() -> WireLog:
    wire = WireLog("dns")
    DNSClient().query("example.com", "A", "8.8.8.8", "UDP", wire=wire)
    return wire


if __name__ == "__main__":
    sys.exit(main())
