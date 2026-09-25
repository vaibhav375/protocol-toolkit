import pytest

from protocol_toolkit import http3
from protocol_toolkit.httpclient import HTTPClient
from protocol_toolkit.net import ConnectionError_


def test_quic_long_header_is_labelled():
    # Initial packet: form+fixed bits, type Initial, version 1, DCID 8 bytes, SCID 0, token 0, length 5
    packet = bytes([0xC3]) + (1).to_bytes(4, "big") + bytes([8]) + b"\x11" * 8 + bytes([0]) + bytes([0]) + bytes([5]) + b"\x00" * 5
    summary, fields = http3.annotate_quic(packet + b"\x00" * 20)  # followed by datagram padding
    labels = {f.label: f.value for f in fields}
    assert summary == "Initial"
    assert labels["Version"] == "QUIC v1" and labels["Destination connection ID"] == "11" * 8
    assert labels["Padding"] == "20 bytes"


def test_quic_short_header():
    summary, _ = http3.annotate_quic(bytes([0x40]) + b"\x22" * 30)
    assert summary == "1-RTT"


def test_http3_needs_https():
    with pytest.raises(ConnectionError_, match="https"):
        HTTPClient().send("http://example.com/", http_version="3")


@pytest.mark.network
@pytest.mark.skipif(not http3.AIOQUIC_AVAILABLE, reason="aioquic not installed")
def test_live_http3():
    r = HTTPClient().send("https://www.cloudflare.com/cdn-cgi/trace", http_version="3", follow_redirects=False)
    assert r.http_version == "HTTP/3" and r.status_code == 200 and b"http=http/3" in r.body
    assert any(e.layer == "QUIC" and e.summary.startswith("Initial") for e in r.wire.events)
    assert r.wire.keylog and list(r.wire.flows.values())[0].proto == "udp"
