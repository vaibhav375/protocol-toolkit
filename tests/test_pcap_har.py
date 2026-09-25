import ipaddress
import json
import struct

import pytest

from protocol_toolkit.har import to_har
from protocol_toolkit.httpclient import HTTPClient
from protocol_toolkit.pcap import _checksum, read_pcapng, to_pcapng
from protocol_toolkit.wire import WireLog


def parse_ip(packet: bytes):
    """Return (version, src, dst, proto, transport bytes) and check the IPv4 header checksum"""
    version = packet[0] >> 4
    if version == 4:
        ihl = (packet[0] & 0x0F) * 4
        assert _checksum(packet[:ihl]) == 0, "bad IPv4 header checksum"
        return 4, str(ipaddress.ip_address(packet[12:16])), str(ipaddress.ip_address(packet[16:20])), packet[9], packet[ihl:]
    return 6, str(ipaddress.ip_address(packet[8:24])), str(ipaddress.ip_address(packet[24:40])), packet[6], packet[40:]


def transport_ok(src, dst, proto, seg) -> bool:
    s, d = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    if s.version == 4:
        pseudo = s.packed + d.packed + struct.pack("!BBH", 0, proto, len(seg))
    else:
        pseudo = s.packed + d.packed + struct.pack("!IxxxB", len(seg), proto)
    return _checksum(pseudo + seg) in (0, 0xFFFF)


def sample_wire() -> WireLog:
    w = WireLog("sample")
    tcp = w.open_flow("tcp", ("192.0.2.10", 50000), ("198.51.100.7", 443))
    w.segment(tcp, "out", b"\x16\x03\x01" + b"A" * 3000)   # bigger than one MSS: must be split
    w.segment(tcp, "in", b"\x16\x03\x03" + b"B" * 100)
    w.close_flow(tcp)
    udp = w.open_flow("udp", ("2001:db8::1", 53000), ("2001:db8::53", 53))
    w.segment(udp, "out", b"query")
    w.segment(udp, "in", b"answer")
    w.add_keylog(["CLIENT_TRAFFIC_SECRET_0 aa bb", "# comment", "CLIENT_TRAFFIC_SECRET_0 aa bb"])
    return w


def test_pcapng_structure_checksums_and_reassembly():
    parsed = read_pcapng(to_pcapng(sample_wire()))
    assert parsed["linktype"] == 101
    assert parsed["secrets"] == b"CLIENT_TRAFFIC_SECRET_0 aa bb\n"  # comments and duplicates dropped
    tcp_out, tcp_in, flags, udp = b"", b"", [], []
    for _, packet in parsed["packets"]:
        version, src, dst, proto, seg = parse_ip(packet)
        assert transport_ok(src, dst, proto, seg), "bad TCP/UDP checksum"
        if proto == 6:
            sport, dport, seq, ack, off, fl = struct.unpack("!HHIIBB", seg[:14])
            payload = seg[(off >> 4) * 4:]
            flags.append(fl)
            if sport == 50000:
                tcp_out += payload
            else:
                tcp_in += payload
        else:
            assert version == 6
            udp.append(seg[8:])
    assert tcp_out == b"\x16\x03\x01" + b"A" * 3000 and tcp_in == b"\x16\x03\x03" + b"B" * 100
    assert flags[:3] == [0x02, 0x12, 0x10]  # SYN, SYN-ACK, ACK
    assert flags[-3:] == [0x11, 0x11, 0x10]  # FIN-ACK both ways, final ACK
    assert udp == [b"query", b"answer"]


def test_pcapng_without_keys():
    assert read_pcapng(to_pcapng(sample_wire(), include_keys=False))["secrets"] == b""


def test_wirelog_round_trips_through_json():
    w = sample_wire()
    w.add("out", "HTTP/1.1", b"GET / HTTP/1.1\r\n\r\n", "GET /")
    with w.phase("TCP connect"):
        pass
    w.meta["x"] = 1
    back = WireLog.from_dict(json.loads(json.dumps(w.to_dict())))
    assert to_pcapng(back) == to_pcapng(w)
    assert back.events[0].data == b"GET / HTTP/1.1\r\n\r\n" and back.phases[0].name == "TCP connect"
    assert back.meta == {"x": 1}


def read_request(h):
    lines = []
    while True:
        line = h.rfile.readline()
        if line in (b"\r\n", b""):
            break
        lines.append(line.decode().rstrip("\r\n"))
    headers = dict(l.split(": ", 1) for l in lines[1:])
    return lines[0], headers, h.rfile.read(int(headers.get("Content-Length", 0)))


def test_har_for_a_redirect_chain(tcp_server):
    def handle(h):
        line, _, _ = read_request(h)
        if line.startswith("POST /login"):
            h.wfile.write(b"HTTP/1.1 302 Found\r\nLocation: /home?x=1\r\nSet-Cookie: sid=secret\r\nContent-Length: 0\r\n\r\n")
        else:
            h.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello")

    server = tcp_server(handle)
    r = HTTPClient().send(server.url + "/login", "POST", {"Content-Type": "text/plain", "Authorization": "Bearer abc"}, "user=me")
    har = json.loads(to_har(r.wire))
    first, second = har["log"]["entries"]
    assert har["log"]["version"] == "1.2"
    assert first["request"]["method"] == "POST" and first["request"]["postData"]["text"] == "user=me"
    assert first["response"]["status"] == 302 and first["response"]["redirectURL"] == "/home?x=1"
    assert second["request"]["queryString"] == [{"name": "x", "value": "1"}]
    assert second["response"]["content"]["text"] == "hello"
    assert {"name": "Authorization", "value": "[redacted]"} in first["request"]["headers"]
    assert {"name": "Set-Cookie", "value": "[redacted]"} in first["response"]["headers"]
    assert all(v >= 0 or v == -1 for v in second["timings"].values())
    raw = json.loads(to_har(r.wire, sanitize=False))
    assert {"name": "Set-Cookie", "value": "sid=secret"} in raw["log"]["entries"][0]["response"]["headers"]


def test_binary_bodies_are_base64_in_har(tcp_server):
    def handle(h):
        read_request(h)
        h.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Type: image/png\r\nContent-Length: 4\r\n\r\n\x89PNG")

    content = json.loads(to_har(HTTPClient().send(tcp_server(handle).url).wire))["log"]["entries"][0]["response"]["content"]
    assert content["encoding"] == "base64" and content["text"] == "iVBORw=="


@pytest.mark.network
def test_live_https_pcap_has_tls_and_keys():
    r = HTTPClient().send("https://example.com/", http_version="1.1")
    parsed = read_pcapng(to_pcapng(r.wire))
    assert b"CLIENT_TRAFFIC_SECRET_0" in parsed["secrets"]
    payloads = [parse_ip(p)[4][20:] for _, p in parsed["packets"] if parse_ip(p)[3] == 6]
    assert any(p.startswith(b"\x16\x03") for p in payloads)  # a TLS handshake record
