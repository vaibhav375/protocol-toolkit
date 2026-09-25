import socket
import struct
import threading

import pytest

from protocol_toolkit.dnsclient import (DNSClient, DNSPacket, decode_name, encode_name, reverse_name,
                                        validate_domain)
from protocol_toolkit.wire import WireLog

from conftest import free_port


def build_response(query: bytes, answers: list, flags: int = 0x8180) -> bytes:
    """answers: list of (type, rdata) for the question name (compressed pointer to offset 12)"""
    qid = query[:2]
    question_end = query.index(b"\x00", 12) + 5
    out = qid + struct.pack("!HHHHH", flags, 1, len(answers), 0, 0) + query[12:question_end]
    for rtype, rdata in answers:
        out += b"\xc0\x0c" + struct.pack("!HHIH", rtype, 1, 300, len(rdata)) + rdata
    return out


def test_query_encoding_with_edns():
    packet = DNSPacket.query("example.com", 1)
    data = packet.to_bytes()
    assert data[12:25] == b"\x07example\x03com\x00"
    assert data[4:12] == b"\x00\x01\x00\x00\x00\x00\x00\x01"  # 1 question, 1 additional (OPT)
    assert data.endswith(b"\x00\x00\x29\x04\xd0\x00\x00\x00\x00\x00\x00")  # OPT, UDP size 1232


def test_parse_answers_with_compression_and_fields():
    query = DNSPacket.query("example.com", 16, edns=False).to_bytes()
    txt = b"\x05hello\x06 world"  # two strings, joined
    resp = DNSPacket.from_bytes(build_response(query, [(16, txt), (28, bytes(15) + b"\x01"), (1, b"\x7f\x00\x00\x01")]))
    assert [r.value for r in resp.answers] == ["hello world", "::1", "127.0.0.1"]
    assert resp.answers[0].name == "example.com"
    assert any(f.label == "Answer" for f in resp.fields)
    assert resp.rcode_name == "NOERROR"


def test_compression_loop_is_rejected():
    data = bytearray(12) + b"\xc0\x0c"
    with pytest.raises(ValueError, match="loop"):
        decode_name(bytes(data), 12)


def test_names_and_reverse_lookups():
    assert encode_name("a.b.") == b"\x01a\x01b\x00"
    assert reverse_name("8.8.4.4") == "4.4.8.8.in-addr.arpa"
    assert reverse_name("::1").endswith(".0.ip6.arpa") and reverse_name("::1").startswith("1.0.0")
    assert validate_domain("_dmarc.Example.com.") == "_dmarc.Example.com"
    assert validate_domain("bücher.de") == "xn--bcher-kva.de"
    with pytest.raises(ValueError):
        validate_domain("bad..name")


def test_udp_truncation_falls_back_to_tcp():
    """A local server answers UDP with TC set and the full answer over TCP"""
    port = free_port()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", port))
    tcp = socket.socket()
    tcp.bind(("127.0.0.1", port))
    tcp.listen()

    def serve_udp():
        data, addr = udp.recvfrom(512)
        udp.sendto(build_response(data, [], flags=0x8380), addr)  # QR RD RA + TC

    def serve_tcp():
        conn, _ = tcp.accept()
        with conn:
            length = struct.unpack("!H", conn.recv(2))[0]
            query = conn.recv(length)
            answer = build_response(query, [(1, bytes([10, 0, 0, i])) for i in range(1, 40)])
            conn.sendall(struct.pack("!H", len(answer)) + answer)

    threading.Thread(target=serve_udp, daemon=True).start()
    threading.Thread(target=serve_tcp, daemon=True).start()
    client = DNSClient()
    client.PORT = port
    wire = WireLog()
    try:
        resp = client.query("big.example", "A", "127.0.0.1", "UDP", timeout=3, wire=wire)
    finally:
        udp.close()
        tcp.close()
    assert resp.transport == "UDP→TCP" and len(resp.answers) == 39
    assert any("truncated" in e.summary for e in wire.events)
    assert any(f.label == "Length prefix" for e in wire.events for f in e.fields)


def test_mismatched_ids_are_ignored():
    port = free_port()
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", port))

    def serve():
        data, addr = udp.recvfrom(512)
        spoof = bytearray(build_response(data, [(1, b"\x06\x06\x06\x06")]))
        spoof[0] ^= 0xFF  # wrong ID first
        udp.sendto(bytes(spoof), addr)
        udp.sendto(build_response(data, [(1, b"\x01\x02\x03\x04")]), addr)

    threading.Thread(target=serve, daemon=True).start()
    client = DNSClient()
    client.PORT = port
    try:
        resp = client.query("x.example", "A", "127.0.0.1", "UDP", timeout=3)
    finally:
        udp.close()
    assert [r.value for r in resp.answers] == ["1.2.3.4"]


@pytest.mark.network
@pytest.mark.parametrize("transport", ["UDP", "TCP", "DoT", "DoH"])
def test_live_transports(transport):
    resp = DNSClient().query("example.com", "A", "1.1.1.1", transport)
    assert resp.rcode_name == "NOERROR" and resp.answers


@pytest.mark.network
def test_live_trace_and_nxdomain():
    steps = DNSClient().trace("www.example.com", "A")
    assert steps[0][0].endswith("root-servers.net") and steps[-1][2].answers
    assert DNSClient().query("does-not-exist-7a1c9.invalid").rcode_name == "NXDOMAIN"
