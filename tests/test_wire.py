import ssl

from protocol_toolkit.net import make_tls_context
from protocol_toolkit.wire import WireLog, annotate_http1, annotate_tls, hexdump, printable


def client_hello(host="example.com", alpn=("h2", "http/1.1")) -> bytes:
    """Produce a real ClientHello without touching the network"""
    ctx = make_tls_context(alpn=alpn)
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(incoming, outgoing, server_hostname=host)
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def test_hexdump_layout():
    out = hexdump(b"GET / HTTP/1.1\r\n")
    assert out.startswith("00000000  47 45 54 20")
    assert out.endswith("GET / HTTP/1.1..")
    # the ASCII column starts at a fixed position the inspector relies on
    assert out.index("GET /") == 59


def test_printable_text_and_binary():
    assert printable(b"hello\r\nworld") == "hello\nworld"
    assert printable(b"\x00\x01\x02").startswith("00000000")


def test_client_hello_is_annotated_with_sni_and_alpn():
    summary, fields = annotate_tls(client_hello("example.com"))
    assert summary == "ClientHello"
    labels = {f.label: f.value for f in fields}
    assert labels["Extension: server_name (SNI)"] == "example.com"
    assert labels["Extension: ALPN"] == "h2, http/1.1"
    assert "TLS 1.3" in labels["Extension: supported_versions"]


def test_partial_tls_record_is_flagged():
    data = client_hello()
    summary, fields = annotate_tls(data[:40])
    assert "continues" in fields[0].label


def test_http1_annotation():
    msg = b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n\r\nhi"
    fields = annotate_http1(msg)
    assert fields[0].value == "HTTP/1.1 200 OK"
    assert fields[1].label == "Header: Content-Type"
    assert fields[-1].label == "Body" and fields[-1].offset == len(msg) - 2


def test_wirelog_phases_and_transcript():
    wire = WireLog("demo")
    with wire.phase("TCP connect"):
        pass
    wire.add("out", "HTTP/1.1", b"GET / HTTP/1.1\r\n\r\n", "GET /")
    wire.add("in", "TLS", b"\x17\x03\x03\x00\x01x", "ApplicationData")
    text = wire.transcript()
    assert "TCP connect" in text and "-> HTTP/1.1: GET /" in text
    assert "\\x17" not in text  # encrypted TLS payloads are summarised, not dumped


def test_wirelog_caps_huge_events():
    wire = WireLog()
    event = wire.add("in", "HTTP/1.1", b"x" * (WireLog.MAX_EVENT_BYTES + 10), "big")
    assert len(event.data) == WireLog.MAX_EVENT_BYTES and "showing first" in event.summary
