import gzip
import time
import zlib

import pytest

from protocol_toolkit import http2
from protocol_toolkit.httpclient import (CookieJar, HTTPClient, HTTPRequest, HTTPResponse, decode_chunked,
                                         decode_content, parse_url)


def read_request(h) -> tuple:
    """Read one HTTP/1.1 request from a StreamRequestHandler"""
    lines = []
    while True:
        line = h.rfile.readline()
        if line in (b"\r\n", b""):
            break
        lines.append(line.decode().rstrip("\r\n"))
    headers = dict(l.split(": ", 1) for l in lines[1:])
    body = h.rfile.read(int(headers.get("Content-Length", 0)))
    return lines[0], headers, body


# ------------------------------------------------------------ parsing

def test_status_line_without_reason():
    assert HTTPResponse.from_bytes(b"HTTP/1.1 204\r\nX-A: 1\r\n\r\n").status_code == 204


def test_repeated_and_case_insensitive_headers():
    r = HTTPResponse.from_bytes(b"HTTP/1.1 200 OK\r\nset-cookie: a=1\r\nSet-Cookie: b=2\r\n\r\n")
    assert r.get_all("Set-Cookie") == ["a=1", "b=2"]
    assert r.get_header("SET-COOKIE") == "a=1, b=2"


def test_chunked_decoding():
    assert decode_chunked(b"5\r\nhello\r\n6;ext=1\r\n world\r\n0\r\n\r\n") == (b"hello world", True)
    assert decode_chunked(b"5\r\nhel")[1] is False
    assert decode_chunked(b"5\r\nhello\r\n0\r\n")[1] is False  # trailer section not finished yet
    assert decode_chunked(b"5\r\nhello\r\n0\r\nX-Trailer: 1\r\n\r\n") == (b"hello", True)


def test_content_decoding():
    assert decode_content(gzip.compress(b"hi"), "gzip") == b"hi"
    assert decode_content(zlib.compress(b"hi"), "deflate") == b"hi"
    raw = zlib.compressobj(wbits=-15)
    assert decode_content(raw.compress(b"hi") + raw.flush(), "deflate") == b"hi"
    brotli = pytest.importorskip("brotli")
    assert decode_content(brotli.compress(b"hi"), "br") == b"hi"
    with pytest.raises(ValueError):
        decode_content(b"x", "zstd-unknown")


@pytest.mark.parametrize("url,expected", [
    ("example.com", ("example.com", 80, "/", False)),
    ("example.com?q=1", ("example.com", 80, "/?q=1", False)),
    ("https://x.io:8443/a/b?c=d#frag", ("x.io", 8443, "/a/b?c=d", True)),
    ("HTTPS://X.IO", ("x.io", 443, "/", True)),
])
def test_parse_url(url, expected):
    assert parse_url(url) == expected


def test_parse_url_rejects_other_schemes():
    with pytest.raises(ValueError):
        parse_url("ftp://example.com")


def test_empty_post_gets_content_length():
    assert b"Content-Length: 0\r\n" in HTTPRequest("POST", "/").to_bytes()
    assert b"Content-Length" not in HTTPRequest("GET", "/").to_bytes()


# ------------------------------------------------------------ cookies

def test_cookie_jar_rules():
    jar = CookieJar()
    jar.update("app.example.com", "/login", [
        "sid=1; Path=/; HttpOnly",
        "wide=2; Domain=.example.com",
        "evil=3; Domain=attacker.com",          # not our domain: must be ignored
        "secure=4; Secure",
        "gone=5; Max-Age=0",
    ])
    assert ("attacker.com", "/", "evil") not in jar.cookies
    assert jar.header_for("app.example.com", "/", secure=False) == "sid=1; wide=2"
    assert "secure=4" not in jar.header_for("app.example.com", "/", secure=False)
    assert "wide=2" in jar.header_for("other.example.com", "/", secure=True)
    assert "sid=1" not in jar.header_for("other.example.com", "/", secure=True)  # host-only
    jar.update("app.example.com", "/", ["sid=; Expires=Thu, 01 Jan 1970 00:00:00 GMT"])
    assert "sid" not in jar.header_for("app.example.com", "/", secure=False)


# ------------------------------------------------------------ against local servers

def test_content_length_framing_does_not_wait_for_close(tcp_server):
    def handle(h):
        read_request(h)
        h.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: keep-alive\r\n\r\nhello")
        h.wfile.flush()
        time.sleep(3)  # keep the socket open: the client must stop at Content-Length

    server = tcp_server(handle)
    started = time.time()
    r = HTTPClient().send(server.url, timeout=10)
    assert r.body == b"hello" and time.time() - started < 2


def test_chunked_gzip_response(tcp_server):
    payload = gzip.compress(b'{"ok": true}')

    def handle(h):
        read_request(h)
        h.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Encoding: gzip\r\n"
                      b"Transfer-Encoding: chunked\r\n\r\n")
        for i in range(0, len(payload), 7):
            part = payload[i:i + 7]
            h.wfile.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
        h.wfile.write(b"0\r\n\r\n")

    r = HTTPClient().send(tcp_server(handle).url)
    assert r.get_json() == {"ok": True} and r.content_encoding == "gzip"
    assert "Waiting (TTFB)" in [p.name for p in r.wire.phases]


def test_redirects_cookies_and_303(tcp_server):
    seen = []

    def handle(h):
        line, headers, body = read_request(h)
        seen.append((line, headers.get("Cookie"), body))
        if line.startswith("POST /login"):
            h.wfile.write(b"HTTP/1.1 303 See Other\r\nLocation: /home\r\nSet-Cookie: sid=abc; Path=/\r\n"
                          b"Content-Length: 0\r\n\r\n")
        else:
            h.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    server = tcp_server(handle)
    client = HTTPClient()
    r = client.send(server.url + "/login", "POST", {"Content-Type": "text/plain"}, "user=me")
    assert r.status_code == 200 and len(r.history) == 1
    assert seen[1][0] == "GET /home HTTP/1.1"  # 303 switches to GET
    assert seen[1][1] == "sid=abc" and seen[1][2] == b""


def test_too_many_redirects(tcp_server):
    def handle(h):
        read_request(h)
        h.wfile.write(b"HTTP/1.1 302 Found\r\nLocation: /again\r\nContent-Length: 0\r\n\r\n")

    with pytest.raises(OSError, match="Too many redirects"):
        HTTPClient().send(tcp_server(handle).url, max_redirects=3)


def test_interim_100_continue_is_skipped(tcp_server):
    def handle(h):
        read_request(h)
        h.wfile.write(b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 201 Created\r\nContent-Length: 0\r\n\r\n")

    assert HTTPClient().send(tcp_server(handle).url, "POST", body="x").status_code == 201


def test_https_to_local_server(self_signed_cert):
    import socketserver
    import ssl
    import threading

    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(*self_signed_cert)

    class Handler(socketserver.StreamRequestHandler):
        def setup(self):
            self.request = ctx.wrap_socket(self.request, server_side=True)
            super().setup()

        def handle(self):
            read_request(self)
            self.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecure")

    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"https://localhost:{server.server_address[1]}/"
    try:
        with pytest.raises(OSError, match="certificate verification failed"):
            HTTPClient().send(url)
        r = HTTPClient().send(url, verify_tls=False)
        assert r.body == b"secure" and r.tls_info["version"].startswith("TLS")
        layers = {e.layer for e in r.wire.events}
        assert {"TLS", "HTTP/1.1"} <= layers
        assert any(e.summary.startswith("ClientHello") for e in r.wire.events)
    finally:
        server.shutdown()
        server.server_close()


# ------------------------------------------------------------ HTTP/2 framing

def test_frame_pack_and_describe():
    frame = http2.pack_frame(http2.SETTINGS, 0, 0, b"\x00\x02\x00\x00\x00\x00")
    assert frame[:9] == b"\x00\x00\x06\x04\x00\x00\x00\x00\x00"
    summary, fields = http2.describe_frame(frame)
    assert summary == "SETTINGS stream 0 ENABLE_PUSH=0"
    summary, _ = http2.describe_frame(http2.pack_frame(http2.DATA, http2.END_STREAM, 1, b"abc"))
    assert summary == "DATA stream 1 [END_STREAM] 3 bytes"
    summary, _ = http2.describe_frame(http2.pack_frame(http2.GOAWAY, 0, 0, b"\x00\x00\x00\x01\x00\x00\x00\x0b"))
    assert "ENHANCE_YOUR_CALM" in summary


@pytest.mark.network
def test_live_http2_and_http1():
    client = HTTPClient()
    r2 = client.send("https://www.google.com/", http_version="auto")
    assert r2.http_version == "HTTP/2" and r2.status_code == 200
    assert any(e.layer == "HTTP/2" and e.summary.startswith("HEADERS") for e in r2.wire.events)
    r1 = client.send("https://example.com/", http_version="1.1")
    assert r1.http_version == "HTTP/1.1" and r1.status_code == 200


@pytest.mark.network
def test_live_http2_post_with_body():
    r = HTTPClient().send("https://httpbin.org/post", "POST", {"Content-Type": "application/json"}, '{"a": 1}',
                          http_version="2")
    assert r.status_code == 200 and r.get_json()["json"] == {"a": 1}
