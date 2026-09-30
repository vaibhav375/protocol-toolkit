"""HTTP client built on raw sockets: HTTP/1.1 and HTTP/2, TLS, redirects, cookies, compression."""
from __future__ import annotations

import base64
import gzip
import json
import re
import time
import urllib.parse
import zlib
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from typing import Dict, List, Optional, Tuple, Union

from . import __version__, http2, http3
from .net import Connection, ConnectionError_
from .wire import WireLog, annotate_http1

try:
    import brotli
except ImportError:  # pragma: no cover - optional
    brotli = None

USER_AGENT = f"Protocol-Toolkit/{__version__}"
HAR_BODY_LIMIT = 1024 * 1024  # response bytes kept for HAR export
VALID_METHODS = {"GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"}


class HTTPRequest:
    """An HTTP/1.1 request message"""

    def __init__(self, method: str = "GET", path: str = "/",
                 headers: Dict[str, str] = None, body: Union[str, bytes, None] = None,
                 http_version: str = "HTTP/1.1"):
        self.method = method.upper()
        self.path = path
        self.headers = dict(headers or {})
        self.body = body.encode("utf-8") if isinstance(body, str) else body
        self.http_version = http_version

        self.headers.setdefault("Host", "localhost")
        self.headers.setdefault("User-Agent", USER_AGENT)
        # Servers such as nginx answer 411 Length Required to a POST/PUT/PATCH
        # without Content-Length, so send "0" for an empty body on those methods
        if "Content-Length" not in self.headers and (self.body or self.method in ("POST", "PUT", "PATCH")):
            self.headers["Content-Length"] = str(len(self.body or b""))

    def to_bytes(self) -> bytes:
        if self.method not in VALID_METHODS:
            raise ValueError(f"Invalid HTTP method: {self.method}")
        if not self.path.startswith("/"):
            raise ValueError("Path must start with '/'")
        head = f"{self.method} {self.path} {self.http_version}\r\n"
        head += "".join(f"{k}: {v}\r\n" for k, v in self.headers.items()) + "\r\n"
        return head.encode("utf-8") + (self.body or b"")

    def __str__(self) -> str:
        return self.to_bytes().decode("utf-8", "replace")


class HTTPResponse:
    def __init__(self, status_code: int = 0, status_message: str = "", header_list=None,
                 body: bytes = b"", http_version: str = "HTTP/1.1"):
        self.status_code = status_code
        self.status_message = status_message
        # Every header in order, so repeated headers like Set-Cookie are kept
        self.header_list: List[Tuple[str, str]] = list(header_list or [])
        self.body = body          # after Content-Encoding is removed
        self.raw_body = body      # exactly as received
        self.http_version = http_version
        self.elapsed_ms = 0.0
        self.tls_info: Optional[dict] = None
        self.url = ""
        self.history: List["HTTPResponse"] = []
        self.content_encoding = ""
        self.wire: Optional[WireLog] = None

    @property
    def headers(self) -> Dict[str, str]:
        combined: Dict[str, str] = {}
        for k, v in self.header_list:
            combined[k] = f"{combined[k]}, {v}" if k in combined else v
        return combined

    def get_header(self, name: str, default: str = "") -> str:
        """Case-insensitive lookup, as RFC 9110 requires"""
        name = name.lower()
        values = [v for k, v in self.header_list if k.lower() == name]
        return ", ".join(values) if values else default

    def get_all(self, name: str) -> List[str]:
        return [v for k, v in self.header_list if k.lower() == name.lower()]

    @classmethod
    def from_bytes(cls, data: bytes) -> "HTTPResponse":
        """Parse a complete HTTP/1.x response (headers + possibly chunked body)"""
        if not data:
            return cls(0, "Empty Response")
        header_end = data.find(b"\r\n\r\n")
        if header_end == -1:
            return cls(0, "Invalid Response", body=data)
        response = cls.parse_head(data[:header_end])
        body = data[header_end + 4:]
        if response.get_header("Transfer-Encoding").lower().endswith("chunked"):
            body, _ = decode_chunked(body)
        response.body = response.raw_body = body
        return response

    @classmethod
    def parse_head(cls, head: bytes) -> "HTTPResponse":
        lines = head.split(b"\r\n")
        # Header bytes are ISO-8859-1 per RFC 9110; the reason phrase is optional
        match = re.match(r"(HTTP/[\d.]+)\s+(\d{3})\s*(.*)", lines[0].decode("latin-1"))
        if not match:
            return cls(0, "Invalid Status Line", body=head)
        headers = []
        for line in lines[1:]:
            text = line.decode("latin-1")
            if ":" in text:
                k, v = text.split(":", 1)
                headers.append((k.strip(), v.strip()))
        return cls(int(match.group(2)), match.group(3), headers, http_version=match.group(1))

    def is_json(self) -> bool:
        return "json" in self.get_header("Content-Type").lower()

    def get_json(self):
        if not self.is_json() or not self.body:
            return None
        try:
            return json.loads(self.body.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError):
            return None

    def text(self) -> str:
        charset = "utf-8"
        m = re.search(r"charset=([\w-]+)", self.get_header("Content-Type"), re.I)
        if m:
            charset = m.group(1)
        try:
            return self.body.decode(charset)
        except (UnicodeDecodeError, LookupError):
            return f"[Binary data of length {len(self.body)}]"

    def pretty_body(self) -> str:
        parsed = self.get_json()
        if parsed is not None:
            return json.dumps(parsed, indent=2, ensure_ascii=False)
        return self.text()

    def __str__(self) -> str:
        head = f"{self.http_version} {self.status_code} {self.status_message}\r\n"
        head += "".join(f"{k}: {v}\r\n" for k, v in self.header_list) + "\r\n"
        return head + (self.text() if self.body else "")


def decode_chunked(data: bytes) -> Tuple[bytes, bool]:
    """Decode a chunked body. Returns (body, complete)."""
    result = bytearray()
    pos = 0
    while True:
        line_end = data.find(b"\r\n", pos)
        if line_end == -1:
            return bytes(result), False
        try:
            size = int(data[pos:line_end].split(b";")[0].strip() or b"x", 16)
        except ValueError:
            return bytes(result), True  # malformed: give up with what we have
        if size == 0:
            # Last chunk; complete once the trailer section's blank line has arrived
            return bytes(result), data.find(b"\r\n\r\n", line_end) != -1 or data.endswith(b"0\r\n\r\n")
        start = line_end + 2
        if start + size + 2 > len(data):
            return bytes(result), False
        result += data[start:start + size]
        pos = start + size + 2


def decode_content(body: bytes, encoding: str) -> bytes:
    """Undo Content-Encoding (possibly several, applied in order)"""
    for enc in reversed([e.strip().lower() for e in encoding.split(",") if e.strip()]):
        if enc in ("gzip", "x-gzip"):
            body = gzip.decompress(body)
        elif enc == "deflate":
            try:
                body = zlib.decompress(body)
            except zlib.error:  # some servers send raw deflate without the zlib header
                body = zlib.decompress(body, -zlib.MAX_WBITS)
        elif enc == "br" and brotli:
            body = brotli.decompress(body)
        elif enc != "identity":
            raise ValueError(f"Unsupported Content-Encoding: {enc}")
    return body


# ---------------------------------------------------------------- cookies

@dataclass
class Cookie:
    name: str
    value: str
    domain: str
    path: str = "/"
    expires: Optional[float] = None
    secure: bool = False
    http_only: bool = False
    host_only: bool = True

    def matches(self, host: str, path: str, secure: bool) -> bool:
        if self.expires is not None and self.expires < time.time():
            return False
        if self.secure and not secure:
            return False
        if self.host_only:
            if host != self.domain:
                return False
        elif not (host == self.domain or host.endswith("." + self.domain)):
            return False
        return path == self.path or path.startswith(self.path.rstrip("/") + "/") or self.path == "/"


@dataclass
class CookieJar:
    """RFC 6265 subset: enough to keep a login session across requests"""
    cookies: Dict[Tuple[str, str, str], Cookie] = field(default_factory=dict)

    def update(self, host: str, request_path: str, set_cookie_values: List[str]) -> None:
        for raw in set_cookie_values:
            parts = [p.strip() for p in raw.split(";")]
            if "=" not in parts[0]:
                continue
            name, value = parts[0].split("=", 1)
            default_path = request_path.rsplit("/", 1)[0] or "/"
            cookie = Cookie(name.strip(), value.strip(), host, default_path)
            max_age = None
            for attr in parts[1:]:
                key, _, val = attr.partition("=")
                key = key.strip().lower()
                if key == "domain" and val:
                    domain = val.strip().lstrip(".").lower()
                    # A server may only set cookies for its own domain or a parent of it
                    if not (host == domain or host.endswith("." + domain)):
                        cookie = None
                        break
                    cookie.domain, cookie.host_only = domain, False
                elif key == "path" and val.startswith("/"):
                    cookie.path = val
                elif key == "max-age":
                    try:
                        max_age = int(val)
                    except ValueError:
                        pass
                elif key == "expires" and max_age is None:
                    try:
                        cookie.expires = parsedate_to_datetime(val).timestamp()
                    except (TypeError, ValueError):
                        pass
                elif key == "secure":
                    cookie.secure = True
                elif key == "httponly":
                    cookie.http_only = True
            if cookie is None:
                continue
            if max_age is not None:
                cookie.expires = time.time() + max_age
            key = (cookie.domain, cookie.path, cookie.name)
            if cookie.expires is not None and cookie.expires <= time.time():
                self.cookies.pop(key, None)  # deleting a cookie = setting it expired
            else:
                self.cookies[key] = cookie

    def header_for(self, host: str, path: str, secure: bool) -> str:
        matching = [c for c in self.cookies.values() if c.matches(host, path, secure)]
        matching.sort(key=lambda c: -len(c.path))  # more specific paths first (RFC 6265 §5.4)
        return "; ".join(f"{c.name}={c.value}" for c in matching)

    def clear(self) -> None:
        self.cookies.clear()

    def __len__(self) -> int:
        return len(self.cookies)


# ---------------------------------------------------------------- client

def parse_url(url: str) -> Tuple[str, int, str, bool]:
    """(host, port, path-with-query, use_tls)"""
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url):
        url = "http://" + url
    parts = urllib.parse.urlsplit(url)
    if parts.scheme.lower() not in ("http", "https"):
        raise ValueError(f"Unsupported scheme: {parts.scheme}")
    use_tls = parts.scheme.lower() == "https"
    host = parts.hostname
    if not host:
        raise ValueError(f"Could not find a host name in URL: {url}")
    port = parts.port or (443 if use_tls else 80)
    path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
    return host, port, path, use_tls


class HTTPClient:
    REDIRECT_CODES = {301, 302, 303, 307, 308}

    def __init__(self):
        self.cookies = CookieJar()
        self.last_response: Optional[HTTPResponse] = None

    def send(self, url: str, method: str = "GET", headers: Optional[Dict[str, str]] = None,
             body: Union[str, bytes, None] = None, *, timeout: float = 15.0, verify_tls: bool = True,
             follow_redirects: bool = True, max_redirects: int = 10, http_version: str = "auto",
             use_cookies: bool = True, wire: Optional[WireLog] = None) -> HTTPResponse:
        """Send a request. http_version is "auto" (HTTP/2 when the server offers it), "1.1" or "2"."""
        wire = wire or WireLog(f"{method} {url}")
        body_bytes = body.encode("utf-8") if isinstance(body, str) else body
        headers = dict(headers or {})
        history: List[HTTPResponse] = []
        started = time.perf_counter()

        for _ in range(max_redirects + 1):
            response = self._send_once(url, method, headers, body_bytes, timeout, verify_tls,
                                       http_version, use_cookies, wire)
            response.url = url
            location = response.get_header("Location")
            if not (follow_redirects and response.status_code in self.REDIRECT_CODES and location):
                break
            history.append(response)
            new_url = urllib.parse.urljoin(url, location)
            if response.status_code == 303 or (response.status_code in (301, 302) and method == "POST"):
                method, body_bytes = "GET", None  # browsers switch to GET here
                headers = {k: v for k, v in headers.items() if k.lower() not in ("content-type", "content-length")}
            if urllib.parse.urlsplit(new_url).hostname != urllib.parse.urlsplit(url).hostname:
                # Never leak credentials to a different host
                headers = {k: v for k, v in headers.items() if k.lower() not in ("authorization", "cookie", "host")}
            wire.info("HTTP", f"Redirect {response.status_code} -> {new_url}")
            url = new_url
        else:
            raise ConnectionError_(f"Too many redirects (more than {max_redirects})")

        response.history = history
        response.elapsed_ms = (time.perf_counter() - started) * 1000
        response.wire = wire
        self.last_response = response
        return response

    def _send_once(self, url, method, headers, body, timeout, verify_tls, http_version,
                   use_cookies, wire: WireLog) -> HTTPResponse:
        host, port, path, use_tls = parse_url(url)
        headers = dict(headers)
        hop_started, first_phase = time.time(), len(wire.phases)
        default_port = 443 if use_tls else 80
        authority = host if port == default_port else f"{host}:{port}"
        if not any(k.lower() == "host" for k in headers):
            headers["Host"] = authority
        headers.setdefault("User-Agent", USER_AGENT)
        if not any(k.lower() == "accept-encoding" for k in headers):
            headers["Accept-Encoding"] = "gzip, deflate" + (", br" if brotli else "")
        headers.setdefault("Accept", "*/*")
        # Optional in HTTP/2, but some servers (e.g. Cloudflare's DoH endpoint) reject a
        # POST body without it, so always send it like curl does
        if (body or method in ("POST", "PUT", "PATCH")) and not any(k.lower() == "content-length" for k in headers):
            headers["Content-Length"] = str(len(body or b""))
        if use_cookies and not any(k.lower() == "cookie" for k in headers):
            cookie_header = self.cookies.header_for(host, path, use_tls)
            if cookie_header:
                headers["Cookie"] = cookie_header

        if http_version == "3":
            if not use_tls:
                raise ConnectionError_("HTTP/3 always runs over QUIC with TLS; use an https:// URL")
            status, header_list, raw_body, server_ip, flow_id, tls_info = http3.request(
                host, port, method, authority, path, list(headers.items()), body, wire, timeout, verify_tls)
            response = HTTPResponse(status, "", header_list, raw_body, "HTTP/3")
            response.tls_info = tls_info
            return self._finish(response, host, path, use_cookies, wire, method, url, headers, body,
                                hop_started, first_phase, server_ip, flow_id)

        want_h2 = use_tls and http_version in ("auto", "2") and http2.HPACK_AVAILABLE
        if http_version == "2" and not http2.HPACK_AVAILABLE:
            raise ConnectionError_("HTTP/2 needs the 'hpack' package: pip install hpack")
        alpn = (["h2", "http/1.1"] if http_version == "auto" else ["h2"]) if want_h2 else (["http/1.1"] if use_tls else None)

        conn = Connection(host, port, timeout=timeout, wire=wire)
        try:
            conn.open(tls=use_tls, verify=verify_tls, alpn=alpn)
            negotiated_h2 = conn.tls_info and conn.tls_info.get("alpn") == "h2"
            if http_version == "2" and not negotiated_h2:
                raise ConnectionError_(f"{host} did not agree to HTTP/2 during the TLS handshake (ALPN)")
            if negotiated_h2:
                session = http2.HTTP2Session(conn, wire)
                header_list, raw_body = session.request(method, "https", authority, path,
                                                        list(headers.items()), body)
                status = int(dict(header_list).get(":status", "0"))
                response = HTTPResponse(status, "", [(k, v) for k, v in header_list if not k.startswith(":")],
                                        raw_body, "HTTP/2")
            else:
                response = self._http1(conn, method, path, headers, body, wire)
            response.tls_info = conn.tls_info
            server_ip, flow_id = conn.peer_ip, conn.flow
        finally:
            conn.close()

        return self._finish(response, host, path, use_cookies, wire, method, url, headers, body,
                            hop_started, first_phase, server_ip, flow_id)

    def _finish(self, response, host, path, use_cookies, wire, method, url, headers, body,
                hop_started, first_phase, server_ip, flow_id) -> HTTPResponse:
        """Cookies, content decoding and the HAR record, shared by HTTP/1.1, /2 and /3"""
        if use_cookies:
            self.cookies.update(host, path.split("?")[0], response.get_all("Set-Cookie"))
        encoding = response.get_header("Content-Encoding")
        if encoding and response.raw_body:
            try:
                response.body = decode_content(response.raw_body, encoding)
                response.content_encoding = encoding
            except Exception as e:  # keep the raw body if decoding fails
                wire.info("HTTP", f"Could not decode Content-Encoding {encoding}: {e}")
        # Everything a HAR export needs about this hop (redirects add one entry each)
        wire.meta.setdefault("http_entries", []).append({
            "started": hop_started, "method": method, "url": url, "http_version": response.http_version,
            "request_headers": list(headers.items()),
            "request_body": body.decode("utf-8", "replace") if body else None,
            "status": response.status_code, "status_text": response.status_message,
            "response_headers": response.header_list, "raw_size": len(response.raw_body),
            "body_b64": base64.b64encode(response.body[:HAR_BODY_LIMIT]).decode(),
            "body_truncated": len(response.body) > HAR_BODY_LIMIT,
            "timings": [(p.name, round(p.duration_ms, 3)) for p in wire.phases[first_phase:]],
            "server_ip": server_ip, "connection": flow_id,
        })
        return response

    def _http1(self, conn: Connection, method: str, path: str, headers: Dict[str, str],
               body: Optional[bytes], wire: WireLog) -> HTTPResponse:
        headers.setdefault("Connection", "close")
        request = HTTPRequest(method, path, headers, body)
        data = request.to_bytes()
        wire.add("out", "HTTP/1.1", data, f"{method} {path}", annotate_http1(data))
        conn.sendall(data)

        waiting = wire.begin("Waiting (TTFB)")
        buf = b""
        download = None
        try:
            # Headers (skipping any 1xx interim responses such as 100 Continue)
            while True:
                while b"\r\n\r\n" not in buf:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    if download is None:
                        wire.end(waiting)
                        download = wire.begin("Content download")
                    buf += chunk
                if b"\r\n\r\n" not in buf:
                    response = HTTPResponse.from_bytes(buf)
                    wire.add("in", "HTTP/1.1", buf, "Incomplete response", annotate_http1(buf))
                    return response
                head, rest = buf.split(b"\r\n\r\n", 1)
                response = HTTPResponse.parse_head(head)
                if 100 <= response.status_code < 200 and response.status_code != 101:
                    wire.add("in", "HTTP/1.1", head + b"\r\n\r\n", f"{response.status_code} (interim)",
                             annotate_http1(head + b"\r\n\r\n"))
                    buf = rest
                    continue
                break

            # Body framing (RFC 9112 §6.3)
            te = response.get_header("Transfer-Encoding").lower()
            length = response.get_header("Content-Length")
            if method == "HEAD" or response.status_code in (204, 304):
                body_raw = b""
            elif te.endswith("chunked"):
                while True:
                    body_raw, complete = decode_chunked(rest)
                    if complete:
                        break
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    rest += chunk
            elif length.isdigit():
                need = int(length)
                while len(rest) < need:
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    rest += chunk
                body_raw = rest[:need]
            else:
                while True:  # read until the server closes the connection
                    chunk = conn.recv(65536)
                    if not chunk:
                        break
                    rest += chunk
                body_raw = rest
        finally:
            wire.end(waiting)
            if download:
                wire.end(download)

        message = head + b"\r\n\r\n" + rest
        wire.add("in", "HTTP/1.1", message, f"{response.status_code} {response.status_message}",
                 annotate_http1(message))
        response.body = response.raw_body = body_raw
        return response


def stream_lines(url: str, method: str = "POST", headers: Optional[Dict[str, str]] = None,
                 body: Optional[bytes] = None, timeout: float = 120.0, wire: Optional[WireLog] = None):
    """HTTP/1.1 request whose response body is yielded line by line as it arrives
    (for streaming APIs such as Ollama's NDJSON). Yields the HTTPResponse head first."""
    host, port, path, use_tls = parse_url(url)
    wire = wire or WireLog(f"{method} {url}")
    headers = dict(headers or {})
    headers.setdefault("Host", host if port in (80, 443) else f"{host}:{port}")
    conn = Connection(host, port, timeout=timeout, wire=wire)
    try:
        conn.open(tls=use_tls, alpn=["http/1.1"] if use_tls else None)
        headers["Connection"] = "close"
        request = HTTPRequest(method, path, headers, body)
        data = request.to_bytes()
        wire.add("out", "HTTP/1.1", data, f"{method} {path}", annotate_http1(data))
        conn.sendall(data)
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = conn.recv(65536)
            if not chunk:
                raise ConnectionError_("Server closed the connection before responding")
            buf += chunk
        head, buf = buf.split(b"\r\n\r\n", 1)
        response = HTTPResponse.parse_head(head)
        wire.add("in", "HTTP/1.1", head + b"\r\n\r\n", f"{response.status_code} {response.status_message}",
                 annotate_http1(head + b"\r\n\r\n"))
        yield response
        chunked = response.get_header("Transfer-Encoding").lower().endswith("chunked")
        pending = b""   # decoded body bytes not yet split into lines
        while True:
            if chunked:
                # Decode as many complete chunks as the buffer holds
                while True:
                    end = buf.find(b"\r\n")
                    if end == -1:
                        break
                    size = int(buf[:end].split(b";")[0] or b"0", 16)
                    if size == 0:
                        if pending:
                            yield pending.decode("utf-8", "replace")
                        return
                    if len(buf) < end + 2 + size + 2:
                        break
                    pending += buf[end + 2:end + 2 + size]
                    buf = buf[end + 2 + size + 2:]
            else:
                pending, buf = pending + buf, b""
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                if line.strip():
                    yield line.decode("utf-8", "replace")
            chunk = conn.recv(65536)
            if not chunk:
                if pending.strip():
                    yield pending.decode("utf-8", "replace")
                return
            buf += chunk
    finally:
        conn.close()
