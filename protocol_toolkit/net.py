"""TCP connections with optional TLS, recording every byte and timing phase.

TLS is driven through ssl.MemoryBIO instead of ssl.wrap_socket(), so we feed the
TLS engine ourselves and can log the real encrypted records (ClientHello,
ServerHello, ...) as well as the plaintext above them.
"""
from __future__ import annotations

import os
import socket
import ssl
import tempfile
from typing import Optional, Sequence

from .wire import WireLog, annotate_tls

CERT_HELP = ("On macOS with python.org Python, run 'Install Certificates.command' from "
             "your Python folder (or `pip install certifi`), or turn off 'Verify TLS'.")


MAX_RECEIVE: Optional[int] = None  # bytes per connection; set by the public demo (see guard.py)


class ConnectionError_(OSError):
    """Connection failure with a human-readable explanation"""


def check_size(received: int) -> None:
    if MAX_RECEIVE is not None and received > MAX_RECEIVE:
        raise ConnectionError_(f"Stopped after {MAX_RECEIVE // (1024 * 1024)} MB: the public demo limits "
                               "how much one request may download")


def make_tls_context(verify: bool = True, alpn: Optional[Sequence[str]] = None) -> ssl.SSLContext:
    context = ssl.create_default_context()
    try:
        # python.org builds on macOS ship without CA certificates; certifi fills the gap
        import certifi
        context.load_verify_locations(certifi.where())
    except ImportError:
        pass
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if alpn:
        context.set_alpn_protocols(list(alpn))
    return context


class Connection:
    def __init__(self, host: str, port: int, *, timeout: float = 10.0,
                 wire: Optional[WireLog] = None):
        self.host = host
        self.port = port
        self.timeout = timeout
        self.wire = wire or WireLog()
        self.sock: Optional[socket.socket] = None
        self.peer_ip: Optional[str] = None
        self._tls: Optional[ssl.SSLObject] = None
        self._in_bio: Optional[ssl.MemoryBIO] = None
        self._out_bio: Optional[ssl.MemoryBIO] = None
        self._eof = False
        self.tls_info: Optional[dict] = None
        self.flow: Optional[int] = None
        self._keylog_path: Optional[str] = None
        self._received = 0

    # ------------------------------------------------------------ connect

    def open(self, tls: bool = False, verify: bool = True, alpn: Optional[Sequence[str]] = None,
             server_hostname: Optional[str] = None) -> "Connection":
        with self.wire.phase("DNS lookup"):
            try:
                infos = socket.getaddrinfo(self.host, self.port, type=socket.SOCK_STREAM)
            except socket.gaierror as e:
                raise ConnectionError_(f"Could not resolve {self.host}: {e}") from e
        # Prefer IPv4 when both exist: fewer surprises on home networks without IPv6 routing
        infos.sort(key=lambda info: info[0] != socket.AF_INET)
        last_error = None
        with self.wire.phase("TCP connect"):
            for family, stype, proto, _, addr in infos:
                sock = socket.socket(family, stype, proto)
                sock.settimeout(self.timeout)
                try:
                    sock.connect(addr)
                except OSError as e:
                    sock.close()
                    last_error = e
                    continue
                self.sock, self.peer_ip = sock, addr[0]
                self.flow = self.wire.open_flow("tcp", sock.getsockname()[:2], addr[:2])
                break
        if not self.sock:
            raise ConnectionError_(f"Could not connect to {self.host}:{self.port}: {last_error}")
        self.wire.info("TCP", f"Connected to {self.host} ({self.peer_ip}) port {self.port}")
        if tls:
            self.start_tls(verify=verify, alpn=alpn, server_hostname=server_hostname)
        return self

    def start_tls(self, verify: bool = True, alpn: Optional[Sequence[str]] = None,
                  server_hostname: Optional[str] = None) -> None:
        """Run a TLS handshake over the already-open TCP socket (also used by STARTTLS)"""
        context = make_tls_context(verify, alpn)
        # Record the session keys (SSLKEYLOGFILE format) so an exported pcap can be
        # decrypted in Wireshark. The temp file is read into memory and deleted.
        fd, self._keylog_path = tempfile.mkstemp(prefix="pt-keylog-", suffix=".txt")
        os.close(fd)
        context.keylog_filename = self._keylog_path
        self._in_bio, self._out_bio = ssl.MemoryBIO(), ssl.MemoryBIO()
        # server_hostname sends SNI, which CDNs like Cloudflare require, and is what
        # the certificate is checked against
        self._tls = context.wrap_bio(self._in_bio, self._out_bio,
                                     server_hostname=server_hostname or self.host)
        with self.wire.phase("TLS handshake"):
            while True:
                try:
                    self._tls.do_handshake()
                    self._flush()
                    break
                except ssl.SSLWantReadError:
                    self._flush()
                    if not self._fill():
                        raise ConnectionError_("Server closed the connection during the TLS handshake")
                except ssl.SSLCertVerificationError as e:
                    self._flush()
                    raise ConnectionError_(f"TLS certificate verification failed: {e.verify_message}. {CERT_HELP}") from e
                except ssl.SSLError as e:
                    self._flush()
                    raise ConnectionError_(f"TLS handshake failed: {e.reason or e}") from e
        self._collect_keylog()
        cert = self._tls.getpeercert() or {}
        subject = dict(x[0] for x in cert.get("subject", ()))
        issuer = dict(x[0] for x in cert.get("issuer", ()))
        self.tls_info = {
            "version": self._tls.version(),
            "cipher": self._tls.cipher()[0],
            "alpn": self._tls.selected_alpn_protocol(),
            "subject": subject.get("commonName", ""),
            "issuer": issuer.get("organizationName", issuer.get("commonName", "")),
            "expires": cert.get("notAfter", ""),
            "san": [v for k, v in cert.get("subjectAltName", ()) if k == "DNS"][:10],
            "verified": verify,
        }
        alpn_text = f", ALPN {self.tls_info['alpn']}" if self.tls_info["alpn"] else ""
        self.wire.info("TLS", f"{self.tls_info['version']} established, {self.tls_info['cipher']}{alpn_text}"
                              + (f", certificate for {self.tls_info['subject']} issued by {self.tls_info['issuer']}"
                                 if self.tls_info["subject"] else " (certificate not verified)"))

    @property
    def is_tls(self) -> bool:
        return self._tls is not None

    def _collect_keylog(self, remove: bool = False) -> None:
        if not self._keylog_path:
            return
        try:
            with open(self._keylog_path, encoding="ascii", errors="replace") as fh:
                self.wire.add_keylog(fh.readlines())
        except OSError:
            pass
        if remove:
            try:
                os.remove(self._keylog_path)
            except OSError:
                pass
            self._keylog_path = None

    # ------------------------------------------------------------ raw I/O

    def _flush(self) -> None:
        data = self._out_bio.read() if self._out_bio else b""
        if data:
            self.sock.sendall(data)
            self.wire.segment(self.flow, "out", data)
            summary, fields = annotate_tls(data)
            self.wire.add("out", "TLS", data, summary, fields)

    def _fill(self) -> bool:
        """Read one TCP segment into the TLS engine. False on EOF."""
        data = self.sock.recv(65536)
        if not data:
            self._in_bio.write_eof()
            return False
        self.wire.segment(self.flow, "in", data)
        summary, fields = annotate_tls(data)
        self.wire.add("in", "TLS", data, summary, fields)
        self._in_bio.write(data)
        return True

    # ------------------------------------------------------------ plaintext API

    def sendall(self, data: bytes) -> None:
        if not self._tls:
            self.sock.sendall(data)
            self.wire.segment(self.flow, "out", data)
            return
        view = memoryview(data)
        while view:
            written = self._tls.write(view)
            view = view[written:]
            self._flush()

    def recv(self, size: int = 65536) -> bytes:
        """Plaintext bytes; b'' on EOF. Raises socket.timeout like a normal socket."""
        if self._eof:
            return b""
        if not self._tls:
            data = self.sock.recv(size)
            self._eof = not data
            self.wire.segment(self.flow, "in", data)
            self._received += len(data)
            check_size(self._received)
            return data
        while True:
            try:
                data = self._tls.read(size)
                self._received += len(data)
                check_size(self._received)
                return data
            except ssl.SSLWantReadError:
                self._flush()
                if not self._fill():
                    self._eof = True
                    return b""
            except (ssl.SSLZeroReturnError, ssl.SSLEOFError):
                # Many servers close without a TLS close_notify; treat it as EOF
                self._eof = True
                return b""

    def settimeout(self, timeout: float) -> None:
        self.timeout = timeout
        if self.sock:
            self.sock.settimeout(timeout)

    def close(self) -> None:
        if self.sock:
            try:
                if self._tls:
                    try:
                        self._tls.unwrap()
                    except ssl.SSLError:
                        pass
                    self._flush()
            except OSError:
                pass
            finally:
                self.sock.close()
                self.sock = None
                self._collect_keylog(remove=True)
                if self.flow is not None:
                    self.wire.close_flow(self.flow)

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


class LineReader:
    """Buffered CRLF line reading over a Connection (SMTP, banners)"""

    def __init__(self, conn: Connection):
        self.conn = conn
        self.buffer = b""

    def readline(self) -> bytes:
        while b"\r\n" not in self.buffer:
            chunk = self.conn.recv(4096)
            if not chunk:
                raise ConnectionError_("Server closed the connection")
            self.buffer += chunk
        line, self.buffer = self.buffer.split(b"\r\n", 1)
        return line

    def read_exact(self, n: int) -> bytes:
        while len(self.buffer) < n:
            chunk = self.conn.recv(max(4096, n - len(self.buffer)))
            if not chunk:
                raise ConnectionError_("Connection closed early")
            self.buffer += chunk
        data, self.buffer = self.buffer[:n], self.buffer[n:]
        return data
