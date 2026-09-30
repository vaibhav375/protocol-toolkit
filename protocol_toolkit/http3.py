"""HTTP/3 over QUIC (RFC 9114 / RFC 9000).

QUIC's transport and packet protection come from `aioquic`, used in its sans-I/O form:
the toolkit owns the UDP socket and the clock, so every datagram is captured like any
other traffic, QUIC packet headers are labelled here, and the TLS secrets are kept so
an exported pcapng decrypts in Wireshark.
"""
from __future__ import annotations

import importlib.util
import select
import socket
import ssl
import time
from typing import List, Optional, Tuple

from .net import ConnectionError_, check_size
from .wire import Field, WireLog

AIOQUIC_AVAILABLE = importlib.util.find_spec("aioquic") is not None
LONG_TYPES = {0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry"}
VERSIONS = {0x00000001: "QUIC v1", 0x6B3343CF: "QUIC v2", 0x00000000: "Version Negotiation"}


def _varint(data: bytes, pos: int) -> Tuple[int, int]:
    first = data[pos]
    length = 1 << (first >> 6)
    value = first & 0x3F
    for b in data[pos + 1:pos + length]:
        value = (value << 8) | b
    return value, pos + length


def annotate_quic(data: bytes) -> Tuple[str, List[Field]]:
    """Label the QUIC packets in one UDP datagram (several can be coalesced).
    Everything past the header is protected, so only headers are readable."""
    fields: List[Field] = []
    names = []
    pos = 0
    try:
        while pos < len(data):
            first = data[pos]
            if not first & 0x40:
                # Every QUIC v1/v2 packet has the fixed bit set, so this is datagram padding
                # (clients pad their first flight to 1200 bytes)
                fields.append(Field(pos, len(data) - pos, "Padding", f"{len(data) - pos} bytes"))
                break
            if not first & 0x80:  # short header: 1-RTT, runs to the end of the datagram
                fields.append(Field(pos, len(data) - pos, "1-RTT packet (short header)", f"{len(data) - pos} bytes"))
                fields.append(Field(pos, 1, "Header form", "short", 1))
                fields.append(Field(pos + 1, len(data) - pos - 1, "Destination CID + protected payload", "encrypted", 1))
                names.append("1-RTT")
                break
            version = int.from_bytes(data[pos + 1:pos + 5], "big")
            kind = LONG_TYPES[(first >> 4) & 0x03] if version else "Version Negotiation"
            start = pos
            p = pos + 5
            dcid_len = data[p]
            dcid = data[p + 1:p + 1 + dcid_len]
            p += 1 + dcid_len
            scid_len = data[p]
            scid = data[p + 1:p + 1 + scid_len]
            p += 1 + scid_len
            sub = [Field(start, 1, "Header form / type", f"long, {kind}", 1),
                   Field(start + 1, 4, "Version", VERSIONS.get(version, hex(version)), 1),
                   Field(start + 5, 1 + dcid_len, "Destination connection ID", dcid.hex() or "(empty)", 1),
                   Field(start + 6 + dcid_len, 1 + scid_len, "Source connection ID", scid.hex() or "(empty)", 1)]
            if kind in ("Retry", "Version Negotiation"):
                end = len(data)
            else:
                if kind == "Initial":
                    token_len, q = _varint(data, p)
                    sub.append(Field(p, q - p + token_len, "Token", f"{token_len} bytes", 1))
                    p = q + token_len
                length, q = _varint(data, p)
                sub.append(Field(p, q - p, "Length", str(length), 1))
                sub.append(Field(q, min(length, len(data) - q), "Protected payload", f"{length} bytes, encrypted", 1))
                end = q + length
            fields.append(Field(start, min(end, len(data)) - start, f"{kind} packet", f"{min(end, len(data)) - start} bytes"))
            fields.extend(sub)
            names.append(kind)
            pos = end
    except (IndexError, KeyError):
        pass
    counts = {}
    for n in names:
        counts[n] = counts.get(n, 0) + 1
    return ", ".join(n + (f" x{c}" if c > 1 else "") for n, c in counts.items()) or f"{len(data)} bytes", fields


class _SecretsLog:
    """File-like sink for aioquic's TLS key log"""

    def __init__(self, wire: WireLog):
        self.wire = wire

    def write(self, text: str) -> None:
        self.wire.add_keylog(text.splitlines())

    def flush(self) -> None:
        pass


def request(host: str, port: int, method: str, authority: str, path: str, headers: List[Tuple[str, str]],
            body: Optional[bytes], wire: WireLog, timeout: float = 15, verify: bool = True):
    """One HTTP/3 request. Returns (status, header_list, body, peer_ip, flow, tls_info)."""
    if not AIOQUIC_AVAILABLE:
        raise ConnectionError_("HTTP/3 needs the aioquic package: pip install aioquic")
    from aioquic.h3.connection import H3_ALPN, H3Connection
    from aioquic.h3.events import DataReceived, HeadersReceived
    from aioquic.quic.configuration import QuicConfiguration
    from aioquic.quic.connection import QuicConnection
    from aioquic.quic.events import ConnectionTerminated, HandshakeCompleted

    config = QuicConfiguration(is_client=True, alpn_protocols=H3_ALPN, server_name=host,
                               secrets_log_file=_SecretsLog(wire))
    try:
        import certifi
        config.load_verify_locations(certifi.where())
    except ImportError:
        pass
    if not verify:
        config.verify_mode = ssl.CERT_NONE

    with wire.phase("DNS lookup"):
        try:
            infos = socket.getaddrinfo(host, port, type=socket.SOCK_DGRAM)
        except socket.gaierror as e:
            raise ConnectionError_(f"Could not resolve {host}: {e}") from e
    infos.sort(key=lambda info: info[0] != socket.AF_INET)
    family, _, _, _, addr = infos[0]
    sock = socket.socket(family, socket.SOCK_DGRAM)
    sock.setblocking(False)
    sock.connect(addr)
    flow = wire.open_flow("udp", sock.getsockname()[:2], addr[:2])
    wire.info("QUIC", f"Sending QUIC to {host} ({addr[0]}) UDP port {port}")

    quic = QuicConnection(configuration=config)
    h3 = H3Connection(quic)
    deadline = time.monotonic() + timeout
    status, response_headers, response_body = None, [], bytearray()
    done = handshake_done = False
    handshake = wire.begin("QUIC handshake (TLS 1.3)")
    waiting = download = None
    stream_id = None

    def flush() -> None:
        for data, _ in quic.datagrams_to_send(now=time.time()):
            sock.send(data)
            wire.segment(flow, "out", data)
            summary, fields = annotate_quic(data)
            wire.add("out", "QUIC", data, summary, fields)

    try:
        quic.connect(addr, now=time.time())
        flush()
        while not done:
            if time.monotonic() > deadline:
                raise ConnectionError_(f"HTTP/3 timed out after {timeout}s. The server may not support HTTP/3, "
                                       "or UDP port 443 may be blocked on this network.")
            timer = quic.get_timer()
            wait = 0.05 if timer is None else max(0.0, min(timer - time.time(), 0.5))
            readable, _, _ = select.select([sock], [], [], wait)
            if readable:
                try:
                    data = sock.recv(65536)
                except ConnectionRefusedError:
                    raise ConnectionError_(f"{host} refused UDP port {port}: nothing is serving HTTP/3 there")
                wire.segment(flow, "in", data)
                summary, fields = annotate_quic(data)
                wire.add("in", "QUIC", data, summary, fields)
                quic.receive_datagram(data, addr, now=time.time())
            elif timer is not None and time.time() >= timer:
                quic.handle_timer(now=time.time())

            event = quic.next_event()
            while event is not None:
                if isinstance(event, HandshakeCompleted) and not handshake_done:
                    handshake_done = True
                    wire.end(handshake)
                    wire.info("QUIC", f"Handshake complete, ALPN {event.alpn_protocol}")
                    stream_id = quic.get_next_available_stream_id()
                    req = [(b":method", method.encode()), (b":scheme", b"https"), (b":authority", authority.encode()),
                           (b":path", path.encode())]
                    req += [(k.lower().encode(), v.encode()) for k, v in headers
                            if k.lower() not in ("host", "connection", "keep-alive", "transfer-encoding", "upgrade")]
                    h3.send_headers(stream_id, req, end_stream=not body)
                    shown = [(k.decode(), v.decode()) for k, v in req]
                    wire.add("out", "HTTP/3", "\n".join(f"{k}: {v}" for k, v in shown).encode(),
                             f"HEADERS stream {stream_id} {method} {path}",
                             [Field(0, 0, name, value, 3) for name, value in shown])
                    if body:
                        h3.send_data(stream_id, body, end_stream=True)
                        wire.add("out", "HTTP/3", body, f"DATA stream {stream_id} {len(body)} bytes")
                    waiting = wire.begin("Waiting (TTFB)")
                elif isinstance(event, ConnectionTerminated):
                    raise ConnectionError_(f"The server closed the QUIC connection: {event.reason_phrase or event.error_code}")
                for h3_event in h3.handle_event(event):
                    if getattr(h3_event, "stream_id", None) != stream_id:
                        continue
                    if waiting and download is None:
                        wire.end(waiting)
                        download = wire.begin("Content download")
                    if isinstance(h3_event, HeadersReceived):
                        decoded = [(k.decode(), v.decode("latin-1")) for k, v in h3_event.headers]
                        if status is None or decoded and decoded[0] == (":status", decoded[0][1]) and decoded[0][1].startswith("1"):
                            status = int(dict(decoded).get(":status", "0"))
                            response_headers = [(k, v) for k, v in decoded if not k.startswith(":")]
                        wire.add("in", "HTTP/3", "\n".join(f"{k}: {v}" for k, v in decoded).encode(),
                                 f"HEADERS stream {stream_id} {dict(decoded).get(':status', '')}",
                                 [Field(0, 0, k, v, 3) for k, v in decoded])
                    elif isinstance(h3_event, DataReceived):
                        response_body += h3_event.data
                        check_size(len(response_body))
                        if h3_event.data:
                            wire.add("in", "HTTP/3", h3_event.data, f"DATA stream {stream_id} {len(h3_event.data)} bytes")
                    if h3_event.stream_ended:
                        done = True
                event = quic.next_event()
            flush()
        tls_info = {"version": "TLSv1.3 (QUIC)", "cipher": "", "alpn": "h3", "subject": "", "issuer": "",
                    "expires": "", "san": [], "verified": verify}
        cert = getattr(quic.tls, "_peer_certificate", None)
        if cert is not None:
            try:
                from cryptography.x509.oid import NameOID
                cn = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                org = cert.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
                tls_info.update(subject=cn[0].value if cn else "", issuer=org[0].value if org else "",
                                expires=cert.not_valid_after_utc.strftime("%b %d %H:%M:%S %Y GMT"))
            except Exception:  # certificate details are a nicety; never fail the request over them
                pass
        return status or 0, response_headers, bytes(response_body), addr[0], flow, tls_info
    finally:
        wire.end(handshake)
        for p in (waiting, download):
            if p:
                wire.end(p)
        try:
            quic.close()
            flush()
        except Exception:
            pass
        sock.close()
        wire.close_flow(flow)
