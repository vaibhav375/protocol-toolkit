"""Minimal HTTP/2 client (RFC 9113): one request per connection, frames built by hand.

Only HPACK header compression comes from the `hpack` package (its Huffman table
and dynamic table are tedious to reimplement); every frame is packed, parsed and
logged here so the Wire Inspector can show them.
"""
from __future__ import annotations

import importlib.util
import struct
from typing import List, Optional, Tuple

from .net import Connection, ConnectionError_
from .wire import Field, WireLog

# hpack is installed alongside the `h2` package; without it only HTTP/1.1 is offered
HPACK_AVAILABLE = importlib.util.find_spec("hpack") is not None

PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING, GOAWAY, WINDOW_UPDATE, CONTINUATION = range(10)
FRAME_TYPES = {DATA: "DATA", HEADERS: "HEADERS", PRIORITY: "PRIORITY", RST_STREAM: "RST_STREAM",
               SETTINGS: "SETTINGS", PUSH_PROMISE: "PUSH_PROMISE", PING: "PING", GOAWAY: "GOAWAY",
               WINDOW_UPDATE: "WINDOW_UPDATE", CONTINUATION: "CONTINUATION"}
END_STREAM, ACK, END_HEADERS, PADDED, PRIORITY_FLAG = 0x1, 0x1, 0x4, 0x8, 0x20
FLAG_NAMES = {
    DATA: {END_STREAM: "END_STREAM", PADDED: "PADDED"},
    HEADERS: {END_STREAM: "END_STREAM", END_HEADERS: "END_HEADERS", PADDED: "PADDED", PRIORITY_FLAG: "PRIORITY"},
    SETTINGS: {ACK: "ACK"}, PING: {ACK: "ACK"}, CONTINUATION: {END_HEADERS: "END_HEADERS"},
    PUSH_PROMISE: {END_HEADERS: "END_HEADERS", PADDED: "PADDED"},
}
SETTINGS_NAMES = {1: "HEADER_TABLE_SIZE", 2: "ENABLE_PUSH", 3: "MAX_CONCURRENT_STREAMS",
                  4: "INITIAL_WINDOW_SIZE", 5: "MAX_FRAME_SIZE", 6: "MAX_HEADER_LIST_SIZE",
                  8: "ENABLE_CONNECT_PROTOCOL", 9: "NO_RFC7540_PRIORITIES"}
ERROR_CODES = {0: "NO_ERROR", 1: "PROTOCOL_ERROR", 2: "INTERNAL_ERROR", 3: "FLOW_CONTROL_ERROR",
               4: "SETTINGS_TIMEOUT", 5: "STREAM_CLOSED", 6: "FRAME_SIZE_ERROR", 7: "REFUSED_STREAM",
               8: "CANCEL", 9: "COMPRESSION_ERROR", 10: "CONNECT_ERROR", 11: "ENHANCE_YOUR_CALM",
               12: "INADEQUATE_SECURITY", 13: "HTTP_1_1_REQUIRED"}
MAX_WINDOW = 2 ** 31 - 1

# Hop-by-hop headers are forbidden in HTTP/2 (RFC 9113 §8.2.2)
CONNECTION_HEADERS = {"connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade", "host"}


class HTTP2Error(ConnectionError_):
    pass


def pack_frame(ftype: int, flags: int, stream_id: int, payload: bytes = b"") -> bytes:
    return struct.pack("!I", len(payload))[1:] + struct.pack("!BBI", ftype, flags, stream_id & 0x7FFFFFFF) + payload


def flag_names(ftype: int, flags: int) -> List[str]:
    return [name for bit, name in FLAG_NAMES.get(ftype, {}).items() if flags & bit]


def describe_frame(frame: bytes, headers: Optional[List[Tuple[str, str]]] = None) -> Tuple[str, List[Field]]:
    """Summary and labelled fields for one complete frame"""
    length = int.from_bytes(frame[:3], "big")
    ftype, flags = frame[3], frame[4]
    stream_id = int.from_bytes(frame[5:9], "big") & 0x7FFFFFFF
    payload = frame[9:9 + length]
    tname = FRAME_TYPES.get(ftype, f"type {ftype}")
    flist = flag_names(ftype, flags)
    fields = [
        Field(0, 9 + length, f"{tname} frame", f"stream {stream_id}"),
        Field(0, 3, "Length", str(length), 1),
        Field(3, 1, "Type", tname, 1),
        Field(4, 1, "Flags", " | ".join(flist) or "none", 1),
        Field(5, 4, "Stream ID", str(stream_id), 1),
    ]
    detail = ""
    if ftype == SETTINGS and not flags & ACK:
        items = []
        for i in range(0, len(payload) - 5, 6):
            key, value = struct.unpack("!HI", payload[i:i + 6])
            name = SETTINGS_NAMES.get(key, f"0x{key:x}")
            items.append(f"{name}={value}")
            fields.append(Field(9 + i, 6, name, str(value), 2))
        detail = ", ".join(items)
    elif ftype == WINDOW_UPDATE and len(payload) >= 4:
        increment = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
        detail = f"+{increment:,}"
        fields.append(Field(9, 4, "Window increment", f"{increment:,}", 2))
    elif ftype in (RST_STREAM, GOAWAY) and payload:
        code = int.from_bytes(payload[-4:] if ftype == RST_STREAM else payload[4:8], "big")
        detail = ERROR_CODES.get(code, str(code))
        if ftype == GOAWAY:
            fields.append(Field(9, 4, "Last stream ID", str(int.from_bytes(payload[:4], "big") & 0x7FFFFFFF), 2))
            fields.append(Field(13, 4, "Error code", detail, 2))
            if len(payload) > 8:
                debug = payload[8:].decode("utf-8", "replace")
                fields.append(Field(17, len(payload) - 8, "Debug data", debug, 2))
                detail += f" ({debug})"
        else:
            fields.append(Field(9, 4, "Error code", detail, 2))
    elif ftype == PING:
        fields.append(Field(9, len(payload), "Opaque data", payload.hex(), 2))
    elif ftype == DATA:
        fields.append(Field(9, length, "Data", f"{length} bytes", 2))
        detail = f"{length} bytes"
    elif ftype in (HEADERS, CONTINUATION):
        fields.append(Field(9, length, "HPACK header block", f"{length} bytes compressed", 2))
        for name, value in headers or []:
            fields.append(Field(9, length, name, value, 3))
        if headers:
            status = dict(headers).get(":status") or f"{dict(headers).get(':method', '')} {dict(headers).get(':path', '')}"
            detail = f"{status}, {len(headers)} headers"
    summary = f"{tname} stream {stream_id}" + (f" [{', '.join(flist)}]" if flist else "") + (f" {detail}" if detail else "")
    return summary, fields


class HTTP2Session:
    """Sends one request on stream 1 and collects the response"""

    def __init__(self, conn: Connection, wire: WireLog):
        if not HPACK_AVAILABLE:
            raise HTTP2Error("HTTP/2 needs the 'hpack' package: pip install hpack")
        import hpack
        self.conn = conn
        self.wire = wire
        self.encoder = hpack.Encoder()
        self.decoder = hpack.Decoder()
        self.buffer = b""
        self.max_frame_size = 16384
        self.send_window = {0: 65535, 1: 65535}
        self.peer_initial_window = 65535
        self.stream_id = 1
        # response state
        self.header_block = b""
        self.response_headers: Optional[List[Tuple[str, str]]] = None
        self.trailers: List[Tuple[str, str]] = []
        self.body = bytearray()
        self.done = False
        self.first_byte_phase = None

    def _send_frame(self, ftype: int, flags: int, stream_id: int, payload: bytes = b"",
                    headers: Optional[List[Tuple[str, str]]] = None) -> None:
        frame = pack_frame(ftype, flags, stream_id, payload)
        summary, fields = describe_frame(frame, headers)
        self.wire.add("out", "HTTP/2", frame, summary, fields)
        self.conn.sendall(frame)

    def _read_exact(self, n: int) -> bytes:
        while len(self.buffer) < n:
            chunk = self.conn.recv(65536)
            if not chunk:
                raise HTTP2Error("Server closed the HTTP/2 connection")
            self.buffer += chunk
        data, self.buffer = self.buffer[:n], self.buffer[n:]
        return data

    def _read_frame(self) -> Tuple[int, int, int, bytes, bytes]:
        header = self._read_exact(9)
        length = int.from_bytes(header[:3], "big")
        payload = self._read_exact(length)
        return header[3], header[4], int.from_bytes(header[5:9], "big") & 0x7FFFFFFF, payload, header + payload

    @staticmethod
    def _strip_padding(flags: int, payload: bytes, has_priority: bool = False) -> bytes:
        if flags & PADDED:
            pad = payload[0]
            payload = payload[1:len(payload) - pad]
        if has_priority:
            payload = payload[5:]
        return payload

    def _handle_frame(self) -> None:
        ftype, flags, stream_id, payload, raw = self._read_frame()
        decoded = None
        if stream_id == self.stream_id and self.first_byte_phase is not None:
            self.wire.end(self.first_byte_phase)
            self.first_byte_phase = None

        if ftype == SETTINGS:
            if not flags & ACK:
                for i in range(0, len(payload) - 5, 6):
                    key, value = struct.unpack("!HI", payload[i:i + 6])
                    if key == 1:
                        self.encoder.header_table_size = value
                    elif key == 4:
                        # Adjust open stream windows by the change (RFC 9113 §6.9.2)
                        self.send_window[self.stream_id] += value - self.peer_initial_window
                        self.peer_initial_window = value
                    elif key == 5:
                        self.max_frame_size = value
                self._log_in(raw)
                self._send_frame(SETTINGS, ACK, 0)
                return
        elif ftype == PING and not flags & ACK:
            self._log_in(raw)
            self._send_frame(PING, ACK, 0, payload)
            return
        elif ftype == WINDOW_UPDATE:
            self.send_window[stream_id] = self.send_window.get(stream_id, 0) + (int.from_bytes(payload, "big") & 0x7FFFFFFF)
        elif ftype in (HEADERS, CONTINUATION) and stream_id == self.stream_id:
            block = self._strip_padding(flags, payload, ftype == HEADERS and bool(flags & PRIORITY_FLAG)) \
                if ftype == HEADERS else payload
            self.header_block += block
            if flags & END_HEADERS:
                decoded = self.decoder.decode(self.header_block)
                self.header_block = b""
                if self.response_headers is None or dict(decoded).get(":status", "").startswith("1"):
                    self.response_headers = decoded  # 1xx interim headers are replaced by the final ones
                else:
                    self.trailers = decoded
            if flags & END_STREAM:
                self.done = True
        elif ftype == DATA and stream_id == self.stream_id:
            self.body += self._strip_padding(flags, payload)
            if flags & END_STREAM:
                self.done = True
        elif ftype == RST_STREAM and stream_id == self.stream_id:
            self._log_in(raw)
            code = int.from_bytes(payload[:4], "big")
            raise HTTP2Error(f"Server reset the stream: {ERROR_CODES.get(code, code)}")
        elif ftype == GOAWAY:
            self._log_in(raw)
            last_stream = int.from_bytes(payload[:4], "big") & 0x7FFFFFFF
            code = int.from_bytes(payload[4:8], "big")
            if last_stream < self.stream_id or code != 0:
                raise HTTP2Error(f"Server sent GOAWAY: {ERROR_CODES.get(code, code)} "
                                 f"{payload[8:].decode('utf-8', 'replace')}")
            return
        self._log_in(raw, decoded)

    def _log_in(self, raw: bytes, headers=None) -> None:
        summary, fields = describe_frame(raw, headers)
        self.wire.add("in", "HTTP/2", raw, summary, fields)

    def request(self, method: str, scheme: str, authority: str, path: str,
                headers: List[Tuple[str, str]], body: Optional[bytes]) -> Tuple[List[Tuple[str, str]], bytes]:
        self.wire.add("out", "HTTP/2", PREFACE, "Connection preface",
                      [Field(0, len(PREFACE), "Client connection preface", "PRI * HTTP/2.0")])
        self.conn.sendall(PREFACE)
        # We never push-receive and accept up to 2 GiB without WINDOW_UPDATE round trips
        settings = struct.pack("!HI", 2, 0) + struct.pack("!HI", 4, MAX_WINDOW)
        self._send_frame(SETTINGS, 0, 0, settings)
        self._send_frame(WINDOW_UPDATE, 0, 0, struct.pack("!I", MAX_WINDOW - 65535))

        request_headers = [(":method", method), (":scheme", scheme), (":authority", authority), (":path", path)]
        for name, value in headers:
            lname = name.lower()
            if lname in CONNECTION_HEADERS or (lname == "te" and value.lower() != "trailers"):
                continue
            request_headers.append((lname, value))
        block = self.encoder.encode(request_headers)
        flags = END_HEADERS | (0 if body else END_STREAM)
        # Header blocks larger than one frame continue in CONTINUATION frames
        first, rest = block[:self.max_frame_size], block[self.max_frame_size:]
        self._send_frame(HEADERS, flags if not rest else flags & ~END_HEADERS, self.stream_id, first, request_headers)
        while rest:
            chunk, rest = rest[:self.max_frame_size], rest[self.max_frame_size:]
            self._send_frame(CONTINUATION, END_HEADERS if not rest else 0, self.stream_id, chunk)

        if body:
            view = memoryview(body)
            while view:
                allowed = min(len(view), self.max_frame_size, self.send_window[0], self.send_window[self.stream_id])
                if allowed <= 0:
                    self._handle_frame()  # wait for WINDOW_UPDATE
                    continue
                chunk, view = bytes(view[:allowed]), view[allowed:]
                self.send_window[0] -= allowed
                self.send_window[self.stream_id] -= allowed
                self._send_frame(DATA, END_STREAM if not view else 0, self.stream_id, chunk)

        self.first_byte_phase = self.wire.begin("Waiting (TTFB)")
        download = None
        while not self.done:
            self._handle_frame()
            if download is None and self.first_byte_phase is None:
                download = self.wire.begin("Content download")
        if download:
            self.wire.end(download)
        try:
            self._send_frame(GOAWAY, 0, 0, struct.pack("!II", self.stream_id, 0))
        except OSError:
            pass
        if self.response_headers is None:
            raise HTTP2Error("Stream ended without response headers")
        return self.response_headers + self.trailers, bytes(self.body)
