"""Wire capture: every byte a protocol client sends or receives, with labelled fields.

A WireLog is shared by all layers of one exchange (TCP -> TLS -> HTTP/2 -> ...),
so the Wire Inspector can show exactly what went over the network and how long
each phase took (DNS lookup, TCP connect, TLS handshake, time to first byte...).
"""
from __future__ import annotations

import base64
import struct
import threading
import time
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Tuple


@dataclass
class Field:
    """A labelled byte range inside a WireEvent's data"""
    offset: int
    length: int
    label: str
    value: str = ""
    depth: int = 0  # nesting level, for tree display


@dataclass
class WireEvent:
    t: float            # seconds since the exchange started
    direction: str      # "out" (we sent), "in" (we received), "info"
    layer: str          # "TCP", "TLS", "UDP", "HTTP/1.1", "HTTP/2", "DNS", "SMTP"
    data: bytes
    summary: str
    fields: List[Field] = field(default_factory=list)
    redacted: bool = False  # data was altered to hide a secret


@dataclass
class Phase:
    name: str
    start: float  # seconds since the exchange started
    end: Optional[float] = None

    @property
    def duration_ms(self) -> float:
        return ((self.end if self.end is not None else self.start) - self.start) * 1000


@dataclass
class Flow:
    """One transport connection (TCP) or socket (UDP) seen in an exchange"""
    id: int
    proto: str                 # "tcp" or "udp"
    local: Tuple[str, int]
    remote: Tuple[str, int]
    opened: float              # seconds since the exchange started
    closed: Optional[float] = None


@dataclass
class Segment:
    """Bytes exactly as they crossed the socket (TLS ciphertext for encrypted flows)"""
    t: float
    flow: int
    direction: str             # "out" or "in"
    data: bytes


class WireLog:
    """Thread-safe record of one exchange.

    `events` is the labelled, layered view shown in the inspector. `flows`, `segments`
    and `keylog` are the raw socket-level record used to build packet captures
    (pcapng) that Wireshark can open and, with the TLS keys, decrypt.
    """

    MAX_EVENT_BYTES = 256 * 1024  # keep the inspector responsive on big downloads

    def __init__(self, title: str = ""):
        self.title = title
        self.started = time.perf_counter()
        self.started_wall = time.time()
        self.events: List[WireEvent] = []
        self.phases: List[Phase] = []
        self.flows: Dict[int, Flow] = {}
        self.segments: List[Segment] = []
        self.keylog: List[str] = []    # NSS key log lines (SSLKEYLOGFILE format)
        self.meta: Dict[str, Any] = {}  # protocol extras, e.g. HTTP entries for HAR export
        self._lock = threading.Lock()

    # ------------------------------------------------------------ raw socket record

    def open_flow(self, proto: str, local: Tuple[str, int], remote: Tuple[str, int]) -> int:
        with self._lock:
            fid = len(self.flows) + 1
            self.flows[fid] = Flow(fid, proto, (local[0], int(local[1])), (remote[0], int(remote[1])), self.now())
        return fid

    def segment(self, flow: int, direction: str, data: bytes) -> None:
        if data:
            with self._lock:
                self.segments.append(Segment(self.now(), flow, direction, bytes(data)))

    def close_flow(self, flow: int) -> None:
        with self._lock:
            if flow in self.flows and self.flows[flow].closed is None:
                self.flows[flow].closed = self.now()

    def add_keylog(self, lines) -> None:
        with self._lock:
            for line in lines:
                line = line.strip()
                if line and not line.startswith("#") and line not in self.keylog:
                    self.keylog.append(line)

    # ------------------------------------------------------------ saving

    def to_dict(self) -> dict:
        b64 = lambda b: base64.b64encode(b).decode()
        return {
            "version": 1, "title": self.title, "started_wall": self.started_wall,
            "events": [{**{k: v for k, v in asdict(e).items() if k != "data"}, "data": b64(e.data)} for e in self.events],
            "phases": [asdict(p) for p in self.phases],
            "flows": [asdict(f) for f in self.flows.values()],
            "segments": [{"t": s.t, "flow": s.flow, "direction": s.direction, "data": b64(s.data)} for s in self.segments],
            "keylog": list(self.keylog), "meta": self.meta,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "WireLog":
        w = cls(d.get("title", ""))
        w.started_wall = d.get("started_wall", w.started_wall)
        w.events = [WireEvent(e["t"], e["direction"], e["layer"], base64.b64decode(e["data"]), e["summary"],
                              [Field(**f) for f in e.get("fields", [])], e.get("redacted", False))
                    for e in d.get("events", [])]
        w.phases = [Phase(**p) for p in d.get("phases", [])]
        w.flows = {f["id"]: Flow(f["id"], f["proto"], tuple(f["local"]), tuple(f["remote"]), f["opened"], f.get("closed"))
                   for f in d.get("flows", [])}
        w.segments = [Segment(s["t"], s["flow"], s["direction"], base64.b64decode(s["data"])) for s in d.get("segments", [])]
        w.keylog = list(d.get("keylog", []))
        w.meta = d.get("meta", {})
        return w

    def now(self) -> float:
        return time.perf_counter() - self.started

    def add(self, direction: str, layer: str, data: bytes, summary: str = "",
            fields: Optional[List[Field]] = None, redacted: bool = False) -> WireEvent:
        if len(data) > self.MAX_EVENT_BYTES:
            summary += f" (showing first {self.MAX_EVENT_BYTES:,} of {len(data):,} bytes)"
            data = data[:self.MAX_EVENT_BYTES]
        event = WireEvent(self.now(), direction, layer, bytes(data), summary or f"{len(data)} bytes",
                          fields or [], redacted)
        with self._lock:
            self.events.append(event)
        return event

    def info(self, layer: str, message: str) -> None:
        self.add("info", layer, b"", message)

    @contextmanager
    def phase(self, name: str) -> Iterator[Phase]:
        p = self.begin(name)
        try:
            yield p
        finally:
            self.end(p)

    def begin(self, name: str) -> Phase:
        p = Phase(name, self.now())
        with self._lock:
            self.phases.append(p)
        return p

    def end(self, p: Phase) -> None:
        if p.end is None:
            p.end = self.now()

    @property
    def total_ms(self) -> float:
        ends = [p.end for p in self.phases if p.end is not None] + [e.t for e in self.events]
        return max(ends, default=0.0) * 1000

    def transcript(self, max_bytes_per_event: int = 4000, layers: Optional[set] = None) -> str:
        """Human/LLM-readable text version of the exchange"""
        lines = [f"# {self.title}" if self.title else "# Exchange"]
        if self.phases:
            lines.append("Timing: " + ", ".join(f"{p.name} {p.duration_ms:.1f} ms" for p in self.phases))
        for e in self.events:
            if layers and e.layer not in layers and e.direction != "info":
                continue
            arrow = {"out": "->", "in": "<-", "info": "--"}[e.direction]
            lines.append(f"[{e.t * 1000:8.1f} ms] {arrow} {e.layer}: {e.summary}")
            if e.layer == "HTTP/2":
                # HPACK-compressed bytes are unreadable; show the decoded headers and DATA text
                for f in e.fields:
                    if f.depth == 3:
                        lines.append(f"    {f.label}: {f.value}")
                if e.data[3:4] == b"\x00" and len(e.data) > 9:
                    lines.append("    " + printable(e.data[9:9 + max_bytes_per_event]).replace("\n", "\n    "))
            elif e.data and e.layer not in ("TLS", "TCP"):
                text = printable(e.data[:max_bytes_per_event])
                lines.append("    " + text.replace("\n", "\n    "))
                if len(e.data) > max_bytes_per_event:
                    lines.append(f"    ... ({len(e.data) - max_bytes_per_event:,} more bytes)")
        return "\n".join(lines)


def printable(data: bytes) -> str:
    """Decode for display: text stays text, anything else becomes a hex dump"""
    try:
        text = data.decode("utf-8")
        if all(c.isprintable() or c in "\r\n\t" for c in text):
            return text.replace("\r\n", "\n")
    except UnicodeDecodeError:
        pass
    return hexdump(data)


def hexdump(data: bytes, width: int = 16, start: int = 0) -> str:
    rows = []
    for i in range(0, len(data), width):
        chunk = data[i:i + width]
        hexpart = " ".join(f"{b:02x}" for b in chunk)
        text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        rows.append(f"{start + i:08x}  {hexpart:<{width * 3}} {text}")
    return "\n".join(rows)


# ---------------------------------------------------------------- annotators

TLS_CONTENT_TYPES = {20: "ChangeCipherSpec", 21: "Alert", 22: "Handshake", 23: "ApplicationData"}
TLS_HANDSHAKE_TYPES = {
    1: "ClientHello", 2: "ServerHello", 4: "NewSessionTicket", 8: "EncryptedExtensions",
    11: "Certificate", 12: "ServerKeyExchange", 13: "CertificateRequest", 14: "ServerHelloDone",
    15: "CertificateVerify", 16: "ClientKeyExchange", 20: "Finished",
}
TLS_VERSIONS = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}


def annotate_tls(data: bytes) -> tuple[str, List[Field]]:
    """Label TLS records. Only record headers and plaintext handshake messages
    (ClientHello/ServerHello) are readable; everything after is encrypted."""
    fields: List[Field] = []
    names = []
    pos = 0
    while pos + 5 <= len(data):
        ctype, version, length = struct.unpack("!BHH", data[pos:pos + 5])
        tname = TLS_CONTENT_TYPES.get(ctype, f"type {ctype}")
        complete = pos + 5 + length <= len(data)
        label = f"TLS record: {tname}" + ("" if complete else " (continues in next segment)")
        fields.append(Field(pos, min(5 + length, len(data) - pos), label, f"{length} bytes"))
        fields.append(Field(pos, 1, "Content type", tname, 1))
        fields.append(Field(pos + 1, 2, "Legacy version", TLS_VERSIONS.get(version, hex(version)), 1))
        fields.append(Field(pos + 3, 2, "Length", str(length), 1))
        name = tname
        if ctype == 22 and pos + 9 <= len(data):
            htype = data[pos + 5]
            hlen = int.from_bytes(data[pos + 6:pos + 9], "big")
            hname = TLS_HANDSHAKE_TYPES.get(htype, f"handshake {htype}")
            # In TLS 1.3 only the hellos are plaintext; later handshake records are
            # wrapped in ApplicationData, so a readable type here is trustworthy
            fields.append(Field(pos + 5, 1, "Handshake type", hname, 1))
            fields.append(Field(pos + 6, 3, "Handshake length", str(hlen), 1))
            name = hname
            if htype in (1, 2):
                fields.extend(_annotate_hello(data, pos + 9, htype, min(pos + 5 + length, len(data))))
        elif ctype == 21 and pos + 7 <= len(data):
            level = {1: "warning", 2: "fatal"}.get(data[pos + 5], str(data[pos + 5]))
            fields.append(Field(pos + 5, 2, "Alert", f"{level}, code {data[pos + 6]}", 1))
            name = f"Alert ({level})"
        elif ctype == 23:
            fields.append(Field(pos + 5, min(length, len(data) - pos - 5), "Encrypted payload",
                                f"{length} bytes", 1))
        names.append(name)
        pos += 5 + length
    if pos < len(data) and not fields:
        return f"TLS continuation, {len(data)} bytes", [Field(0, len(data), "Continuation of previous record")]
    counts = {}
    for n in names:
        counts[n] = counts.get(n, 0) + 1
    summary = ", ".join(f"{n}" + (f" x{c}" if c > 1 else "") for n, c in counts.items())
    return summary or f"{len(data)} bytes", fields


TLS_EXTENSIONS = {0: "server_name (SNI)", 10: "supported_groups", 13: "signature_algorithms",
                  16: "ALPN", 43: "supported_versions", 45: "psk_key_exchange_modes", 51: "key_share",
                  23: "extended_master_secret", 35: "session_ticket", 65281: "renegotiation_info",
                  11: "ec_point_formats", 5: "status_request", 18: "signed_certificate_timestamp",
                  41: "pre_shared_key", 27: "compress_certificate", 17513: "application_settings"}


def _annotate_hello(data: bytes, pos: int, htype: int, end: int) -> List[Field]:
    """Walk a Client/ServerHello far enough to label SNI, ALPN and the TLS version"""
    fields = []
    try:
        fields.append(Field(pos, 2, "Hello version", TLS_VERSIONS.get(int.from_bytes(data[pos:pos + 2], "big"), "?"), 2))
        pos += 2
        fields.append(Field(pos, 32, "Random", data[pos:pos + 32].hex()[:16] + "...", 2))
        pos += 32
        sid_len = data[pos]
        pos += 1 + sid_len
        if htype == 1:
            cs_len = int.from_bytes(data[pos:pos + 2], "big")
            fields.append(Field(pos, 2 + cs_len, "Cipher suites", f"{cs_len // 2} offered", 2))
            pos += 2 + cs_len
            comp_len = data[pos]
            pos += 1 + comp_len
        else:
            suite = int.from_bytes(data[pos:pos + 2], "big")
            fields.append(Field(pos, 2, "Chosen cipher suite", f"0x{suite:04x}", 2))
            pos += 3
        ext_total = int.from_bytes(data[pos:pos + 2], "big")
        pos += 2
        ext_end = min(pos + ext_total, end)
        while pos + 4 <= ext_end:
            etype, elen = struct.unpack("!HH", data[pos:pos + 4])
            body = data[pos + 4:pos + 4 + elen]
            value = ""
            if etype == 0 and len(body) > 5:
                value = body[5:5 + int.from_bytes(body[3:5], "big")].decode("ascii", "replace")
            elif etype == 16 and len(body) > 2:
                protos, i = [], 2
                while i < len(body):
                    n = body[i]
                    protos.append(body[i + 1:i + 1 + n].decode("ascii", "replace"))
                    i += 1 + n
                value = ", ".join(protos)
            elif etype == 43:
                if htype == 2 and len(body) == 2:
                    value = TLS_VERSIONS.get(int.from_bytes(body, "big"), "?")
                elif len(body) > 1:
                    value = ", ".join(TLS_VERSIONS.get(int.from_bytes(body[i:i + 2], "big"), "GREASE")
                                      for i in range(1, len(body), 2))
            fields.append(Field(pos, 4 + elen, f"Extension: {TLS_EXTENSIONS.get(etype, etype)}", value, 2))
            pos += 4 + elen
    except (IndexError, struct.error):
        pass
    return fields


def annotate_http1(data: bytes) -> List[Field]:
    """Label the start line, each header, and the body of an HTTP/1.x message"""
    fields = []
    head_end = data.find(b"\r\n\r\n")
    head = data if head_end == -1 else data[:head_end]
    pos = 0
    for i, line in enumerate(head.split(b"\r\n")):
        text = line.decode("latin-1")
        if i == 0:
            fields.append(Field(pos, len(line), "Start line", text))
        elif ":" in text:
            name, value = text.split(":", 1)
            fields.append(Field(pos, len(line), f"Header: {name}", value.strip()))
        pos += len(line) + 2
    if head_end != -1:
        fields.append(Field(head_end, 4, "End of headers", "CRLF CRLF"))
        if len(data) > head_end + 4:
            fields.append(Field(head_end + 4, len(data) - head_end - 4, "Body", f"{len(data) - head_end - 4} bytes"))
    return fields


def annotate_lines(data: bytes, label: str = "Line") -> List[Field]:
    """Label each CRLF-terminated line (SMTP, banners)"""
    fields, pos = [], 0
    for line in data.split(b"\r\n"):
        if line:
            fields.append(Field(pos, len(line), label, line.decode("utf-8", "replace")))
        pos += len(line) + 2
    return fields
