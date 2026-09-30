"""Tiny local servers to test the clients against: an SMTP sink (like MailHog/Mailpit)
and an authoritative DNS server for a small editable zone.

They listen on 127.0.0.1 only, so nothing on your network can reach them.
"""
from __future__ import annotations

import email
import email.policy
import socket
import socketserver
import struct
import threading
import time
from dataclasses import dataclass
from typing import Callable, List, Optional, Tuple

from .dnsclient import RECORD_TYPES, TYPE_BY_NAME, DNSPacket, encode_name

LOCALHOST = "127.0.0.1"


class _TCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


# ---------------------------------------------------------------- SMTP sink

@dataclass
class ReceivedMail:
    received: float
    peer: str
    mail_from: str
    rcpt_to: List[str]
    raw: str
    authenticated_as: str = ""

    @property
    def message(self) -> email.message.EmailMessage:
        return email.message_from_string(self.raw, policy=email.policy.default)

    @property
    def subject(self) -> str:
        return str(self.message.get("Subject", "(no subject)"))

    def body_text(self) -> str:
        msg = self.message
        part = msg.get_body(preferencelist=("plain", "html")) if msg.is_multipart() else msg
        try:
            return part.get_content() if part else ""
        except (KeyError, LookupError):
            return part.get_payload() if part else ""


class SMTPTestServer:
    """Accepts any message (and any login) and keeps it in memory. Never relays."""

    MAX_SIZE = 10 * 1024 * 1024

    def __init__(self, port: int = 1025, on_message: Callable[[ReceivedMail], None] = lambda m: None,
                 on_log: Callable[[str], None] = lambda s: None):
        self.port = port
        self.on_message, self.on_log = on_message, on_log
        self.messages: List[ReceivedMail] = []
        self._server: Optional[_TCPServer] = None

    @property
    def running(self) -> bool:
        return self._server is not None

    def start(self) -> None:
        outer = self

        class Handler(socketserver.StreamRequestHandler):
            timeout = 120

            def w(self, line: str) -> None:
                self.wfile.write(line.encode() + b"\r\n")
                self.wfile.flush()

            def handle(self):
                peer = f"{self.client_address[0]}:{self.client_address[1]}"
                outer.on_log(f"SMTP connection from {peer}")
                self.w("220 toolkit.local ESMTP Protocol Toolkit test server")
                sender, rcpts, user = "", [], ""
                while True:
                    raw = self.rfile.readline(4096)
                    if not raw:
                        return
                    line = raw.decode("utf-8", "replace").rstrip("\r\n")
                    verb = line.split(" ", 1)[0].upper()
                    arg = line[len(verb):].strip()
                    if verb == "EHLO":
                        for text in ("250-toolkit.local greets " + (arg or "you"), f"250-SIZE {outer.MAX_SIZE}",
                                     "250-8BITMIME", "250-SMTPUTF8", "250-AUTH PLAIN LOGIN", "250 HELP"):
                            self.w(text)
                    elif verb == "HELO":
                        self.w("250 toolkit.local")
                    elif verb == "AUTH":
                        user = self.auth(arg) or user
                    elif verb == "MAIL" and arg.upper().startswith("FROM:"):
                        sender, rcpts = arg[5:].split(">")[0].strip(" <"), []
                        self.w("250 OK")
                    elif verb == "RCPT" and arg.upper().startswith("TO:"):
                        if not sender:
                            self.w("503 MAIL FROM first")
                            continue
                        rcpts.append(arg[3:].split(">")[0].strip(" <"))
                        self.w("250 OK")
                    elif verb == "DATA":
                        if not rcpts:
                            self.w("503 RCPT TO first")
                            continue
                        self.w("354 End data with <CR><LF>.<CR><LF>")
                        lines, size = [], 0
                        while True:
                            data = self.rfile.readline()
                            if not data or data == b".\r\n":
                                break
                            size += len(data)
                            # Undo dot-stuffing (RFC 5321 §4.5.2)
                            lines.append(data[1:] if data.startswith(b"..") else data)
                        if size > outer.MAX_SIZE:
                            self.w("552 Message too large")
                            continue
                        mail = ReceivedMail(time.time(), peer, sender, rcpts,
                                            b"".join(lines).decode("utf-8", "replace"), user)
                        outer.messages.append(mail)
                        outer.on_message(mail)
                        outer.on_log(f"Received \"{mail.subject}\" from {sender} for {', '.join(rcpts)}")
                        self.w(f"250 OK: queued as {len(outer.messages)}")
                        sender, rcpts = "", []
                    elif verb == "RSET":
                        sender, rcpts = "", []
                        self.w("250 OK")
                    elif verb == "NOOP":
                        self.w("250 OK")
                    elif verb == "VRFY":
                        self.w("252 Cannot verify, but will accept")
                    elif verb == "QUIT":
                        self.w("221 Bye")
                        return
                    elif verb == "STARTTLS":
                        self.w("454 TLS not available on the test server")
                    else:
                        self.w("502 Command not implemented")

            def auth(self, arg: str) -> str:
                import base64
                parts = arg.split()
                mech = parts[0].upper() if parts else ""
                try:
                    if mech == "PLAIN":
                        token = parts[1] if len(parts) > 1 else None
                        if token is None:
                            self.w("334 ")
                            token = self.rfile.readline().decode().strip()
                        user = base64.b64decode(token).split(b"\0")[1].decode()
                    elif mech == "LOGIN":
                        self.w("334 VXNlcm5hbWU6")  # "Username:"
                        user = base64.b64decode(self.rfile.readline().strip()).decode()
                        self.w("334 UGFzc3dvcmQ6")  # "Password:"
                        self.rfile.readline()
                    else:
                        self.w("504 Unrecognized authentication type")
                        return ""
                except (IndexError, ValueError):
                    self.w("501 Malformed AUTH input")
                    return ""
                self.w("235 Authentication successful (test server accepts any password)")
                return user

        try:
            self._server = _TCPServer((LOCALHOST, self.port), Handler)
        except OSError as e:
            raise OSError(f"Could not listen on {LOCALHOST}:{self.port}: {e.strerror or e}") from e
        threading.Thread(target=self._server.serve_forever, daemon=True).start()
        self.on_log(f"SMTP test server listening on {LOCALHOST}:{self.port}")

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
            self.on_log("SMTP test server stopped")


# ---------------------------------------------------------------- DNS server

DEFAULT_ZONE = """\
; name                  type   value
toolkit.test            A      127.0.0.1
toolkit.test            AAAA   ::1
toolkit.test            MX     10 mail.toolkit.test
toolkit.test            TXT    "v=spf1 ip4:127.0.0.1 -all"
mail.toolkit.test       A      127.0.0.1
www.toolkit.test        CNAME  toolkit.test
_dmarc.toolkit.test     TXT    "v=DMARC1; p=reject; rua=mailto:dmarc@toolkit.test"
_sip._tcp.toolkit.test  SRV    10 5 5060 toolkit.test
*.dev.test              A      127.0.0.1
"""


@dataclass
class ZoneRecord:
    name: str
    type: int
    value: str
    ttl: int = 300


def parse_zone(text: str) -> List[ZoneRecord]:
    """Lines of 'name TYPE value [ttl=N]'. ';' and '#' start comments."""
    records = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if '"' not in line:  # quoted TXT values may legitimately contain ';'
            line = line.split(";", 1)[0].split("#", 1)[0].strip()
        if not line or line.startswith((";", "#")):
            continue
        parts = line.split(None, 2)
        if len(parts) < 3:
            raise ValueError(f"Line {number}: expected 'name TYPE value'")
        name, rtype, value = parts[0].rstrip(".").lower(), parts[1].upper(), parts[2].strip()
        if rtype not in TYPE_BY_NAME:
            raise ValueError(f"Line {number}: unknown record type {rtype}")
        ttl = 300
        if " ttl=" in value:
            value, ttl_text = value.rsplit(" ttl=", 1)
            ttl = int(ttl_text)
        records.append(ZoneRecord(name, TYPE_BY_NAME[rtype], value.strip(), ttl))
    return records


def encode_rdata(record: ZoneRecord) -> bytes:
    t, v = record.type, record.value
    if t == 1:
        return socket.inet_pton(socket.AF_INET, v)
    if t == 28:
        return socket.inet_pton(socket.AF_INET6, v)
    if t in (2, 5, 12):
        return encode_name(v)
    if t == 15:
        pref, host = v.split(None, 1)
        return struct.pack("!H", int(pref)) + encode_name(host)
    if t == 16:
        text = v[1:-1] if len(v) >= 2 and v[0] == v[-1] == '"' else v
        data = text.encode()
        return b"".join(bytes([len(data[i:i + 255])]) + data[i:i + 255] for i in range(0, max(len(data), 1), 255))
    if t == 33:
        prio, weight, port, target = v.split()
        return struct.pack("!HHH", int(prio), int(weight), int(port)) + encode_name(target)
    raise ValueError(f"The test server can't serve {RECORD_TYPES.get(t, t)} records")


class DNSTestServer:
    """Authoritative-only DNS server over UDP and TCP for a zone you can edit"""

    def __init__(self, port: int = 10325, zone: str = DEFAULT_ZONE,
                 on_log: Callable[[str], None] = lambda s: None):
        self.port = port
        self.on_log = on_log
        self.records = parse_zone(zone)
        self.queries: List[Tuple[float, str, str, str, str]] = []  # time, peer, name, type, result
        self._udp: Optional[socket.socket] = None
        self._tcp: Optional[_TCPServer] = None
        self._stop = threading.Event()

    @property
    def running(self) -> bool:
        return self._udp is not None

    def set_zone(self, text: str) -> None:
        self.records = parse_zone(text)  # raises ValueError with a line number on mistakes

    def _match(self, name: str) -> List[ZoneRecord]:
        exact = [r for r in self.records if r.name == name]
        if exact:
            return exact
        # Wildcards match any name below them that has no records of its own (RFC 4592, simplified)
        labels = name.split(".")
        for i in range(1, len(labels)):
            wildcard = "*." + ".".join(labels[i:])
            found = [ZoneRecord(name, r.type, r.value, r.ttl) for r in self.records if r.name == wildcard]
            if found:
                return found
        return []

    def answer(self, query: bytes, peer: str = "") -> bytes:
        try:
            q = DNSPacket.from_bytes(query)
        except (ValueError, struct.error, IndexError):
            return b""
        if not q.questions:
            return b""
        qname, qtype, _ = q.questions[0]
        name = qname.lower().rstrip(".")
        answers: List[ZoneRecord] = []
        records = self._match(name)
        cname = next((r for r in records if r.type == 5), None)
        if cname and qtype != 5:
            # Follow the CNAME within our own zone, as authoritative servers do
            answers.append(cname)
            answers += [r for r in self._match(cname.value.lower().rstrip(".")) if r.type == qtype]
        else:
            answers = [r for r in records if r.type == qtype or qtype == 255]
        name_exists = bool(records) or any(r.name.endswith("." + name) for r in self.records)
        rcode = 0 if name_exists else 3
        flags = 0x8000 | 0x0400 | (q.flags & 0x0100) | rcode  # QR, AA, copy RD
        out = struct.pack("!HHHHHH", q.id, flags, 1, len(answers), 0, 0)
        out += encode_name(qname) + struct.pack("!HH", qtype, 1)
        for r in answers:
            rdata = encode_rdata(r)
            out += encode_name(r.name) + struct.pack("!HHIH", r.type, 1, r.ttl, len(rdata)) + rdata
        result = {0: f"{len(answers)} answer(s)" if answers else "NODATA", 3: "NXDOMAIN"}[rcode]
        self.queries.append((time.time(), peer, qname, RECORD_TYPES.get(qtype, str(qtype)), result))
        self.on_log(f"DNS query {qname} {RECORD_TYPES.get(qtype, qtype)} -> {result}")
        return out

    def start(self) -> None:
        self._stop.clear()
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            udp.bind((LOCALHOST, self.port))
        except OSError as e:
            udp.close()
            raise OSError(f"Could not listen on UDP {LOCALHOST}:{self.port}: {e.strerror or e}") from e
        udp.settimeout(0.5)
        self._udp = udp

        def serve_udp():
            while not self._stop.is_set():
                try:
                    data, addr = udp.recvfrom(4096)
                except socket.timeout:
                    continue
                except OSError:
                    break
                reply = self.answer(data, f"{addr[0]}:{addr[1]}")
                if reply:
                    udp.sendto(reply, addr)

        outer = self

        class TCPHandler(socketserver.BaseRequestHandler):
            def handle(self):
                sock = self.request
                sock.settimeout(10)
                while True:
                    head = sock.recv(2)
                    if len(head) < 2:
                        return
                    length = struct.unpack("!H", head)[0]
                    data = b""
                    while len(data) < length:
                        chunk = sock.recv(length - len(data))
                        if not chunk:
                            return
                        data += chunk
                    reply = outer.answer(data, f"{self.client_address[0]}:{self.client_address[1]}")
                    sock.sendall(struct.pack("!H", len(reply)) + reply)

        try:
            self._tcp = _TCPServer((LOCALHOST, self.port), TCPHandler)
        except OSError as e:
            self.stop()
            raise OSError(f"Could not listen on TCP {LOCALHOST}:{self.port}: {e.strerror or e}") from e
        threading.Thread(target=serve_udp, daemon=True).start()
        threading.Thread(target=self._tcp.serve_forever, daemon=True).start()
        self.on_log(f"DNS test server answering for {len({r.name for r in self.records})} name(s) "
                    f"on {LOCALHOST}:{self.port} (UDP and TCP)")

    def stop(self) -> None:
        self._stop.set()
        if self._udp:
            self._udp.close()
            self._udp = None
        if self._tcp:
            self._tcp.shutdown()
            self._tcp.server_close()
            self._tcp = None
        self.on_log("DNS test server stopped")


def port_in_use(port: int, host: str = LOCALHOST) -> bool:
    with socket.socket() as s:
        s.settimeout(0.3)
        return s.connect_ex((host, port)) == 0


