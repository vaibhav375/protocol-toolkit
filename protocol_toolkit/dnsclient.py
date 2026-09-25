"""DNS client over UDP, TCP, DNS-over-TLS (RFC 7858) and DNS-over-HTTPS (RFC 8484),
plus an iterative "trace" resolver that walks from the root servers like `dig +trace`."""
from __future__ import annotations

import random
import re
import socket
import struct
import time
from dataclasses import dataclass, field
from typing import List, Optional, Tuple, Union

from .net import Connection, LineReader
from .wire import Field, WireLog

RECORD_TYPES = {
    1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA",
    33: "SRV", 41: "OPT", 43: "DS", 46: "RRSIG", 48: "DNSKEY", 64: "SVCB", 65: "HTTPS", 257: "CAA",
}
TYPE_BY_NAME = {v: k for k, v in RECORD_TYPES.items()}
QUERY_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "CAA", "HTTPS", "DS", "DNSKEY"]
RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}
TRANSPORTS = ["UDP", "TCP", "DoT", "DoH"]

# Well-known encrypted resolvers: IP -> TLS name (DoT) and DoH URL
KNOWN_RESOLVERS = {
    "1.1.1.1": ("cloudflare-dns.com", "https://cloudflare-dns.com/dns-query"),
    "1.0.0.1": ("cloudflare-dns.com", "https://cloudflare-dns.com/dns-query"),
    "8.8.8.8": ("dns.google", "https://dns.google/dns-query"),
    "8.8.4.4": ("dns.google", "https://dns.google/dns-query"),
    "9.9.9.9": ("dns.quad9.net", "https://dns.quad9.net/dns-query"),
    "149.112.112.112": ("dns.quad9.net", "https://dns.quad9.net/dns-query"),
}

ROOT_SERVERS = [("a.root-servers.net", "198.41.0.4"), ("b.root-servers.net", "170.247.170.2"),
                ("c.root-servers.net", "192.33.4.12"), ("k.root-servers.net", "193.0.14.129"),
                ("m.root-servers.net", "202.12.27.33")]


@dataclass
class DNSRecord:
    name: str
    type: int
    rclass: int
    ttl: int
    rdata: bytes
    value: object = None
    summary: str = ""

    @property
    def type_name(self) -> str:
        return RECORD_TYPES.get(self.type, f"TYPE{self.type}")


@dataclass
class DNSPacket:
    id: int = 0
    flags: int = 0
    questions: List[Tuple[str, int, int]] = field(default_factory=list)
    answers: List[DNSRecord] = field(default_factory=list)
    authorities: List[DNSRecord] = field(default_factory=list)
    additionals: List[DNSRecord] = field(default_factory=list)
    edns_udp_size: Optional[int] = None
    edns_do: bool = False
    raw: bytes = b""
    fields: List[Field] = field(default_factory=list)
    transport: str = "UDP"
    server: str = ""
    elapsed_ms: float = 0.0

    # --- flags
    rcode = property(lambda self: self.flags & 0x000F)
    truncated = property(lambda self: bool(self.flags & 0x0200))
    authoritative = property(lambda self: bool(self.flags & 0x0400))
    authenticated = property(lambda self: bool(self.flags & 0x0020))  # AD: resolver validated DNSSEC
    rcode_name = property(lambda self: RCODES.get(self.rcode, f"RCODE{self.rcode}"))

    def flag_names(self) -> List[str]:
        names = {0x8000: "QR", 0x0400: "AA", 0x0200: "TC", 0x0100: "RD", 0x0080: "RA", 0x0020: "AD", 0x0010: "CD"}
        return [n for bit, n in names.items() if self.flags & bit]

    # --- building
    @classmethod
    def query(cls, domain: str, qtype: int, recursion: bool = True, edns: bool = True,
              dnssec_ok: bool = False) -> "DNSPacket":
        # A random ID makes spoofed replies harder to match (time-based IDs are guessable)
        packet = cls(id=random.randint(0, 0xFFFF), flags=0x0100 if recursion else 0)
        packet.questions = [(domain, qtype, 1)]
        if edns:
            packet.edns_udp_size = 1232  # the DNS Flag Day 2020 recommended size
            packet.edns_do = dnssec_ok
        return packet

    def to_bytes(self) -> bytes:
        arcount = 1 if self.edns_udp_size else 0
        out = struct.pack("!HHHHHH", self.id, self.flags, len(self.questions), 0, 0, arcount)
        for name, qtype, qclass in self.questions:
            out += encode_name(name) + struct.pack("!HH", qtype, qclass)
        if self.edns_udp_size:
            # OPT pseudo-record: root name, type 41, class = UDP payload size, TTL = flags
            out += b"\x00" + struct.pack("!HHIH", 41, self.edns_udp_size, 0x8000 if self.edns_do else 0, 0)
        return out

    # --- parsing
    @classmethod
    def from_bytes(cls, data: bytes) -> "DNSPacket":
        if len(data) < 12:
            raise ValueError("DNS packet too short")
        pid, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", data[:12])
        packet = cls(id=pid, flags=flags, raw=data)
        f = packet.fields
        f.append(Field(0, 12, "Header", f"ID {pid}, {' '.join(packet.flag_names())}, {packet.rcode_name}"))
        f.append(Field(0, 2, "ID", str(pid), 1))
        f.append(Field(2, 2, "Flags", f"0x{flags:04x} {' '.join(packet.flag_names())} rcode={packet.rcode_name}", 1))
        for i, (label, n) in enumerate([("Questions", qd), ("Answers", an), ("Authority", ns), ("Additional", ar)]):
            f.append(Field(4 + i * 2, 2, f"{label} count", str(n), 1))
        offset = 12
        for _ in range(qd):
            start = offset
            qname, offset = decode_name(data, offset)
            qtype, qclass = struct.unpack("!HH", data[offset:offset + 4])
            offset += 4
            packet.questions.append((qname, qtype, qclass))
            f.append(Field(start, offset - start, "Question", f"{qname} {RECORD_TYPES.get(qtype, qtype)}"))
        for section, count, target in (("Answer", an, packet.answers), ("Authority", ns, packet.authorities),
                                       ("Additional", ar, packet.additionals)):
            for _ in range(count):
                start = offset
                record, offset = parse_record(data, offset)
                if record.type == 41:
                    packet.edns_udp_size = record.rclass
                    packet.edns_do = bool(record.ttl & 0x8000)
                    f.append(Field(start, offset - start, "EDNS (OPT)", f"UDP size {record.rclass}"))
                    continue
                target.append(record)
                f.append(Field(start, offset - start, section, record.summary))
                f.append(Field(start, offset - start - 10 - len(record.rdata), "Name", record.name, 1))
                f.append(Field(offset - 10 - len(record.rdata), 2, "Type", record.type_name, 1))
                f.append(Field(offset - 6 - len(record.rdata), 4, "TTL", f"{record.ttl} s", 1))
                f.append(Field(offset - len(record.rdata), len(record.rdata), "RDATA", str(record.value), 1))
        return packet

    def summary_line(self) -> str:
        q = self.questions[0] if self.questions else ("?", 0, 1)
        kind = "response" if self.flags & 0x8000 else "query"
        return (f"{kind} ID {self.id}: {q[0]} {RECORD_TYPES.get(q[1], q[1])} -> {self.rcode_name}, "
                f"{len(self.answers)} answer(s)" if kind == "response"
                else f"query ID {self.id}: {q[0]} {RECORD_TYPES.get(q[1], q[1])}")

    def __str__(self) -> str:
        out = [f";; {self.transport} {self.server}  {self.elapsed_ms:.0f} ms" if self.server else "",
               f";; ID {self.id}  status: {self.rcode_name}  flags: {' '.join(self.flag_names())}"
               + (f"  EDNS udp={self.edns_udp_size}" if self.edns_udp_size else "")]
        if self.authenticated:
            out.append(";; AD flag set: the resolver validated these answers with DNSSEC")
        for title, records in (("ANSWER", self.answers), ("AUTHORITY", self.authorities),
                               ("ADDITIONAL", self.additionals)):
            if records:
                out.append(f"\n;; {title} SECTION:")
                for r in records:
                    out.append(f"{r.name + '.':<32} {r.ttl:<7} {r.type_name:<7} {format_value(r)}")
        return "\n".join(line for line in out if line is not None)


def format_value(r: DNSRecord) -> str:
    v = r.value
    if r.type == 15:
        return f"{v[0]} {v[1]}."
    if r.type == 6:
        return f"{v[0]}. {v[1]}. {' '.join(map(str, v[2:]))}"
    if r.type == 16:
        return f'"{v}"'
    if r.type == 33:
        return f"{v[0]} {v[1]} {v[2]} {v[3]}."
    if r.type in (2, 5, 12):
        return f"{v}."
    return str(v)


def encode_name(name: str) -> bytes:
    out = b""
    for part in name.rstrip(".").split("."):
        if part:
            label = part.encode("idna") if not part.isascii() else part.encode("ascii")
            if len(label) > 63:
                raise ValueError(f"DNS label too long: {part}")
            out += bytes([len(label)]) + label
    return out + b"\x00"


def decode_name(data: bytes, offset: int, _depth: int = 0) -> Tuple[str, int]:
    if _depth > 20:
        raise ValueError("DNS name compression loop detected")
    parts = []
    i = offset
    while True:
        if i >= len(data):
            raise ValueError("DNS name runs past end of packet")
        length = data[i]
        i += 1
        if length & 0xC0 == 0xC0:
            pointer = ((length & 0x3F) << 8) | data[i]
            name, _ = decode_name(data, pointer, _depth + 1)
            if name:
                parts.append(name)
            i += 1
            break
        if length == 0:
            break
        parts.append(data[i:i + length].decode("utf-8", "replace"))
        i += length
    return ".".join(parts), i


def parse_record(data: bytes, offset: int) -> Tuple[DNSRecord, int]:
    name, offset = decode_name(data, offset)
    if offset + 10 > len(data):
        raise ValueError("DNS record header truncated")
    rtype, rclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset + 10])
    offset += 10
    start = offset
    rdata = data[offset:offset + rdlength]
    offset += rdlength
    r = DNSRecord(name, rtype, rclass, ttl, rdata)
    try:
        if rtype == 1 and rdlength == 4:
            r.value = socket.inet_ntop(socket.AF_INET, rdata)
        elif rtype == 28 and rdlength == 16:
            r.value = socket.inet_ntop(socket.AF_INET6, rdata)
        elif rtype in (2, 5, 12):
            r.value = decode_name(data, start)[0]
        elif rtype == 15:
            r.value = (struct.unpack("!H", rdata[:2])[0], decode_name(data, start + 2)[0])
        elif rtype == 16:
            # One or more <length><text> strings; long SPF/DKIM values are split
            strings, pos = [], 0
            while pos < len(rdata):
                n = rdata[pos]
                strings.append(rdata[pos + 1:pos + 1 + n].decode("utf-8", "replace"))
                pos += 1 + n
            r.value = "".join(strings)
        elif rtype == 6:
            mname, pos = decode_name(data, start)
            rname, pos = decode_name(data, pos)
            r.value = (mname, rname) + struct.unpack("!IIIII", data[pos:pos + 20])
        elif rtype == 33:
            prio, weight, port = struct.unpack("!HHH", rdata[:6])
            r.value = (prio, weight, port, decode_name(data, start + 6)[0])
        elif rtype == 257:
            flags, tag_len = rdata[0], rdata[1]
            r.value = f'{flags} {rdata[2:2 + tag_len].decode()} "{rdata[2 + tag_len:].decode("utf-8", "replace")}"'
        elif rtype == 43 and rdlength >= 4:
            key_tag, alg, digest_type = struct.unpack("!HBB", rdata[:4])
            r.value = f"{key_tag} {alg} {digest_type} {rdata[4:].hex()}"
        elif rtype == 48 and rdlength >= 4:
            flags, proto, alg = struct.unpack("!HBB", rdata[:4])
            role = "KSK" if flags & 1 else "ZSK"
            r.value = f"{flags} {proto} {alg} ({role}, {len(rdata) - 4} byte key)"
        elif rtype == 46 and rdlength >= 18:
            covered, alg, labels, orig_ttl, expire, incept, key_tag = struct.unpack("!HBBIIIH", rdata[:18])
            signer = decode_name(data, start + 18)[0]
            r.value = f"{RECORD_TYPES.get(covered, covered)} alg {alg} key {key_tag} signer {signer}"
        elif rtype in (64, 65) and rdlength >= 2:
            prio = struct.unpack("!H", rdata[:2])[0]
            target, _ = decode_name(data, start + 2)
            r.value = f"{prio} {target or '.'} ({rdlength} bytes of params)"
        else:
            r.value = f"\\# {rdlength} {rdata.hex()}"
    except (struct.error, IndexError, ValueError, UnicodeDecodeError):
        r.value = f"\\# {rdlength} {rdata.hex()} (could not parse)"
    r.summary = f"{name} {r.type_name} {format_value(r) if r.value is not None else ''}".strip()
    return r, offset


def reverse_name(value: str) -> str:
    """8.8.8.8 -> 8.8.8.8.in-addr.arpa, IPv6 -> nibble format under ip6.arpa"""
    try:
        socket.inet_aton(value)
        if value.count(".") == 3:
            return ".".join(reversed(value.split("."))) + ".in-addr.arpa"
    except OSError:
        pass
    try:
        packed = socket.inet_pton(socket.AF_INET6, value)
        return ".".join(reversed(packed.hex())) + ".ip6.arpa"
    except OSError:
        return value


LABEL = r"[a-zA-Z0-9_]([a-zA-Z0-9_-]{0,61}[a-zA-Z0-9])?"


def validate_domain(domain: str) -> str:
    domain = domain.strip().rstrip(".")
    try:
        domain = domain.encode("idna").decode("ascii") if not domain.isascii() else domain
    except UnicodeError:
        raise ValueError("Invalid internationalised domain name")
    # Underscores are allowed: _dmarc.example.com, selector._domainkey.example.com
    if domain and not re.match(rf"^{LABEL}(\.{LABEL})*$", domain):
        raise ValueError(f"Invalid domain name: {domain}")
    return domain


def split_server(server: str, default_port: int) -> Tuple[str, int]:
    """'1.1.1.1' -> ('1.1.1.1', 53); '127.0.0.1:10325' -> ('127.0.0.1', 10325); '[::1]:5353' -> ('::1', 5353)"""
    server = server.strip()
    m = re.match(r"^\[(.+)\]:(\d+)$", server)
    if m:
        return m.group(1), int(m.group(2))
    if server.count(":") == 1:  # host:port (a bare IPv6 address has several colons)
        host, port = server.rsplit(":", 1)
        if port.isdigit():
            return host, int(port)
    return server.strip("[]"), default_port


class DNSClient:
    PORT = 53

    def __init__(self, http_client=None):
        self._http_client = http_client

    def query(self, domain: str, qtype: Union[str, int] = "A", server: str = "8.8.8.8", transport: str = "UDP",
              timeout: float = 5.0, recursion: bool = True, dnssec_ok: bool = False,
              wire: Optional[WireLog] = None) -> DNSPacket:
        qtype_num = TYPE_BY_NAME[qtype] if isinstance(qtype, str) else qtype
        if qtype_num == 12:
            domain = reverse_name(domain.strip())
        domain = validate_domain(domain)
        wire = wire or WireLog(f"DNS {RECORD_TYPES.get(qtype_num, qtype_num)} {domain} via {transport}")
        query = DNSPacket.query(domain, qtype_num, recursion=recursion, dnssec_ok=dnssec_ok)
        payload = query.to_bytes()
        started = time.perf_counter()

        transport = transport.upper() if transport.lower() != "doh" else "DoH"
        if transport == "DOT":
            transport = "DoT"
        if transport == "UDP":
            response = self._udp(server, query, payload, timeout, wire)
            if response.truncated:
                # Too big for UDP: RFC 7766 says retry over TCP
                wire.info("DNS", "Response truncated (TC flag); retrying over TCP")
                response = self._stream(server, payload, timeout, wire, tls=False)
                transport = "UDP→TCP"
        elif transport == "TCP":
            response = self._stream(server, payload, timeout, wire, tls=False)
        elif transport == "DoT":
            response = self._stream(server, payload, timeout, wire, tls=True)
        elif transport == "DoH":
            response = self._doh(server, payload, timeout, wire)
        else:
            raise ValueError(f"Unknown transport {transport}")
        response.transport, response.server = transport, server
        response.elapsed_ms = (time.perf_counter() - started) * 1000
        return response

    @staticmethod
    def _log(wire: WireLog, direction: str, data: bytes, layer: str = "DNS", prefix_len: int = 0) -> DNSPacket:
        packet = DNSPacket.from_bytes(data[prefix_len:])
        fields = [Field(f.offset + prefix_len, f.length, f.label, f.value, f.depth) for f in packet.fields]
        if prefix_len:
            fields.insert(0, Field(0, prefix_len, "Length prefix", str(len(data) - prefix_len)))
        wire.add(direction, layer, data, packet.summary_line(), fields)
        return packet

    def _udp(self, server: str, query: DNSPacket, payload: bytes, timeout: float, wire: WireLog) -> DNSPacket:
        host, port = split_server(server, self.PORT)
        try:
            family = socket.AF_INET6 if ":" in host else socket.AF_INET
            addr = socket.getaddrinfo(host, port, family, socket.SOCK_DGRAM)[0][4]
        except socket.gaierror as e:
            raise ValueError(f"Could not resolve DNS server {host}: {e}")
        with socket.socket(family, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            self._log(wire, "out", payload, "UDP")
            with wire.phase("Query round trip"):
                sock.sendto(payload, addr)
                flow = wire.open_flow("udp", sock.getsockname()[:2], addr[:2])
                wire.segment(flow, "out", payload)
                deadline = time.time() + timeout
                while True:
                    try:
                        data, _ = sock.recvfrom(65535)
                    except ConnectionRefusedError:
                        # The OS got an ICMP "port unreachable": nothing is listening there
                        raise ConnectionRefusedError(
                            f"Nothing is listening on {host} UDP port {port}"
                            + (" (start the local DNS test server in the Test Servers tab)" if port != 53 else ""))
                    except socket.timeout:
                        hint = ("port 53 may be blocked on this network - try DoH" if port == 53
                                else "is a DNS server running on that port?")
                        raise TimeoutError(f"No answer from {host}:{port} within {timeout}s over UDP ({hint})")
                    wire.segment(flow, "in", data)
                    packet = DNSPacket.from_bytes(data)
                    # Ignore datagrams whose ID doesn't match (stale or spoofed replies)
                    if packet.id == query.id:
                        break
                    wire.info("DNS", f"Ignored reply with wrong ID {packet.id}")
                    if time.time() > deadline:
                        raise TimeoutError("No response with a matching query ID")
        wire.close_flow(flow)
        return self._log(wire, "in", data, "UDP")

    def _stream(self, server: str, payload: bytes, timeout: float, wire: WireLog, tls: bool) -> DNSPacket:
        host, port = split_server(server, 853 if tls else self.PORT)
        tls_name = KNOWN_RESOLVERS.get(host, (host, None))[0]
        conn = Connection(host, port, timeout=timeout, wire=wire)
        with conn:
            conn.open(tls=tls, server_hostname=tls_name)
            framed = struct.pack("!H", len(payload)) + payload  # 2-byte length prefix on TCP
            self._log(wire, "out", framed, "DNS", prefix_len=2)
            with wire.phase("Query round trip"):
                conn.sendall(framed)
                reader = LineReader(conn)
                (length,) = struct.unpack("!H", reader.read_exact(2))
                data = reader.read_exact(length)
        return self._log(wire, "in", struct.pack("!H", length) + data, "DNS", prefix_len=2)

    def _doh(self, server: str, payload: bytes, timeout: float, wire: WireLog) -> DNSPacket:
        from .httpclient import HTTPClient
        url = server if server.startswith("https://") else KNOWN_RESOLVERS.get(server, (None, None))[1]
        if not url:
            url = f"https://{server}/dns-query"
        self._log(wire, "out", payload, "DNS")
        client = self._http_client or HTTPClient()
        response = client.send(url, "POST", {"Content-Type": "application/dns-message",
                                             "Accept": "application/dns-message"},
                               payload, timeout=timeout, use_cookies=False, wire=wire)
        if response.status_code != 200:
            raise RuntimeError(f"DoH server returned HTTP {response.status_code} {response.status_message}")
        return self._log(wire, "in", response.body, "DNS")

    # ------------------------------------------------------------ trace

    def trace(self, domain: str, qtype: str = "A", timeout: float = 4.0,
              wire: Optional[WireLog] = None) -> List[Tuple[str, str, DNSPacket]]:
        """Resolve iteratively from the root like `dig +trace`.
        Returns [(server name, server ip, response)] for every step."""
        qnum = TYPE_BY_NAME[qtype]
        name = reverse_name(domain) if qnum == 12 else domain
        wire = wire or WireLog(f"DNS trace {qtype} {domain}")
        servers = list(ROOT_SERVERS)
        random.shuffle(servers)
        steps: List[Tuple[str, str, DNSPacket]] = []
        for _ in range(16):
            response = None
            for ns_name, ns_ip in servers[:3]:
                wire.info("DNS", f"Asking {ns_name} ({ns_ip})")
                try:
                    response = self.query(name, qnum, ns_ip, "UDP", timeout, recursion=False, wire=wire)
                    break
                except (OSError, TimeoutError, ValueError) as e:
                    wire.info("DNS", f"{ns_name} failed: {e}")
            if response is None:
                raise RuntimeError("No name server in the referral answered")
            steps.append((ns_name, ns_ip, response))
            if response.answers or response.rcode != 0:
                return steps
            referral = [r for r in response.authorities if r.type == 2]
            if not referral:
                return steps  # NODATA: the name exists but has no record of this type
            glue = {r.name.lower(): r.value for r in response.additionals if r.type == 1}
            next_servers = [(r.value, glue[r.value.lower()]) for r in referral if r.value.lower() in glue]
            if not next_servers:
                # No glue records: look up a name server's address separately
                ns = referral[0].value
                wire.info("DNS", f"No glue for {ns}; resolving it with a recursive lookup")
                lookup = self.query(ns, "A", "8.8.8.8", "UDP", timeout)
                addresses = [r.value for r in lookup.answers if r.type == 1]
                if not addresses:
                    raise RuntimeError(f"Could not find an address for name server {ns}")
                next_servers = [(ns, addresses[0])]
            random.shuffle(next_servers)
            servers = next_servers
        raise RuntimeError("Too many referrals")

    # ------------------------------------------------------------ helpers

    def lookup(self, domain: str, qtype: str, server: str = "8.8.8.8", transport: str = "UDP",
               timeout: float = 5.0) -> List[DNSRecord]:
        """Answers of one type, following nothing; empty on NXDOMAIN/NODATA"""
        response = self.query(domain, qtype, server, transport, timeout)
        return [r for r in response.answers if r.type == TYPE_BY_NAME[qtype]]

