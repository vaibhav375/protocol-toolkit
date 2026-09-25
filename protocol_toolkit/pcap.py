"""Export a capture as pcapng that Wireshark and tshark can open.

The toolkit captures bytes at the socket, not packets, so the IP and TCP/UDP headers
are rebuilt here: a TCP handshake, sequence and acknowledgement numbers, payloads split
at a typical MSS, FIN at close, and real checksums. TLS session keys go into a
Decryption Secrets Block, so Wireshark decrypts HTTPS, HTTP/2 and DoT without any
setup (QUIC keys are included too).
"""
from __future__ import annotations

import ipaddress
import struct
from typing import Dict, List, Tuple

from .wire import WireLog

LINKTYPE_RAW = 101        # raw IPv4/IPv6 packets, no link layer
SECRETS_TLS = 0x544C534B  # "TLSK": NSS key log format
MSS = 1400
FIN, SYN, PSH, ACK = 0x01, 0x02, 0x08, 0x10


def _pad4(data: bytes) -> bytes:
    return data + b"\0" * (-len(data) % 4)


def _block(block_type: int, body: bytes) -> bytes:
    length = 12 + len(_pad4(body))
    return struct.pack("<II", block_type, length) + _pad4(body) + struct.pack("<I", length)


def _checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF


def _ip_packet(src: str, dst: str, proto: int, transport: bytes, ident: int) -> bytes:
    """Wrap a TCP/UDP segment (with checksum field zeroed) in an IP header, fixing the checksum"""
    s, d = ipaddress.ip_address(src), ipaddress.ip_address(dst)
    if s.version == 4:
        pseudo = s.packed + d.packed + struct.pack("!BBH", 0, proto, len(transport))
    else:
        pseudo = s.packed + d.packed + struct.pack("!IxxxB", len(transport), proto)
    csum_at = 16 if proto == 6 else 6
    csum = _checksum(pseudo + transport) or 0xFFFF
    transport = transport[:csum_at] + struct.pack("!H", csum) + transport[csum_at + 2:]
    if s.version == 4:
        header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(transport), ident & 0xFFFF, 0x4000, 64, proto, 0,
                             s.packed, d.packed)
        header = header[:10] + struct.pack("!H", _checksum(header)) + header[12:]
        return header + transport
    return struct.pack("!IHBB16s16s", 0x60000000, len(transport), proto, 64, s.packed, d.packed) + transport


def _tcp(sport: int, dport: int, seq: int, ack: int, flags: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, seq & 0xFFFFFFFF, ack & 0xFFFFFFFF, 5 << 4, flags, 65535, 0, 0) + payload


def _udp(sport: int, dport: int, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _normalize(ip: str) -> str:
    """IPv4-mapped IPv6 addresses (::ffff:1.2.3.4) become plain IPv4"""
    addr = ipaddress.ip_address(ip.split("%")[0])
    return str(addr.ipv4_mapped) if addr.version == 6 and addr.ipv4_mapped else str(addr)


def build_packets(wire: WireLog) -> List[Tuple[float, bytes]]:
    """(seconds since start, raw IP packet) for every flow, in time order"""
    packets: List[Tuple[float, bytes]] = []
    ident = 1
    by_flow: Dict[int, list] = {}
    for seg in wire.segments:
        by_flow.setdefault(seg.flow, []).append(seg)

    for fid, flow in wire.flows.items():
        local, remote = (_normalize(flow.local[0]), flow.local[1]), (_normalize(flow.remote[0]), flow.remote[1])
        if ipaddress.ip_address(local[0]).version != ipaddress.ip_address(remote[0]).version:
            continue  # can't happen for a real socket; skip rather than write a broken packet
        segs = by_flow.get(fid, [])

        def emit(t, out, transport, proto):
            nonlocal ident
            src, dst = (local, remote) if out else (remote, local)
            packets.append((t, _ip_packet(src[0], dst[0], proto, transport, ident)))
            ident += 1

        if flow.proto == "udp":
            for seg in segs:
                out = seg.direction == "out"
                sport, dport = (local[1], remote[1]) if out else (remote[1], local[1])
                emit(seg.t, out, _udp(sport, dport, seg.data), 17)
            continue

        # TCP: synthesise the handshake and sequence numbers around the real payload
        cseq, sseq = 1000, 5000
        t0 = flow.opened
        lp, rp = local[1], remote[1]
        emit(t0, True, _tcp(lp, rp, cseq, 0, SYN), 6)
        emit(t0, False, _tcp(rp, lp, sseq, cseq + 1, SYN | ACK), 6)
        cseq, sseq = cseq + 1, sseq + 1
        emit(t0, True, _tcp(lp, rp, cseq, sseq, ACK), 6)
        for seg in segs:
            out = seg.direction == "out"
            for i in range(0, len(seg.data), MSS):
                chunk = seg.data[i:i + MSS]
                if out:
                    emit(seg.t, True, _tcp(lp, rp, cseq, sseq, PSH | ACK, chunk), 6)
                    cseq += len(chunk)
                else:
                    emit(seg.t, False, _tcp(rp, lp, sseq, cseq, PSH | ACK, chunk), 6)
                    sseq += len(chunk)
        tc = flow.closed if flow.closed is not None else (segs[-1].t if segs else t0)
        emit(tc, True, _tcp(lp, rp, cseq, sseq, FIN | ACK), 6)
        emit(tc, False, _tcp(rp, lp, sseq, cseq + 1, FIN | ACK), 6)
        emit(tc, True, _tcp(lp, rp, cseq + 1, sseq + 1, ACK), 6)

    packets.sort(key=lambda p: p[0])  # stable: packets at the same instant keep their order
    return packets


def to_pcapng(wire: WireLog, include_keys: bool = True) -> bytes:
    """The capture as a pcapng file. include_keys embeds TLS secrets for decryption."""
    out = bytearray()
    shb_opts = _option(4, b"Protocol Toolkit") + _option(0, b"")  # shb_userappl, opt_endofopt
    out += _block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1) + shb_opts)
    idb_opts = _option(2, b"toolkit") + _option(9, b"\x06") + _option(0, b"")  # if_name, if_tsresol=10^-6
    out += _block(0x00000001, struct.pack("<HHI", LINKTYPE_RAW, 0, 0) + idb_opts)
    if include_keys and wire.keylog:
        secrets = ("\n".join(wire.keylog) + "\n").encode()
        out += _block(0x0000000A, struct.pack("<II", SECRETS_TLS, len(secrets)) + secrets)
    for t, packet in build_packets(wire):
        micros = int((wire.started_wall + t) * 1_000_000)
        out += _block(0x00000006, struct.pack("<IIIII", 0, micros >> 32, micros & 0xFFFFFFFF, len(packet), len(packet)) + packet)
    return bytes(out)


def _option(code: int, value: bytes) -> bytes:
    return struct.pack("<HH", code, len(value)) + _pad4(value)


def read_pcapng(data: bytes) -> dict:
    """Minimal reader used by the tests and for sanity checks: blocks and packets"""
    pos, result = 0, {"linktype": None, "secrets": b"", "packets": []}
    while pos < len(data):
        btype, blen = struct.unpack_from("<II", data, pos)
        body = data[pos + 8:pos + blen - 4]
        if struct.unpack_from("<I", data, pos + blen - 4)[0] != blen:
            raise ValueError(f"Corrupt block at {pos}")
        if btype == 1:
            result["linktype"] = struct.unpack_from("<H", body)[0]
        elif btype == 0x0A:
            _, slen = struct.unpack_from("<II", body)
            result["secrets"] = body[8:8 + slen]
        elif btype == 6:
            _, hi, lo, caplen, _ = struct.unpack_from("<IIIII", body)
            result["packets"].append(((hi << 32 | lo) / 1e6, body[20:20 + caplen]))
        pos += blen
    return result
