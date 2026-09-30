"""Outbound network rules for the public demo.

When the toolkit runs as a public website, visitors choose where it connects, so it could be
used to reach the host's private network (cloud metadata, internal services) - a server-side
request forgery. This guard checks the address of every outbound TCP connect and UDP send in
the process, after DNS resolution, so it also holds for redirects, DNS rebinding, MTA-STS
fetches and the assistant's tools.

Allowed: public addresses on a short list of ports, the built-in test servers on loopback,
and any port on the preset scan targets. Everything else raises BlockedAddress.
It is installed only in demo mode; the desktop app is unrestricted.
"""
from __future__ import annotations

import errno
import ipaddress
import socket
import threading
from typing import Iterable, Optional, Set

from . import net

TCP_PORTS = {53, 80, 443, 853, 8000, 8080, 8443}  # DNS, HTTP(S), DoT and common alternative web ports
UDP_PORTS = {53, 443}  # DNS and QUIC
MAX_RECEIVE = 5 * 1024 * 1024  # bytes per connection

_NAT64 = ipaddress.ip_network("64:ff9b::/96")
_6TO4 = ipaddress.ip_network("2002::/16")
_original = {}
_lock = threading.Lock()


class BlockedAddress(PermissionError):
    pass


class Policy:
    def __init__(self, loopback_ports: Iterable[int] = (), open_hosts: Iterable[str] = ()):
        self.loopback_ports: Set[int] = set(loopback_ports)
        self.open_hosts: Set[str] = set(open_hosts)  # IPs where every port may be probed (scan targets)

    def check(self, ip: str, port: int, udp: bool = False) -> Optional[str]:
        """Why this destination is blocked, or None when it is allowed"""
        try:
            addr = ipaddress.ip_address(ip.split("%")[0])
        except ValueError:
            return f"{ip} is not an IP address"
        if addr.version == 6:  # addresses that embed an IPv4 address are judged by that address
            if addr.ipv4_mapped:
                addr = addr.ipv4_mapped
            elif addr in _NAT64:
                addr = ipaddress.IPv4Address(int(addr) & 0xFFFFFFFF)
            elif addr in _6TO4:
                return f"{ip} is a 6to4 address"
        if addr.is_loopback:
            return None if port in self.loopback_ports else f"{addr} port {port} is on this server"
        if not addr.is_global or addr.is_multicast:
            return f"{addr} is a private or reserved address"
        if str(addr) in self.open_hosts:
            return None
        allowed = UDP_PORTS if udp else TCP_PORTS
        if port not in allowed:
            return f"port {port} is not one of {', '.join(map(str, sorted(allowed)))}"
        return None


_policy: Optional[Policy] = None


def _blocked(reason: str) -> BlockedAddress:
    return BlockedAddress(errno.EACCES, f"Blocked in the public demo: {reason}. "
                                        "Run the toolkit on your own machine to reach it.")


def _resolve(sock, address) -> tuple:
    """Pick an allowed IP for (host, port). Resolving here and connecting to that exact IP
    means a name can't be re-pointed at a private address between the check and the connect."""
    host, port = address[0], address[1]
    try:
        ipaddress.ip_address(host.split("%")[0])
        infos = [(sock.family, None, None, None, address)]
    except ValueError:
        infos = socket.getaddrinfo(host, port, sock.family, sock.type)
    reason = "no address"
    for *_, sockaddr in infos:
        reason = _policy.check(sockaddr[0], sockaddr[1], sock.type == socket.SOCK_DGRAM)
        if reason is None:
            return sockaddr
    raise _blocked(reason)


def _internet(sock) -> bool:
    return sock.family in (socket.AF_INET, socket.AF_INET6)


def _connect(self, address):
    if _policy and _internet(self):
        address = _resolve(self, address)
    return _original["connect"](self, address)


def _connect_ex(self, address):
    if _policy and _internet(self):
        try:
            address = _resolve(self, address)
        except BlockedAddress:
            return errno.EACCES
    return _original["connect_ex"](self, address)


def _is_loopback(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.split("%")[0]).is_loopback
    except ValueError:
        return False


def _sendto(self, data, *args):
    if _policy and _internet(self):
        address = args[-1]
        # The built-in DNS server answers visitors' queries on loopback from its own port
        replying = self.getsockname()[1] in _policy.loopback_ports and _is_loopback(address[0])
        if not replying:
            args = (*args[:-1], _resolve(self, address))
    return _original["sendto"](self, data, *args)


_PATCHES = {"connect": _connect, "connect_ex": _connect_ex, "sendto": _sendto}


def install(policy: Policy) -> None:
    global _policy
    with _lock:
        if not _original:
            for name, patch in _PATCHES.items():
                _original[name] = getattr(socket.socket, name)
                setattr(socket.socket, name, patch)
        _policy = policy
        net.MAX_RECEIVE = MAX_RECEIVE


def uninstall() -> None:
    global _policy
    with _lock:
        for name in _original:
            delattr(socket.socket, name)  # back to the methods inherited from _socket.socket
        _original.clear()
        _policy = None
        net.MAX_RECEIVE = None


def active() -> Optional[Policy]:
    return _policy
