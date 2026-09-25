"""TCP connect scanner with banner grabbing and TLS certificate peeking.

Only scan hosts you own or have permission to test.
"""
from __future__ import annotations

import csv
import errno
import io
import json
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from typing import Callable, Dict, List, Optional

from .net import make_tls_context

OPEN, CLOSED, FILTERED = "Open", "Closed", "Filtered"

COMMON_PORTS = [
    20, 21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995,
    1025,   # MailHog / Mailpit SMTP
    1433,   # SQL Server
    3000,   # Node / dev servers
    3306,   # MySQL
    3389,   # RDP
    5000,   # Flask / dev servers
    5173,   # Vite
    5432,   # PostgreSQL
    5672,   # RabbitMQ
    6379,   # Redis
    8000, 8025, 8080, 8443, 8888, 9000, 9090, 9200, 11434, 27017,
]
TLS_PORTS = {443, 465, 636, 853, 993, 995, 8443}
EXTRA_SERVICES = {1025: "smtp (MailHog/Mailpit)", 3000: "http-dev", 5000: "http-dev", 5173: "vite",
                  6379: "redis", 8025: "mailhog/mailpit web", 9200: "elasticsearch", 11434: "ollama",
                  27017: "mongodb", 5672: "amqp"}

SIGNATURES = [  # (regex on banner, service)
    (r"^SSH-", "ssh"), (r"^220.*(SMTP|ESMTP|Postfix|Exim|MailHog|Mailpit)", "smtp"),
    (r"^220.*FTP", "ftp"), (r"^\* OK.*IMAP", "imap"), (r"^\+OK", "pop3"),
    (r"^HTTP/", "http"), (r"mysql_native_password|caching_sha2_password", "mysql"),
    (r"^-ERR|^\+PONG|redis", "redis"), (r"^RFB \d", "vnc"),
]


@dataclass
class PortResult:
    port: int
    status: str
    service: str = ""
    banner: str = ""
    tls: str = ""


def service_name(port: int) -> str:
    if port in EXTRA_SERVICES:
        return EXTRA_SERVICES[port]
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return "unknown"


def resolve(host: str) -> str:
    try:
        return socket.gethostbyname(host.strip())
    except socket.gaierror as e:
        raise ValueError(f"Could not resolve host {host}: {e}")


def probe_port(ip: str, port: int, timeout: float = 0.5, grab_banner: bool = True,
               host_name: Optional[str] = None) -> PortResult:
    """TCP connect scan of one port: Open, Closed (refused) or Filtered (no answer)"""
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    try:
        code = sock.connect_ex((ip, port))
        if code != 0:
            sock.close()
            return PortResult(port, CLOSED if code == errno.ECONNREFUSED else FILTERED)
        result = PortResult(port, OPEN, service_name(port))
        if grab_banner:
            try:
                _grab(sock, port, result, host_name or ip, max(timeout, 1.5))
            except (OSError, ssl.SSLError):
                pass
        return result
    except OSError:
        return PortResult(port, FILTERED)
    finally:
        sock.close()


def _grab(sock: socket.socket, port: int, result: PortResult, host: str, timeout: float) -> None:
    sock.settimeout(timeout)
    if port in TLS_PORTS:
        # Peek at the certificate without verifying it: we want to identify, not trust
        ctx = make_tls_context(verify=False)
        tls = ctx.wrap_socket(sock, server_hostname=host if not re.match(r"^[\d.]+$", host) else None)
        der = tls.getpeercert(binary_form=True)
        result.tls = f"{tls.version()}" + (f", cert {len(der)} bytes" if der else "")
        if port in (443, 8443):
            tls.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
        data = tls.recv(1024)
    else:
        try:
            data = sock.recv(1024)  # many services greet first (SSH, SMTP, FTP, ...)
        except socket.timeout:
            data = b""
        if not data:
            # Silent service: try HTTP, the most common thing on unknown ports
            sock.sendall(f"HEAD / HTTP/1.0\r\nHost: {host}\r\n\r\n".encode())
            data = sock.recv(1024)
    text = data.decode("utf-8", "replace").strip()
    if text.startswith("HTTP/"):
        server = re.search(r"^Server:\s*(.+)$", text, re.M | re.I)
        result.banner = text.splitlines()[0] + (f" ({server.group(1).strip()})" if server else "")
    else:
        result.banner = text.splitlines()[0][:120] if text else ""
    for pattern, service in SIGNATURES:
        if re.search(pattern, text, re.I):
            if service not in result.service:
                result.service = f"{service}" if result.service in ("unknown", "") else f"{result.service} / {service}"
            break
    if result.tls and "https" not in result.service and port in (443, 8443):
        result.service = "https"


def parse_ports(spec: str) -> List[int]:
    """'22,80,8000-8010' -> [22, 80, 8000, ..., 8010]"""
    ports = set()
    for part in spec.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        else:
            ports.add(int(part))
    if not ports or min(ports) < 1 or max(ports) > 65535:
        raise ValueError("Ports must be between 1 and 65535")
    return sorted(ports)


def scan(host: str, ports: List[int], timeout: float = 0.5, workers: int = 200, grab_banner: bool = True,
         on_result: Callable[[PortResult], None] = None,
         should_stop: Callable[[], bool] = lambda: False) -> Dict[int, PortResult]:
    """Scan concurrently. One port at a time at 0.5 s each, 1024 filtered ports take
    over 8 minutes; with 200 workers it's a few seconds."""
    ip = resolve(host)
    results: Dict[int, PortResult] = {}
    with ThreadPoolExecutor(max_workers=min(workers, len(ports)) or 1) as pool:
        futures = {pool.submit(probe_port, ip, p, timeout, grab_banner, host): p for p in ports}
        for future in as_completed(futures):
            if should_stop():
                for f in futures:
                    f.cancel()
                break
            r = future.result()
            results[r.port] = r
            if on_result:
                on_result(r)
    return results


def export(results: List[PortResult], fmt: str) -> str:
    rows = [asdict(r) for r in sorted(results, key=lambda r: r.port)]
    if fmt == "json":
        return json.dumps(rows, indent=2)
    out = io.StringIO()
    writer = csv.DictWriter(out, fieldnames=["port", "status", "service", "banner", "tls"])
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue()
