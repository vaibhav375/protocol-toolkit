"""Rules for the public demo (a website anyone can open), shared by the web API and the assistant.

The network guard (guard.py) already keeps every connection on public addresses and a few
ports. These rules cover what the guard can't see: which HTTP methods may be used, where
mail may go and which hosts may be scanned.
"""
from __future__ import annotations

import threading
from typing import List, Optional

from . import guard, scanner

HTTP_METHODS = ("GET", "HEAD")
MAX_TIMEOUT = 20.0
MAX_SCAN_PORTS = 100
# Hosts whose owners invite port scans. Nmap's scanme asks for scans, not floods.
SCAN_TARGETS = {"scanme.nmap.org": "Nmap's test host; its owners allow scanning it"}

PROMPT = """

This copy of the toolkit is a public demo website, so some things are limited:
- HTTP requests may only use GET or HEAD, and only reach public addresses.
- Email can only go to the built-in test inbox (server 127.0.0.1 port {smtp}); nothing reaches real mailboxes.
- Port scans may only target: {targets}.
- The test servers are always running. There is no STARTTLS probe in mail checks.
If the user asks for something outside these limits, explain that it works when they run the toolkit on
their own computer (https://github.com/vaibhav375/protocol-toolkit)."""


class Busy(ValueError):
    """Someone else is using a shared resource; try again shortly"""


class DemoRules:
    def __init__(self, smtp_port: int, dns_port: int):
        self.smtp_port, self.dns_port = smtp_port, dns_port
        self._scan = threading.Lock()  # one scan at a time across all visitors

    def prompt(self) -> str:
        return PROMPT.format(smtp=self.smtp_port, targets=", ".join(SCAN_TARGETS))

    def info(self) -> dict:
        """What the UI needs to show only what works"""
        return {"http_methods": list(HTTP_METHODS), "scan_targets": SCAN_TARGETS, "max_scan_ports": MAX_SCAN_PORTS,
                "smtp": {"server": "127.0.0.1", "port": self.smtp_port}, "dns_test": f"127.0.0.1:{self.dns_port}"}

    def http(self, method: str, body: Optional[str] = None) -> None:
        if method.upper() not in HTTP_METHODS:
            raise ValueError(f"The public demo only sends {' and '.join(HTTP_METHODS)} requests. "
                             "Run the toolkit locally to use other methods.")
        if body:
            raise ValueError("The public demo doesn't send request bodies.")

    def smtp(self, server: str, port: int) -> None:
        if server.strip().lower() not in ("127.0.0.1", "localhost") or port != self.smtp_port:
            raise ValueError(f"In the public demo, mail can only go to the built-in test inbox "
                             f"(127.0.0.1 port {self.smtp_port}). Nothing is delivered to real mailboxes.")

    def begin_scan(self, host: str, ports: str) -> List[int]:
        """Check a scan and take the scan slot; call end_scan() when it finishes"""
        if host.strip().lower() not in SCAN_TARGETS:
            raise ValueError(f"The public demo only scans {', '.join(SCAN_TARGETS)}, whose owners allow it. "
                             "Run the toolkit locally to scan your own machines.")
        chosen = scanner.COMMON_PORTS if ports.strip() == "common" else scanner.parse_ports(ports)
        if len(chosen) > MAX_SCAN_PORTS:
            raise ValueError(f"The public demo scans at most {MAX_SCAN_PORTS} ports at a time.")
        ip = scanner.resolve(host)
        if not self._scan.acquire(blocking=False):
            raise Busy("Another visitor is scanning right now; please try again in a few seconds.")
        policy = guard.active()
        if policy:
            policy.open_hosts.add(ip)  # the network guard lets scans reach any port on this target
        return chosen

    def end_scan(self) -> None:
        self._scan.release()
