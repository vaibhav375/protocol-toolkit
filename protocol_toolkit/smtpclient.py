"""SMTP client (RFC 5321) with STARTTLS, implicit TLS and AUTH PLAIN/LOGIN."""
from __future__ import annotations

import base64
import re
import socket
from dataclasses import dataclass, field
from email.utils import formatdate, make_msgid
from typing import Callable, List, Optional

from .net import Connection, LineReader
from .wire import WireLog, annotate_lines

EMAIL_RE = re.compile(r"^[^@\s<>]+@[^@\s<>]+\.[^@\s<>]+$")
LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

# TLS modes
TLS_NONE, TLS_STARTTLS, TLS_IMPLICIT = "none", "starttls", "implicit"


class SMTPError(RuntimeError):
    pass


@dataclass
class SMTPResponse:
    code: int
    lines: List[str] = field(default_factory=list)

    @property
    def message(self) -> str:
        return " | ".join(self.lines)

    @property
    def ok(self) -> bool:
        return 200 <= self.code < 400

    def __str__(self) -> str:
        return f"{self.code} {self.message}"


class SMTPClient:
    def __init__(self, host: str = "localhost", port: int = 1025, *, timeout: float = 15.0,
                 wire: Optional[WireLog] = None, log: Callable[[str], None] = lambda s: None):
        self.host, self.port, self.timeout = host, port, timeout
        self.wire = wire or WireLog(f"SMTP {host}:{port}")
        self.log = log
        self.conn: Optional[Connection] = None
        self.reader: Optional[LineReader] = None
        self.features: dict = {}
        self.local_name = socket.getfqdn() or "localhost"

    # ------------------------------------------------------------ low level

    def _read_response(self) -> SMTPResponse:
        # Multi-line replies look like "250-first", "250-second", "250 last"
        lines, raw = [], b""
        while True:
            line = self.reader.readline()
            raw += line + b"\r\n"
            lines.append(line)
            if len(line) < 4 or line[3:4] != b"-":
                break
        try:
            code = int(lines[0][:3])
        except ValueError:
            raise SMTPError(f"Not an SMTP reply: {lines[0][:80]!r}")
        response = SMTPResponse(code, [line[4:].decode("utf-8", "replace") for line in lines])
        self.wire.add("in", "SMTP", raw, str(response)[:120], annotate_lines(raw, "Reply"))
        for text in response.lines:
            self.log(f"S: {code} {text}")
        return response

    def command(self, line: str, display: Optional[str] = None) -> SMTPResponse:
        """Send one command. `display` replaces it in logs (used to hide credentials)."""
        data = (line + "\r\n").encode("utf-8")
        shown = display or line
        self.log(f"C: {shown}")
        logged = (shown + "\r\n").encode("utf-8")
        self.wire.add("out", "SMTP", logged, shown, annotate_lines(logged, "Command"), redacted=display is not None)
        self.conn.sendall(data)
        return self._read_response()

    def expect(self, response: SMTPResponse, *codes: int, what: str = "") -> SMTPResponse:
        if (codes and response.code not in codes) or (not codes and not response.ok):
            raise SMTPError(f"{what or 'Command'} failed: {response}")
        return response

    # ------------------------------------------------------------ session

    def connect(self, tls_mode: str = TLS_NONE, verify_tls: bool = True) -> SMTPResponse:
        self.log(f"Connecting to {self.host}:{self.port}" + (" with TLS" if tls_mode == TLS_IMPLICIT else ""))
        self.conn = Connection(self.host, self.port, timeout=self.timeout, wire=self.wire)
        self.conn.open(tls=tls_mode == TLS_IMPLICIT, verify=verify_tls)
        self.reader = LineReader(self.conn)
        greeting = self.expect(self._read_response(), 220, what="Connection")
        self.ehlo()
        if tls_mode == TLS_STARTTLS:
            if "STARTTLS" not in self.features:
                raise SMTPError("Server does not offer STARTTLS")
            self.expect(self.command("STARTTLS"), 220, what="STARTTLS")
            if self.reader.buffer:
                # Bytes sent before the TLS handshake would be a STARTTLS injection attack
                raise SMTPError("Server sent data before the TLS handshake; aborting")
            self.conn.start_tls(verify=verify_tls)
            info = self.conn.tls_info
            self.log(f"TLS: {info['version']} {info['cipher']}")
            self.ehlo()  # capabilities must be re-read after STARTTLS (RFC 3207)
        return greeting

    def ehlo(self) -> SMTPResponse:
        # Prefer EHLO (ESMTP) and fall back to HELO for very old servers
        response = self.command(f"EHLO {self.local_name}")
        if response.ok:
            self.features = {}
            for line in response.lines[1:]:
                parts = line.split(None, 1)
                if parts:
                    self.features[parts[0].upper()] = parts[1] if len(parts) > 1 else ""
        else:
            self.expect(self.command(f"HELO {self.local_name}"), what="HELO")
        return response

    def login(self, username: str, password: str) -> None:
        if not self.conn.is_tls and self.host not in LOCAL_HOSTS:
            raise SMTPError("Refusing to send a password over an unencrypted connection. "
                            "Use STARTTLS or TLS (port 465), or a server on localhost.")
        mechanisms = self.features.get("AUTH", "").upper().split()
        if "PLAIN" in mechanisms or not mechanisms:
            token = base64.b64encode(f"\0{username}\0{password}".encode()).decode()
            self.expect(self.command(f"AUTH PLAIN {token}", display="AUTH PLAIN <credentials hidden>"),
                        235, what="Authentication")
        elif "LOGIN" in mechanisms:
            self.expect(self.command("AUTH LOGIN"), 334, what="AUTH LOGIN")
            self.expect(self.command(base64.b64encode(username.encode()).decode(), display="<username hidden>"),
                        334, what="AUTH LOGIN username")
            self.expect(self.command(base64.b64encode(password.encode()).decode(), display="<password hidden>"),
                        235, what="Authentication")
        else:
            raise SMTPError(f"No supported AUTH mechanism (server offers: {' '.join(mechanisms)})")
        self.log("Authenticated")

    def quit(self) -> None:
        try:
            if self.conn and self.conn.sock:
                self.command("QUIT")
        except (OSError, SMTPError):
            pass  # a failed QUIT after the message was accepted doesn't matter
        finally:
            self.close()

    def close(self) -> None:
        if self.conn:
            self.conn.close()
            self.conn = None

    # ------------------------------------------------------------ mail

    @staticmethod
    def build_message(sender: str, recipients: List[str], subject: str, body: str) -> str:
        """RFC 5322 message text, ready for the DATA phase"""
        headers = [
            f"From: {sender}",
            f"To: {', '.join(recipients)}",
            f"Subject: {subject}",
            f"Date: {formatdate(localtime=True)}",
            f"Message-ID: {make_msgid(domain=sender.split('@')[-1])}",
            "MIME-Version: 1.0",
            "Content-Type: text/plain; charset=utf-8",
            "Content-Transfer-Encoding: 8bit",
        ]
        # CRLF line endings, and "dot-stuffing": a body line starting with "." gets an
        # extra "." or a line containing just "." would end the message early
        lines = body.replace("\r\n", "\n").split("\n")
        lines = ["." + line if line.startswith(".") else line for line in lines]
        return "\r\n".join(headers) + "\r\n\r\n" + "\r\n".join(lines) + "\r\n.\r\n"

    def send_mail(self, sender: str, recipients: List[str], subject: str, body: str) -> SMTPResponse:
        if not EMAIL_RE.match(sender):
            raise ValueError(f"Invalid sender address: {sender}")
        for rcpt in recipients:
            if not EMAIL_RE.match(rcpt):
                raise ValueError(f"Invalid recipient address: {rcpt}")
        message = self.build_message(sender, recipients, subject, body).encode("utf-8")
        size = f" SIZE={len(message)}" if "SIZE" in self.features else ""
        self.expect(self.command(f"MAIL FROM:<{sender}>{size}"), what="MAIL FROM")
        for rcpt in recipients:
            self.expect(self.command(f"RCPT TO:<{rcpt}>"), what=f"RCPT TO {rcpt}")
        self.expect(self.command("DATA"), 354, what="DATA")
        self.log("C: <message content>")
        self.wire.add("out", "SMTP", message, f"Message content ({len(message)} bytes)", annotate_lines(message, "Line"))
        self.conn.sendall(message)
        return self.expect(self._read_response(), what="Message")


def send_email(host: str, port: int, sender: str, recipients: List[str], subject: str, body: str, *,
               tls_mode: str = TLS_NONE, username: str = "", password: str = "", verify_tls: bool = True,
               timeout: float = 15.0, wire: Optional[WireLog] = None,
               log: Callable[[str], None] = lambda s: None) -> SMTPResponse:
    """Run a full SMTP conversation and always close the connection"""
    client = SMTPClient(host, port, timeout=timeout, wire=wire, log=log)
    try:
        client.connect(tls_mode, verify_tls)
        if username:
            client.login(username, password)
        result = client.send_mail(sender, recipients, subject, body)
        client.quit()
        return result
    finally:
        client.close()
