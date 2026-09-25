"""Network assistant: an LLM that can call the toolkit's own clients as tools.

Read-only tools (DNS, HTTP GET/HEAD, TLS, mail check, reading the current capture) run
automatically. Anything with side effects - port scans, sending email, HTTP methods that
change data - waits for the user's approval. Every tool result is redacted and capped
before it goes back to the model, and each network call's capture goes to the Wire Inspector.
"""
from __future__ import annotations

import ipaddress
import json
import socket
import threading
from dataclasses import dataclass
from typing import Callable, Dict, Optional

from . import dnsclient, scanner, smtpclient
from .explain import redact
from .httpclient import HTTPClient
from .llm import LLMError, Provider, ToolCall, ToolSpec
from .mailcheck import DeliverabilityChecker
from .net import Connection
from .wire import WireLog

MAX_RESULT_CHARS = 6000
MAX_STEPS = 10

SYSTEM_PROMPT = """You are the assistant inside Protocol Toolkit, a desktop app for learning and \
debugging network protocols (HTTP, DNS, SMTP, TLS). You can call tools that perform real network \
operations with the toolkit's own hand-written clients.

How to work:
- When a question can be answered by looking something up, use the tools instead of guessing, \
then explain what the results mean in plain language.
- Prefer the cheapest tool that answers the question. Don't repeat a call you already made.
- Port scans, sending email and HTTP methods other than GET/HEAD need the user's approval; the app \
asks them. If they decline, carry on without it.
- Only scan hosts the user owns or clearly has permission to test.
- Quote values from tool results exactly (addresses, names, codes). Some secrets in results are
  replaced with the literal text [redacted]; never write [redacted] yourself.
- Keep answers short and concrete, with headings or bullets when there are several findings.

Local test servers the user can start from the Test Servers tab: an SMTP server on 127.0.0.1:1025 \
that catches mail, and a DNS server on 127.0.0.1:10325 serving the zone toolkit.test \
(query it with server "127.0.0.1:10325")."""


@dataclass
class Tool:
    spec: ToolSpec
    run: Callable[[dict], str]
    approval: Callable[[dict], Optional[str]] = lambda args: None  # reason string when approval is needed


def _is_local(host: str) -> bool:
    try:
        return ipaddress.ip_address(socket.gethostbyname(host)).is_loopback
    except (OSError, ValueError):
        return False


def _cap(text: str) -> str:
    text = redact(text)
    if len(text) > MAX_RESULT_CHARS:
        text = text[:MAX_RESULT_CHARS] + f"\n[truncated: {len(text) - MAX_RESULT_CHARS:,} more characters not shown]"
    return text


def build_tools(publish_wire: Callable[[WireLog], None], current_capture: Callable[[], str]) -> Dict[str, Tool]:
    """The toolkit's clients exposed as tools. publish_wire sends each capture to the inspector."""

    def dns_lookup(a):
        # Models naturally ask for several types at once ("A, MX and TXT"), so accept a list
        qtypes = a.get("type", "A")
        qtypes = [qtypes] if isinstance(qtypes, str) else list(dict.fromkeys(qtypes))[:6] or ["A"]
        wire = WireLog(f"Assistant: DNS {','.join(qtypes)} {a['name']}")
        results = []
        try:
            for qtype in qtypes:
                p = dnsclient.DNSClient().query(a["name"], qtype, a.get("server", "8.8.8.8"),
                                                a.get("transport", "UDP"), wire=wire)
                results.append(f";; {qtype} query\n{p}")
        finally:
            publish_wire(wire)
        return "\n\n".join(results)

    def dns_trace(a):
        wire = WireLog(f"Assistant: DNS trace {a['name']}")
        try:
            steps = dnsclient.DNSClient().trace(a["name"], a.get("type", "A"), wire=wire)
        finally:
            publish_wire(wire)
        out = []
        for i, (name, ip, p) in enumerate(steps, 1):
            out.append(f"step {i}: asked {name} ({ip}), {p.elapsed_ms:.0f} ms, {p.rcode_name}")
            out += [f"  {r.summary}" for r in (p.answers or [r for r in p.authorities if r.type in (2, 6)])]
        return "\n".join(out)

    def http_request(a):
        wire = WireLog(f"Assistant: {a.get('method', 'GET')} {a['url']}")
        try:
            r = HTTPClient().send(a["url"], a.get("method", "GET").upper(), a.get("headers") or {},
                                  a.get("body") or None, timeout=20, use_cookies=False, wire=wire)
        finally:
            publish_wire(wire)
        lines = [f"{r.http_version} {r.status_code} {r.status_message}".strip(), f"final URL: {r.url}"]
        lines += [f"redirect: {h.status_code} {h.url} -> {h.get_header('Location')}" for h in r.history]
        lines.append("timing: " + ", ".join(f"{p.name} {p.duration_ms:.0f} ms" for p in r.wire.phases))
        if r.tls_info:
            t = r.tls_info
            lines.append(f"tls: {t['version']} {t['cipher']} alpn={t['alpn']} cert={t['subject']} "
                         f"issuer={t['issuer']} expires={t['expires']}")
        lines += ["", "headers:"] + [f"{k}: {v}" for k, v in r.header_list]
        body = r.pretty_body() if r.body else "(empty)"
        lines += ["", f"body ({len(r.body):,} bytes):", body[:2500] + ("\n[body truncated]" if len(body) > 2500 else "")]
        return "\n".join(lines)

    def http_approval(a):
        method = a.get("method", "GET").upper()
        return None if method in ("GET", "HEAD", "OPTIONS") else f"{method} requests can change data on the server"

    def tls_certificate(a):
        host, port = a["host"], int(a.get("port", 443))
        wire = WireLog(f"Assistant: TLS {host}:{port}")
        try:
            try:
                with Connection(host, port, timeout=10, wire=wire) as conn:
                    conn.open(tls=True, alpn=["h2", "http/1.1"])
                    info, note = conn.tls_info, "certificate is valid for this host name"
            except OSError as e:
                if "certificate" not in str(e).lower():
                    raise
                with Connection(host, port, timeout=10, wire=wire) as conn:
                    conn.open(tls=True, verify=False, alpn=["h2", "http/1.1"])
                    info, note = conn.tls_info, f"CERTIFICATE PROBLEM: {e}"
        finally:
            publish_wire(wire)
        return json.dumps({**info, "verification": note}, indent=2)

    def check_email_domain(a):
        report = DeliverabilityChecker().run(a["domain"], a.get("dkim_selectors") or None,
                                             probe_smtp=bool(a.get("probe_smtp", False)))
        return report.to_text()

    def port_scan(a):
        ports = scanner.COMMON_PORTS if a.get("ports", "common") == "common" else scanner.parse_ports(a["ports"])
        if len(ports) > 2000:
            raise ValueError("At most 2000 ports per scan from the assistant")
        results = scanner.scan(a["host"], ports, 0.5)
        found = sorted((r for r in results.values() if r.status == scanner.OPEN), key=lambda r: r.port)
        lines = [f"{len(found)} open of {len(results)} scanned on {a['host']}"]
        lines += [f"{r.port}/tcp {r.service or scanner.service_name(r.port)} {r.banner}".rstrip() for r in found]
        return "\n".join(lines)

    def scan_approval(a):
        where = "your own machine" if _is_local(a["host"]) else a["host"]
        return f"Port scan of {where} ({a.get('ports', 'common')} ports)"

    def send_email(a):
        wire = WireLog(f"Assistant: SMTP {a['server']}:{a.get('port', 1025)}")
        try:
            result = smtpclient.send_email(a["server"], int(a.get("port", 1025)), a["from"], [a["to"]],
                                           a.get("subject", ""), a.get("body", ""),
                                           tls_mode=a.get("security", "none"), wire=wire)
        finally:
            publish_wire(wire)
        return f"Accepted by the server: {result}"

    def read_capture(a):
        return current_capture() or "There is no capture yet. Run a request in one of the tabs first."

    string = {"type": "string"}
    tools = [
        Tool(ToolSpec("dns_lookup", "Query a DNS resolver for records of one type. Returns the answer, authority "
                      "and additional sections with TTLs, the status (NOERROR/NXDOMAIN/...) and flags.",
                      {"type": "object", "properties": {
                          "name": {"type": "string", "description": "Domain name, or an IP address for PTR"},
                          "type": {"type": ["string", "array"], "items": {"type": "string", "enum": dnsclient.QUERY_TYPES},
                                   "enum": dnsclient.QUERY_TYPES,
                                   "description": "Record type like \"A\", or a list like [\"A\", \"MX\"]. Default A"},
                          "server": {"type": "string", "description": "Resolver IP, optionally host:port. Default 8.8.8.8"},
                          "transport": {"type": "string", "enum": dnsclient.TRANSPORTS, "description": "Default UDP"}},
                       "required": ["name"]}), dns_lookup),
        Tool(ToolSpec("dns_trace", "Resolve a name step by step from the root servers (like dig +trace) to see "
                      "which name servers are authoritative and where resolution fails.",
                      {"type": "object", "properties": {"name": string,
                                                        "type": {"type": "string", "enum": dnsclient.QUERY_TYPES}},
                       "required": ["name"]}), dns_trace),
        Tool(ToolSpec("http_request", "Send an HTTP(S) request and get the status, redirects, timing breakdown "
                      "(DNS/TCP/TLS/wait/download), TLS details, headers and the start of the body.",
                      {"type": "object", "properties": {
                          "url": string,
                          "method": {"type": "string", "enum": ["GET", "HEAD", "OPTIONS", "POST", "PUT", "PATCH", "DELETE"]},
                          "headers": {"type": "object", "additionalProperties": {"type": "string"}},
                          "body": string},
                       "required": ["url"]}), http_request, http_approval),
        Tool(ToolSpec("tls_certificate", "Connect with TLS and report the protocol version, cipher, ALPN and the "
                      "certificate's subject, issuer, expiry and names, including whether it validates.",
                      {"type": "object", "properties": {"host": string, "port": {"type": "integer"}},
                       "required": ["host"]}), tls_certificate),
        Tool(ToolSpec("check_email_domain", "Email deliverability report for a domain: MX, SPF, DMARC, DKIM, "
                      "MTA-STS, TLS-RPT, BIMI, optionally a STARTTLS test of its mail server. Sends no mail.",
                      {"type": "object", "properties": {
                          "domain": string,
                          "dkim_selectors": {"type": "array", "items": string},
                          "probe_smtp": {"type": "boolean", "description": "Also test STARTTLS on port 25 (slower)"}},
                       "required": ["domain"]}), check_email_domain),
        Tool(ToolSpec("port_scan", "TCP connect scan with banner grabbing. Needs the user's approval. Only for "
                      "hosts the user owns or may test.",
                      {"type": "object", "properties": {
                          "host": string,
                          "ports": {"type": "string", "description": "'common' or a list like 22,80,8000-8100"}},
                       "required": ["host"]}), port_scan, scan_approval),
        Tool(ToolSpec("send_email", "Send a plain-text email over SMTP (no login). Needs the user's approval. "
                      "For testing use server 127.0.0.1 port 1025 (the local test server).",
                      {"type": "object", "properties": {
                          "server": string, "port": {"type": "integer"}, "from": string, "to": string,
                          "subject": string, "body": string,
                          "security": {"type": "string", "enum": ["none", "starttls", "implicit"]}},
                       "required": ["server", "from", "to"]}), send_email,
             lambda a: f"Send an email from {a.get('from')} to {a.get('to')} via {a.get('server')}"),
        Tool(ToolSpec("read_current_capture", "Read the capture currently shown in the Wire Inspector "
                      "(the user's last request): timing plus every message sent and received.",
                      {"type": "object", "properties": {}}), read_capture),
    ]
    return {t.spec.name: t for t in tools}


def validate(args: dict, schema: dict) -> Optional[str]:
    """Minimal JSON-Schema check (required, types, enums). Returns an error message or None."""
    if not isinstance(args, dict):
        return "arguments must be an object"
    props = schema.get("properties", {})
    for key in schema.get("required", []):
        if key not in args or args[key] in (None, ""):
            return f"missing required argument '{key}'"
    types = {"string": str, "integer": int, "boolean": bool, "object": dict, "array": list}
    for key, value in args.items():
        if key not in props:
            return f"unknown argument '{key}'"
        spec = props[key]
        expected = spec.get("type")
        allowed = expected if isinstance(expected, list) else [expected]
        if "integer" in allowed and isinstance(value, str) and value.isdigit():
            args[key] = int(value)  # small models often quote numbers
            continue
        if expected and not any(t in types and isinstance(value, types[t]) for t in allowed):
            return f"argument '{key}' should be {' or '.join(allowed)}, got {type(value).__name__}"
        if isinstance(value, list):
            enum = spec.get("items", {}).get("enum")
            bad = [v for v in value if enum and v not in enum]
            if bad:
                return f"argument '{key}' has invalid values {bad}; allowed: {enum}"
        elif "enum" in spec and value not in spec["enum"]:
            return f"argument '{key}' must be one of {spec['enum']}"
    return None


class Agent:
    """Runs one conversation. Call ask() from a worker thread; callbacks report progress."""

    def __init__(self, provider: Provider, tools: Dict[str, Tool],
                 approve: Callable[[ToolCall, str], bool],
                 on_text: Callable[[str], None] = lambda s: None,
                 on_tool: Callable[[str, ToolCall, str], None] = lambda stage, call, info: None):
        self.provider = provider
        self.tools = tools
        self.approve, self.on_text, self.on_tool = approve, on_text, on_tool
        self.cancel = threading.Event()
        provider.reset(SYSTEM_PROMPT)

    def ask(self, text: str) -> str:
        self.cancel.clear()
        self.provider.add_user(text)
        specs = [t.spec for t in self.tools.values()]
        for _ in range(MAX_STEPS):
            if self.cancel.is_set():
                return "(stopped)"
            reply, calls = self.provider.step(specs, self.on_text)
            if not calls:
                return reply
            results = []
            for call in calls:
                results.append(self._run(call))
                if self.cancel.is_set():
                    break
            self.provider.add_tool_results(results)
        raise LLMError(f"Stopped after {MAX_STEPS} tool rounds without a final answer.")

    def _run(self, call: ToolCall):
        tool = self.tools.get(call.name)
        if tool is None:
            return call, f"Unknown tool '{call.name}'. Available: {', '.join(self.tools)}", True
        error = call.invalid or validate(call.args, tool.spec.parameters)
        if error:
            self.on_tool("invalid", call, error)
            return call, f"Invalid arguments ({error}); nothing was run. Fix them and try again.", True
        reason = tool.approval(call.args)
        if reason and not self.approve(call, reason):
            self.on_tool("denied", call, reason)
            return call, "The user declined this action. Do not retry it; continue without it.", True
        self.on_tool("start", call, "")
        try:
            result = _cap(tool.run(call.args))
        except Exception as e:  # tool failures go back to the model as error results
            self.on_tool("error", call, str(e))
            return call, f"Tool failed: {e}", True
        self.on_tool("done", call, result)
        return call, result, False
