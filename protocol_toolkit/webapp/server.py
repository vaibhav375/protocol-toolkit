"""Web backend for the React UI. It runs in one of two modes.

Desktop (the default): everything runs on this machine. The browser talks only to 127.0.0.1,
and this server runs the toolkit's own protocol clients. A local server that can scan ports
and send mail is attractive to malicious web pages, so every request must:
  * carry the per-launch secret (cookie set from the launch URL, or an X-Token header),
  * use a Host header of 127.0.0.1/localhost (blocks DNS-rebinding attacks), and
  * come from our own origin if it has an Origin header (blocks cross-site requests).

Public demo (PT_DEMO=1): a website anyone can open.
  * Each visitor gets a private session (captures, cookies, test inbox, assistant key), kept in
    memory only and dropped when idle.
  * Outbound connections may only reach public addresses and a few ports (guard.py), and
    demo.py limits HTTP methods, where mail goes and what may be scanned.
  * Requests are rate limited per visitor and overall.
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import itertools
import json
import os
import re
import sys
import secrets
import threading
import time
from collections import OrderedDict, deque
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from .. import __version__, dnsclient, guard, llm, scanner, smtpclient
from ..agent import SYSTEM_PROMPT, Agent, build_tools
from ..demo import Busy, DemoRules
from ..explain import redact
from ..har import has_http, to_har
from ..pcap import to_pcapng
from ..httpclient import HTTPClient
from ..mailcheck import DeliverabilityChecker
from ..testservers import DEFAULT_ZONE, DNSTestServer, SMTPTestServer, port_in_use
from ..wire import WireLog

STATIC_DIR = Path(__file__).parent / "static"
COOKIE = "pt_token"
SESSION_COOKIE = "pt_session"
MAX_EVENT_BYTES = 64 * 1024  # bytes per wire event sent to the browser
MAX_BODY_CHARS = 1_000_000

# Public demo limits
DEMO_SESSIONS = 40              # visitors kept in memory; the least recently active are dropped first
DEMO_IDLE_SECONDS = 30 * 60
DEMO_CAPTURES = 30              # captures per visitor
DEMO_CAPTURE_BYTES = 6 * 1024 * 1024
PER_MINUTE, CONCURRENT = 30, 3              # actions per visitor
GLOBAL_PER_MINUTE, GLOBAL_CONCURRENT = 600, 16
MAX_REQUEST_BYTES = 256 * 1024
# Scripts and connections only to this site; inline styles are needed by the animation library
DEMO_CSP = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; "
            "font-src 'self' data:; connect-src 'self' {ws}://{host}; frame-ancestors 'none'; base-uri 'none'; form-action 'self'")
HOST_CHARS = re.compile(r"[A-Za-z0-9.\-]+(:\d{1,5})?|\[[0-9A-Fa-f:.]+\](:\d{1,5})?")
ACTIONS = {"/api/http", "/api/dns", "/api/dns/trace", "/api/smtp", "/api/mailcheck", "/api/scan"}


# ---------------------------------------------------------------- live events

class EventHub:
    """Fan-out of live events to every connected browser (thread-safe publish)"""

    def __init__(self):
        self._subs: List[tuple] = []
        self._lock = threading.Lock()

    def subscribe(self) -> "asyncio.Queue":
        queue: asyncio.Queue = asyncio.Queue(maxsize=1000)
        with self._lock:
            self._subs.append((asyncio.get_running_loop(), queue))
        return queue

    def unsubscribe(self, queue) -> None:
        with self._lock:
            self._subs = [s for s in self._subs if s[1] is not queue]

    def publish(self, event: dict) -> None:
        with self._lock:
            subs = list(self._subs)
        for loop, queue in subs:
            try:
                loop.call_soon_threadsafe(self._put, queue, event)
            except RuntimeError:
                pass  # loop closed

    @staticmethod
    def _put(queue, event):
        if not queue.full():
            queue.put_nowait(event)


def default_data_dir() -> Path:
    if os.environ.get("PT_DATA_DIR"):
        return Path(os.environ["PT_DATA_DIR"])
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "Protocol Toolkit"
    return Path(os.environ.get("XDG_DATA_HOME", Path.home() / ".local" / "share")) / "protocol-toolkit"


def wire_size(wire: WireLog) -> int:
    return sum(len(e.data) for e in wire.events) + sum(len(s.data) for s in wire.segments)


class WireStore:
    """Captures, newest last. On the desktop each one is also saved to disk, so sessions survive
    restarts; the public demo keeps them in memory within a byte budget."""

    def __init__(self, hub: EventHub, data_dir: Optional[Path] = None, keep: int = 200,
                 max_bytes: Optional[int] = None):
        self.hub, self.keep, self.max_bytes = hub, keep, max_bytes
        self.items: "OrderedDict[int, dict]" = OrderedDict()
        self._lock = threading.Lock()
        self.dir = (data_dir / "captures") if data_dir else None
        if self.dir:
            self.dir.mkdir(parents=True, exist_ok=True)
            os.chmod(self.dir, 0o700)  # captures can contain private traffic
            self._load()
        self._ids = itertools.count(max(self.items, default=0) + 1)

    def _load(self) -> None:
        for path in sorted(self.dir.glob("*.json"))[-self.keep:]:
            try:
                saved = json.loads(path.read_text())
                wire = WireLog.from_dict(saved["wire"])
                self.items[saved["id"]] = {"wire": wire, "source": saved["source"], "created": saved["created"],
                                           "size": wire_size(wire)}
            except (OSError, ValueError, KeyError, TypeError):
                continue  # skip a damaged file rather than refusing to start

    def _path(self, wid: int) -> Optional[Path]:
        return self.dir / f"{wid:07d}.json" if self.dir else None

    def _over(self) -> bool:
        if len(self.items) > self.keep:
            return True
        return (self.max_bytes is not None and len(self.items) > 1
                and sum(i["size"] for i in self.items.values()) > self.max_bytes)

    def add(self, wire: WireLog, source: str) -> int:
        with self._lock:
            wid = next(self._ids)
            item = {"wire": wire, "source": source, "created": time.time(), "size": wire_size(wire)}
            self.items[wid] = item
            dropped = []
            while self._over():
                dropped.append(self.items.popitem(last=False)[0])
        if self.dir:
            path = self._path(wid)
            path.write_text(json.dumps({"id": wid, "source": source, "created": item["created"], "wire": wire.to_dict()}))
            os.chmod(path, 0o600)
            for old in dropped:
                self._path(old).unlink(missing_ok=True)
        self.hub.publish({"type": "wire", "wire": self.summary(wid)})
        return wid

    def get(self, wid: int) -> WireLog:
        if wid not in self.items:
            raise HTTPException(404, "That capture is no longer kept; run the request again.")
        return self.items[wid]["wire"]

    def delete(self, wid: int) -> None:
        with self._lock:
            self.items.pop(wid, None)
        if self.dir:
            self._path(wid).unlink(missing_ok=True)

    def clear(self) -> None:
        with self._lock:
            ids = list(self.items)
            self.items.clear()
        for wid in ids:
            if self.dir:
                self._path(wid).unlink(missing_ok=True)

    def summary(self, wid: int) -> dict:
        item = self.items[wid]
        wire: WireLog = item["wire"]
        events = [{"t": round(e.t * 1000, 2), "direction": e.direction, "layer": e.layer, "size": len(e.data),
                   "summary": e.summary, "sample": base64.b64encode(e.data[:48]).decode()}
                  for e in wire.events]
        return {"id": wid, "title": wire.title, "source": item["source"], "created": item["created"],
                "total_ms": round(wire.total_ms, 2), "phases": phases(wire), "events": events,
                "layers": sorted({e.layer for e in wire.events if e.direction != "info"}),
                "exports": {"pcapng": bool(wire.flows), "har": has_http(wire), "keys": bool(wire.keylog)}}

    def detail(self, wid: int) -> dict:
        wire = self.get(wid)
        out = self.summary(wid)
        out["events"] = [{
            "i": i, "t": round(e.t * 1000, 2), "direction": e.direction, "layer": e.layer, "size": len(e.data),
            "summary": e.summary, "redacted": e.redacted, "truncated": len(e.data) > MAX_EVENT_BYTES,
            "data": base64.b64encode(e.data[:MAX_EVENT_BYTES]).decode(),
            "fields": [{"offset": f.offset, "length": f.length, "label": f.label, "value": f.value, "depth": f.depth}
                       for f in e.fields],
        } for i, e in enumerate(wire.events)]
        out["transcript"] = wire.transcript()
        return out


def phases(wire: WireLog) -> list:
    return [{"name": p.name, "start": round(p.start * 1000, 2), "ms": round(p.duration_ms, 2)} for p in wire.phases]


# ---------------------------------------------------------------- sessions

class Session:
    """One person's state: the desktop has exactly one, the public demo one per visitor"""

    def __init__(self, sid: str, data_dir: Optional[Path] = None, keep: int = 200,
                 max_bytes: Optional[int] = None):
        self.id = sid
        self.hub = EventHub()
        self.wires = WireStore(self.hub, data_dir, keep, max_bytes)
        self.http = HTTPClient()  # its cookie jar belongs to this person
        self.api_key = ""         # memory only, never written to disk
        self.scans: Dict[str, threading.Event] = {}
        self.inbox: list = []     # demo: mail this visitor sent to the shared test server
        self.dns_log: List[str] = []  # demo: this visitor's queries to the test DNS server
        self.seen = time.monotonic()
        self.actions: deque = deque()  # times of recent actions, for rate limiting
        self.running = 0

    def close(self) -> None:
        for stop in list(self.scans.values()):
            stop.set()


class SessionStore:
    """Public-demo visitors, in memory only. Idle sessions expire; when full, the least
    recently active visitor's session is dropped."""

    def __init__(self, limit: int = DEMO_SESSIONS, idle: float = DEMO_IDLE_SECONDS):
        self.limit, self.idle = limit, idle
        self._items: "OrderedDict[str, Session]" = OrderedDict()
        self._lock = threading.Lock()

    def _drop_oldest(self) -> None:
        self._items.popitem(last=False)[1].close()

    def _expire(self) -> None:
        cutoff = time.monotonic() - self.idle
        while self._items and next(iter(self._items.values())).seen < cutoff:
            self._drop_oldest()

    def create(self) -> Session:
        with self._lock:
            self._expire()
            while len(self._items) >= self.limit:
                self._drop_oldest()
            session = Session(secrets.token_urlsafe(24), keep=DEMO_CAPTURES, max_bytes=DEMO_CAPTURE_BYTES)
            self._items[session.id] = session
            return session

    def get(self, sid: Optional[str]) -> Optional[Session]:
        with self._lock:
            self._expire()
            session = self._items.get(sid or "")
            if session:
                session.seen = time.monotonic()
                self._items.move_to_end(session.id)
            return session

    def __len__(self) -> int:
        return len(self._items)


def split_host(host: str) -> Tuple[str, Optional[int]]:
    if host.startswith("["):
        name, _, rest = host.partition("]")
        port = rest[1:] if rest.startswith(":") else ""
        name += "]"
    else:
        name, _, port = host.partition(":") if host.count(":") == 1 else (host, "", "")
    return name.lower(), int(port) if port.isdigit() else None


def is_loopback(name: str) -> bool:
    if name == "localhost":
        return True
    try:
        return ipaddress.ip_address(name.strip("[]")).is_loopback
    except ValueError:
        return False


# ---------------------------------------------------------------- request models

class HTTPIn(BaseModel):
    url: str
    method: str = "GET"
    headers: Dict[str, str] = {}
    body: Optional[str] = None
    http_version: str = "auto"
    verify_tls: bool = True
    follow_redirects: bool = True
    use_cookies: bool = True
    timeout: float = 15


class DNSIn(BaseModel):
    name: str
    type: str = "A"
    server: str = "8.8.8.8"
    transport: str = "UDP"
    dnssec: bool = False


class SMTPIn(BaseModel):
    server: str
    port: int = 1025
    sender: str = Field(alias="from")
    to: List[str]
    subject: str = ""
    body: str = ""
    security: str = "none"
    username: str = ""
    password: str = ""
    verify_tls: bool = True


class MailIn(BaseModel):
    domain: str
    selectors: List[str] = []
    probe_smtp: bool = False


class ScanIn(BaseModel):
    host: str
    ports: str = "common"
    timeout: float = 0.5
    banners: bool = True


class ServerIn(BaseModel):
    port: Optional[int] = None


class ZoneIn(BaseModel):
    zone: str


class SettingsIn(BaseModel):
    api_key: str = ""


# ---------------------------------------------------------------- app

def create_app(token: Optional[str] = None, allowed_ports: Optional[set] = None,
               data_dir: Optional[Path] = None, *, demo: bool = False,
               public_hosts: Iterable[str] = (), demo_ports: Tuple[int, int] = (1025, 10325)) -> FastAPI:
    """demo=True builds the public website. public_hosts are the host names it answers to
    (loopback when empty, for trying the demo locally); demo_ports are the SMTP and DNS
    test servers' ports."""
    token = token or secrets.token_urlsafe(24)
    state: Dict[str, Any] = {"smtp": None, "dns": None, "ollama": None, "zone": DEFAULT_ZONE}
    rules = DemoRules(*demo_ports) if demo else None
    policy = guard.Policy(loopback_ports=demo_ports) if demo else None
    public_hosts = {h.strip().lower() for h in public_hosts if h.strip()} or {"127.0.0.1", "localhost", "[::1]"}
    sessions = SessionStore() if demo else None
    local = None if demo else Session("local", data_dir if data_dir is not None else default_data_dir())
    limits = {"actions": deque(), "running": 0, "lock": threading.Lock(), "claim": threading.Lock()}

    @asynccontextmanager
    async def lifespan(_app):
        if demo:
            guard.install(policy)
            # Always on and shared; each visitor only sees the mail and queries they sent
            state["smtp"] = SMTPTestServer(demo_ports[0])
            state["dns"] = DNSTestServer(demo_ports[1], DEFAULT_ZONE)
            state["smtp"].start()
            state["dns"].start()
        try:
            yield
        finally:
            # Stop the test servers and any Ollama we started when the toolkit exits
            for key in ("smtp", "dns"):
                if state[key] and state[key].running:
                    state[key].stop()
            if state["ollama"] and state["ollama"].poll() is None:
                state["ollama"].terminate()
            if demo:
                guard.uninstall()

    app = FastAPI(title="Protocol Toolkit", version=__version__, docs_url=None, redoc_url=None, openapi_url=None,
                  lifespan=lifespan)
    app.state.token = token
    app.state.allowed_ports = allowed_ports  # set by the launcher once the port is known
    app.state.demo = demo
    app.state.sessions = sessions

    # ------------------------------------------------------------ security

    def host_ok(host: str) -> bool:
        name, port = split_host(host)
        if demo:
            return HOST_CHARS.fullmatch(host) is not None and name in public_hosts
        if name not in ("127.0.0.1", "localhost", "[::1]"):
            return False
        return app.state.allowed_ports is None or port in app.state.allowed_ports

    dev_origin = os.environ.get("PT_DEV_ORIGIN")  # e.g. http://localhost:5173 for `npm run dev`

    def origin_ok(origin: Optional[str], host: str) -> bool:
        if origin is None or (dev_origin is not None and origin == dev_origin):
            return True
        if demo and not is_loopback(split_host(host)[0]):
            return origin == f"https://{host}"
        return origin == f"http://{host}"

    def authorized(headers, cookies) -> bool:
        supplied = headers.get("x-token") or cookies.get(COOKIE) or ""
        return secrets.compare_digest(supplied, token)

    def find_session(headers, cookies) -> Optional[Session]:
        if demo:
            return sessions.get(cookies.get(SESSION_COOKIE))
        return local if authorized(headers, cookies) else None

    def admit(s: Session) -> Optional[str]:
        """Take a slot for one action, or say why not (public demo only)"""
        now = time.monotonic()
        with limits["lock"]:
            for q in (s.actions, limits["actions"]):
                while q and q[0] < now - 60:
                    q.popleft()
            if len(s.actions) >= PER_MINUTE:
                return "That's a lot of requests for the public demo; please wait a minute."
            if s.running >= CONCURRENT:
                return "Wait for your other requests to finish first."
            if len(limits["actions"]) >= GLOBAL_PER_MINUTE or limits["running"] >= GLOBAL_CONCURRENT:
                return "The demo is busy right now; please try again in a minute."
            s.actions.append(now)
            limits["actions"].append(now)
            s.running += 1
            limits["running"] += 1
        return None

    def release(s: Session) -> None:
        with limits["lock"]:
            s.running -= 1
            limits["running"] -= 1

    expired = ("Your demo session has expired. Reload the page to start a new one." if demo
               else "Open the toolkit from the link printed when it started.")

    @app.middleware("http")
    async def guard_requests(request: Request, call_next):
        path = request.url.path
        if demo and path == "/healthz":  # the host's health check
            return JSONResponse({"ok": True})
        host = request.headers.get("host", "")
        if not host_ok(host):
            return JSONResponse({"detail": "Blocked: unexpected Host header"}, status_code=403)
        if not origin_ok(request.headers.get("origin"), host):
            return JSONResponse({"detail": "Blocked: cross-site request"}, status_code=403)
        size = request.headers.get("content-length", "0")
        if demo and (not size.isdigit() or int(size) > MAX_REQUEST_BYTES):
            return JSONResponse({"detail": "Request too large for the public demo"}, status_code=413)
        counted = None
        if path.startswith("/api/"):
            session = find_session(request.headers, request.cookies)
            if session is None:
                return JSONResponse({"detail": expired}, status_code=401)
            request.state.session = session
            if demo and request.method == "POST" and path in ACTIONS:
                refusal = admit(session)
                if refusal:
                    return JSONResponse({"detail": refusal}, status_code=429)
                counted = session
        try:
            response = await call_next(request)
        finally:
            if counted:
                release(counted)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if demo:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
            ws = "ws" if is_loopback(split_host(host)[0]) else "wss"
            response.headers["Content-Security-Policy"] = DEMO_CSP.format(ws=ws, host=host)
        return response

    def sess(request: Request) -> Session:
        return request.state.session

    def claim(s: Session, wire: WireLog) -> None:
        """Public demo: move the mail and DNS queries this capture sent to the shared test
        servers into the visitor's session, matched by the connection's local port."""
        ports = {"smtp": set(), "dns": set()}
        for flow in wire.flows.values():
            if is_loopback(flow.remote[0]):
                if flow.remote[1] == demo_ports[0]:
                    ports["smtp"].add(flow.local[1])
                elif flow.remote[1] == demo_ports[1]:
                    ports["dns"].add(flow.local[1])

        def from_ports(peer: str, wanted: set) -> bool:
            return peer.rpartition(":")[2].isdigit() and int(peer.rpartition(":")[2]) in wanted

        with limits["claim"]:
            smtp, dns = state["smtp"], state["dns"]
            mine = [m for m in smtp.messages if from_ports(m.peer, ports["smtp"])] if ports["smtp"] else []
            queries = [q for q in dns.queries if from_ports(q[1], ports["dns"])] if ports["dns"] else []
            smtp.messages[:] = [m for m in smtp.messages if m not in mine][-100:]
            dns.queries[:] = [q for q in dns.queries if q not in queries][-200:]
        for m in mine:
            s.inbox.append(m)
            s.hub.publish({"type": "mail", "mail": mail_json(len(s.inbox) - 1, m)})
        for _, _, name, qtype, result in queries:
            line = f"DNS query {name} {qtype} -> {result}"
            s.dns_log = (s.dns_log + [line])[-40:]
            s.hub.publish({"type": "log", "source": "dns", "line": line})
        del s.inbox[:-50]
        if mine or queries:
            publish_servers(s)

    def capture(s: Session, wire: WireLog, source: str) -> int:
        if demo:
            claim(s, wire)
        return s.wires.add(wire, source)

    # ------------------------------------------------------------ pages

    @app.get("/")
    def index(request: Request, t: Optional[str] = None):
        page = STATIC_DIR / "index.html"
        if not page.exists():
            return JSONResponse({"detail": "The web UI isn't built. Run: cd web && npm install && npm run build"}, 500)
        # The page must always be fresh so it points at the latest hashed asset files
        headers = {"Cache-Control": "no-cache"}
        if demo:
            if sessions.get(request.cookies.get(SESSION_COOKIE)):
                return FileResponse(page, headers=headers)
            session = sessions.create()
            response = FileResponse(page, headers=headers)
            # Lax, not Strict, so following a link to the demo keeps the visitor's session
            response.set_cookie(SESSION_COOKIE, session.id, httponly=True, samesite="lax",
                                secure=not is_loopback(split_host(request.headers.get("host", ""))[0]))
            return response
        if t is not None:
            if not secrets.compare_digest(t, token):
                raise HTTPException(401, "Wrong launch token")
            # Move the secret from the URL into an HttpOnly, same-site cookie
            response = RedirectResponse("/", status_code=303)
            response.set_cookie(COOKIE, token, httponly=True, samesite="strict")
            return response
        if not authorized(request.headers, request.cookies):
            return JSONResponse({"detail": "Open the toolkit from the link printed when it started."}, 401)
        return FileResponse(page, headers=headers)

    @app.get("/assets/{name}")
    def asset(name: str):
        path = (STATIC_DIR / "assets" / name).resolve()
        if path.parent != (STATIC_DIR / "assets").resolve() or not path.exists():
            raise HTTPException(404)
        return FileResponse(path, headers={"Cache-Control": "public, max-age=31536000, immutable"})

    # ------------------------------------------------------------ events + captures

    @app.get("/api/events")
    async def events(request: Request):
        hub = sess(request).hub
        queue = hub.subscribe()

        async def stream():
            try:
                yield "retry: 1500\n\n"
                while not await request.is_disconnected():
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=15)
                        yield f"data: {json.dumps(event)}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keep-alive\n\n"
            finally:
                hub.unsubscribe(queue)

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    @app.get("/api/wires")
    def list_wires(request: Request):
        wires = sess(request).wires
        return [wires.summary(w) for w in list(wires.items)]

    @app.get("/api/wires/{wid}")
    def get_wire(request: Request, wid: int):
        return sess(request).wires.detail(wid)

    @app.delete("/api/wires/{wid}")
    def delete_wire(request: Request, wid: int):
        sess(request).wires.delete(wid)
        return {"deleted": wid}

    @app.delete("/api/wires")
    def clear_wires(request: Request):
        s = sess(request)
        s.wires.clear()
        s.hub.publish({"type": "wires_cleared"})
        return {"deleted": "all"}

    def download(data, filename: str, media_type: str) -> Response:
        return Response(data, media_type=media_type,
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    @app.get("/api/wires/{wid}/export/pcapng")
    def export_pcapng(request: Request, wid: int, keys: bool = True):
        wire = sess(request).wires.get(wid)
        if not wire.flows:
            raise HTTPException(404, "This capture has no network packets to export.")
        return download(to_pcapng(wire, include_keys=keys), f"capture-{wid}.pcapng", "application/x-pcapng")

    @app.get("/api/wires/{wid}/export/har")
    def export_har(request: Request, wid: int, sanitize: bool = True):
        wire = sess(request).wires.get(wid)
        if not has_http(wire):
            raise HTTPException(404, "HAR files only describe HTTP; this capture has no HTTP requests.")
        return download(to_har(wire, sanitize=sanitize), f"capture-{wid}.har", "application/json")

    @app.get("/api/wires/{wid}/export/transcript")
    def export_transcript(request: Request, wid: int):
        return download(sess(request).wires.get(wid).transcript(), f"capture-{wid}.txt", "text/plain; charset=utf-8")

    @app.get("/api/info")
    def info():
        from .. import http2
        return {"version": __version__, "http2": http2.HPACK_AVAILABLE,
                "query_types": dnsclient.QUERY_TYPES, "transports": dnsclient.TRANSPORTS,
                "common_ports": scanner.COMMON_PORTS, "demo": rules.info() if demo else None}

    def refuse(e: ValueError):
        raise HTTPException(403, str(e))

    # ------------------------------------------------------------ HTTP

    @app.post("/api/http")
    def http_request(request: Request, req: HTTPIn):
        s = sess(request)
        timeout = req.timeout
        if demo:
            try:
                rules.http(req.method, req.body)
            except ValueError as e:
                refuse(e)
            timeout = min(timeout, 20.0)
        wire = WireLog(f"{req.method} {req.url}")
        try:
            r = s.http.send(req.url, req.method, req.headers, req.body or None, timeout=timeout,
                            verify_tls=req.verify_tls, follow_redirects=req.follow_redirects,
                            http_version=req.http_version, use_cookies=req.use_cookies, wire=wire)
        except (OSError, ValueError) as e:
            return {"error": str(e), "wire_id": capture(s, wire, "HTTP")}
        body = r.pretty_body() if r.body else ""
        return {
            "status": r.status_code, "reason": r.status_message, "version": r.http_version, "url": r.url,
            "elapsed_ms": round(r.elapsed_ms, 1), "headers": r.header_list,
            "body": body[:MAX_BODY_CHARS], "body_truncated": len(body) > MAX_BODY_CHARS,
            "body_size": len(r.body), "raw_size": len(r.raw_body), "encoding": r.content_encoding,
            "content_type": r.get_header("Content-Type"), "tls": r.tls_info,
            "history": [{"status": h.status_code, "url": h.url, "location": h.get_header("Location")} for h in r.history],
            "phases": phases(wire), "cookies": cookie_list(s), "wire_id": capture(s, wire, "HTTP"),
            "offers_h3": "h3" in r.get_header("Alt-Svc"),
        }

    def cookie_list(s: Session):
        return [{"name": c.name, "value": c.value, "domain": c.domain, "path": c.path, "secure": c.secure,
                 "http_only": c.http_only, "expires": c.expires} for c in s.http.cookies.cookies.values()]

    @app.get("/api/http/cookies")
    def get_cookies(request: Request):
        return cookie_list(sess(request))

    @app.delete("/api/http/cookies")
    def clear_cookies(request: Request):
        sess(request).http.cookies.clear()
        return []

    # ------------------------------------------------------------ DNS

    def record(r) -> dict:
        return {"name": r.name, "type": r.type_name, "ttl": r.ttl, "value": dnsclient.format_value(r)}

    @app.post("/api/dns")
    def dns_query(request: Request, req: DNSIn):
        s = sess(request)
        wire = WireLog(f"DNS {req.type} {req.name} via {req.transport} {req.server}")
        try:
            p = dnsclient.DNSClient().query(req.name, req.type, req.server, req.transport,
                                            dnssec_ok=req.dnssec, wire=wire)
        except (OSError, ValueError, RuntimeError) as e:
            return {"error": str(e), "wire_id": capture(s, wire, "DNS")}
        return {"rcode": p.rcode_name, "flags": p.flag_names(), "transport": p.transport, "server": p.server,
                "elapsed_ms": round(p.elapsed_ms, 1), "authenticated": p.authenticated, "id": p.id,
                "edns": p.edns_udp_size, "answers": [record(r) for r in p.answers],
                "authority": [record(r) for r in p.authorities], "additional": [record(r) for r in p.additionals],
                "text": str(p), "wire_id": capture(s, wire, "DNS")}

    @app.post("/api/dns/trace")
    def dns_trace(request: Request, req: DNSIn):
        s = sess(request)
        wire = WireLog(f"DNS trace {req.type} {req.name}")
        try:
            steps = dnsclient.DNSClient().trace(req.name, req.type, wire=wire)
        except (OSError, ValueError, RuntimeError) as e:
            return {"error": str(e), "wire_id": capture(s, wire, "DNS")}
        return {"steps": [{"server": name, "ip": ip, "rcode": p.rcode_name, "elapsed_ms": round(p.elapsed_ms, 1),
                           "answers": [record(r) for r in p.answers],
                           "referral": [record(r) for r in p.authorities if r.type in (2, 6)]}
                          for name, ip, p in steps],
                "wire_id": capture(s, wire, "DNS")}

    # ------------------------------------------------------------ SMTP

    @app.post("/api/smtp")
    def smtp_send(request: Request, req: SMTPIn):
        s = sess(request)
        if demo:
            try:
                rules.smtp(req.server, req.port)
            except ValueError as e:
                refuse(e)
        wire, log = WireLog(f"SMTP {req.server}:{req.port}"), []
        try:
            result = smtpclient.send_email(req.server, req.port, req.sender, req.to, req.subject, req.body,
                                           tls_mode=req.security, username=req.username, password=req.password,
                                           verify_tls=req.verify_tls, wire=wire, log=log.append)
        except (OSError, ValueError, RuntimeError) as e:
            hint = ""
            if "refused" in str(e).lower() and req.server in ("localhost", "127.0.0.1", "::1"):
                hint = "Nothing is listening there. Start the built-in SMTP server in Test Servers."
            return {"error": str(e), "hint": hint, "log": log, "wire_id": capture(s, wire, "SMTP")}
        return {"result": str(result), "log": log, "wire_id": capture(s, wire, "SMTP")}

    # ------------------------------------------------------------ Mail check

    @app.post("/api/mailcheck")
    def mailcheck(req: MailIn):
        # The demo host can't be used to probe other people's mail servers on port 25
        report = DeliverabilityChecker().run(req.domain, req.selectors or None, probe_smtp=req.probe_smtp and not demo)
        return {"domain": report.domain, "grade": report.grade, "counts": report.counts,
                "checks": [{"area": c.area, "status": c.status, "title": c.title, "detail": c.detail,
                            "records": c.records} for c in report.checks],
                "text": report.to_text()}

    # ------------------------------------------------------------ Scanner

    @app.post("/api/scan")
    def scan_start(request: Request, req: ScanIn):
        s = sess(request)
        timeout = req.timeout
        try:
            if demo:
                ports = rules.begin_scan(req.host, req.ports)
                timeout = min(max(timeout, 0.3), 2.0)
            else:
                ports = scanner.COMMON_PORTS if req.ports.strip() == "common" else scanner.parse_ports(req.ports)
                scanner.resolve(req.host)
        except Busy as e:
            raise HTTPException(429, str(e))
        except ValueError as e:
            raise HTTPException(403 if demo and "public demo" in str(e) else 400, str(e))
        job = secrets.token_hex(6)
        stop = threading.Event()
        s.scans[job] = stop

        def run():
            def on_result(r):
                s.hub.publish({"type": "scan", "job": job, "result": {
                    "port": r.port, "status": r.status, "service": r.service or scanner.service_name(r.port),
                    "banner": r.banner, "tls": r.tls}})
            try:
                results = scanner.scan(req.host, ports, timeout, workers=50 if demo else 200,
                                       grab_banner=req.banners, on_result=on_result, should_stop=stop.is_set)
                open_count = sum(r.status == scanner.OPEN for r in results.values())
                s.hub.publish({"type": "scan_done", "job": job, "scanned": len(results), "open": open_count,
                               "stopped": stop.is_set()})
            except Exception as e:  # reported to the page, never silently dropped
                s.hub.publish({"type": "scan_done", "job": job, "error": str(e)})
            finally:
                s.scans.pop(job, None)
                if demo:
                    rules.end_scan()

        threading.Thread(target=run, daemon=True).start()
        return {"job": job, "total": len(ports)}

    @app.post("/api/scan/{job}/stop")
    def scan_stop(request: Request, job: str):
        stop = sess(request).scans.get(job)
        if stop:
            stop.set()
        return {"stopping": bool(stop)}

    # ------------------------------------------------------------ Test servers

    def servers_state(s: Session):
        smtp, dns = state["smtp"], state["dns"]
        if demo:
            return {"locked": True,
                    "smtp": {"running": bool(smtp and smtp.running), "port": demo_ports[0], "messages": len(s.inbox)},
                    "dns": {"running": bool(dns and dns.running), "port": demo_ports[1], "zone": DEFAULT_ZONE,
                            "queries": s.dns_log[-40:]}}
        return {"locked": False,
                "smtp": {"running": bool(smtp and smtp.running), "port": smtp.port if smtp else 1025,
                         "messages": len(smtp.messages) if smtp else 0},
                "dns": {"running": bool(dns and dns.running), "port": dns.port if dns else 10325,
                        "zone": state["zone"],
                        # recent queries, so the log survives switching screens
                        "queries": [f"DNS query {name} {qtype} -> {result}"
                                    for _, _, name, qtype, result in (dns.queries[-40:] if dns else [])]}}

    def publish_servers(s: Session):
        s.hub.publish({"type": "servers", "state": servers_state(s)})

    def mail_json(i, m):
        return {"id": i, "received": m.received, "from": m.mail_from, "to": m.rcpt_to, "subject": m.subject,
                "authenticated_as": m.authenticated_as}

    def inbox_of(s: Session) -> list:
        if demo:
            return s.inbox
        return state["smtp"].messages if state["smtp"] else []

    def desktop_only():
        if demo:
            raise HTTPException(403, "The public demo's test servers are always on and shared, so they can't "
                                     "be stopped or changed here. Run the toolkit locally to edit the zone.")

    @app.get("/api/servers")
    def get_servers(request: Request):
        return servers_state(sess(request))

    @app.post("/api/servers/smtp/start")
    def smtp_start(req: ServerIn):
        desktop_only()
        if state["smtp"] and state["smtp"].running:
            return servers_state(local)
        port = req.port or 1025
        if port_in_use(port):
            raise HTTPException(409, f"Port {port} is already in use (MailHog or Mailpit may be running; "
                                     "that works too). Pick another port.")

        def on_message(mail):
            smtp = state["smtp"]
            local.hub.publish({"type": "mail", "mail": mail_json(smtp.messages.index(mail), mail)})
            publish_servers(local)

        server = SMTPTestServer(port, on_message=on_message,
                                on_log=lambda line: local.hub.publish({"type": "log", "source": "smtp", "line": line}))
        try:
            server.start()
        except OSError as e:
            raise HTTPException(409, str(e))
        state["smtp"] = server
        publish_servers(local)
        return servers_state(local)

    @app.post("/api/servers/smtp/stop")
    def smtp_stop():
        desktop_only()
        if state["smtp"]:
            state["smtp"].stop()
        publish_servers(local)
        return servers_state(local)

    @app.get("/api/servers/inbox")
    def inbox(request: Request):
        return [mail_json(i, m) for i, m in enumerate(inbox_of(sess(request)))]

    @app.get("/api/servers/inbox/{mid}")
    def inbox_message(request: Request, mid: int):
        messages = inbox_of(sess(request))
        if not 0 <= mid < len(messages):
            raise HTTPException(404, "No such message")
        m = messages[mid]
        head = m.raw.split("\r\n\r\n", 1)[0] if "\r\n\r\n" in m.raw else m.raw.split("\n\n", 1)[0]
        return {**mail_json(mid, m), "headers": head.replace("\r\n", "\n"), "body": m.body_text()}

    @app.delete("/api/servers/inbox")
    def clear_inbox(request: Request):
        s = sess(request)
        inbox_of(s).clear()
        publish_servers(s)
        return []

    @app.post("/api/servers/dns/start")
    def dns_start(req: ServerIn):
        desktop_only()
        if state["dns"] and state["dns"].running:
            return servers_state(local)
        server = DNSTestServer(req.port or 10325, state["zone"],
                               on_log=lambda line: local.hub.publish({"type": "log", "source": "dns", "line": line}))
        try:
            server.start()
        except (OSError, ValueError) as e:
            raise HTTPException(409, str(e))
        state["dns"] = server
        publish_servers(local)
        return servers_state(local)

    @app.post("/api/servers/dns/stop")
    def dns_stop():
        desktop_only()
        if state["dns"]:
            state["dns"].stop()
        publish_servers(local)
        return servers_state(local)

    @app.put("/api/servers/dns/zone")
    def set_zone(req: ZoneIn):
        desktop_only()
        from ..testservers import parse_zone
        try:
            parse_zone(req.zone)
            if state["dns"]:
                state["dns"].set_zone(req.zone)
        except ValueError as e:
            raise HTTPException(400, str(e))
        state["zone"] = req.zone
        publish_servers(local)
        return servers_state(local)

    # ------------------------------------------------------------ AI

    @app.get("/api/llm/status")
    def llm_status(request: Request):
        from .. import explain
        if demo:  # no model runs on the demo host; visitors use Claude with their own key
            ollama = {"running": False, "version": None, "models": [], "installed": False, "default": "",
                      "disabled": True}
        else:
            running, version, models = llm.ollama_status()
            ollama = {"running": running, "version": version, "models": models,
                      "installed": llm.ollama_binary() is not None, "default": llm.default_ollama_model(models)}
        return {"ollama": ollama, "claude": {"sdk": explain.available(), "model": llm.CLAUDE_MODEL,
                                             "key_set": bool(sess(request).api_key), "own_key_required": demo}}

    @app.post("/api/llm/start-ollama")
    def start_ollama():
        desktop_only()
        try:
            state["ollama"] = llm.start_ollama()
        except llm.LLMError as e:
            raise HTTPException(400, str(e))
        return {"started": True}

    @app.post("/api/settings")
    def settings(request: Request, req: SettingsIn):
        s = sess(request)
        s.api_key = req.api_key.strip()  # memory only, never written to disk
        return {"key_set": bool(s.api_key)}

    @app.websocket("/api/assistant")
    async def assistant(ws: WebSocket):
        host = ws.headers.get("host", "")
        s = find_session(ws.headers, ws.cookies)
        if not host_ok(host) or not origin_ok(ws.headers.get("origin"), host) or s is None:
            await ws.close(code=4403)
            return
        await ws.accept()
        loop = asyncio.get_running_loop()
        outgoing: asyncio.Queue = asyncio.Queue()
        approvals: Dict[str, dict] = {}
        chat: Dict[str, Any] = {"agent": None, "key": None}

        def send(msg: dict) -> None:
            loop.call_soon_threadsafe(outgoing.put_nowait, msg)

        def approve(call, reason) -> bool:
            rid = secrets.token_hex(4)
            waiter = {"event": threading.Event(), "allow": False}
            approvals[rid] = waiter
            send({"type": "approval", "id": rid, "tool": call.name, "args": call.args, "reason": reason})
            waiter["event"].wait()
            approvals.pop(rid, None)
            return waiter["allow"]

        def run(msg: dict) -> None:
            kind, model = msg.get("provider", "ollama"), msg.get("model", "")
            if demo:
                if kind != "claude" or not s.api_key:
                    send({"type": "error", "message": "The public demo runs the assistant with Claude, using "
                                                      "your own Anthropic API key. Paste it above; it stays in "
                                                      "this session's memory only."})
                    return
                refusal = admit(s)
                if refusal:
                    send({"type": "error", "message": refusal})
                    return
            try:
                if chat["agent"] is None or chat["key"] != (kind, model):
                    provider = llm.make_provider(kind, model, s.api_key)
                    tools = build_tools(lambda wire: capture(s, wire, "Assistant"), latest_transcript, demo=rules)
                    chat["agent"] = Agent(provider, tools, approve,
                                          on_text=lambda text: send({"type": "text", "text": text}),
                                          on_tool=lambda stage, call, info: send({
                                              "type": "tool", "stage": stage, "id": call.id, "name": call.name,
                                              "args": call.args, "info": info[:400]}),
                                          system=SYSTEM_PROMPT + (rules.prompt() if demo else ""))
                    chat["key"] = (kind, model)
                text = msg["text"]
                if msg.get("attachment"):
                    title, body = msg["attachment"].get("title", "capture"), redact(msg["attachment"].get("text", ""))
                    limit = 12_000 if kind == "ollama" else 80_000
                    if len(body) > limit:
                        body = body[:limit] + f"\n[capture truncated: {len(body) - limit:,} more characters]"
                    text += f"\n\n<capture title=\"{title}\">\n{body}\n</capture>"
                answer = chat["agent"].ask(text)
                send({"type": "done", "text": answer})
            except Exception as e:  # shown in the chat
                send({"type": "error", "message": str(e)})
            finally:
                if demo:
                    release(s)

        def latest_transcript() -> str:
            if not s.wires.items:
                return ""
            return s.wires.items[next(reversed(s.wires.items))]["wire"].transcript()

        async def sender():
            while True:
                await ws.send_json(await outgoing.get())

        send_task = asyncio.create_task(sender())
        try:
            while True:
                msg = await ws.receive_json()
                if msg.get("type") == "ask":
                    threading.Thread(target=run, args=(msg,), daemon=True).start()
                elif msg.get("type") == "approval" and msg.get("id") in approvals:
                    approvals[msg["id"]]["allow"] = bool(msg.get("allow"))
                    approvals[msg["id"]]["event"].set()
                elif msg.get("type") == "cancel" and chat["agent"]:
                    chat["agent"].cancel.set()
                elif msg.get("type") == "reset":
                    chat["agent"] = None
        except WebSocketDisconnect:
            pass
        finally:
            for waiter in approvals.values():  # never leave a worker blocked on a closed page
                waiter["event"].set()
            if chat["agent"]:
                chat["agent"].cancel.set()
            send_task.cancel()

    return app
