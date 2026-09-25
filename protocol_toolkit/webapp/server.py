"""Local web backend for the React UI.

Everything runs on this machine: the browser talks only to 127.0.0.1, and this server
runs the toolkit's own protocol clients. Because a local server that can scan ports and
send mail is attractive to malicious web pages, every request must:
  * carry the per-launch secret (cookie set from the launch URL, or an X-Token header),
  * use a Host header of 127.0.0.1/localhost (blocks DNS-rebinding attacks), and
  * come from our own origin if it has an Origin header (blocks cross-site requests).
"""
from __future__ import annotations

import asyncio
import base64
import itertools
import json
import os
import sys
import secrets
import threading
import time
from collections import OrderedDict
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, Response, StreamingResponse
from pydantic import BaseModel, Field

from .. import __version__, dnsclient, llm, scanner, smtpclient
from ..agent import Agent, build_tools
from ..explain import redact
from ..har import has_http, to_har
from ..pcap import to_pcapng
from ..httpclient import HTTPClient
from ..mailcheck import DeliverabilityChecker
from ..testservers import DEFAULT_ZONE, DNSTestServer, SMTPTestServer, port_in_use
from ..wire import WireLog

STATIC_DIR = Path(__file__).parent / "static"
COOKIE = "pt_token"
MAX_EVENT_BYTES = 64 * 1024  # bytes per wire event sent to the browser
MAX_BODY_CHARS = 1_000_000


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


class WireStore:
    """Captures, newest last. Each one is also saved to disk, so sessions survive restarts."""

    def __init__(self, hub: EventHub, data_dir: Optional[Path] = None, keep: int = 200):
        self.hub, self.keep = hub, keep
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
                self.items[saved["id"]] = {"wire": WireLog.from_dict(saved["wire"]), "source": saved["source"],
                                           "created": saved["created"]}
            except (OSError, ValueError, KeyError, TypeError):
                continue  # skip a damaged file rather than refusing to start

    def _path(self, wid: int) -> Optional[Path]:
        return self.dir / f"{wid:07d}.json" if self.dir else None

    def add(self, wire: WireLog, source: str) -> int:
        with self._lock:
            wid = next(self._ids)
            item = {"wire": wire, "source": source, "created": time.time()}
            self.items[wid] = item
            dropped = []
            while len(self.items) > self.keep:
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
               data_dir: Optional[Path] = None) -> FastAPI:
    token = token or secrets.token_urlsafe(24)
    state: Dict[str, Any] = {"smtp": None, "dns": None, "api_key": "", "ollama": None, "scans": {}}

    @asynccontextmanager
    async def lifespan(_app):
        yield
        # Stop the test servers and any Ollama we started when the toolkit exits
        for key in ("smtp", "dns"):
            if state[key] and state[key].running:
                state[key].stop()
        if state["ollama"] and state["ollama"].poll() is None:
            state["ollama"].terminate()

    app = FastAPI(title="Protocol Toolkit", version=__version__, docs_url=None, redoc_url=None, openapi_url=None,
                  lifespan=lifespan)
    app.state.token = token
    app.state.allowed_ports = allowed_ports  # set by the launcher once the port is known
    hub = EventHub()
    wires = WireStore(hub, data_dir if data_dir is not None else default_data_dir())
    http_client = HTTPClient()

    # ------------------------------------------------------------ security

    def host_ok(host: str) -> bool:
        name, _, port = host.rpartition(":")
        if name not in ("127.0.0.1", "localhost", "[::1]"):
            return False
        return app.state.allowed_ports is None or (port.isdigit() and int(port) in app.state.allowed_ports)

    dev_origin = os.environ.get("PT_DEV_ORIGIN")  # e.g. http://localhost:5173 for `npm run dev`

    def origin_ok(origin: Optional[str], host: str) -> bool:
        return origin is None or origin == f"http://{host}" or (dev_origin is not None and origin == dev_origin)

    def authorized(headers, cookies) -> bool:
        supplied = headers.get("x-token") or cookies.get(COOKIE) or ""
        return secrets.compare_digest(supplied, token)

    @app.middleware("http")
    async def guard(request: Request, call_next):
        host = request.headers.get("host", "")
        if not host_ok(host):
            return JSONResponse({"detail": "Blocked: unexpected Host header"}, status_code=403)
        if not origin_ok(request.headers.get("origin"), host):
            return JSONResponse({"detail": "Blocked: cross-site request"}, status_code=403)
        path = request.url.path
        if path.startswith("/api/") and not authorized(request.headers, request.cookies):
            return JSONResponse({"detail": "Open the toolkit from the link printed when it started."},
                                status_code=401)
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    def capture(wire: WireLog, source: str) -> int:
        return wires.add(wire, source)

    # ------------------------------------------------------------ pages

    @app.get("/")
    def index(request: Request, t: Optional[str] = None):
        if t is not None:
            if not secrets.compare_digest(t, token):
                raise HTTPException(401, "Wrong launch token")
            # Move the secret from the URL into an HttpOnly, same-site cookie
            response = RedirectResponse("/", status_code=303)
            response.set_cookie(COOKIE, token, httponly=True, samesite="strict")
            return response
        if not authorized(request.headers, request.cookies):
            return JSONResponse({"detail": "Open the toolkit from the link printed when it started."}, 401)
        page = STATIC_DIR / "index.html"
        if not page.exists():
            return JSONResponse({"detail": "The web UI isn't built. Run: cd web && npm install && npm run build"}, 500)
        # The page must always be fresh so it points at the latest hashed asset files
        return FileResponse(page, headers={"Cache-Control": "no-cache"})

    @app.get("/assets/{name}")
    def asset(name: str):
        path = (STATIC_DIR / "assets" / name).resolve()
        if path.parent != (STATIC_DIR / "assets").resolve() or not path.exists():
            raise HTTPException(404)
        return FileResponse(path, headers={"Cache-Control": "public, max-age=31536000, immutable"})

    # ------------------------------------------------------------ events + captures

    @app.get("/api/events")
    async def events(request: Request):
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
    def list_wires():
        return [wires.summary(w) for w in list(wires.items)]

    @app.get("/api/wires/{wid}")
    def get_wire(wid: int):
        return wires.detail(wid)

    @app.delete("/api/wires/{wid}")
    def delete_wire(wid: int):
        wires.delete(wid)
        return {"deleted": wid}

    @app.delete("/api/wires")
    def clear_wires():
        wires.clear()
        hub.publish({"type": "wires_cleared"})
        return {"deleted": "all"}

    def download(data, filename: str, media_type: str) -> Response:
        return Response(data, media_type=media_type,
                        headers={"Content-Disposition": f'attachment; filename="{filename}"'})

    @app.get("/api/wires/{wid}/export/pcapng")
    def export_pcapng(wid: int, keys: bool = True):
        wire = wires.get(wid)
        if not wire.flows:
            raise HTTPException(404, "This capture has no network packets to export.")
        return download(to_pcapng(wire, include_keys=keys), f"capture-{wid}.pcapng", "application/x-pcapng")

    @app.get("/api/wires/{wid}/export/har")
    def export_har(wid: int, sanitize: bool = True):
        wire = wires.get(wid)
        if not has_http(wire):
            raise HTTPException(404, "HAR files only describe HTTP; this capture has no HTTP requests.")
        return download(to_har(wire, sanitize=sanitize), f"capture-{wid}.har", "application/json")

    @app.get("/api/wires/{wid}/export/transcript")
    def export_transcript(wid: int):
        return download(wires.get(wid).transcript(), f"capture-{wid}.txt", "text/plain; charset=utf-8")

    @app.get("/api/info")
    def info():
        from .. import http2
        return {"version": __version__, "http2": http2.HPACK_AVAILABLE,
                "query_types": dnsclient.QUERY_TYPES, "transports": dnsclient.TRANSPORTS,
                "common_ports": scanner.COMMON_PORTS}

    # ------------------------------------------------------------ HTTP

    @app.post("/api/http")
    def http_request(req: HTTPIn):
        wire = WireLog(f"{req.method} {req.url}")
        try:
            r = http_client.send(req.url, req.method, req.headers, req.body or None, timeout=req.timeout,
                                 verify_tls=req.verify_tls, follow_redirects=req.follow_redirects,
                                 http_version=req.http_version, use_cookies=req.use_cookies, wire=wire)
        except (OSError, ValueError) as e:
            return {"error": str(e), "wire_id": capture(wire, "HTTP")}
        body = r.pretty_body() if r.body else ""
        return {
            "status": r.status_code, "reason": r.status_message, "version": r.http_version, "url": r.url,
            "elapsed_ms": round(r.elapsed_ms, 1), "headers": r.header_list,
            "body": body[:MAX_BODY_CHARS], "body_truncated": len(body) > MAX_BODY_CHARS,
            "body_size": len(r.body), "raw_size": len(r.raw_body), "encoding": r.content_encoding,
            "content_type": r.get_header("Content-Type"), "tls": r.tls_info,
            "history": [{"status": h.status_code, "url": h.url, "location": h.get_header("Location")} for h in r.history],
            "phases": phases(wire), "cookies": cookie_list(), "wire_id": capture(wire, "HTTP"),
            "offers_h3": "h3" in r.get_header("Alt-Svc"),
        }

    def cookie_list():
        return [{"name": c.name, "value": c.value, "domain": c.domain, "path": c.path, "secure": c.secure,
                 "http_only": c.http_only, "expires": c.expires} for c in http_client.cookies.cookies.values()]

    @app.get("/api/http/cookies")
    def get_cookies():
        return cookie_list()

    @app.delete("/api/http/cookies")
    def clear_cookies():
        http_client.cookies.clear()
        return []

    # ------------------------------------------------------------ DNS

    def record(r) -> dict:
        return {"name": r.name, "type": r.type_name, "ttl": r.ttl, "value": dnsclient.format_value(r)}

    @app.post("/api/dns")
    def dns_query(req: DNSIn):
        wire = WireLog(f"DNS {req.type} {req.name} via {req.transport} {req.server}")
        try:
            p = dnsclient.DNSClient().query(req.name, req.type, req.server, req.transport,
                                            dnssec_ok=req.dnssec, wire=wire)
        except (OSError, ValueError, RuntimeError) as e:
            return {"error": str(e), "wire_id": capture(wire, "DNS")}
        return {"rcode": p.rcode_name, "flags": p.flag_names(), "transport": p.transport, "server": p.server,
                "elapsed_ms": round(p.elapsed_ms, 1), "authenticated": p.authenticated, "id": p.id,
                "edns": p.edns_udp_size, "answers": [record(r) for r in p.answers],
                "authority": [record(r) for r in p.authorities], "additional": [record(r) for r in p.additionals],
                "text": str(p), "wire_id": capture(wire, "DNS")}

    @app.post("/api/dns/trace")
    def dns_trace(req: DNSIn):
        wire = WireLog(f"DNS trace {req.type} {req.name}")
        try:
            steps = dnsclient.DNSClient().trace(req.name, req.type, wire=wire)
        except (OSError, ValueError, RuntimeError) as e:
            return {"error": str(e), "wire_id": capture(wire, "DNS")}
        return {"steps": [{"server": name, "ip": ip, "rcode": p.rcode_name, "elapsed_ms": round(p.elapsed_ms, 1),
                           "answers": [record(r) for r in p.answers],
                           "referral": [record(r) for r in p.authorities if r.type in (2, 6)]}
                          for name, ip, p in steps],
                "wire_id": capture(wire, "DNS")}

    # ------------------------------------------------------------ SMTP

    @app.post("/api/smtp")
    def smtp_send(req: SMTPIn):
        wire, log = WireLog(f"SMTP {req.server}:{req.port}"), []
        try:
            result = smtpclient.send_email(req.server, req.port, req.sender, req.to, req.subject, req.body,
                                           tls_mode=req.security, username=req.username, password=req.password,
                                           verify_tls=req.verify_tls, wire=wire, log=log.append)
        except (OSError, ValueError, RuntimeError) as e:
            hint = ""
            if "refused" in str(e).lower() and req.server in ("localhost", "127.0.0.1", "::1"):
                hint = "Nothing is listening there. Start the built-in SMTP server in Test Servers."
            return {"error": str(e), "hint": hint, "log": log, "wire_id": capture(wire, "SMTP")}
        return {"result": str(result), "log": log, "wire_id": capture(wire, "SMTP")}

    # ------------------------------------------------------------ Mail check

    @app.post("/api/mailcheck")
    def mailcheck(req: MailIn):
        report = DeliverabilityChecker().run(req.domain, req.selectors or None, probe_smtp=req.probe_smtp)
        return {"domain": report.domain, "grade": report.grade, "counts": report.counts,
                "checks": [{"area": c.area, "status": c.status, "title": c.title, "detail": c.detail,
                            "records": c.records} for c in report.checks],
                "text": report.to_text()}

    # ------------------------------------------------------------ Scanner

    @app.post("/api/scan")
    def scan_start(req: ScanIn):
        try:
            ports = scanner.COMMON_PORTS if req.ports.strip() == "common" else scanner.parse_ports(req.ports)
            scanner.resolve(req.host)
        except ValueError as e:
            raise HTTPException(400, str(e))
        job = secrets.token_hex(6)
        stop = threading.Event()
        state["scans"][job] = stop

        def run():
            def on_result(r):
                hub.publish({"type": "scan", "job": job, "result": {
                    "port": r.port, "status": r.status, "service": r.service or scanner.service_name(r.port),
                    "banner": r.banner, "tls": r.tls}})
            try:
                results = scanner.scan(req.host, ports, req.timeout, grab_banner=req.banners,
                                       on_result=on_result, should_stop=stop.is_set)
                open_count = sum(r.status == scanner.OPEN for r in results.values())
                hub.publish({"type": "scan_done", "job": job, "scanned": len(results), "open": open_count,
                             "stopped": stop.is_set()})
            except Exception as e:  # reported to the page, never silently dropped
                hub.publish({"type": "scan_done", "job": job, "error": str(e)})
            finally:
                state["scans"].pop(job, None)

        threading.Thread(target=run, daemon=True).start()
        return {"job": job, "total": len(ports)}

    @app.post("/api/scan/{job}/stop")
    def scan_stop(job: str):
        stop = state["scans"].get(job)
        if stop:
            stop.set()
        return {"stopping": bool(stop)}

    # ------------------------------------------------------------ Test servers

    def servers_state():
        smtp, dns = state["smtp"], state["dns"]
        return {"smtp": {"running": bool(smtp and smtp.running), "port": smtp.port if smtp else 1025,
                         "messages": len(smtp.messages) if smtp else 0},
                "dns": {"running": bool(dns and dns.running), "port": dns.port if dns else 10325,
                        "zone": state.get("zone", DEFAULT_ZONE),
                        # recent queries, so the log survives switching screens
                        "queries": [f"DNS query {name} {qtype} -> {result}"
                                    for _, _, name, qtype, result in (dns.queries[-40:] if dns else [])]}}

    def publish_servers():
        hub.publish({"type": "servers", "state": servers_state()})

    def mail_json(i, m):
        return {"id": i, "received": m.received, "from": m.mail_from, "to": m.rcpt_to, "subject": m.subject,
                "authenticated_as": m.authenticated_as}

    @app.get("/api/servers")
    def get_servers():
        return servers_state()

    @app.post("/api/servers/smtp/start")
    def smtp_start(req: ServerIn):
        if state["smtp"] and state["smtp"].running:
            return servers_state()
        port = req.port or 1025
        if port_in_use(port):
            raise HTTPException(409, f"Port {port} is already in use (MailHog or Mailpit may be running; "
                                     "that works too). Pick another port.")

        def on_message(mail):
            smtp = state["smtp"]
            hub.publish({"type": "mail", "mail": mail_json(smtp.messages.index(mail), mail)})
            publish_servers()

        server = SMTPTestServer(port, on_message=on_message,
                                on_log=lambda s: hub.publish({"type": "log", "source": "smtp", "line": s}))
        try:
            server.start()
        except OSError as e:
            raise HTTPException(409, str(e))
        state["smtp"] = server
        publish_servers()
        return servers_state()

    @app.post("/api/servers/smtp/stop")
    def smtp_stop():
        if state["smtp"]:
            state["smtp"].stop()
        publish_servers()
        return servers_state()

    @app.get("/api/servers/inbox")
    def inbox():
        smtp = state["smtp"]
        return [mail_json(i, m) for i, m in enumerate(smtp.messages)] if smtp else []

    @app.get("/api/servers/inbox/{mid}")
    def inbox_message(mid: int):
        smtp = state["smtp"]
        if not smtp or not 0 <= mid < len(smtp.messages):
            raise HTTPException(404, "No such message")
        m = smtp.messages[mid]
        head = m.raw.split("\r\n\r\n", 1)[0] if "\r\n\r\n" in m.raw else m.raw.split("\n\n", 1)[0]
        return {**mail_json(mid, m), "headers": head.replace("\r\n", "\n"), "body": m.body_text()}

    @app.delete("/api/servers/inbox")
    def clear_inbox():
        if state["smtp"]:
            state["smtp"].messages.clear()
        publish_servers()
        return []

    @app.post("/api/servers/dns/start")
    def dns_start(req: ServerIn):
        if state["dns"] and state["dns"].running:
            return servers_state()
        server = DNSTestServer(req.port or 10325, state.get("zone", DEFAULT_ZONE),
                               on_log=lambda s: hub.publish({"type": "log", "source": "dns", "line": s}))
        try:
            server.start()
        except (OSError, ValueError) as e:
            raise HTTPException(409, str(e))
        state["dns"] = server
        publish_servers()
        return servers_state()

    @app.post("/api/servers/dns/stop")
    def dns_stop():
        if state["dns"]:
            state["dns"].stop()
        publish_servers()
        return servers_state()

    @app.put("/api/servers/dns/zone")
    def set_zone(req: ZoneIn):
        from ..testservers import parse_zone
        try:
            parse_zone(req.zone)
            if state["dns"]:
                state["dns"].set_zone(req.zone)
        except ValueError as e:
            raise HTTPException(400, str(e))
        state["zone"] = req.zone
        publish_servers()
        return servers_state()

    # ------------------------------------------------------------ AI

    @app.get("/api/llm/status")
    def llm_status():
        from .. import explain
        running, version, models = llm.ollama_status()
        return {"ollama": {"running": running, "version": version, "models": models,
                           "installed": llm.ollama_binary() is not None,
                           "default": llm.default_ollama_model(models)},
                "claude": {"sdk": explain.available(), "model": llm.CLAUDE_MODEL,
                           "key_set": bool(state["api_key"])}}

    @app.post("/api/llm/start-ollama")
    def start_ollama():
        try:
            state["ollama"] = llm.start_ollama()
        except llm.LLMError as e:
            raise HTTPException(400, str(e))
        return {"started": True}

    @app.post("/api/settings")
    def settings(req: SettingsIn):
        state["api_key"] = req.api_key.strip()  # memory only, never written to disk
        return {"key_set": bool(state["api_key"])}

    @app.websocket("/api/assistant")
    async def assistant(ws: WebSocket):
        host = ws.headers.get("host", "")
        if not host_ok(host) or not origin_ok(ws.headers.get("origin"), host) or not authorized(ws.headers, ws.cookies):
            await ws.close(code=4403)
            return
        await ws.accept()
        loop = asyncio.get_running_loop()
        outgoing: asyncio.Queue = asyncio.Queue()
        approvals: Dict[str, dict] = {}
        session: Dict[str, Any] = {"agent": None, "key": None}

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
            try:
                kind, model = msg.get("provider", "ollama"), msg.get("model", "")
                if session["agent"] is None or session["key"] != (kind, model):
                    provider = llm.make_provider(kind, model, state["api_key"])
                    tools = build_tools(lambda wire: capture(wire, "Assistant"), latest_transcript)
                    session["agent"] = Agent(provider, tools, approve,
                                             on_text=lambda s: send({"type": "text", "text": s}),
                                             on_tool=lambda stage, call, info: send({
                                                 "type": "tool", "stage": stage, "id": call.id, "name": call.name,
                                                 "args": call.args, "info": info[:400]}))
                    session["key"] = (kind, model)
                text = msg["text"]
                if msg.get("attachment"):
                    title, body = msg["attachment"].get("title", "capture"), redact(msg["attachment"].get("text", ""))
                    limit = 12_000 if kind == "ollama" else 80_000
                    if len(body) > limit:
                        body = body[:limit] + f"\n[capture truncated: {len(body) - limit:,} more characters]"
                    text += f"\n\n<capture title=\"{title}\">\n{body}\n</capture>"
                answer = session["agent"].ask(text)
                send({"type": "done", "text": answer})
            except Exception as e:  # shown in the chat
                send({"type": "error", "message": str(e)})

        def latest_transcript() -> str:
            if not wires.items:
                return ""
            return wires.items[next(reversed(wires.items))]["wire"].transcript()

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
                elif msg.get("type") == "cancel" and session["agent"]:
                    session["agent"].cancel.set()
                elif msg.get("type") == "reset":
                    session["agent"] = None
        except WebSocketDisconnect:
            pass
        finally:
            for waiter in approvals.values():  # never leave a worker blocked on a closed page
                waiter["event"].set()
            if session["agent"]:
                session["agent"].cancel.set()
            send_task.cancel()

    return app
