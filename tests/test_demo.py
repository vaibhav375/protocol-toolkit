"""Public demo mode: the network guard, the demo rules and per-visitor sessions."""
import socket

import pytest

from protocol_toolkit import guard, net
from protocol_toolkit.agent import build_tools
from protocol_toolkit.demo import DemoRules
from protocol_toolkit.httpclient import HTTPClient

from conftest import free_port

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from protocol_toolkit.webapp.server import SESSION_COOKIE, SessionStore, create_app  # noqa: E402

BASE = "http://127.0.0.1:8765"


# ------------------------------------------------------------ the guard's address rules

@pytest.mark.parametrize("ip, port, udp, allowed", [
    ("93.184.215.14", 443, False, True),
    ("8.8.8.8", 53, True, True),
    ("2606:4700:4700::1111", 443, False, True),
    ("8.8.8.8", 22, False, False),             # not a web or DNS port
    ("8.8.8.8", 25, False, False),             # no mail servers
    ("127.0.0.1", 80, False, False),           # this server
    ("127.0.0.1", 1025, False, True),          # the built-in test SMTP server
    ("::1", 8000, False, False),
    ("10.0.0.5", 443, False, False),           # private networks
    ("192.168.1.1", 80, False, False),
    ("172.16.0.1", 80, False, False),
    ("100.64.0.1", 80, False, False),          # carrier-grade NAT
    ("169.254.169.254", 80, False, False),     # cloud metadata
    ("0.0.0.0", 80, False, False),
    ("fd00::1", 443, False, False),            # IPv6 unique local
    ("fe80::1", 443, False, False),            # IPv6 link local
    ("::ffff:10.0.0.1", 443, False, False),    # IPv4-mapped private address
    ("64:ff9b::a00:1", 443, False, False),     # NAT64 of 10.0.0.1
    ("2002:a00:1::", 443, False, False),       # 6to4
    ("224.0.0.251", 53, True, False),          # multicast
])
def test_policy(ip, port, udp, allowed):
    policy = guard.Policy(loopback_ports={1025})
    assert (policy.check(ip, port, udp) is None) == allowed


def test_scan_targets_may_use_any_port():
    policy = guard.Policy(open_hosts={"45.33.32.156"})
    assert policy.check("45.33.32.156", 22) is None
    assert policy.check("45.33.32.157", 22) is not None


@pytest.fixture
def guarded():
    def install(**kwargs):
        guard.install(guard.Policy(**kwargs))
    try:
        yield install
    finally:
        guard.uninstall()


def test_guard_blocks_private_connections_and_uninstalls(guarded, tcp_server):
    server = tcp_server(lambda h: h.wfile.write(b"hi"))
    guarded()
    with pytest.raises(guard.BlockedAddress, match="Blocked in the public demo"):
        socket.create_connection(("127.0.0.1", server.port), timeout=2)
    with pytest.raises(guard.BlockedAddress):
        socket.create_connection(("localhost", server.port), timeout=2)  # names are resolved and checked
    s = socket.socket()
    assert s.connect_ex(("127.0.0.1", server.port)) != 0  # the scanner's call is blocked too
    s.close()
    guard.uninstall()
    socket.create_connection(("127.0.0.1", server.port), timeout=2).close()


def test_guard_checks_the_address_a_name_resolves_to(guarded, monkeypatch):
    """A public-looking name that resolves to a private address (DNS rebinding) is refused"""
    real = socket.getaddrinfo

    def fake(host, *args, **kwargs):
        if host == "rebind.example":
            return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", 80))]
        return real(host, *args, **kwargs)
    monkeypatch.setattr(socket, "getaddrinfo", fake)
    guarded()
    with pytest.raises(OSError, match="private or reserved"):
        HTTPClient().send("http://rebind.example/", timeout=2)


def test_guard_follows_redirects(guarded, tcp_server):
    """An allowed server can't redirect the client to a blocked address"""
    inner = tcp_server(lambda h: h.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: 6\r\n\r\nsecret"))

    def redirect(h):
        h.rfile.readline()
        h.wfile.write(f"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{inner.port}/\r\n"
                      "Content-Length: 0\r\n\r\n".encode())
    outer = tcp_server(redirect)
    guarded(loopback_ports={outer.port})
    with pytest.raises(OSError, match=f"127.0.0.1 port {inner.port} is on this server"):
        HTTPClient().send(outer.url + "/", timeout=5)


def test_download_size_limit(guarded, tcp_server, monkeypatch):
    body = b"x" * 50_000

    def big(h):
        h.rfile.readline()
        h.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % len(body) + body)
    server = tcp_server(big)
    guarded(loopback_ports={server.port})
    monkeypatch.setattr(guard, "MAX_RECEIVE", 10_000)
    guard.install(guard.active())  # re-apply with the smaller limit
    with pytest.raises(OSError, match="limits how much one request may download"):
        HTTPClient().send(server.url + "/", timeout=5)
    guard.uninstall()
    assert net.MAX_RECEIVE is None
    assert len(HTTPClient().send(server.url + "/", timeout=5).body) == len(body)


# ------------------------------------------------------------ the assistant's tools

def test_assistant_tools_follow_the_demo_rules():
    tools = build_tools(lambda wire: None, lambda: "", demo=DemoRules(1025, 10325))
    with pytest.raises(ValueError, match="only sends GET and HEAD"):
        tools["http_request"].run({"url": "https://example.com", "method": "POST"})
    with pytest.raises(ValueError, match="test inbox"):
        tools["send_email"].run({"server": "smtp.gmail.com", "port": 587, "from": "a@b.c", "to": "d@e.f"})
    with pytest.raises(ValueError, match="only scans scanme.nmap.org"):
        tools["port_scan"].run({"host": "192.168.1.1"})


def test_demo_rules():
    rules = DemoRules(1025, 10325)
    rules.http("get")
    rules.smtp("localhost", 1025)
    with pytest.raises(ValueError):
        rules.http("GET", body="x")
    with pytest.raises(ValueError):
        rules.smtp("127.0.0.1", 25)
    with pytest.raises(ValueError, match="at most 100 ports"):
        rules.begin_scan("scanme.nmap.org", "1-1000")


# ------------------------------------------------------------ sessions

def test_session_store_limits_and_expiry(monkeypatch):
    store = SessionStore(limit=2, idle=60)
    a, b = store.create(), store.create()
    assert store.get(a.id) is a  # a is now the most recently used
    c = store.create()
    assert store.get(b.id) is None and store.get(a.id) is a and store.get(c.id) is c
    clock = [1000.0]
    monkeypatch.setattr("protocol_toolkit.webapp.server.time.monotonic", lambda: clock[0])
    a.seen = c.seen = clock[0]
    clock[0] += 61
    assert store.get(a.id) is None and len(store) == 0
    assert store.get("") is None


@pytest.fixture
def demo():
    ports = (free_port(), free_port())
    app = create_app(demo=True, demo_ports=ports)
    with TestClient(app, base_url=BASE) as c:
        yield c, ports


def visitor(c) -> dict:
    """Start a new visitor session; returns the headers that identify it"""
    c.cookies.clear()
    r = c.get("/")
    assert r.status_code == 200
    sid = r.cookies[SESSION_COOKIE]
    c.cookies.clear()
    return {"Cookie": f"{SESSION_COOKIE}={sid}"}


def test_demo_session_cookie(demo):
    c, _ = demo
    assert c.get("/api/info").status_code == 401
    r = c.get("/")
    cookie = r.headers["set-cookie"].lower()
    assert SESSION_COOKIE in cookie and "httponly" in cookie and "samesite=lax" in cookie
    assert "secure" not in cookie  # plain http is only allowed on loopback, for trying the demo locally
    info = c.get("/api/info").json()
    assert info["demo"]["http_methods"] == ["GET", "HEAD"]
    assert "set-cookie" not in c.get("/").headers  # an existing session is kept


def test_demo_visitors_are_isolated(demo):
    c, (smtp_port, dns_port) = demo
    a, b = visitor(c), visitor(c)
    mail = {"server": "127.0.0.1", "port": smtp_port, "from": "a@example.com", "to": ["b@example.com"],
            "subject": "only for a", "body": "hi"}
    assert "error" not in c.post("/api/smtp", json=mail, headers=a).json()
    r = c.post("/api/dns", json={"name": "toolkit.test", "type": "A", "server": f"127.0.0.1:{dns_port}"}, headers=a)
    assert r.json()["rcode"] == "NOERROR"

    inbox_a, inbox_b = c.get("/api/servers/inbox", headers=a).json(), c.get("/api/servers/inbox", headers=b).json()
    assert [m["subject"] for m in inbox_a] == ["only for a"] and inbox_b == []
    assert c.get("/api/servers/inbox/0", headers=a).json()["body"].strip() == "hi"
    assert c.get("/api/servers/inbox/0", headers=b).status_code == 404
    servers_a, servers_b = c.get("/api/servers", headers=a).json(), c.get("/api/servers", headers=b).json()
    assert servers_a["locked"] and servers_a["smtp"]["messages"] == 1 and servers_b["smtp"]["messages"] == 0
    assert any("toolkit.test" in q for q in servers_a["dns"]["queries"]) and servers_b["dns"]["queries"] == []

    wires_a = c.get("/api/wires", headers=a).json()
    assert len(wires_a) == 2 and c.get("/api/wires", headers=b).json() == []
    assert c.get(f"/api/wires/{wires_a[0]['id']}", headers=b).status_code == 404
    c.delete("/api/wires", headers=b)
    assert len(c.get("/api/wires", headers=a).json()) == 2


def test_demo_refuses_what_it_does_not_allow(demo):
    c, (smtp_port, _) = demo
    v = visitor(c)
    r = c.post("/api/http", json={"url": "https://example.com", "method": "POST"}, headers=v)
    assert r.status_code == 403 and "GET and HEAD" in r.json()["detail"]
    for url in ("http://127.0.0.1:8765/api/info", "http://169.254.169.254/latest/meta-data/", "http://10.0.0.1/",
                "http://[::1]:8765/"):
        r = c.post("/api/http", json={"url": url}, headers=v).json()
        assert "Blocked in the public demo" in r["error"], url
    r = c.post("/api/smtp", json={"server": "smtp.gmail.com", "port": 587, "from": "a@b.co", "to": ["c@d.co"]}, headers=v)
    assert r.status_code == 403
    assert c.post("/api/scan", json={"host": "10.0.0.1"}, headers=v).status_code == 403
    r = c.post("/api/dns", json={"name": "example.com", "server": "10.0.0.1"}, headers=v).json()
    assert "Blocked in the public demo" in r["error"]
    for path in ("/api/servers/smtp/stop", "/api/servers/dns/stop", "/api/servers/smtp/start", "/api/llm/start-ollama"):
        assert c.post(path, json={}, headers=v).status_code == 403, path
    assert c.put("/api/servers/dns/zone", json={"zone": "x. 60 A 1.2.3.4"}, headers=v).status_code == 403
    big = c.post("/api/http", content=b"x" * 300_000, headers={**v, "Content-Type": "application/json"})
    assert big.status_code == 413
    status = c.get("/api/llm/status", headers=v).json()
    assert status["ollama"]["disabled"] and status["claude"]["own_key_required"]


def test_demo_rate_limit(demo):
    c, _ = demo
    v = visitor(c)
    codes = [c.post("/api/http", json={"url": "https://example.com", "method": "PUT"}, headers=v).status_code
             for _ in range(31)]
    assert codes[:30] == [403] * 30 and codes[30] == 429
    other = visitor(c)
    assert c.post("/api/http", json={"url": "https://example.com", "method": "PUT"}, headers=other).status_code == 403


def test_demo_assistant_needs_the_visitors_own_key(demo):
    c, _ = demo
    v = visitor(c)
    with c.websocket_connect("ws://127.0.0.1:8765/api/assistant", headers=v) as ws:
        ws.send_json({"type": "ask", "text": "hi", "provider": "ollama"})
        msg = ws.receive_json()
        assert msg["type"] == "error" and "your own Anthropic API key" in msg["message"]
    assert c.post("/api/settings", json={"api_key": "sk-test"}, headers=v).json() == {"key_set": True}
    assert not c.get("/api/llm/status", headers=visitor(c)).json()["claude"]["key_set"]  # keys are per visitor


def test_demo_public_host_rules():
    app = create_app(demo=True, public_hosts=["demo.example.com"], demo_ports=(free_port(), free_port()))
    with TestClient(app, base_url="https://demo.example.com") as c:
        assert c.get("/healthz", headers={"Host": "10.0.0.7:10000"}).json() == {"ok": True}
        assert c.get("/", headers={"Host": "evil.example"}).status_code == 403
        assert c.get("/", headers={"Host": "demo.example.com:1;x"}).status_code == 403
        r = c.get("/")
        assert "secure" in r.headers["set-cookie"].lower()
        assert r.headers["strict-transport-security"]
        assert "connect-src 'self' wss://demo.example.com;" in r.headers["content-security-policy"]
        assert c.get("/api/info", headers={"Origin": "https://demo.example.com"}).status_code == 200
        assert c.get("/api/info", headers={"Origin": "http://demo.example.com"}).status_code == 403
        with pytest.raises(Exception):
            with c.websocket_connect("wss://demo.example.com/api/assistant", headers={"Origin": "https://evil.example"}):
                pass


def test_demo_assistant_runs_with_the_demo_rules(demo, monkeypatch):
    """With the visitor's key, the assistant's tools follow the demo rules and its mail lands in their inbox"""
    from protocol_toolkit.llm import ToolCall
    from protocol_toolkit.webapp import server as server_module
    from test_agent import ScriptedProvider
    c, (smtp_port, _) = demo
    provider = ScriptedProvider([
        ("", [ToolCall("1", "http_request", {"url": "https://example.com", "method": "POST"}),
              ToolCall("2", "send_email", {"server": "127.0.0.1", "port": smtp_port, "from": "bot@example.com",
                                           "to": "me@example.com", "subject": "from the assistant"})]),
        ("Done.", []),
    ])
    used = {}
    monkeypatch.setattr(server_module.llm, "make_provider",
                        lambda kind, model, key: used.update(kind=kind, key=key) or provider)
    v, other = visitor(c), visitor(c)
    c.post("/api/settings", json={"api_key": "sk-visitor"}, headers=v)
    with c.websocket_connect("ws://127.0.0.1:8765/api/assistant", headers=v) as ws:
        ws.send_json({"type": "ask", "text": "hi", "provider": "claude", "model": "m"})
        while True:
            msg = ws.receive_json()
            if msg["type"] == "approval":
                ws.send_json({"type": "approval", "id": msg["id"], "allow": True})
            if msg["type"] in ("done", "error"):
                break
    assert msg == {"type": "done", "text": "Done."}
    assert used == {"kind": "claude", "key": "sk-visitor"}
    assert "public demo" in provider.system
    post, mail = provider.results[0]
    assert post[2] is True and "only sends GET and HEAD" in post[1]
    assert mail[2] is False
    assert [m["subject"] for m in c.get("/api/servers/inbox", headers=v).json()] == ["from the assistant"]
    assert c.get("/api/servers/inbox", headers=other).json() == []
