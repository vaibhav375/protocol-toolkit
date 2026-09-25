"""Backend for the React UI: security rules and every endpoint (no browser needed)."""
import pytest

pytest.importorskip("fastapi")
from fastapi.testclient import TestClient  # noqa: E402

from protocol_toolkit.webapp import server as server_module  # noqa: E402
from protocol_toolkit.webapp.server import COOKIE, create_app  # noqa: E402

from conftest import free_port  # noqa: E402

TOKEN = "test-token"
BASE = "http://127.0.0.1:8765"
WS_URL = "ws://127.0.0.1:8765/api/assistant"  # full URL: the test client otherwise uses host "testserver"


@pytest.fixture
def client():
    app = create_app(TOKEN, allowed_ports={8765})
    with TestClient(app, base_url=BASE, headers={"X-Token": TOKEN}) as c:
        yield c
        c.post("/api/servers/smtp/stop")
        c.post("/api/servers/dns/stop")


# ------------------------------------------------------------ security

def test_api_requires_the_session_token():
    app = create_app(TOKEN, allowed_ports={8765})
    with TestClient(app, base_url=BASE) as c:
        assert c.get("/api/info").status_code == 401
        assert c.get("/api/info", headers={"X-Token": "wrong"}).status_code == 401
        # the launch link swaps the token for an HttpOnly same-site cookie
        r = c.get(f"/?t={TOKEN}", follow_redirects=False)
        assert r.status_code == 303 and COOKIE in r.cookies
        assert "samesite=strict" in r.headers["set-cookie"].lower() and "httponly" in r.headers["set-cookie"].lower()
        assert c.get("/api/info").status_code == 200  # cookie now sent automatically


def test_dns_rebinding_and_cross_site_requests_are_blocked(client):
    assert client.get("/api/info", headers={"Host": "evil.example:8765"}).status_code == 403
    assert client.get("/api/info", headers={"Host": "127.0.0.1:9999"}).status_code == 403
    r = client.post("/api/http", json={"url": "http://127.0.0.1:1"}, headers={"Origin": "https://evil.example"})
    assert r.status_code == 403
    assert client.get("/api/info", headers={"Origin": BASE}).status_code == 200


def test_security_headers(client):
    r = client.get("/api/info")
    assert r.headers["x-frame-options"] == "DENY" and r.headers["x-content-type-options"] == "nosniff"


# ------------------------------------------------------------ protocols through the API

def test_test_servers_dns_and_smtp_end_to_end(client):
    dns_port, smtp_port = free_port(), free_port()
    assert client.post("/api/servers/dns/start", json={"port": dns_port}).json()["dns"]["running"]
    r = client.post("/api/dns", json={"name": "toolkit.test", "type": "MX", "server": f"127.0.0.1:{dns_port}"}).json()
    assert r["rcode"] == "NOERROR" and r["answers"][0]["value"] == "10 mail.toolkit.test."
    assert "AA" in r["flags"]

    wire = client.get(f"/api/wires/{r['wire_id']}").json()
    assert [e["direction"] for e in wire["events"]] == ["out", "in"]
    assert any(f["label"] == "Question" for f in wire["events"][0]["fields"])

    bad_zone = client.put("/api/servers/dns/zone", json={"zone": "x.test BOGUS 1"})
    assert bad_zone.status_code == 400 and "Line 1" in bad_zone.json()["detail"]
    client.put("/api/servers/dns/zone", json={"zone": "new.test A 192.0.2.9"})
    r = client.post("/api/dns", json={"name": "new.test", "server": f"127.0.0.1:{dns_port}"}).json()
    assert r["answers"][0]["value"] == "192.0.2.9"

    client.post("/api/servers/smtp/start", json={"port": smtp_port})
    r = client.post("/api/smtp", json={"server": "127.0.0.1", "port": smtp_port, "from": "a@example.com",
                                       "to": ["b@example.com"], "subject": "Via API", "body": "hi"}).json()
    assert r["result"].startswith("250") and any(line.startswith("C: DATA") for line in r["log"])
    inbox = client.get("/api/servers/inbox").json()
    assert inbox[0]["subject"] == "Via API"
    assert client.get("/api/servers/inbox/0").json()["body"].strip() == "hi"


def test_smtp_refused_gives_a_hint(client):
    r = client.post("/api/smtp", json={"server": "127.0.0.1", "port": free_port(), "from": "a@example.com",
                                       "to": ["b@example.com"]}).json()
    assert "refused" in r["error"].lower() and "Test Servers" in r["hint"] and r["wire_id"]


def test_http_against_local_server(client, tcp_server):
    def handle(h):
        while h.rfile.readline() not in (b"\r\n", b""):
            pass
        h.wfile.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nSet-Cookie: s=1\r\n"
                      b"Content-Length: 11\r\n\r\n{\"ok\":true}")

    r = client.post("/api/http", json={"url": tcp_server(handle).url + "/x"}).json()
    assert r["status"] == 200 and '"ok": true' in r["body"] and r["version"] == "HTTP/1.1"
    assert r["cookies"][0]["name"] == "s" and any(p["name"] == "TCP connect" for p in r["phases"])
    summaries = client.get("/api/wires").json()
    assert summaries[-1]["id"] == r["wire_id"] and "HTTP/1.1" in summaries[-1]["layers"]
    assert client.delete("/api/http/cookies").json() == []


def test_http_error_still_returns_the_capture(client):
    r = client.post("/api/http", json={"url": f"http://127.0.0.1:{free_port()}"}).json()
    assert "refused" in r["error"].lower() and client.get(f"/api/wires/{r['wire_id']}").status_code == 200


def test_port_conflict_and_bad_scan_input(client):
    port = free_port()
    client.post("/api/servers/smtp/start", json={"port": port})
    client.post("/api/servers/smtp/stop")
    assert client.post("/api/scan", json={"host": "127.0.0.1", "ports": "0-5"}).status_code == 400
    assert client.post("/api/scan", json={"host": "no-such-host.invalid"}).status_code == 400


# ------------------------------------------------------------ assistant websocket

def test_assistant_websocket_tools_and_approval(client, monkeypatch):
    from protocol_toolkit.llm import ToolCall
    from test_agent import ScriptedProvider
    provider = ScriptedProvider([
        ("Checking.", [ToolCall("1", "read_current_capture", {}),
                       ToolCall("2", "port_scan", {"host": "127.0.0.1", "ports": "1"})]),
        ("All good.", []),
    ])
    monkeypatch.setattr(server_module.llm, "make_provider", lambda *a, **k: provider)
    with client.websocket_connect(WS_URL, headers={"X-Token": TOKEN}) as ws:
        ws.send_json({"type": "ask", "text": "hi", "provider": "ollama", "model": "x"})
        seen = []
        while True:
            msg = ws.receive_json()
            seen.append(msg["type"])
            if msg["type"] == "approval":
                assert msg["tool"] == "port_scan"
                ws.send_json({"type": "approval", "id": msg["id"], "allow": False})
            if msg["type"] in ("done", "error"):
                break
    assert msg == {"type": "done", "text": "All good."}
    assert "text" in seen and "tool" in seen and "approval" in seen
    declined = provider.results[0][1]
    assert declined[2] is True and "declined" in declined[1]


def test_assistant_websocket_rejects_cross_site(client):
    from starlette.websockets import WebSocketDisconnect
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(WS_URL, headers={"X-Token": TOKEN, "Origin": "https://evil.example"}) as ws:
            ws.receive_json()


# ------------------------------------------------------------ saved sessions and exports

def test_captures_persist_and_export(tmp_path):
    from protocol_toolkit.pcap import read_pcapng
    app = create_app(TOKEN, allowed_ports={8765}, data_dir=tmp_path)
    with TestClient(app, base_url=BASE, headers={"X-Token": TOKEN}) as c:
        dns_port = free_port()
        c.post("/api/servers/dns/start", json={"port": dns_port})
        r = c.post("/api/dns", json={"name": "toolkit.test", "server": f"127.0.0.1:{dns_port}"}).json()
        c.post("/api/servers/dns/stop")
        wid = r["wire_id"]
        summary = c.get("/api/wires").json()[-1]
        assert summary["exports"] == {"pcapng": True, "har": False, "keys": False}
        pcap = c.get(f"/api/wires/{wid}/export/pcapng")
        assert pcap.headers["content-type"] == "application/x-pcapng"
        assert "attachment" in pcap.headers["content-disposition"]
        assert len(read_pcapng(pcap.content)["packets"]) == 2  # UDP query and response
        assert c.get(f"/api/wires/{wid}/export/har").status_code == 404
        assert "toolkit.test" in c.get(f"/api/wires/{wid}/export/transcript").text
    saved = list((tmp_path / "captures").glob("*.json"))
    assert len(saved) == 1 and oct(saved[0].stat().st_mode)[-3:] == "600"

    # a new app instance (i.e. after a restart) still has the capture, and new ids don't collide
    app2 = create_app(TOKEN, allowed_ports={8765}, data_dir=tmp_path)
    with TestClient(app2, base_url=BASE, headers={"X-Token": TOKEN}) as c:
        assert [w["id"] for w in c.get("/api/wires").json()] == [wid]
        new = c.post("/api/http", json={"url": f"http://127.0.0.1:{free_port()}"}).json()["wire_id"]
        assert new > wid
        c.delete(f"/api/wires/{wid}")
        assert [w["id"] for w in c.get("/api/wires").json()] == [new]
        c.delete("/api/wires")
        assert c.get("/api/wires").json() == []
    assert not list((tmp_path / "captures").glob("*.json"))
