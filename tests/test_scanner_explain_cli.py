import json
import socket

import pytest

from protocol_toolkit import explain, scanner
from protocol_toolkit.__main__ import main


def test_parse_ports():
    assert scanner.parse_ports("22, 80,8000-8002") == [22, 80, 8000, 8001, 8002]
    with pytest.raises(ValueError):
        scanner.parse_ports("0-10")
    with pytest.raises(ValueError):
        scanner.parse_ports("70000")


def test_scan_finds_services_and_banners(tcp_server):
    def ssh_like(h):
        h.wfile.write(b"SSH-2.0-OpenSSH_9.9 test\r\n")

    def http_like(h):
        h.rfile.readline()
        h.wfile.write(b"HTTP/1.1 200 OK\r\nServer: toy/1.0\r\n\r\n")

    ssh, web = tcp_server(ssh_like), tcp_server(http_like)
    closed = socket.socket()
    closed.bind(("127.0.0.1", 0))
    closed_port = closed.getsockname()[1]
    closed.close()

    results = scanner.scan("127.0.0.1", [ssh.port, web.port, closed_port], timeout=0.5)
    assert results[ssh.port].status == scanner.OPEN and results[ssh.port].service.endswith("ssh")
    assert results[ssh.port].banner.startswith("SSH-2.0-OpenSSH_9.9")
    assert "toy/1.0" in results[web.port].banner and "http" in results[web.port].service
    assert results[closed_port].status == scanner.CLOSED

    rows = json.loads(scanner.export(list(results.values()), "json"))
    assert [r["port"] for r in rows] == sorted(results)
    assert scanner.export(list(results.values()), "csv").startswith("port,status,service,banner,tls")


def test_scan_can_be_stopped():
    results = scanner.scan("127.0.0.1", list(range(20000, 20400)), 0.2, workers=4, should_stop=lambda: True)
    assert len(results) < 400


def test_redaction():
    text = ("Authorization: Bearer abcdefghijklmnop\n    cookie: sid=secret\nSet-Cookie: a=b; HttpOnly\n"
            "GET /?api_key=XYZ123&x=1\nhttps://user:pa55@host/\nkey sk-ant-api03-abcdef\nX-Api-Key: k\n"
            "Content-Type: text/html")
    out = explain.redact(text)
    for secret in ("abcdefghijklmnop", "sid=secret", "a=b", "XYZ123", "pa55", "sk-ant-api03", ": k\n"):
        assert secret not in out
    assert "Content-Type: text/html" in out and "x=1" in out


def test_claude_provider_reports_missing_sdk(monkeypatch):
    import builtins
    from protocol_toolkit.llm import ClaudeProvider, LLMError
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "anthropic":
            raise ImportError
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(LLMError, match="pip install anthropic"):
        ClaudeProvider()


def test_cli_scan(tcp_server, capsys):
    server = tcp_server(lambda h: h.wfile.write(b"220 hello SMTP\r\n"))
    assert main(["scan", "127.0.0.1", "--ports", str(server.port)]) == 0
    out = capsys.readouterr().out
    assert f"{server.port}/tcp" in out and "1 open of 1 scanned" in out


def test_cli_reports_errors(capsys):
    assert main(["scan", "no-such-host.invalid", "--ports", "80"]) == 2
    assert "Could not resolve" in capsys.readouterr().err
