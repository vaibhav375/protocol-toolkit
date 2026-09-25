import base64
import ssl

import pytest

from protocol_toolkit import smtpclient
from protocol_toolkit.smtpclient import SMTPClient, SMTPError
from protocol_toolkit.wire import WireLog


def fake_smtp(received: dict, tls_context=None, auth=True):
    """Handler for a fake SMTP server; records commands and the message"""
    def handle(h):
        rfile, wfile = h.rfile, h.wfile

        def w(line):
            wfile.write(line.encode() + b"\r\n")
            wfile.flush()

        w("220 fake ESMTP ready")
        while True:
            line = rfile.readline().decode().rstrip("\r\n")
            if not line:
                return
            received.setdefault("cmds", []).append(line)
            verb = line.split()[0].upper()
            if verb == "EHLO":
                w("250-fake greets you")
                w("250-SIZE 10000000")
                if tls_context and not received.get("tls"):
                    w("250-STARTTLS")
                if auth:
                    w("250-AUTH PLAIN LOGIN")
                w("250 8BITMIME")
            elif verb == "STARTTLS":
                w("220 go ahead")
                sock = tls_context.wrap_socket(h.connection, server_side=True)
                received["tls"] = sock.version()
                rfile, wfile = sock.makefile("rb"), sock.makefile("wb")
            elif verb == "AUTH":
                received["auth"] = line
                w("235 ok")
            elif verb == "DATA":
                w("354 end with .")
                data = []
                while True:
                    l = rfile.readline().decode()
                    if l == ".\r\n":
                        break
                    data.append(l)
                received["data"] = "".join(data)
                w("250 queued")
            elif verb == "QUIT":
                w("221 bye")
                return
            else:
                w("250 ok")
    return handle


def test_send_preserves_case_dot_stuffs_and_closes(tcp_server):
    received = {}
    server = tcp_server(fake_smtp(received))
    wire = WireLog()
    result = smtpclient.send_email("127.0.0.1", server.port, "Alice.Smith@Example.com", ["bob@example.com"],
                                   "Hi", "line1\n.starts with dot\nlast", wire=wire)
    assert result.code == 250
    assert "MAIL FROM:<Alice.Smith@Example.com> SIZE=" in " ".join(received["cmds"])
    assert "\r\n..starts with dot\r\n" in received["data"]
    assert "Message-ID:" in received["data"] and "Date:" in received["data"]
    assert received["cmds"][-1] == "QUIT"
    assert any(e.layer == "SMTP" and e.direction == "in" for e in wire.events)


def test_multiline_ehlo_features(tcp_server):
    server = tcp_server(fake_smtp({}))
    client = SMTPClient("127.0.0.1", server.port)
    try:
        client.connect()
        assert {"SIZE", "AUTH", "8BITMIME"} <= set(client.features)
        assert client.features["AUTH"] == "PLAIN LOGIN"
    finally:
        client.quit()


def test_auth_is_hidden_from_logs_and_wire(tcp_server):
    received = {}
    server = tcp_server(fake_smtp(received))
    wire, log = WireLog(), []
    smtpclient.send_email("localhost", server.port, "a@example.com", ["b@example.com"], "s", "b",
                          username="me", password="hunter2-secret", wire=wire, log=log.append)
    token = base64.b64encode(b"\0me\0hunter2-secret").decode()
    assert received["auth"] == f"AUTH PLAIN {token}"
    everything = "\n".join(log) + "".join(e.data.decode("utf-8", "replace") for e in wire.events)
    assert token not in everything and "hunter2" not in everything
    assert "<credentials hidden>" in everything


def test_refuses_password_over_plaintext_to_remote_host():
    client = SMTPClient("mail.example.com", 25)

    class PlainConn:
        is_tls = False

    client.conn = PlainConn()
    with pytest.raises(SMTPError, match="unencrypted"):
        client.login("me", "pw")


def test_starttls_upgrade(tcp_server, self_signed_cert):
    ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ctx.load_cert_chain(*self_signed_cert)
    received = {}
    server = tcp_server(fake_smtp(received, tls_context=ctx))
    wire = WireLog()
    smtpclient.send_email("127.0.0.1", server.port, "a@example.com", ["b@example.com"], "s", "body",
                          tls_mode=smtpclient.TLS_STARTTLS, verify_tls=False, username="u", password="p", wire=wire)
    assert received["tls"].startswith("TLS")
    assert received["cmds"].count("EHLO " + SMTPClient("x", 1).local_name) == 2  # EHLO again after STARTTLS
    assert any(e.layer == "TLS" and e.summary.startswith("ClientHello") for e in wire.events)


def test_invalid_addresses():
    client = SMTPClient()
    with pytest.raises(ValueError):
        client.send_mail("not-an-address", ["b@example.com"], "s", "b")
