import pytest

from protocol_toolkit import smtpclient
from protocol_toolkit.dnsclient import DNSClient, split_server
from protocol_toolkit.testservers import DNSTestServer, SMTPTestServer, parse_zone, port_in_use

from conftest import free_port


@pytest.mark.parametrize("server,expected", [
    ("8.8.8.8", ("8.8.8.8", 53)), ("127.0.0.1:10325", ("127.0.0.1", 10325)),
    ("[::1]:5353", ("::1", 5353)), ("::1", ("::1", 53)), ("dns.google", ("dns.google", 53)),
])
def test_split_server(server, expected):
    assert split_server(server, 53) == expected


def test_zone_parsing():
    records = parse_zone('a.test A 10.0.0.1\n; comment\nt.test TXT "v=DMARC1; p=reject" ttl=60\n')
    assert [(r.name, r.type, r.value, r.ttl) for r in records] == [
        ("a.test", 1, "10.0.0.1", 300), ("t.test", 16, '"v=DMARC1; p=reject"', 60)]
    with pytest.raises(ValueError, match="Line 1"):
        parse_zone("a.test BOGUS 1")


@pytest.fixture
def dns_server():
    server = DNSTestServer(free_port())
    server.start()
    yield f"127.0.0.1:{server.port}", server
    server.stop()


@pytest.mark.parametrize("transport", ["UDP", "TCP"])
def test_dns_server_answers(dns_server, transport):
    addr, _ = dns_server
    c = DNSClient()
    a = c.query("toolkit.test", "A", addr, transport)
    assert a.authoritative and [r.value for r in a.answers] == ["127.0.0.1"]
    cname = c.query("www.toolkit.test", "A", addr, transport)
    assert [r.type_name for r in cname.answers] == ["CNAME", "A"]
    assert c.query("anything.dev.test", "A", addr, transport).answers[0].value == "127.0.0.1"
    assert c.query("missing.test", "A", addr, transport).rcode_name == "NXDOMAIN"
    nodata = c.query("toolkit.test", "SRV", addr, transport)
    assert nodata.rcode_name == "NOERROR" and not nodata.answers


def test_dns_zone_can_be_changed_live(dns_server):
    addr, server = dns_server
    server.set_zone("new.test A 192.0.2.7")
    assert DNSClient().query("new.test", "A", addr).answers[0].value == "192.0.2.7"
    assert len(server.queries) == 1


def test_udp_to_closed_port_explains_itself():
    with pytest.raises(OSError, match="Nothing is listening|No answer"):
        DNSClient().query("toolkit.test", "A", f"127.0.0.1:{free_port()}", "UDP", timeout=1)


def test_smtp_sink_receives_mail():
    received = []
    server = SMTPTestServer(free_port(), on_message=received.append)
    server.start()
    try:
        assert port_in_use(server.port)
        smtpclient.send_email("127.0.0.1", server.port, "a@example.com", ["b@example.com", "c@example.com"],
                              "Hi there", "line\n.leading dot", username="me", password="pw")
    finally:
        server.stop()
    mail = received[0]
    assert mail.subject == "Hi there" and mail.rcpt_to == ["b@example.com", "c@example.com"]
    assert mail.body_text().splitlines() == ["line", ".leading dot"]  # dot-stuffing undone
    assert mail.authenticated_as == "me"
    assert not port_in_use(server.port)


def test_port_conflict_is_reported():
    first = SMTPTestServer(free_port())
    first.start()
    try:
        with pytest.raises(OSError, match="Could not listen"):
            SMTPTestServer(first.port).start()
    finally:
        first.stop()
