import base64
import shutil
import subprocess

import pytest

from protocol_toolkit.mailcheck import (FAIL, PASS, WARN, DeliverabilityChecker, MailReport, parse_spf,
                                        parse_tags, rsa_key_bits)


class FakeRecord:
    def __init__(self, type_, value):
        self.type, self.value = type_, value


class FakeDNS:
    def __init__(self, txt=None, mx=None):
        self.txt, self.mx = txt or {}, mx or []

    def lookup(self, name, qtype, *args, **kwargs):
        if qtype == "TXT":
            return [FakeRecord(16, v) for v in self.txt.get(name, [])]
        if qtype == "MX":
            return [FakeRecord(15, v) for v in self.mx]
        return []


def checker(**kwargs) -> DeliverabilityChecker:
    return DeliverabilityChecker(dns=FakeDNS(**kwargs))


def statuses(report: MailReport, area: str):
    return [c.status for c in report.checks if c.area == area]


def test_parsers():
    assert parse_spf("v=spf1 ip4:1.2.3.0/24 include:_spf.google.com -all redirect=x.com") == [
        ("+", "ip4", "1.2.3.0/24"), ("+", "include", "_spf.google.com"), ("-", "all", ""), ("+", "redirect", "x.com")]
    assert parse_tags("v=DMARC1; p=reject; rua=mailto:a@b.c") == {"v": "DMARC1", "p": "reject", "rua": "mailto:a@b.c"}


@pytest.mark.parametrize("record,expected", [
    ("v=spf1 include:a.test -all", PASS),
    ("v=spf1 mx ~all", PASS),
    ("v=spf1 +all", FAIL),
    ("v=spf1 mx", WARN),
])
def test_spf_policies(record, expected):
    report = MailReport("x.test")
    checker(txt={"x.test": [record], "a.test": ["v=spf1 ip4:1.1.1.1 -all"]}).check_spf("x.test", report)
    assert statuses(report, "SPF") == [expected]


def test_spf_multiple_records_and_lookup_limit():
    report = MailReport("x.test")
    checker(txt={"x.test": ["v=spf1 -all", "v=spf1 ~all"]}).check_spf("x.test", report)
    assert statuses(report, "SPF") == [FAIL]

    chain = {f"n{i}.test": [f"v=spf1 include:n{i + 1}.test a mx -all"] for i in range(6)}
    chain["x.test"] = ["v=spf1 include:n0.test -all"]
    report = MailReport("x.test")
    checker(txt=chain).check_spf("x.test", report)
    assert statuses(report, "SPF") == [FAIL] and "too many" in report.checks[0].title


def test_dmarc_levels_and_inheritance():
    for policy, expected in (("reject", PASS), ("quarantine", PASS), ("none", WARN)):
        report = MailReport("x.test")
        checker(txt={"_dmarc.x.test": [f"v=DMARC1; p={policy}; rua=mailto:r@x.test"]}).check_dmarc("x.test", report)
        assert statuses(report, "DMARC") == [expected]
    report = MailReport("mail.x.test")
    checker(txt={"_dmarc.x.test": ["v=DMARC1; p=reject"]}).check_dmarc("mail.x.test", report)
    assert statuses(report, "DMARC") == [PASS] and "inherited" in report.checks[0].detail
    report = MailReport("x.test")
    checker().check_dmarc("x.test", report)
    assert statuses(report, "DMARC") == [FAIL]


def test_lookup_failure_is_not_reported_as_missing():
    class FlakyDNS(FakeDNS):
        def lookup(self, name, qtype, *args, **kwargs):
            if qtype == "TXT":
                raise TimeoutError("No answer from 8.8.8.8 within 5s")
            return super().lookup(name, qtype)

    report = DeliverabilityChecker(dns=FlakyDNS(mx=[(10, "mx.x.test")])).run("x.test", probe_smtp=False)
    spf = [c for c in report.checks if c.area == "SPF"][0]
    assert spf.status == WARN and spf.title == "Couldn't check SPF" and "No answer" in spf.detail
    assert not any(c.status == FAIL for c in report.checks)


def test_mx_and_null_mx():
    report = MailReport("x.test")
    hosts = checker(mx=[(20, "b.x.test"), (10, "a.x.test")]).check_mx("x.test", report)
    assert hosts == ["a.x.test", "b.x.test"] and statuses(report, "MX") == [PASS]
    report = MailReport("x.test")
    assert checker(mx=[(0, "")]).check_mx("x.test", report) == []


@pytest.mark.skipif(not shutil.which("openssl"), reason="openssl CLI not available")
@pytest.mark.parametrize("bits", [1024, 2048])
def test_rsa_key_size_from_dkim_record(bits, tmp_path):
    key = tmp_path / "k.pem"
    subprocess.run(["openssl", "genrsa", "-out", str(key), str(bits)], check=True, capture_output=True)
    der = subprocess.run(["openssl", "rsa", "-in", str(key), "-pubout", "-outform", "DER"],
                         check=True, capture_output=True).stdout
    assert rsa_key_bits(base64.b64encode(der).decode()) == bits
    report = MailReport("x.test")
    checker(txt={"s1._domainkey.x.test": [f"v=DKIM1; k=rsa; p={base64.b64encode(der).decode()}"]}).check_dkim(
        "x.test", report, ["s1"])
    assert statuses(report, "DKIM") == [PASS if bits >= 2048 else WARN]


def test_grades():
    report = MailReport("x.test")
    report.add("A", PASS, "ok")
    assert report.grade == "A"
    report.add("B", WARN, "meh")
    assert report.grade == "B"
    report.add("C", FAIL, "bad")
    assert report.grade == "D"


@pytest.mark.network
def test_live_gmail():
    report = DeliverabilityChecker().run("gmail.com", probe_smtp=False)
    assert statuses(report, "MX") == [PASS] and statuses(report, "SPF") == [PASS]
