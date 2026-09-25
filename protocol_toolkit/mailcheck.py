"""Email deliverability checker: MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI and a
STARTTLS probe of the primary mail server. Read-only: it never sends a message."""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .dnsclient import DNSClient
from .smtpclient import SMTPClient, SMTPError, TLS_NONE
from .net import ConnectionError_

PASS, WARN, FAIL, INFO = "pass", "warn", "fail", "info"
COMMON_DKIM_SELECTORS = ["google", "selector1", "selector2", "default", "k1", "k2", "s1", "s2",
                         "dkim", "mail", "smtp", "mandrill", "mxvault", "sig1", "everlytickey1", "zoho"]
SPF_LOOKUP_LIMIT = 10  # RFC 7208 §4.6.4


@dataclass
class Check:
    area: str
    status: str
    title: str
    detail: str = ""
    records: List[str] = field(default_factory=list)


@dataclass
class MailReport:
    domain: str
    checks: List[Check] = field(default_factory=list)

    def add(self, *args, **kwargs) -> Check:
        check = Check(*args, **kwargs)
        self.checks.append(check)
        return check

    @property
    def counts(self) -> Dict[str, int]:
        out = {PASS: 0, WARN: 0, FAIL: 0, INFO: 0}
        for c in self.checks:
            out[c.status] += 1
        return out

    @property
    def grade(self) -> str:
        c = self.counts
        if c[FAIL] == 0 and c[WARN] == 0:
            return "A"
        if c[FAIL] == 0:
            return "B" if c[WARN] <= 2 else "C"
        return "D" if c[FAIL] == 1 else "F"

    def to_text(self) -> str:
        icon = {PASS: "✔", WARN: "!", FAIL: "✘", INFO: "·"}
        lines = [f"Email deliverability report for {self.domain} - grade {self.grade}", ""]
        for c in self.checks:
            lines.append(f"[{icon[c.status]}] {c.area}: {c.title}")
            if c.detail:
                lines.append(f"      {c.detail}")
            for r in c.records:
                lines.append(f"      {r}")
        return "\n".join(lines)


# ---------------------------------------------------------------- parsers (pure, testable)

def parse_tags(record: str) -> Dict[str, str]:
    """'v=DMARC1; p=reject; rua=mailto:x' -> {'v': 'DMARC1', 'p': 'reject', ...}"""
    tags = {}
    for part in record.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    return tags


def parse_spf(record: str) -> List[Tuple[str, str, str]]:
    """'v=spf1 include:_spf.google.com ~all' -> [('+', 'include', '_spf.google.com'), ('~', 'all', '')]"""
    terms = []
    for term in record.split()[1:]:
        qualifier = term[0] if term[0] in "+-~?" else "+"
        term = term.lstrip("+-~?")
        if "=" in term and ":" not in term.split("=")[0]:
            name, value = term.split("=", 1)  # modifier (redirect=, exp=)
        else:
            name, _, value = term.partition(":")
            name = name.split("/")[0]
        terms.append((qualifier, name.lower(), value))
    return terms


def rsa_key_bits(p_value: str) -> Optional[int]:
    """Key size from a DKIM p= value (DER SubjectPublicKeyInfo holding an RSA key)"""
    try:
        der = base64.b64decode(p_value + "=" * (-len(p_value) % 4))
    except ValueError:
        return None

    def read(buf: bytes, pos: int) -> Tuple[int, int, int]:
        tag, length = buf[pos], buf[pos + 1]
        pos += 2
        if length & 0x80:
            n = length & 0x7F
            length = int.from_bytes(buf[pos:pos + n], "big")
            pos += n
        return tag, pos, length

    try:
        _, pos, _ = read(der, 0)            # SubjectPublicKeyInfo SEQUENCE
        _, alg_pos, alg_len = read(der, pos)
        pos = alg_pos + alg_len              # skip AlgorithmIdentifier
        tag, pos, _ = read(der, pos)         # BIT STRING
        if tag != 0x03:
            return None
        pos += 1                             # unused-bits byte
        _, pos, _ = read(der, pos)           # RSAPublicKey SEQUENCE
        tag, pos, length = read(der, pos)    # modulus INTEGER
        modulus = der[pos:pos + length].lstrip(b"\x00")
        return len(modulus) * 8
    except IndexError:
        return None


# ---------------------------------------------------------------- checker

class LookupFailed(RuntimeError):
    pass


class DeliverabilityChecker:
    def __init__(self, dns: Optional[DNSClient] = None, resolver: str = "8.8.8.8", transport: str = "UDP",
                 timeout: float = 5.0, progress: Callable[[str], None] = lambda s: None):
        self.dns = dns or DNSClient()
        self.resolver, self.transport, self.timeout = resolver, transport, timeout
        self.progress = progress

    def txt(self, name: str) -> List[str]:
        """TXT values; [] means the name has none. A failed lookup (timeout, SERVFAIL...)
        is retried once and then raised, so it is never mistaken for a missing record."""
        for attempt in range(2):
            try:
                return [r.value for r in self.dns.lookup(name, "TXT", self.resolver, self.transport, self.timeout)]
            except (ValueError, OSError, TimeoutError, RuntimeError) as e:
                error = e
        raise LookupFailed(f"Looking up {name} failed: {error}")

    def run(self, domain: str, dkim_selectors: Optional[List[str]] = None, probe_smtp: bool = True) -> MailReport:
        domain = domain.strip().lower().rstrip(".")
        if "@" in domain:
            domain = domain.split("@", 1)[1]
        report = MailReport(domain)
        steps = [("MX records", self.check_mx), ("SPF", self.check_spf), ("DMARC", self.check_dmarc),
                 ("DKIM", lambda d, r: self.check_dkim(d, r, dkim_selectors)),
                 ("MTA-STS", self.check_mta_sts), ("TLS-RPT", self.check_tls_rpt), ("BIMI", self.check_bimi)]
        mx_hosts: List[str] = []
        for name, step in steps:
            self.progress(f"Checking {name}...")
            try:
                result = step(domain, report)
            except LookupFailed as e:
                # Report "couldn't check", never "missing", when the network let us down
                area = "MX" if name == "MX records" else name
                report.add(area, WARN, f"Couldn't check {name}", f"{e}. Try again, or pick another resolver.")
                continue
            if name == "MX records":
                mx_hosts = result or []
        if probe_smtp and mx_hosts:
            self.progress(f"Probing {mx_hosts[0]} on port 25...")
            self.check_smtp_tls(mx_hosts[0], report)
        self.progress("Done")
        return report

    def check_mx(self, domain: str, report: MailReport) -> List[str]:
        try:
            records = self.dns.lookup(domain, "MX", self.resolver, self.transport, self.timeout)
        except (OSError, TimeoutError, RuntimeError, ValueError) as e:
            report.add("MX", FAIL, "MX lookup failed", str(e))
            return []
        if not records:
            a = self.dns.lookup(domain, "A", self.resolver, self.transport, self.timeout)
            if a:
                report.add("MX", WARN, "No MX records; mail falls back to the A record",
                           "RFC 5321 allows this, but an explicit MX is expected.")
                return [domain]
            report.add("MX", FAIL, "No MX records", "This domain cannot receive email.")
            return []
        records.sort(key=lambda r: r.value[0])
        if len(records) == 1 and records[0].value[1] in ("", "."):
            report.add("MX", INFO, "Null MX: the domain declares it accepts no mail (RFC 7505)")
            return []
        report.add("MX", PASS, f"{len(records)} mail server(s)",
                   records=[f"{r.value[0]:>3} {r.value[1]}" for r in records])
        return [r.value[1] for r in records]

    def _count_spf_lookups(self, domain: str, depth: int = 0, seen: Optional[set] = None) -> int:
        seen = seen if seen is not None else set()
        if depth > 10 or domain in seen:
            return 0
        seen.add(domain)
        try:
            records = [t for t in self.txt(domain) if t.lower().startswith("v=spf1")]
        except LookupFailed:
            return 0  # an include we couldn't read; counted as zero rather than failing the check
        if not records:
            return 0
        count = 0
        for _, mech, value in parse_spf(records[0]):
            if mech in ("include", "redirect"):
                count += 1 + self._count_spf_lookups(value, depth + 1, seen)
            elif mech in ("a", "mx", "ptr", "exists"):
                count += 1
        return count

    def check_spf(self, domain: str, report: MailReport) -> None:
        records = [t for t in self.txt(domain) if t.lower().startswith("v=spf1")]
        if not records:
            report.add("SPF", FAIL, "No SPF record",
                       "Without SPF, receivers can't tell which servers may send for this domain.")
            return
        if len(records) > 1:
            report.add("SPF", FAIL, "Multiple SPF records", "RFC 7208 makes this a permanent error; merge them.",
                       records=records)
            return
        terms = parse_spf(records[0])
        all_term = next((q for q, m, _ in terms if m == "all"), None)
        redirect = next((v for _, m, v in terms if m == "redirect"), None)
        lookups = self._count_spf_lookups(domain)
        detail = f"{lookups} DNS lookup{'' if lookups == 1 else 's'} (limit {SPF_LOOKUP_LIMIT})"
        if any(m == "ptr" for _, m, _ in terms):
            detail += "; uses deprecated 'ptr'"
        if lookups > SPF_LOOKUP_LIMIT:
            report.add("SPF", FAIL, "SPF needs too many DNS lookups", detail + " - receivers return permerror.",
                       records=records)
        elif all_term in ("-", "~"):
            policy = "hard fail (-all)" if all_term == "-" else "soft fail (~all)"
            report.add("SPF", PASS, f"SPF record found, {policy}", detail, records=records)
        elif all_term in ("+", "?"):
            report.add("SPF", FAIL, f"SPF ends in '{all_term}all', which lets anyone send as this domain",
                       detail, records=records)
        elif redirect:
            report.add("SPF", PASS, f"SPF redirects to {redirect}", detail, records=records)
        else:
            report.add("SPF", WARN, "SPF has no 'all' mechanism", detail + "; add ~all or -all.", records=records)

    def check_dmarc(self, domain: str, report: MailReport) -> None:
        records = [t for t in self.txt(f"_dmarc.{domain}") if t.upper().startswith("V=DMARC1")]
        source = domain
        if not records and domain.count(".") > 1:
            # Subdomains inherit the organisational domain's policy (simplified: last two labels)
            source = ".".join(domain.split(".")[-2:])
            records = [t for t in self.txt(f"_dmarc.{source}") if t.upper().startswith("V=DMARC1")]
        if not records:
            report.add("DMARC", FAIL, "No DMARC record",
                       "Gmail and Yahoo require DMARC for bulk senders since 2024.")
            return
        tags = parse_tags(records[0])
        policy = tags.get("p", "").lower()
        notes = []
        if source != domain:
            notes.append(f"inherited from {source}")
        if "rua" in tags:
            notes.append("aggregate reports enabled")
        else:
            notes.append("no rua= address, so you get no reports")
        if tags.get("pct", "100") != "100":
            notes.append(f"applies to only {tags['pct']}% of mail")
        detail = "; ".join(notes)
        if policy in ("reject", "quarantine"):
            report.add("DMARC", PASS, f"DMARC policy p={policy}", detail, records=records)
        elif policy == "none":
            report.add("DMARC", WARN, "DMARC is monitoring only (p=none)",
                       detail + ". Move to quarantine/reject once reports look clean.", records=records)
        else:
            report.add("DMARC", FAIL, "DMARC record has no valid p= policy", detail, records=records)

    def check_dkim(self, domain: str, report: MailReport, selectors: Optional[List[str]]) -> None:
        found = []
        for selector in selectors or COMMON_DKIM_SELECTORS:
            try:
                selector_records = self.txt(f"{selector}._domainkey.{domain}")
            except LookupFailed:
                continue
            for record in selector_records:
                tags = parse_tags(record)
                if "p" not in tags:
                    continue
                if not tags["p"]:
                    found.append((selector, "revoked (empty p=)", WARN))
                    continue
                key_type = tags.get("k", "rsa").lower()
                if key_type == "ed25519":
                    found.append((selector, "Ed25519 key", PASS))
                else:
                    bits = rsa_key_bits(tags["p"])
                    status = PASS if (bits or 0) >= 2048 else WARN
                    found.append((selector, f"RSA {bits or '?'}-bit key" +
                                  ("" if status == PASS else " (use 2048+ bits)"), status))
        if not found:
            report.add("DKIM", WARN, "No DKIM key at common selectors",
                       "Selectors are chosen by each mail provider, so this may be a false negative. "
                       "Enter your selector (from a DKIM-Signature header's s= tag) to check it.")
            return
        worst = FAIL if any(s == FAIL for *_, s in found) else WARN if any(s == WARN for *_, s in found) else PASS
        report.add("DKIM", worst, f"DKIM key(s) found for {len(found)} selector(s)",
                   records=[f"{sel}._domainkey: {desc}" for sel, desc, _ in found])

    def check_mta_sts(self, domain: str, report: MailReport) -> None:
        records = [t for t in self.txt(f"_mta-sts.{domain}") if t.lower().startswith("v=stsv1")]
        if not records:
            report.add("MTA-STS", INFO, "No MTA-STS",
                       "Optional: MTA-STS makes other servers require TLS when delivering to you.")
            return
        from .httpclient import HTTPClient
        try:
            policy = HTTPClient().send(f"https://mta-sts.{domain}/.well-known/mta-sts.txt",
                                       timeout=self.timeout, use_cookies=False)
            text = policy.text() if policy.status_code == 200 else ""
        except (OSError, ValueError) as e:
            report.add("MTA-STS", FAIL, "MTA-STS record exists but the policy file can't be fetched", str(e),
                       records=records)
            return
        mode = re.search(r"^mode:\s*(\w+)", text, re.M)
        if not mode:
            report.add("MTA-STS", FAIL, f"MTA-STS policy file missing or invalid (HTTP {policy.status_code})",
                       records=records)
        elif mode.group(1) == "enforce":
            report.add("MTA-STS", PASS, "MTA-STS in enforce mode", records=records + text.strip().splitlines())
        else:
            report.add("MTA-STS", WARN, f"MTA-STS in {mode.group(1)} mode",
                       "Switch to enforce once TLS-RPT reports are clean.", records=records)

    def check_tls_rpt(self, domain: str, report: MailReport) -> None:
        records = [t for t in self.txt(f"_smtp._tls.{domain}") if t.lower().startswith("v=tlsrptv1")]
        if records:
            report.add("TLS-RPT", PASS, "TLS reporting enabled", records=records)
        else:
            report.add("TLS-RPT", INFO, "No TLS-RPT record", "Optional: get reports about TLS delivery failures.")

    def check_bimi(self, domain: str, report: MailReport) -> None:
        records = [t for t in self.txt(f"default._bimi.{domain}") if t.lower().startswith("v=bimi1")]
        if records:
            report.add("BIMI", PASS, "BIMI logo published", records=records)
        else:
            report.add("BIMI", INFO, "No BIMI record", "Optional: shows your logo in supporting inboxes.")

    def check_smtp_tls(self, mx: str, report: MailReport) -> None:
        def probe(verify: bool):
            client = SMTPClient(mx, 25, timeout=8)
            try:
                client.connect(TLS_NONE)
                offered = "STARTTLS" in client.features
                banner = f"EHLO features: {', '.join(sorted(client.features)) or 'none'}"
                if not offered:
                    return offered, None, banner
                client.expect(client.command("STARTTLS"), 220, what="STARTTLS")
                client.conn.start_tls(verify=verify, server_hostname=mx)
                return offered, client.conn.tls_info, banner
            finally:
                client.quit()

        try:
            try:
                offered, tls, banner = probe(verify=True)
                cert_ok = True
            except ConnectionError_ as e:
                if "certificate" not in str(e).lower():
                    raise
                offered, tls, banner = probe(verify=False)
                cert_ok = False
        except (OSError, SMTPError, TimeoutError) as e:
            report.add("SMTP TLS", WARN, f"Could not test {mx}:25",
                       f"{e}. Many home and cloud networks block outbound port 25.")
            return
        if not offered:
            report.add("SMTP TLS", FAIL, f"{mx} does not offer STARTTLS", banner)
        elif tls["version"] in ("TLSv1", "TLSv1.1"):
            report.add("SMTP TLS", FAIL, f"{mx} uses outdated {tls['version']}", banner)
        elif not cert_ok:
            report.add("SMTP TLS", WARN, f"{mx} supports {tls['version']} but its certificate "
                       "doesn't validate for that name", banner)
        else:
            report.add("SMTP TLS", PASS, f"{mx} supports STARTTLS with {tls['version']}",
                       f"Certificate for {tls['subject']} issued by {tls['issuer']}")
