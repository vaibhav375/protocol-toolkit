"""Check a running public demo end to end, like a visitor would.

    python scripts/smoke_demo.py http://127.0.0.1:10000            # a local container (CI)
    python scripts/smoke_demo.py https://<name>.onrender.com --live  # also real internet requests

Uses only the standard library. Exits non-zero on the first failed check.
"""
from __future__ import annotations

import http.cookiejar
import json
import ssl
import sys
import time
import urllib.error
import urllib.request


def main() -> int:
    base = sys.argv[1].rstrip("/")
    live = "--live" in sys.argv
    tls = ssl.create_default_context()
    try:  # python.org builds on macOS ship without CA certificates; certifi fills the gap
        import certifi
        tls.load_verify_locations(certifi.where())
    except ImportError:
        pass
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
                                         urllib.request.HTTPSHandler(context=tls))

    def call(method: str, path: str, body=None) -> tuple:
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(base + path, data=data, method=method,
                                     headers={"Content-Type": "application/json"} if data else {})
        try:
            with opener.open(req, timeout=60) as r:
                raw = r.read()
                return r.status, (json.loads(raw) if r.headers.get_content_type() == "application/json" else raw)
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read() or b"{}")

    failures = []

    def check(name: str, ok: bool, detail="") -> None:
        print(f"{'PASS' if ok else 'FAIL'}  {name}  {detail}".rstrip(), flush=True)
        if not ok:
            failures.append(name)

    for _ in range(30):  # the host may still be starting (or waking from sleep)
        try:
            if call("GET", "/healthz")[0] == 200:
                break
        except OSError:
            pass
        time.sleep(2)
    check("health check", call("GET", "/healthz") == (200, {"ok": True}))
    check("API needs a session", call("GET", "/api/info")[0] == 401)
    code, page = call("GET", "/")
    check("page loads and starts a session", code == 200 and b'id="root"' in page)
    code, info = call("GET", "/api/info")
    check("demo mode", code == 200 and info.get("demo") is not None, info.get("version", ""))
    demo = info["demo"]

    code, r = call("POST", "/api/dns", {"name": "toolkit.test", "type": "MX", "server": demo["dns_test"]})
    check("DNS to the built-in test server", r.get("rcode") == "NOERROR", str(r.get("answers") or r.get("error")))
    smtp = demo["smtp"]
    code, r = call("POST", "/api/smtp", {"server": smtp["server"], "port": smtp["port"], "from": "smoke@example.com",
                                         "to": ["inbox@example.com"], "subject": "smoke test", "body": "hello"})
    check("SMTP to the test inbox", "error" not in r and code == 200, r.get("result") or r.get("error", ""))
    code, inbox = call("GET", "/api/servers/inbox")
    check("mail is in this visitor's inbox", [m["subject"] for m in inbox] == ["smoke test"])
    code, r = call("POST", "/api/http", {"url": "http://169.254.169.254/latest/meta-data/"})
    check("cloud metadata address is blocked", "Blocked in the public demo" in r.get("error", ""))
    code, r = call("POST", "/api/http", {"url": "http://127.0.0.1:10000/"})
    check("the server itself is blocked", "Blocked in the public demo" in r.get("error", ""))
    code, r = call("POST", "/api/http", {"url": "https://example.com/", "method": "POST"})
    check("only GET and HEAD", code == 403)
    code, r = call("POST", "/api/smtp", {"server": "smtp.gmail.com", "port": 587, "from": "a@b.co", "to": ["c@d.co"]})
    check("no real mail", code == 403)

    if live:
        code, r = call("POST", "/api/http", {"url": "https://example.com/"})
        check("HTTPS to a real site", r.get("status") == 200, f"{r.get('version')} {r.get('elapsed_ms')} ms {r.get('error', '')}")
        code, r = call("POST", "/api/http", {"url": "https://www.cloudflare.com/cdn-cgi/trace", "http_version": "3"})
        check("HTTP/3 over QUIC (UDP 443)", r.get("version") == "HTTP/3", r.get("error", ""))
        for transport in ("UDP", "TCP", "DoT", "DoH"):
            code, r = call("POST", "/api/dns", {"name": "example.com", "server": "1.1.1.1", "transport": transport})
            check(f"DNS over {transport}", r.get("rcode") == "NOERROR", r.get("error", f"{r.get('elapsed_ms')} ms"))
        code, r = call("POST", "/api/dns/trace", {"name": "www.github.com", "type": "A"})
        check("DNS trace from the root", bool(r.get("steps")), r.get("error", f"{len(r.get('steps') or [])} steps"))
        code, r = call("POST", "/api/mailcheck", {"domain": "gmail.com"})
        check("mail check", bool(r.get("grade")), f"grade {r.get('grade')}")
        code, r = call("POST", "/api/scan", {"host": "scanme.nmap.org", "ports": "22,80"})
        check("scan of scanme.nmap.org starts", code == 200, str(r))

    print(f"\n{len(failures)} failed" if failures else "\nAll checks passed")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
