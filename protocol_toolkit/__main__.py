"""Command-line entry point.

    python -m protocol_toolkit                      # open the web UI in your browser
    python -m protocol_toolkit --window             # ...in a native window (needs pywebview)
    python -m protocol_toolkit http https://example.com --wire
    python -m protocol_toolkit dns example.com AAAA --via doh --server 1.1.1.1
    python -m protocol_toolkit trace www.github.com
    python -m protocol_toolkit mailcheck gmail.com
    python -m protocol_toolkit scan 127.0.0.1 --ports 1-1024
    python -m protocol_toolkit ask "does example.com support HTTP/2?"      # local model via Ollama
    python -m protocol_toolkit explain https://example.com --provider claude
    python -m protocol_toolkit serve                                      # SMTP :1025 + DNS :10325
    python -m protocol_toolkit selftest
"""
from __future__ import annotations

import argparse
import sys

from . import __version__


def cmd_http(args) -> int:
    from .httpclient import HTTPClient
    headers = dict(h.split(":", 1) for h in args.header)
    headers = {k.strip(): v.strip() for k, v in headers.items()}
    r = HTTPClient().send(args.url, args.method, headers, args.data, verify_tls=not args.insecure,
                          http_version=args.http, follow_redirects=not args.no_redirects)
    print(f"{r.http_version} {r.status_code} {r.status_message}".rstrip())
    for k, v in r.header_list:
        print(f"{k}: {v}")
    print()
    print(r.pretty_body() if args.method != "HEAD" else "")
    if args.wire:
        print("\n" + r.wire.transcript(max_bytes_per_event=600), file=sys.stderr)
    return 0 if r.status_code < 400 else 1


def cmd_dns(args) -> int:
    from .dnsclient import DNSClient
    p = DNSClient().query(args.name, args.type.upper(), args.server, args.via.upper() if args.via != "doh" else "DoH",
                          dnssec_ok=args.dnssec)
    print(p)
    return 0 if p.rcode == 0 else 1


def cmd_trace(args) -> int:
    from .dnsclient import DNSClient
    for i, (name, ip, p) in enumerate(DNSClient().trace(args.name, args.type.upper()), 1):
        print(f";; step {i}: {name} ({ip}) {p.elapsed_ms:.0f} ms {p.rcode_name}")
        for r in p.answers or [r for r in p.authorities if r.type in (2, 6)]:
            print(f"   {r.summary}")
    return 0


def cmd_mailcheck(args) -> int:
    from .mailcheck import DeliverabilityChecker, FAIL
    selectors = args.selector or None
    report = DeliverabilityChecker(progress=lambda m: print(m, file=sys.stderr)).run(
        args.domain, selectors, probe_smtp=not args.no_smtp)
    print(report.to_text())
    return 1 if report.counts[FAIL] else 0


def cmd_scan(args) -> int:
    from . import scanner
    ports = scanner.COMMON_PORTS if args.ports == "common" else scanner.parse_ports(args.ports)
    results = scanner.scan(args.host, ports, args.timeout)
    rows = sorted((r for r in results.values() if r.status == scanner.OPEN or args.all), key=lambda r: r.port)
    if args.format != "table":
        print(scanner.export(rows, args.format))
        return 0
    for r in rows:
        print(f"{r.port:>5}/tcp  {r.status:<8} {r.service or scanner.service_name(r.port):<22} {r.banner}")
    print(f"{sum(r.status == scanner.OPEN for r in results.values())} open of {len(results)} scanned")
    return 0


def _agent(args):
    from . import llm
    from .agent import Agent, build_tools
    model = args.model
    if args.provider == "ollama" and not model:
        running, _, models = llm.ollama_status()
        if not running:
            raise RuntimeError("Ollama isn't running. Start it with `ollama serve`, or use --provider claude")
        model = llm.default_ollama_model(models)
    provider = llm.make_provider(args.provider, model)

    def approve(call, reason):
        if args.yes:
            return True
        return input(f"\nAllow: {reason}? [y/N] ").strip().lower() == "y"

    def on_tool(stage, call, info):
        if stage == "start":
            print(f"\n  [tool] {call.name}({', '.join(f'{k}={v!r}' for k, v in call.args.items())})", file=sys.stderr)
        elif stage in ("error", "invalid", "denied"):
            print(f"  [tool {stage}] {info[:200]}", file=sys.stderr)

    tools = build_tools(lambda wire: None, lambda: "")
    return Agent(provider, tools, approve, lambda s: print(s, end="", flush=True), on_tool)


def cmd_ask(args) -> int:
    _agent(args).ask(args.question)
    print()
    return 0


def cmd_explain(args) -> int:
    from .httpclient import HTTPClient
    from .explain import redact
    r = HTTPClient().send(args.url)
    question = args.question or "Explain this capture: what happened, anything unusual, and what to check next."
    _agent(args).ask(f"{question}\n\n<capture>\n{redact(r.wire.transcript())[:12000]}\n</capture>")
    print()
    return 0


def cmd_serve(args) -> int:
    import time
    from .testservers import DNSTestServer, SMTPTestServer
    servers = [SMTPTestServer(args.smtp_port, on_log=print), DNSTestServer(args.dns_port, on_log=print)]
    for s in servers:
        s.start()
    print("Press Ctrl-C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        for s in servers:
            s.stop()
    return 0


def cmd_selftest(args) -> int:
    from .httpclient import HTTPClient
    from .dnsclient import DNSClient
    from . import scanner
    ok = True
    for url in ("http://example.com", "https://example.com", "https://www.google.com"):
        try:
            r = HTTPClient().send(url)
            print(f"HTTP  {url:<26} {r.status_code} {r.http_version:<8} {r.elapsed_ms:6.0f} ms")
        except Exception as e:
            ok = False
            print(f"HTTP  {url:<26} FAILED: {e}")
    for via in ("UDP", "TCP", "DoT", "DoH"):
        try:
            p = DNSClient().query("example.com", "A", "1.1.1.1", via)
            print(f"DNS   {via:<26} {p.rcode_name} {[r.value for r in p.answers]}")
        except Exception as e:
            ok = False
            print(f"DNS   {via:<26} FAILED: {e}")
    print(f"SCAN  example.com:443            {'open' if scanner.probe_port(scanner.resolve('example.com'), 443, 2).status == 'Open' else 'not open'}")
    return 0 if ok else 1


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="protocol-toolkit", description="Raw-socket protocol toolkit")
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--window", action="store_true", help="show the web UI in a native window (pip install pywebview)")
    parser.add_argument("--port", type=int, default=0, help="port for the web UI (default 8765, or any free port)")
    parser.add_argument("--no-browser", action="store_true", help="don't open a browser; just print the link")
    sub = parser.add_subparsers(dest="command")

    p = sub.add_parser("http", help="send an HTTP request")
    p.add_argument("url")
    p.add_argument("-X", "--method", default="GET")
    p.add_argument("-H", "--header", action="append", default=[], help="'Name: value' (repeatable)")
    p.add_argument("-d", "--data")
    p.add_argument("--http", choices=["auto", "1.1", "2", "3"], default="auto")
    p.add_argument("-k", "--insecure", action="store_true", help="don't verify TLS certificates")
    p.add_argument("--no-redirects", action="store_true")
    p.add_argument("--wire", action="store_true", help="print the wire transcript to stderr")
    p.set_defaults(func=cmd_http)

    p = sub.add_parser("dns", help="DNS lookup")
    p.add_argument("name")
    p.add_argument("type", nargs="?", default="A")
    p.add_argument("--server", default="8.8.8.8")
    p.add_argument("--via", choices=["udp", "tcp", "dot", "doh"], default="udp")
    p.add_argument("--dnssec", action="store_true")
    p.set_defaults(func=cmd_dns)

    p = sub.add_parser("trace", help="iterative DNS resolution from the root servers")
    p.add_argument("name")
    p.add_argument("type", nargs="?", default="A")
    p.set_defaults(func=cmd_trace)

    p = sub.add_parser("mailcheck", help="email deliverability report for a domain")
    p.add_argument("domain")
    p.add_argument("--selector", action="append", help="DKIM selector to check (repeatable)")
    p.add_argument("--no-smtp", action="store_true", help="skip the port 25 STARTTLS test")
    p.set_defaults(func=cmd_mailcheck)

    p = sub.add_parser("scan", help="TCP port scan (only hosts you may test)")
    p.add_argument("host")
    p.add_argument("--ports", default="common", help="'common' or e.g. 22,80,8000-8100")
    p.add_argument("--timeout", type=float, default=0.5)
    p.add_argument("--all", action="store_true", help="include closed/filtered ports")
    p.add_argument("--format", choices=["table", "csv", "json"], default="table")
    p.set_defaults(func=cmd_scan)

    def llm_options(p):
        p.add_argument("--provider", choices=["ollama", "claude"], default="ollama")
        p.add_argument("--model", default="", help="default: best installed Ollama model, or claude-opus-5")
        p.add_argument("-y", "--yes", action="store_true", help="allow scans/emails/writes without asking")

    p = sub.add_parser("ask", help="ask the network assistant (it can run DNS/HTTP/TLS/mail tools)")
    p.add_argument("question")
    llm_options(p)
    p.set_defaults(func=cmd_ask)

    p = sub.add_parser("explain", help="fetch a URL and have the assistant explain the exchange")
    p.add_argument("url")
    p.add_argument("question", nargs="?", default="")
    llm_options(p)
    p.set_defaults(func=cmd_explain)

    p = sub.add_parser("serve", help="run the local SMTP (1025) and DNS (10325) test servers")
    p.add_argument("--smtp-port", type=int, default=1025)
    p.add_argument("--dns-port", type=int, default=10325)
    p.set_defaults(func=cmd_serve)

    sub.add_parser("selftest", help="check HTTP, DNS and scanning against public servers").set_defaults(func=cmd_selftest)

    args = parser.parse_args(argv)
    if not args.command:
        from .webapp.launch import run
        run(port=args.port, open_browser=not args.no_browser, window=args.window)
        return 0
    try:
        return args.func(args)
    except (OSError, ValueError, RuntimeError) as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
