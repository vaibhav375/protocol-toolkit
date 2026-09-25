# Protocol Toolkit

[![CI](https://github.com/vaibhav375/protocol-toolkit/actions/workflows/ci.yml/badge.svg)](https://github.com/vaibhav375/protocol-toolkit/actions/workflows/ci.yml)

A network protocol workbench that speaks **HTTP/1.1, HTTP/2, HTTP/3, DNS and SMTP** with protocol
code written on raw sockets, and **records every byte it sends and receives**. You see exactly what
went over the wire, how long each step took, and you can open the same capture in Wireshark or your
browser's dev tools.

Everything runs on your machine and talks to the real internet: real websites, real DNS resolvers
and root servers, real mail servers. See [OVERVIEW.md](OVERVIEW.md) for how it works inside.

## What it does

| | |
|---|---|
| **HTTP** | HTTP/1.1, HTTP/2 (frames built by hand, negotiated with ALPN) and HTTP/3 over QUIC. TLS details, redirects, cookies, gzip/deflate/Brotli, and a timing breakdown (DNS, TCP, TLS, waiting, download). |
| **DNS** | UDP, TCP, DNS-over-TLS and DNS-over-HTTPS, 13 record types, DNSSEC status, and **trace from root** like `dig +trace`. |
| **SMTP** | Real email with STARTTLS or TLS and login, showing the whole conversation. Passwords are never sent unencrypted to a remote server, and never saved. |
| **Mail check** | Deliverability report for any domain: MX, SPF (with the 10-lookup limit), DMARC, DKIM, MTA-STS, TLS-RPT, BIMI. |
| **Scanner** | Concurrent TCP scan with service detection from banners. |
| **Test servers** | Local SMTP inbox (port 1025) and DNS server (port 10325) to practise against. |
| **Assistant** | An LLM that runs the toolkit's own tools (DNS, HTTP, TLS, mail checks), asking before scans or sending mail. Free and local with Ollama, or Claude. |
| **Inspector** | Every frame labelled (TLS ClientHello with SNI, HTTP/2 frames, QUIC headers, DNS flags) with byte highlighting, saved across restarts. |
| **Export** | **pcapng with TLS keys embedded**, so Wireshark shows HTTPS, HTTP/2 and HTTP/3 decrypted, plus **HAR** for browser dev tools. |

## Get it

**Mac app:** download `Protocol-Toolkit-macOS.zip` from
[Releases](https://github.com/vaibhav375/protocol-toolkit/releases), unzip, then right-click the app
and choose **Open** the first time (the build isn't notarised).

**From source** (Python 3.10+):

```bash
git clone https://github.com/vaibhav375/protocol-toolkit && cd protocol-toolkit
pip install -e ".[all]"
python -m protocol_toolkit             # opens the UI in your browser
python -m protocol_toolkit --window    # native window (pip install pywebview)
```

The built UI ships inside the package; Node is only needed to change it.

### Command line

```bash
python -m protocol_toolkit http https://www.cloudflare.com/cdn-cgi/trace --http 3 --wire
python -m protocol_toolkit dns example.com AAAA --via doh --server 1.1.1.1
python -m protocol_toolkit trace www.github.com
python -m protocol_toolkit mailcheck gmail.com
python -m protocol_toolkit scan 127.0.0.1 --ports 1-1024
python -m protocol_toolkit ask "does example.com support HTTP/2?"   # local model, uses tools
python -m protocol_toolkit serve                                   # SMTP :1025 + DNS :10325
```

### The assistant

- **Free and private:** install [Ollama](https://ollama.com), then `ollama pull qwen2.5:3b` (or
  `qwen2.5:7b` for better answers).
- **Claude:** `pip install anthropic` and set `ANTHROPIC_API_KEY`, or paste a key in the Assistant screen.

## Security

The local server listens on 127.0.0.1 only. Each launch creates a session key: the launch link carries
it, then it moves into an HttpOnly, same-site cookie. Requests with an unexpected `Host` or `Origin`
are refused, so a website you visit can't use the toolkit to scan ports or send mail. Captures are
saved with owner-only permissions and can be cleared from the Inspector.

## Development

```bash
pip install -e ".[all,dev]"
python -m pytest                     # 111 tests; add -m "not network" for offline-only

cd web && npm install
npm run dev                          # UI with hot reload (see vite.config.ts for the backend command)
npm run build                        # writes into protocol_toolkit/webapp/static
npm run test:e2e                     # Playwright end-to-end tests against the real app

packaging/macos/build_app.sh         # builds "Protocol Toolkit.app"
```

CI runs lint and tests on Python 3.10, 3.12 and 3.13, the UI type-check, build and end-to-end
tests, and a job that opens exported captures in Wireshark's `tshark` to prove they decrypt.
Pushing a `v*` tag builds the Mac app and attaches it to a GitHub release.

Only scan systems you own or have permission to test.
