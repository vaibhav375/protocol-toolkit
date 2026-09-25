# Protocol Toolkit: project overview

Protocol Toolkit is a network protocol workbench. It speaks **HTTP/1.1, HTTP/2, HTTP/3, DNS
(UDP, TCP, DNS-over-TLS, DNS-over-HTTPS) and SMTP** with protocol code written by hand on top of raw
sockets, and it **records every byte it sends and receives**, so you can see exactly what happened
on the wire and how long each step took.

Around that core it adds an email deliverability checker, a port scanner, local test servers, an
AI assistant that can run the toolkit's own tools, and a React interface with a live view of the
traffic. Captures are saved between sessions and export to **pcapng** (decryptable in Wireshark)
and **HAR** (browser dev tools). It ships as a Mac app, with CI on GitHub.

Everything runs on your own computer and talks to the real internet: real URLs, real DNS
resolvers and root servers, real mail servers. The only simulated parts are the optional local
test servers.

---

## Contents

1. [Where it started](#1-where-it-started)
2. [What it can do](#2-what-it-can-do)
3. [How it's built](#3-how-its-built)
4. [How each protocol is implemented](#4-how-each-protocol-is-implemented)
5. [The assistant and tool calling](#5-the-assistant-and-tool-calling)
6. [The web interface](#6-the-web-interface)
7. [Security and privacy](#7-security-and-privacy)
8. [Testing](#8-testing)
9. [Running it](#9-running-it)
10. [Notable problems solved along the way](#10-notable-problems-solved-along-the-way)
11. [Limitations](#11-limitations)
12. [Repository, CI and releases](#12-repository-ci-and-releases)
13. [Size of the project](#13-size-of-the-project)

---

## 1. Where it started

The project began as a single 2,380-line Tkinter script (`cncncncn.py`) with HTTP, DNS, SMTP and a
port scanner. It ran, but several features were broken:

| Problem in the original | Cause |
|---|---|
| `https://` URLs failed ("plain HTTP request was sent to HTTPS port") | The code detected HTTPS, then ignored it and sent plain text to port 443 |
| Save, Load and every Encode/Decode operation crashed | `filedialog`, `base64`, `html` and `urllib` were never imported |
| The scanner froze the window, then crashed a background thread | Scans ran on the UI thread; the thread used variables that didn't exist |
| "Common ports" scanned 8,000+ ports | It scanned every port from the lowest to the highest common port |
| Email addresses were changed in transit | The whole SMTP command, including the address, was upper-cased |
| Slow servers looked like empty responses | Reading stopped after 0.5 seconds of silence |
| Closing the window made network requests | A second `__main__` block ran "self-tests" against example.com |

Those were fixed first. The toolkit was then rebuilt as a package, and each area was taken
further in turn.

---

## 2. What it can do

| Area | What you can do |
|---|---|
| **HTTP** | Send any method to any URL. HTTP/2 is negotiated automatically during the TLS handshake (ALPN), or forced either way; HTTP/3 runs over QUIC, and the UI suggests it when a server advertises it (Alt-Svc). Shows TLS version, cipher and certificate, follows redirects, keeps a cookie jar, decodes gzip, deflate and Brotli, and breaks the time into DNS lookup, TCP connect, TLS handshake, waiting for the server and download. |
| **DNS** | Query any resolver over UDP, TCP, DNS-over-TLS or DNS-over-HTTPS, for 13 record types including SRV, CAA, HTTPS, DS and DNSKEY. Ask for DNSSEC and see whether the answer was validated. **Trace from root** follows a name from the root servers through the TLD servers to the authoritative ones, like `dig +trace`. |
| **SMTP** | Send real email with plain, STARTTLS or TLS connections and PLAIN/LOGIN authentication, and watch the whole conversation. Passwords are hidden from every log, never saved, and never sent unencrypted except to your own machine. |
| **Mail check** | A deliverability report for any domain: MX, SPF (including the 10-DNS-lookup limit), DMARC, DKIM key strength, MTA-STS, TLS-RPT, BIMI, and an optional STARTTLS test of its mail server. Read-only; it sends nothing. |
| **Scanner** | A concurrent TCP scan with service detection from banners (SSH, SMTP, HTTP and others) and TLS peeking, exported as CSV or JSON. Only for machines you own or may test. |
| **Test servers** | A local SMTP server that catches mail in an inbox (like MailHog or Mailpit, on port 1025), and a local DNS server that answers for a zone you edit (port 10325). Both listen on your machine only. |
| **Assistant** | Ask questions in plain language. The model runs DNS lookups, traces, HTTP requests, TLS checks and email checks itself, and asks you before port scans, sending mail, or requests that change data. It runs on a free local model through Ollama, or on Claude. |
| **Wire column and Inspector** | Every exchange is captured. The Wire column shows frames live as they're sent (cyan) and received (amber), drawn as a barcode of their bytes. The Inspector labels every field (TLS ClientHello with SNI and ALPN, HTTP/2 frames, DNS header flags, SMTP commands) and highlights its bytes in a hex view. |
| **Export and sessions** | Captures are saved on disk and survive restarts. Each one exports as **pcapng**, with IP/TCP/UDP headers rebuilt and TLS keys embedded so Wireshark decrypts HTTPS, HTTP/2, DoT and HTTP/3; as **HAR 1.2** for browser dev tools (cookies and auth headers hidden by default); or as a text transcript. |
| **Command line** | Every feature is also a command: `http`, `dns`, `trace`, `mailcheck`, `scan`, `ask`, `explain`, `serve` and `selftest`. |

---

## 3. How it's built

```
                            ┌─────────────────────────────── your computer ───────────────────────────────┐
                            │                                                                              │
  Browser (React UI) ──────►│  FastAPI server on 127.0.0.1   ──►  protocol clients  ──► real internet     │
   • 8 tool screens         │   • session key + Host/Origin      • httpclient / http2     (web servers,   │
   • live Wire column  ◄────│     checks                           • dnsclient              resolvers,    │
     (Server-Sent Events)   │   • JSON API for each tool         • smtpclient             root servers,   │
   • assistant chat    ◄───►│   • WebSocket for the assistant    • mailcheck              mail servers)   │
     (WebSocket)            │   • capture store (last 60)        • scanner                                │
                            │                                     │                                        │
                            │                                     └─ net.Connection ── every byte ──► WireLog
                            │                                                                              │
                            │  Test servers (SMTP :1025, DNS :10325) ◄── same clients, local traffic       │
                            │  Assistant: agent loop ──► Ollama (local) or Claude API (Anthropic)          │
                            └──────────────────────────────────────────────────────────────────────────────┘
```

### Layout

```
protocol_toolkit/
  wire.py          byte capture: events, timing phases, labelled fields, hex dumps
  net.py           TCP connections; TLS run through ssl.MemoryBIO so encrypted records can be logged
  httpclient.py    HTTP/1.1 framing, redirects, cookies, content decoding, streaming reads
  http2.py         HTTP/2 frames by hand (RFC 9113); only header compression comes from `hpack`
  http3.py         HTTP/3 over QUIC via aioquic's sans-I/O API; QUIC headers labelled here
  pcap.py          pcapng export: rebuilt IP/TCP/UDP packets plus a TLS key block
  har.py           HAR 1.2 export
  dnsclient.py     DNS packets, 4 transports, iterative trace
  smtpclient.py    SMTP, STARTTLS, AUTH
  mailcheck.py     SPF, DMARC, DKIM, MTA-STS, TLS-RPT, BIMI, STARTTLS probe
  scanner.py       concurrent port scanner with banner grabbing
  testservers.py   local SMTP sink and DNS server
  llm.py           chat providers with tool calling: Ollama and Claude
  agent.py         the assistant: tool definitions, argument checks, approvals, the loop
  explain.py       removes secrets before anything is sent to a model
  webapp/          FastAPI backend, saved sessions, and the built React files it serves
  __main__.py      command line
web/               React + TypeScript source for the interface, plus Playwright end-to-end tests
tests/             Python tests
packaging/macos/   builds "Protocol Toolkit.app" with PyInstaller + pywebview
scripts/           verify_pcap_with_tshark.py: proves exports decrypt in Wireshark
.github/workflows/ CI on every push; Mac app release on every version tag
```

The protocol modules know nothing about any interface. The web UI (in a browser or the Mac app's
native window) and the command line are front ends over the same code, and that code is what most
of the tests cover. An earlier Tkinter interface was retired once the React UI matched it.

---

## 4. How each protocol is implemented

**Connections and TLS (`net.py`).** Python's usual way of adding TLS hides the encrypted bytes.
Here the TLS engine is driven by hand through `ssl.MemoryBIO`, so every TLS record passes through
the toolkit's own code and gets recorded. That's why the Inspector can show the real ClientHello,
with the site name (SNI) and the protocols offered (ALPN). Everything after the handshake is
encrypted, so the readable version is logged one layer up.

**HTTP/1.1 (`httpclient.py`).** Builds requests byte by byte and reads responses using the real
framing rules: Content-Length, chunked encoding, or read until close, plus 1xx interim responses.
Around that sit redirects (303 switches to GET, and credentials are dropped when the host
changes), an RFC 6265 cookie jar that rejects cookies for other domains, and content decoding.

**HTTP/2 (`http2.py`).** Written from the specification. It sends the connection preface and
settings, then builds HEADERS, CONTINUATION and DATA frames and handles SETTINGS, PING,
WINDOW_UPDATE, RST_STREAM and GOAWAY. It respects flow-control windows and strips padding. Only
HPACK header compression comes from a library. Every frame is logged with its type, flags and
stream ID.

**DNS (`dnsclient.py`).** Builds and parses DNS packets directly, including name compression, with
protection against compression loops. Requests use a random ID, and replies with the wrong ID are
ignored. EDNS is used for larger UDP answers, and a truncated answer is retried over TCP. The same
packets run over UDP, TCP, TLS on port 853, or HTTPS POST. The trace mode asks a root server
without recursion, follows referrals using glue records, and resolves name servers that come
without them.

**SMTP (`smtpclient.py`).** Reads multi-line replies correctly, uses EHLO with a HELO fallback,
applies dot-stuffing and CRLF line endings, and adds Date and Message-ID headers. STARTTLS rejects
any data sent before the handshake (a known injection attack) and repeats EHLO afterwards, as the
standard requires. Login uses PLAIN or LOGIN and is refused over plain text to remote servers.

**HTTP/3 (`http3.py`).** QUIC is a full transport (packet protection, loss recovery, congestion
control), so it comes from `aioquic`, used in its sans-I/O form: the toolkit owns the UDP socket and
the clock, feeds datagrams in and sends what comes out. Every datagram is captured, QUIC long and
short headers are labelled by the toolkit's own parser (Initial/Handshake/1-RTT, version, connection
IDs, padding), HTTP/3 headers and data are logged, and the QUIC TLS secrets are kept for export.

**Packet capture export (`pcap.py`).** The toolkit captures bytes at the socket, not packets, so
the exporter rebuilds them: a TCP handshake, correct sequence and acknowledgement numbers, payload
split at a typical MSS, FIN at close, UDP datagrams, IPv4 and IPv6 headers, and real checksums.
The TLS session keys (collected through Python's `keylog_filename` and aioquic's secrets log) go
into a pcapng Decryption Secrets Block, so Wireshark decrypts the traffic with no setup. There's a
keyless option for sharing captures safely.

**Mail check (`mailcheck.py`).** SPF lookups are counted recursively against the limit of 10.
DMARC falls back to the organisational domain. DKIM key sizes are read by parsing the public key
itself. The MTA-STS policy file is fetched over HTTPS. A lookup that fails is retried once and then
reported as "couldn't check", never as a missing record.

---

## 5. The assistant and tool calling

The assistant is a language model that can call the toolkit's own functions.

```
you ask ──► model decides ──► tool call ──► argument check ──► approval? ──► run ──► result (secrets removed)
               ▲                                                                            │
               └──────────────────────────── result goes back to the model ◄────────────────┘
                                   (repeats until the model answers; at most 10 rounds)
```

- **Tools:** `dns_lookup` (one type or several), `dns_trace`, `http_request`, `tls_certificate`,
  `check_email_domain`, `port_scan`, `send_email` and `read_current_capture`.
- **Approval rules:** read-only tools run automatically. Port scans, sending mail, and HTTP methods
  other than GET, HEAD and OPTIONS wait for you to allow them in the chat.
- **Safety:** arguments are checked against each tool's schema before anything runs. Results are
  scrubbed of cookies, tokens and passwords, capped in length, and every network call the
  assistant makes appears in the Wire column.
- **Models:**
  - **Ollama (default, free, private):** runs on your computer. `qwen2.5:3b` is fast;
    `qwen2.5:7b` is more accurate. With Ollama 0.9.0, `qwen3` tool calls fail to parse, which a
    newer Ollama fixes.
  - **Claude:** uses the official Anthropic SDK with streaming. Declined requests fall back to
    another model on Anthropic's side. Needs an API key.

Small local models make mistakes. In testing, a 3B model once explained SPF's `-all` backwards.
Use a larger model or Claude when accuracy matters.

---

## 6. The web interface

Built with React 19, TypeScript, Vite, Tailwind CSS 4 and Motion. The built files ship inside the
Python package, so you don't need Node to run it.

- **Design:** a deep navy "instrument panel". Color appears only on data: cyan for bytes sent,
  amber for bytes received, and one hue per protocol layer.
- **Type:** Unbounded for headings, Geist for text, Geist Mono for bytes. The fonts are bundled, so
  the UI works offline.
- **Signature element:** the Wire column. Frames slide in as they happen, each drawn as a barcode
  of its actual bytes.
- **Motion with meaning:** timing bars draw in the order the steps happened, DNS traces step down
  from the root, and assistant answers stream in. Reduced-motion settings are respected.
- **Inspector:** the hex view renders only the visible rows, so large frames stay smooth, and
  hovering a field highlights its bytes.
- **Details:** light and dark themes, Alt+1 to Alt+8 to switch screens, and form inputs remembered
  between sessions.
- **Mac app:** the same UI in a native window (pywebview + WebKit), bundled with PyInstaller into a
  double-clickable `Protocol Toolkit.app` with its own icon, backend included.

---

## 7. Security and privacy

A local server that can scan ports and send email is exactly what a malicious website would try
to reach through your browser. The server defends against that in three ways:

1. **It only listens on 127.0.0.1**, so no other machine can connect.
2. **Each launch creates a secret session key.** The launch link carries it once, and it's then
   stored in an HttpOnly cookie that browsers only send from the toolkit's own page.
3. **It checks the Host and Origin headers.** This blocks DNS-rebinding attacks and requests from
   other websites, including over the websocket. Pages also can't be embedded in frames.

Tests cover all three.

- **Passwords:** kept in memory only, hidden from logs and captures, and never sent unencrypted
  except to your own machine.
- **What leaves your computer:** only the requests you make, plus assistant questions when you
  choose Claude. Those are scrubbed of secrets first. The Ollama assistant sends nothing out.

---

## 8. Testing

**111 Python tests** (`python3 -m pytest`). Most run against local fake servers, so they need no
internet:

- **Protocols:** HTTP (framing, chunked bodies, redirects, cookies, HTTPS with a generated
  certificate, HTTP/2 frames), DNS (packets, compression loops, TCP fallback, spoofed IDs), SMTP
  (dot-stuffing, STARTTLS, hidden credentials).
- **Diagnostics:** mail check scoring, the scanner, and the local test servers.
- **Assistant:** the tool loop, driven by a scripted model and by a fake Ollama server.
- **Web server:** security rules, every endpoint, and the assistant websocket.
- **Exports:** pcapng structure, every IPv4 and TCP/UDP checksum, byte-exact payload reassembly,
  IPv6, key blocks; HAR for redirect chains, POST bodies, binary bodies and sanitising; saved
  sessions surviving a restart.
- **HTTP/3:** QUIC header parsing, plus a live request to Cloudflare.
- **Live checks:** a few run against the real internet (Google, Cloudflare, root servers, Gmail's
  records) and can be skipped with `-m "not network"`.

**End-to-end tests** (`npm run test:e2e`, Playwright): the real app in Chromium. They cover the
security rules, every screen, DNS and SMTP against the built-in servers, inspector byte
highlighting, pcapng and HAR downloads, theme persistence, and the assistant's setup messages.

**Wireshark check** (`scripts/verify_pcap_with_tshark.py`, in CI): real HTTP/2, HTTP/1.1, DNS and
HTTP/3 captures are exported and opened with `tshark`, which must show the decrypted application
layer.

The interface was also checked by driving it in a real browser and taking screenshots. That caught
problems no unit test would: a freeze on single-line 1 MB pages, layout overflow, and a stale
cached page after updates.

---

## 9. Running it

```bash
cd protocol_toolkit
python3 -m protocol_toolkit              # web UI in your browser
python3 -m protocol_toolkit --window     # native window (pip install pywebview)
python3 -m protocol_toolkit selftest     # quick check of HTTP, DNS and scanning
packaging/macos/build_app.sh             # build the Mac app yourself
```

Or download the Mac app from the repository's Releases page (right-click, then Open, the first time,
because the build isn't notarised).

Optional extras: `pip install -e ".[all]"` adds HTTP/2 header compression, HTTP/3 (`aioquic`),
Brotli, `certifi`, the Anthropic SDK and the web server packages. For the free assistant, install Ollama and run
`ollama pull qwen2.5:3b`.

**Sending real email:** use your provider's server, for example Gmail at `smtp.gmail.com`, port
587, STARTTLS, with an app password. Sending directly to a recipient's server on port 25 is usually
blocked by home internet providers. Use an address you own, or the message will fail SPF/DMARC
checks.

---

## 10. Notable problems solved along the way

- **Cloudflare's DoH endpoint rejects HTTP/2 POSTs without `content-length`,** even though HTTP/2
  doesn't require it. The client now always sends it, as curl does.
- **Tk 8.6 on macOS 26 leaves a revisited notebook tab blank.** A bare Tk window reproduces it.
  Flushing pending redraws on every tab change works around it; Tk 9 doesn't have the bug.
- **Tk's text widget freezes on very long lines.** One 1.09 MB line took minutes to lay out.
  Read-only panes now cap and break up long lines for display.
- **A DNS timeout was reported as "No SPF record".** Failed lookups are now retried and reported as
  "couldn't check".
- **Small models pass lists where the schema said a single string.** The DNS tool now accepts both,
  and argument errors explain what went wrong.
- **A small model invented `[redacted]` values** because the system prompt mentioned the marker. The
  prompt now tells it to quote values exactly.
- **Ollama 0.9.0 can't parse `qwen3` tool calls.** Detected, explained in the app, and `qwen2.5` is
  now the default.
- **Client QUIC datagrams end in zero padding,** which a naive parser reads as a 1-RTT packet. The
  labeller checks QUIC's fixed bit and reports padding instead.
- **A PyInstaller build included unrelated libraries** (pygame) from the host Python; the spec now
  excludes them.

---

## 11. Limitations

- **QUIC itself isn't hand-written.** HTTP/3 uses aioquic for the transport; the toolkit handles the
  socket, capture, labelling and HTTP/3 request flow.
- **The scanner is TCP-connect only.** No UDP or SYN scanning, which would need root privileges.
- **One request per connection.** HTTP/2 and HTTP/3 connections aren't reused.
- **Exported packets are reconstructed.** Payloads are exact; TCP handshakes, sequence numbers and
  timing within a single read are synthesised.
- **The Mac app isn't signed or notarised.** macOS asks for confirmation on first launch.
- **Local models are slow on 8 GB machines and can be wrong.** Claude is faster and more reliable.
- **The web UI is designed for desktop widths.** The Wire column hides below about 1280 px.

---

## 12. Repository, CI and releases

- **Repository:** github.com/vaibhav375/protocol-toolkit.
- **CI (`.github/workflows/ci.yml`):** on every push and pull request:
  - lint and offline tests on Python 3.10, 3.12 and 3.13
  - the live network tests
  - the UI type-check, production build and Playwright suite
  - the Wireshark decryption check

  The network-dependent jobs are allowed to fail without blocking, since they rely on third-party
  servers.
- **Releases (`.github/workflows/release.yml`):** pushing a tag such as `v2.2.0` builds the Mac app
  on a macOS runner and attaches `Protocol-Toolkit-macOS.zip` to a GitHub release.

## 13. Size of the project

| Part | Lines |
|---|---|
| Protocol core, exports and assistant (Python) | ~4,450 |
| Web backend (Python) | ~800 |
| React interface (TypeScript/CSS) | ~2,400 |
| Tests | ~1,600 (111 Python + 7 end-to-end) |

Started from a single 2,380-line script.
