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

It also runs as a **public demo website**: the same app, where each visitor gets a private session
and a network guard stops the server being used to reach private networks (see section 8).

---

## Contents

1. [Where it started](#1-where-it-started)
2. [What it can do](#2-what-it-can-do)
3. [How it's built](#3-how-its-built)
4. [How each protocol is implemented](#4-how-each-protocol-is-implemented)
5. [The assistant and tool calling](#5-the-assistant-and-tool-calling)
6. [The web interface](#6-the-web-interface)
7. [Security and privacy](#7-security-and-privacy)
8. [The public demo website](#8-the-public-demo-website)
9. [Testing](#9-testing)
10. [Running it](#10-running-it)
11. [Notable problems solved along the way](#11-notable-problems-solved-along-the-way)
12. [Limitations](#12-limitations)
13. [Repository, CI and releases](#13-repository-ci-and-releases)
14. [Size of the project](#14-size-of-the-project)
15. [Verified results](#15-verified-results)
16. [Resume summary](#16-resume-summary)

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
     (WebSocket)            │   • saved captures (newest 200)    • scanner, http3, exports                │
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
  guard.py         public demo: checks every outbound connection's address and port
  demo.py          public demo: HTTP methods, mail destination and scan targets it allows
  webapp/          FastAPI backend, saved sessions, and the built React files it serves
  __main__.py      command line
web/               React + TypeScript source for the interface, plus Playwright end-to-end tests
tests/             Python tests
packaging/macos/   builds "Protocol Toolkit.app" with PyInstaller + pywebview
scripts/           verify_pcap_with_tshark.py (exports decrypt in Wireshark), smoke_demo.py (demo check)
Dockerfile         the public demo image; render.yaml deploys it on Render
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

## 8. The public demo website

`python -m protocol_toolkit demo` runs the toolkit as a website anyone can open, so its work can be
seen without installing anything. Letting strangers choose where a server connects is dangerous: it
could be used to reach the host's private network or cloud metadata service (server-side request
forgery, SSRF), to send spam, or to scan other people's machines. The demo keeps everything that
shows the protocols working and removes those risks:

| | In the demo |
|---|---|
| **HTTP** | GET and HEAD only, to public addresses, at most 5 MB per connection, 20 s timeout |
| **DNS, trace, mail check** | Fully working, to public resolvers and name servers; no port-25 STARTTLS probe |
| **SMTP** | Only to the built-in test inbox; nothing reaches real mailboxes |
| **Scanner** | Only scanme.nmap.org, a host whose owners invite scans; at most 100 ports, one scan at a time |
| **Test servers** | Always on and shared, but each visitor sees only their own mail and DNS queries |
| **Assistant** | Claude with the visitor's own API key, held in their session's memory only |
| **Inspector and exports** | Fully working, pcapng with TLS keys and HAR included |

**How it's enforced:**
- **A network guard (`guard.py`)** checks the address of every outbound TCP connect and UDP send in
  the process, after DNS resolution. Only public addresses on web, DNS and QUIC ports are allowed
  (plus the test servers on loopback, and any port on the scan target). Because the check is on the
  address actually being connected to, it also covers redirects, DNS rebinding, names like
  `localtest.me` that resolve to 127.0.0.1, IPv4-mapped and NAT64 IPv6 forms, MTA-STS fetches and
  the assistant's tools.
- **Per-visitor sessions:** a random HttpOnly cookie gives each visitor their own captures, cookie
  jar, inbox, live events and API key, all in memory. Sessions expire after 30 idle minutes, and at
  most 40 are kept (the least recently active are dropped first).
- **Shared test servers, private results:** mail and DNS queries are matched to the visitor who sent
  them by the connection's local port, so a shared inbox never shows one visitor's mail to another.
- **Limits:** 30 actions a minute and 3 at a time per visitor, overall caps, 256 KB request bodies,
  and at most 30 captures (6 MB) per visitor.
- **Headers:** Host and Origin checks for the public host name, HSTS, and a Content-Security-Policy
  that only allows the site's own scripts and connections.

The UI reads the limits from the server and adapts: it shows a "Live demo" banner, offers only the
allowed methods and scan targets, locks the SMTP server to the test inbox, and hides controls for
things the demo can't do. A top navigation strip replaces the side rail on phones.

**Deployment:** a two-stage `Dockerfile` builds the React UI with Node, then installs the Python
package; `render.yaml` deploys it as a Render web service, with `/healthz` as the health check.
Render's free tier blocks outbound SMTP ports, which the demo never uses.

---

## 9. Testing

**146 Python tests** (`python3 -m pytest`). Most run against local fake servers, so they need no
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
- **Public demo:** the guard's address rules (private, loopback, link-local, CGNAT, IPv6 unique-local,
  IPv4-mapped, NAT64, 6to4, multicast), blocking through redirects and DNS rebinding, the download
  limit, session isolation of captures, inbox and DNS log, the rate limit, refused features, host,
  origin and CSP headers, and the assistant running with the visitor's key under the demo rules.
- **Live checks:** a few run against the real internet (Google, Cloudflare, root servers, Gmail's
  records) and can be skipped with `-m "not network"`.

**End-to-end tests** (`npm run test:e2e`, Playwright): the real app in Chromium. They cover the
security rules, every screen, DNS and SMTP against the built-in servers, inspector byte
highlighting, pcapng and HAR downloads, theme persistence, and the assistant's setup messages.

**Wireshark check** (`scripts/verify_pcap_with_tshark.py`, in CI): real HTTP/2, HTTP/1.1, DNS and
HTTP/3 captures are exported and opened with `tshark`, which must show the decrypted application
layer.

**Demo container check** (`scripts/smoke_demo.py`, in CI): the Docker image is built and started,
then checked like a visitor would: session cookie, test DNS server, test inbox, blocked addresses
and refused methods. With `--live` it also makes real HTTPS, HTTP/3, DNS, trace, mail check and scan
requests, which is how a deployed copy is checked.

The interface was also checked by driving it in a real browser and taking screenshots. That caught
problems no unit test would: a freeze on single-line 1 MB pages, layout overflow, and a stale
cached page after updates.

---

## 10. Running it

```bash
cd protocol_toolkit
python3 -m protocol_toolkit              # web UI in your browser
python3 -m protocol_toolkit --window     # native window (pip install pywebview)
python3 -m protocol_toolkit selftest     # quick check of HTTP, DNS and scanning
packaging/macos/build_app.sh             # build the Mac app yourself
```

The Mac app can also be downloaded from the repository's Releases page (right-click, then Open, the
first time, because the build isn't notarised).

To run the public demo website locally: `python3 -m protocol_toolkit demo --port 8000`.

Optional extras: `pip install -e ".[all]"` adds HTTP/2 header compression, HTTP/3 (`aioquic`),
Brotli, `certifi`, the Anthropic SDK and the web server packages. For the free assistant, install Ollama and run
`ollama pull qwen2.5:3b`.

**Sending real email:** use your provider's server, for example Gmail at `smtp.gmail.com`, port
587, STARTTLS, with an app password. Sending directly to a recipient's server on port 25 is usually
blocked by home internet providers. Use an address you own, or the message will fail SPF/DMARC
checks.

---

## 11. Notable problems solved along the way

- **Cloudflare's DoH endpoint rejects HTTP/2 POSTs without `content-length`,** even though HTTP/2
  doesn't require it. The client now always sends it, as curl does.
- **Tk 8.6 on macOS 26 leaves a revisited notebook tab blank** (in the retired Tkinter UI). A bare Tk
  window reproduces it, so it's a Tk bug; flushing pending redraws on every tab change worked around
  it, and Tk 9 doesn't have it.
- **Tk's text widget froze on very long lines** (also in the retired UI). One 1.09 MB line took
  minutes to lay out; capping and breaking up long lines for display brought it to 0.03 seconds.
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

## 12. Limitations

- **QUIC itself isn't hand-written.** HTTP/3 uses aioquic for the transport; the toolkit handles the
  socket, capture, labelling and HTTP/3 request flow.
- **The scanner is TCP-connect only.** No UDP or SYN scanning, which would need root privileges.
- **One request per connection.** HTTP/2 and HTTP/3 connections aren't reused.
- **Exported packets are reconstructed.** Payloads are exact; TCP handshakes, sequence numbers and
  timing within a single read are synthesised.
- **The Mac app isn't signed or notarised.** macOS asks for confirmation on first launch.
- **Local models are slow on 8 GB machines and can be wrong.** Claude is faster and more reliable.
- **The web UI is designed for desktop widths.** Phones get a top navigation strip, but the Wire
  column hides below about 1280 px and some tables are cramped on small screens.
- **Demo sessions live in memory.** A restart of the demo server (or the free host going to sleep
  when idle) starts everyone's session afresh.

---

## 13. Repository, CI and releases

- **Repository:** github.com/vaibhav375/protocol-toolkit.
- **CI (`.github/workflows/ci.yml`):** on every push and pull request:
  - lint and offline tests on Python 3.10, 3.12 and 3.13
  - the live network tests
  - the UI type-check, production build and Playwright suite
  - the Wireshark decryption check
  - the public demo's Docker image, built and smoke-tested

  The network-dependent jobs are allowed to fail without blocking, since they rely on third-party
  servers.
- **Releases (`.github/workflows/release.yml`):** pushing a tag such as `v2.2.0` builds the Mac app
  on a macOS runner and attaches `Protocol-Toolkit-macOS.zip` to a GitHub release. Release v2.2.0 was
  published this way; its zip is 25.8 MB. (A local build was 84 MB unzipped.)
- **Deployment (`Dockerfile`, `render.yaml`):** the public demo, deployed from the repository on Render.

## 14. Size of the project

| Part | Lines |
|---|---|
| Protocol core, exports, assistant and demo guard (Python) | ~4,700 |
| Web backend (Python) | ~1,100 |
| React interface (TypeScript/CSS) | ~2,500 |
| Tests | ~1,900 (146 Python + 7 end-to-end) |

Started from a single 2,380-line script.

---

## 15. Verified results

Everything below was measured or observed while building and testing the project.

**Continuous integration.** On the first push to GitHub, all 6 CI jobs passed:
- tests on Python 3.10, 3.12 and 3.13
- the live network tests
- the UI type-check, build and end-to-end suite
- the Wireshark check

**Wireshark decryption.** On a clean Ubuntu runner, Wireshark's `tshark` opened the exported pcapng
files and decoded the encrypted application layer, using only the keys embedded in each file:

| Capture | What tshark showed |
|---|---|
| HTTP/2 over TLS to google.com | Every request and response header, including `:status` |
| HTTP/1.1 over TLS to example.com | The `200` response code |
| HTTP/3 over QUIC to cloudflare.com | The HTTP/3 frames |
| DNS over UDP | The query and answer for example.com |

**Interoperability with real servers:**
- **HTTP/2** negotiated with Google, GitHub, example.com and httpbin.
- **HTTP/3** completed with Cloudflare and Google. The QUIC handshake took 47 ms and 67 ms, and
  Cloudflare's trace endpoint reported `http=http/3`.
- **DNS:** DNS-over-HTTPS answered by Cloudflare, Google and Quad9. DNS-over-TLS by Cloudflare. A
  root-to-authoritative trace for www.github.com (root → .com → AWS name servers → CNAME and address).
- **Email:** a STARTTLS handshake with Gmail's mail server negotiated TLS 1.3. Mail checks of gmail.com
  and github.com matched their published DNS records.

**Performance fixes (before → after):**
- A 1.3 MB page with a 1.09 MB single line went from freezing the UI for minutes to rendering in
  0.03 seconds.
- A mail check that hit a DNS timeout used to report "No SPF record". It now retries, and reports
  "couldn't check" if the lookup still fails.

**Tests:** all 146 Python tests pass in about 40 seconds (one is skipped on machines without its
optional tool). The 7 Playwright end-to-end tests pass in about 20 seconds against the real app.

**Mac app release:** pushing the `v2.2.0` tag built the app on GitHub's macOS runner and published it
as a release with a 25.8 MB download.

**Public demo, run locally** with `scripts/smoke_demo.py --live`, all 20 checks passed:
- HTTPS to example.com over HTTP/2, and HTTP/3 over QUIC to Cloudflare, through the network guard
- DNS over UDP, TCP, TLS and HTTPS, a root-to-authoritative trace, and a mail check of gmail.com
- a scan of scanme.nmap.org that found SSH (with its banner) and HTTP
- mail and DNS queries to the shared test servers appearing only in the sender's session
- requests to the cloud metadata address (169.254.169.254), to the server itself, and to
  `localtest.me` (a public name that resolves to 127.0.0.1) refused with an explanation

**Assistant:** a free local model (`qwen2.5:3b` through Ollama) chose and ran the right tools on its
own. It used `dns_lookup` and `http_request` to answer "what are example.com's addresses and does it
support HTTP/2", and ran one multi-type `dns_lookup` to explain the local test zone. Every call
appeared in the Wire column.

---

## 16. Resume summary

**Protocol Toolkit**: network protocol workbench with LLM tool calling
*Python, sockets, TLS, HTTP/2, HTTP/3/QUIC, DNS, FastAPI, React, TypeScript, Playwright, Docker, GitHub Actions*
github.com/vaibhav375/protocol-toolkit

- **Protocols:** implemented HTTP/1.1, HTTP/2 (RFC 9113 framing and flow control) and DNS over UDP,
  TCP, TLS and HTTPS, with root-to-authoritative tracing, all on raw sockets. Added HTTP/3 over QUIC
  through aioquic's sans-I/O API, and ran TLS through `ssl.MemoryBIO` so every byte is captured and
  labelled.
- **Wireshark export:** built pcapng export that reconstructs IPv4/IPv6 TCP and UDP packets with
  valid checksums and embeds TLS 1.3 session keys. A CI job proves with `tshark` that HTTP/2, HTTP/3
  and DNS captures decrypt in Wireshark.
- **LLM assistant:** built an assistant that calls 8 toolkit functions (DNS trace, HTTP, TLS, mail
  checks, scans), with schema-checked arguments, user approval for scans and email, and secrets
  removed from results. It runs locally on Qwen 2.5 through Ollama, or on Claude.
- **Web app and security:** built a React 19 and TypeScript UI on a FastAPI backend that live-streams
  captured bytes. Secured the local server against DNS rebinding and cross-site requests with a
  loopback-only listener, a per-launch session key and Host/Origin checks. Packaged it as a macOS app
  released through GitHub Actions.
- **Public deployment:** deployed it as a public demo with per-visitor sessions and an SSRF guard
  that checks every outbound connection's resolved address, blocking private networks, cloud
  metadata, DNS rebinding and redirect tricks. Containerised with Docker and deployed on Render.
- **Testing and CI:** 153 automated tests (146 pytest and 7 Playwright end-to-end) run in GitHub
  Actions across Python 3.10 to 3.13, plus a job that builds the demo container and smoke-tests it.

**One-line version:** built a raw-socket protocol workbench (HTTP/1.1, HTTP/2, HTTP/3, DNS, SMTP)
with byte-level capture, Wireshark-decryptable exports verified in CI, and an LLM agent that uses
the toolkit as tools.
