"""Start the web UI on 127.0.0.1 and open it in the browser (or a native window),
or run the public demo website."""
from __future__ import annotations

import os
import secrets
import socket
import threading
import webbrowser


def free_port(preferred: int = 8765) -> int:
    for port in (preferred, 0):
        with socket.socket() as s:
            try:
                s.bind(("127.0.0.1", port))
                return s.getsockname()[1]
            except OSError:
                continue
    raise OSError("No free port")


def run(port: int = 0, open_browser: bool = True, window: bool = False) -> None:
    import uvicorn
    from .server import create_app

    port = port or free_port()
    token = os.environ.get("PT_TOKEN") or secrets.token_urlsafe(24)
    app = create_app(token, allowed_ports={port})
    url = f"http://127.0.0.1:{port}/?t={token}"
    print(f"Protocol Toolkit is running at http://127.0.0.1:{port}")
    print(f"Open this link (it contains your session key): {url}")
    print("Press Ctrl-C to stop.", flush=True)

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", ws="websockets")
    server = uvicorn.Server(config)

    if window:
        try:
            import webview  # pywebview: a native window instead of a browser tab
        except ImportError:
            print("Native window needs pywebview (pip install pywebview); opening the browser instead.")
            window = False
    if window:
        threading.Thread(target=server.run, daemon=True).start()
        webview.create_window("Protocol Toolkit", url, width=1360, height=880, min_size=(1000, 680))
        webview.start()
        server.should_exit = True
        return
    if open_browser:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    server.run()


def run_demo(host: str = "0.0.0.0", port: int = 8000) -> None:
    """The public demo website (see server.py). It answers to the host names in PT_PUBLIC_HOST
    (comma separated) or, on Render, the service's own name; with neither, only to loopback."""
    import uvicorn
    from .server import create_app

    hosts = [h for h in os.environ.get("PT_PUBLIC_HOST", "").split(",") if h.strip()]
    if os.environ.get("RENDER_EXTERNAL_HOSTNAME"):
        hosts.append(os.environ["RENDER_EXTERNAL_HOSTNAME"])
    app = create_app(demo=True, public_hosts=hosts)
    print(f"Protocol Toolkit public demo on {host}:{port}, answering to: {', '.join(hosts) or 'loopback only'}",
          flush=True)
    uvicorn.run(app, host=host, port=port, ws="websockets", ws_max_size=1024 * 1024,
                limit_concurrency=200, log_level="info", server_header=False)
