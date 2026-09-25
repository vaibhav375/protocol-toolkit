"""Start the web UI on 127.0.0.1 and open it in the browser (or a native window)."""
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
