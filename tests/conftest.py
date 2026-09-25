"""Shared fixtures: local fake servers so most tests run without the internet."""
from __future__ import annotations

import os
import shutil
import socket
import socketserver
import subprocess
import threading

import pytest


def pytest_configure(config):
    config.addinivalue_line("markers", "network: needs internet access (skip with -m 'not network')")


@pytest.fixture(autouse=True)
def isolated_data_dir(tmp_path, monkeypatch):
    """Saved sessions go to a temp folder, never the real Application Support folder"""
    monkeypatch.setenv("PT_DATA_DIR", str(tmp_path / "data"))
    return tmp_path / "data"


def pytest_collection_modifyitems(config, items):
    if os.environ.get("NO_NETWORK"):
        skip = pytest.mark.skip(reason="NO_NETWORK is set")
        for item in items:
            if "network" in item.keywords:
                item.add_marker(skip)


class Server:
    """A threaded TCP server running `handler(conn_file_pair)` per connection"""

    def __init__(self, handle):
        outer = self

        class Handler(socketserver.StreamRequestHandler):
            def handle(self):
                try:
                    handle(self)
                except (ConnectionError, OSError):
                    pass

        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        outer.url = f"http://127.0.0.1:{self.port}"

    def close(self):
        self.server.shutdown()
        self.server.server_close()


@pytest.fixture
def tcp_server():
    servers = []

    def start(handle):
        s = Server(handle)
        servers.append(s)
        return s

    yield start
    for s in servers:
        s.close()


@pytest.fixture(scope="session")
def self_signed_cert(tmp_path_factory):
    """(certfile, keyfile) for localhost, made with the openssl CLI"""
    if not shutil.which("openssl"):
        pytest.skip("openssl CLI not available")
    d = tmp_path_factory.mktemp("cert")
    cert, key = d / "cert.pem", d / "key.pem"
    subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                    "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(cert)],
                   check=True, capture_output=True)
    return str(cert), str(key)


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
