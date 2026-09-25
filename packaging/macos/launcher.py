"""Entry point for the double-clickable Mac app: the web UI in a native window."""
from protocol_toolkit.webapp.launch import run

if __name__ == "__main__":
    run(window=True)
