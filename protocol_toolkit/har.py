"""Export HTTP exchanges as HAR 1.2, the format browser dev tools import and export."""
from __future__ import annotations

import base64
import json
import re
import urllib.parse
from datetime import datetime, timezone

from . import __version__
from .explain import SECRET_HEADERS
from .wire import WireLog

_SECRET = re.compile(rf"^{SECRET_HEADERS}$", re.I)


def _headers(pairs, sanitize: bool) -> list:
    return [{"name": k, "value": "[redacted]" if sanitize and _SECRET.match(k) else v} for k, v in pairs]


def _mime(headers) -> str:
    return next((v for k, v in headers if k.lower() == "content-type"), "application/octet-stream")


def _content(body: bytes, mime: str, truncated: bool) -> dict:
    content = {"size": len(body), "mimeType": mime}
    try:
        text = body.decode("utf-8")
        if text and not all(c.isprintable() or c in "\r\n\t" for c in text[:2000]):
            raise UnicodeDecodeError("utf-8", b"", 0, 1, "binary")
        content["text"] = text
    except UnicodeDecodeError:
        content["text"], content["encoding"] = base64.b64encode(body).decode(), "base64"
    if truncated:
        content["comment"] = "Body truncated to the first 1 MB by Protocol Toolkit"
    return content


def _timings(pairs) -> dict:
    """Map the toolkit's phases onto HAR timing fields (ms; -1 means not applicable)"""
    phases = dict(pairs)
    return {"blocked": -1, "dns": phases.get("DNS lookup", -1), "connect": phases.get("TCP connect", -1),
            "ssl": phases.get("TLS handshake", -1), "send": 0, "wait": phases.get("Waiting (TTFB)", 0),
            "receive": phases.get("Content download", 0)}


def has_http(wire: WireLog) -> bool:
    return bool(wire.meta.get("http_entries"))


def to_har(wire: WireLog, sanitize: bool = True) -> str:
    """HAR JSON for every HTTP request in the capture. sanitize hides cookies and auth headers,
    as Chrome does by default when exporting."""
    entries = []
    for e in wire.meta.get("http_entries", []):
        timings = _timings(e["timings"])
        # HAR "connect" includes the TLS handshake
        if timings["ssl"] >= 0 and timings["connect"] >= 0:
            timings["connect"] += timings["ssl"]
        total = sum(v for k, v in timings.items() if v > 0 and k != "ssl")
        url = urllib.parse.urlsplit(e["url"] if "://" in e["url"] else "http://" + e["url"])
        request = {
            "method": e["method"], "url": urllib.parse.urlunsplit(url), "httpVersion": e["http_version"],
            "headers": _headers(e["request_headers"], sanitize), "cookies": [],
            "queryString": [{"name": k, "value": v} for k, v in urllib.parse.parse_qsl(url.query, keep_blank_values=True)],
            "headersSize": -1, "bodySize": len((e["request_body"] or "").encode()),
        }
        if e["request_body"] is not None:
            request["postData"] = {"mimeType": _mime(e["request_headers"]), "text": e["request_body"]}
        body = base64.b64decode(e["body_b64"])
        location = next((v for k, v in e["response_headers"] if k.lower() == "location"), "")
        entries.append({
            "startedDateTime": datetime.fromtimestamp(e["started"], timezone.utc).isoformat().replace("+00:00", "Z"),
            "time": round(total, 3), "request": request,
            "response": {"status": e["status"], "statusText": e["status_text"], "httpVersion": e["http_version"],
                         "headers": _headers(e["response_headers"], sanitize), "cookies": [],
                         "content": _content(body, _mime(e["response_headers"]), e["body_truncated"]),
                         "redirectURL": location, "headersSize": -1, "bodySize": e["raw_size"]},
            "cache": {}, "timings": timings,
            "serverIPAddress": e.get("server_ip") or "", "connection": str(e.get("connection") or ""),
        })
    har = {"log": {"version": "1.2", "creator": {"name": "Protocol Toolkit", "version": __version__},
                   "pages": [], "entries": entries}}
    return json.dumps(har, indent=2, ensure_ascii=False)
