"""Secret redaction for anything sent to a language model."""
from __future__ import annotations

import importlib.util
import re

SECRET_HEADERS = r"(authorization|proxy-authorization|cookie|set-cookie|x-api-key|api-key|x-auth-token|x-csrf-token)"


def redact(text: str) -> str:
    """Strip credentials: auth/cookie header values, bearer tokens, URL passwords, API keys"""
    text = re.sub(rf"(?im)^(\s*{SECRET_HEADERS}\s*[:=]\s*).+$", r"\1[redacted]", text)
    text = re.sub(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/=-]{8,}", r"\1 [redacted]", text)
    text = re.sub(r"(?i)(://[^/\s:@]+:)[^@\s/]+@", r"\1[redacted]@", text)
    text = re.sub(r"\bsk-ant-[A-Za-z0-9_-]+", "[redacted]", text)
    text = re.sub(r"(?i)([?&](?:api_?key|token|access_token|password|secret)=)[^&\s]+", r"\1[redacted]", text)
    return text


def available() -> bool:
    """Is the Anthropic SDK installed (needed for the Claude provider)?"""
    return importlib.util.find_spec("anthropic") is not None
