"""Chat providers with tool calling: Ollama (local, free) and Claude (Anthropic API).

Both expose the same small interface so the agent loop in agent.py doesn't care which
model it's talking to:

    provider.reset(system_prompt)
    provider.add_user(text)
    text, calls = provider.step(tools, on_text)     # appends the assistant turn
    provider.add_tool_results([(call, result, is_error), ...])
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from .httpclient import HTTPClient, stream_lines

OLLAMA_URL = os.environ.get("OLLAMA_HOST", "http://127.0.0.1:11434").rstrip("/")
if not OLLAMA_URL.startswith("http"):
    OLLAMA_URL = "http://" + OLLAMA_URL
# Best first. qwen3's tool calls hit a parser bug in Ollama 0.9.0, so qwen2.5 leads.
PREFERRED_OLLAMA_MODELS = ["qwen2.5:3b", "qwen2.5:7b", "llama3.2:3b", "llama3.1:8b", "qwen3:4b", "qwen3:8b",
                           "mistral-nemo", "llama3.2"]
CLAUDE_MODEL = "claude-opus-5"


class LLMError(RuntimeError):
    pass


@dataclass
class ToolSpec:
    name: str
    description: str
    parameters: dict  # JSON Schema for the arguments


@dataclass
class ToolCall:
    id: str
    name: str
    args: Dict = field(default_factory=dict)
    invalid: str = ""  # set when the model produced arguments we can't use


class Provider:
    label = ""

    def __init__(self, model: str):
        self.model = model
        self.messages: List[dict] = []
        self.system = ""

    def reset(self, system: str) -> None:
        self.system, self.messages = system, []

    def add_user(self, text: str) -> None:
        self.messages.append({"role": "user", "content": text})

    def step(self, tools: List[ToolSpec], on_text: Callable[[str], None]) -> Tuple[str, List[ToolCall]]:
        raise NotImplementedError

    def add_tool_results(self, results: List[Tuple[ToolCall, str, bool]]) -> None:
        raise NotImplementedError


# ---------------------------------------------------------------- Ollama

def ollama_binary() -> Optional[str]:
    for candidate in (shutil.which("ollama"), "/opt/homebrew/bin/ollama", "/usr/local/bin/ollama",
                      "/Applications/Ollama.app/Contents/Resources/ollama"):
        if candidate and os.path.exists(candidate):
            return candidate
    return None


def ollama_status(timeout: float = 2.0) -> Tuple[bool, str, List[str]]:
    """(running, version, installed model names)"""
    client = HTTPClient()
    try:
        version = client.send(f"{OLLAMA_URL}/api/version", timeout=timeout, use_cookies=False).get_json() or {}
        tags = client.send(f"{OLLAMA_URL}/api/tags", timeout=timeout, use_cookies=False).get_json() or {}
    except OSError:
        return False, "", []
    return True, version.get("version", "?"), sorted(m["name"] for m in tags.get("models", []))


def default_ollama_model(installed: List[str]) -> str:
    for name in PREFERRED_OLLAMA_MODELS:
        if name in installed:
            return name
    return installed[0] if installed else "qwen2.5:3b"


def start_ollama() -> subprocess.Popen:
    """Start `ollama serve` in the background (stopped when the toolkit exits)"""
    binary = ollama_binary()
    if not binary:
        raise LLMError("Ollama isn't installed. Get it from https://ollama.com or run: brew install ollama")
    return subprocess.Popen([binary, "serve"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


class OllamaProvider(Provider):
    label = "Ollama (local, free)"

    def step(self, tools, on_text):
        body = {
            "model": self.model,
            "stream": True,
            "messages": [{"role": "system", "content": self.system}] + self.messages,
            "tools": [{"type": "function", "function": {"name": t.name, "description": t.description,
                                                        "parameters": t.parameters}} for t in tools],
            "options": {"num_ctx": 8192},  # the default 2048 is too small for tool results
        }
        text, calls = [], []
        try:
            lines = stream_lines(f"{OLLAMA_URL}/api/chat", "POST", {"Content-Type": "application/json"},
                                 json.dumps(body).encode(), timeout=300)
            head = next(lines)
            if head.status_code != 200:
                raise LLMError(self._error_text("\n".join(lines), head.status_code))
            for line in lines:
                chunk = json.loads(line)
                if "error" in chunk:
                    raise LLMError(self._error_text(line, 200))
                message = chunk.get("message", {})
                if message.get("content"):
                    text.append(message["content"])
                    on_text(message["content"])
                for i, call in enumerate(message.get("tool_calls") or []):
                    fn = call.get("function", {})
                    args = fn.get("arguments", {})
                    if isinstance(args, str):  # some models send a JSON string
                        try:
                            args = json.loads(args)
                        except json.JSONDecodeError:
                            calls.append(ToolCall(f"call_{len(self.messages)}_{i}", fn.get("name", "?"), {}, args))
                            continue
                    calls.append(ToolCall(f"call_{len(self.messages)}_{i}", fn.get("name", "?"), args or {}))
        except OSError as e:
            raise LLMError(f"Can't reach Ollama at {OLLAMA_URL} ({e}). Start it with `ollama serve`, "
                           "or use the Start Ollama button.") from e
        content = "".join(text)
        assistant = {"role": "assistant", "content": content}
        if calls:
            assistant["tool_calls"] = [{"function": {"name": c.name, "arguments": c.args}} for c in calls]
        self.messages.append(assistant)
        return content, calls

    def _error_text(self, raw: str, status: int) -> str:
        try:
            error = json.loads(raw.strip().splitlines()[-1]).get("error", raw)
        except (json.JSONDecodeError, IndexError):
            error = raw or f"HTTP {status}"
        if "not found" in error and "model" in error:
            return f"Model {self.model} isn't downloaded. Run: ollama pull {self.model}"
        if "invalid character '<'" in error:
            return (f"Ollama couldn't parse {self.model}'s tool call (a known bug with qwen3 in older Ollama "
                    "versions). Pick qwen2.5 or llama3.2, or update Ollama: brew upgrade ollama")
        if "does not support tools" in error:
            return f"{self.model} doesn't support tool calling. Pick qwen2.5, llama3.1/3.2 or qwen3."
        return f"Ollama error: {error}"

    def add_tool_results(self, results):
        for call, result, is_error in results:
            self.messages.append({"role": "tool", "tool_name": call.name,
                                  "content": ("ERROR: " if is_error else "") + result})


# ---------------------------------------------------------------- Claude

class ClaudeProvider(Provider):
    label = "Claude (Anthropic API)"

    def __init__(self, model: str = CLAUDE_MODEL, api_key: str = ""):
        super().__init__(model)
        try:
            import anthropic
        except ImportError:
            raise LLMError("Claude needs the Anthropic SDK:  pip install anthropic")
        self.anthropic = anthropic
        self.client = anthropic.Anthropic(api_key=api_key) if api_key else anthropic.Anthropic()

    def step(self, tools, on_text):
        a = self.anthropic
        tool_defs = [{"name": t.name, "description": t.description, "input_schema": t.parameters,
                      # stream tool inputs as generated; agent.py validates them before running
                      "eager_input_streaming": True} for t in tools]
        for attempt in range(2):
            text = []
            try:
                with self.client.beta.messages.stream(
                    model=self.model,
                    max_tokens=16000,
                    thinking={"type": "adaptive"},
                    system=self.system,
                    messages=self.messages,
                    tools=tool_defs,
                    # Network/security tooling can trip safety classifiers; "default" retries a
                    # declined request on Anthropic's recommended fallback model
                    betas=["server-side-fallback-2026-07-01"],
                    extra_body={"fallbacks": "default"},
                ) as stream:
                    for event in stream:
                        if event.type == "content_block_delta" and event.delta.type == "text_delta":
                            text.append(event.delta.text)
                            on_text(event.delta.text)
                    final = stream.get_final_message()
                break
            except ValueError:
                # The SDK couldn't parse a streamed tool input at all: re-issue the request once
                if attempt:
                    raise LLMError("Claude returned a tool call that couldn't be parsed twice in a row.")
            except a.AuthenticationError:
                raise LLMError("No valid Claude API credentials. Set ANTHROPIC_API_KEY, run `ant auth login`, "
                               "or paste a key in Tools > AI Settings.")
            except a.RateLimitError:
                raise LLMError("Rate limited by the Claude API. Wait a minute and try again.")
            except a.APIStatusError as e:
                raise LLMError(f"Claude API error {e.status_code}: {e.message}")
            except a.APIConnectionError:
                raise LLMError("Could not reach the Claude API. Check your internet connection.")

        if final.stop_reason == "refusal":
            raise LLMError("Claude declined this request.")
        # Keep every block (thinking included) so the next request carries the full turn
        self.messages.append({"role": "assistant", "content": final.content})
        calls = [ToolCall(b.id, b.name, b.input if isinstance(b.input, dict) else {})
                 for b in final.content if b.type == "tool_use"]
        if final.stop_reason == "max_tokens" and calls:
            # A tool input cut off by the length limit may parse as a valid-looking partial
            # object; never run it
            for c in calls:
                c.invalid = "the response hit the length limit while writing these arguments"
        return "".join(text), calls

    def add_tool_results(self, results):
        # All results for one turn go back in a single user message
        self.messages.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": call.id, "content": result, "is_error": is_error}
            for call, result, is_error in results]})


def make_provider(kind: str, model: str, api_key: str = "") -> Provider:
    if kind == "claude":
        return ClaudeProvider(model or CLAUDE_MODEL, api_key)
    return OllamaProvider(model)
