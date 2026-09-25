import json

import pytest

from protocol_toolkit import llm
from protocol_toolkit.agent import MAX_RESULT_CHARS, Agent, Tool, _cap, build_tools, validate
from protocol_toolkit.httpclient import stream_lines
from protocol_toolkit.llm import LLMError, OllamaProvider, Provider, ToolCall, ToolSpec


class ScriptedProvider(Provider):
    """Replays canned model turns; records what the agent sends back"""

    def __init__(self, turns):
        super().__init__("scripted")
        self.turns = list(turns)
        self.results = []

    def step(self, tools, on_text):
        text, calls = self.turns.pop(0)
        if text:
            on_text(text)
        return text, calls

    def add_tool_results(self, results):
        self.results.append(results)


def echo_tools():
    return {
        "echo": Tool(ToolSpec("echo", "echo", {"type": "object", "properties": {"x": {"type": "string"}},
                                               "required": ["x"]}), lambda a: f"echo:{a['x']}"),
        "danger": Tool(ToolSpec("danger", "needs approval", {"type": "object", "properties": {}}),
                       lambda a: "did it", lambda a: "does something risky"),
        "boom": Tool(ToolSpec("boom", "fails", {"type": "object", "properties": {}}),
                     lambda a: (_ for _ in ()).throw(RuntimeError("kaput"))),
    }


def test_agent_runs_tools_and_returns_final_answer():
    provider = ScriptedProvider([
        ("Let me check.", [ToolCall("1", "echo", {"x": "hi"}), ToolCall("2", "danger", {})]),
        ("All done.", []),
    ])
    events, approvals = [], []
    agent = Agent(provider, echo_tools(), lambda c, r: approvals.append(r) or False,
                  on_tool=lambda stage, call, info: events.append((stage, call.name)))
    assert agent.ask("go") == "All done."
    (echo, danger), = provider.results
    assert echo[1:] == ("echo:hi", False)
    assert danger[2] is True and "declined" in danger[1]
    assert approvals == ["does something risky"]
    assert events == [("start", "echo"), ("done", "echo"), ("denied", "danger")]


def test_agent_reports_bad_calls_back_to_the_model():
    provider = ScriptedProvider([
        ("", [ToolCall("1", "echo", {}), ToolCall("2", "nope", {}), ToolCall("3", "boom", {}),
              ToolCall("4", "echo", {"x": "a"}, invalid="cut off")]),
        ("ok", []),
    ])
    Agent(provider, echo_tools(), lambda c, r: True).ask("go")
    results = provider.results[0]
    assert all(is_error for _, _, is_error in results)
    assert "missing required argument 'x'" in results[0][1]
    assert "Unknown tool" in results[1][1]
    assert "kaput" in results[2][1]
    assert "cut off" in results[3][1]


def test_agent_stops_runaway_loops():
    provider = ScriptedProvider([("", [ToolCall(str(i), "echo", {"x": "a"})]) for i in range(20)])
    with pytest.raises(LLMError, match="tool rounds"):
        Agent(provider, echo_tools(), lambda c, r: True).ask("loop forever")


def test_validate_and_cap():
    schema = {"type": "object", "properties": {"n": {"type": "integer"}, "t": {"type": "string", "enum": ["A"]}},
              "required": ["t"]}
    args = {"t": "A", "n": "5"}
    assert validate(args, schema) is None and args["n"] == 5  # quoted numbers are coerced
    assert "must be one of" in validate({"t": "B"}, schema)
    assert "unknown argument" in validate({"t": "A", "zzz": 1}, schema)
    multi = {"type": "object", "properties": {"t": {"type": ["string", "array"], "enum": ["A", "MX"],
                                                    "items": {"type": "string", "enum": ["A", "MX"]}}}}
    assert validate({"t": ["A", "MX"]}, multi) is None and validate({"t": "MX"}, multi) is None
    assert "invalid values ['NOPE']" in validate({"t": ["A", "NOPE"]}, multi)
    assert "should be string or array" in validate({"t": 5}, multi)
    capped = _cap("Authorization: Bearer abcdefghijkl\n" + "x" * (MAX_RESULT_CHARS + 50))
    assert "abcdefghijkl" not in capped and capped.endswith("more characters not shown]")


def test_toolkit_tools_are_well_formed():
    tools = build_tools(lambda w: None, lambda: "the capture")
    assert {"dns_lookup", "dns_trace", "http_request", "tls_certificate", "check_email_domain",
            "port_scan", "send_email", "read_current_capture"} == set(tools)
    assert tools["read_current_capture"].run({}) == "the capture"
    assert tools["http_request"].approval({"url": "x", "method": "GET"}) is None
    assert tools["http_request"].approval({"url": "x", "method": "DELETE"})
    assert tools["port_scan"].approval({"host": "127.0.0.1"})
    assert tools["send_email"].approval({"server": "s", "from": "a", "to": "b"})
    for tool in tools.values():
        json.dumps(tool.spec.parameters)  # schemas must be plain JSON


def test_dns_tool_against_local_server():
    from protocol_toolkit.testservers import DNSTestServer
    from conftest import free_port
    server = DNSTestServer(free_port())
    server.start()
    wires = []
    try:
        out = build_tools(wires.append, lambda: "")["dns_lookup"].run(
            {"name": "toolkit.test", "type": ["MX", "TXT"], "server": f"127.0.0.1:{server.port}"})
    finally:
        server.stop()
    assert "mail.toolkit.test" in out and "v=spf1" in out  # both types in one call
    assert len([e for e in wires[0].events if e.direction == "out"]) == 2


# ------------------------------------------------------------ Ollama provider against a fake server

def fake_ollama(tcp_server, lines, status=200, seen=None):
    def handle(h):
        head = b""
        while not head.endswith(b"\r\n\r\n"):
            head += h.rfile.read(1)
        length = int([l for l in head.decode().split("\r\n") if l.lower().startswith("content-length")][0].split(":")[1])
        body = json.loads(h.rfile.read(length))
        if seen is not None:
            seen.append(body)
        h.wfile.write(f"HTTP/1.1 {status} OK\r\nContent-Type: application/x-ndjson\r\n"
                      "Transfer-Encoding: chunked\r\n\r\n".encode())
        for line in lines:
            data = (json.dumps(line) + "\n").encode()
            # split each line across two chunks to exercise the incremental decoder
            for part in (data[:5], data[5:]):
                h.wfile.write(f"{len(part):x}\r\n".encode() + part + b"\r\n")
                h.wfile.flush()
        h.wfile.write(b"0\r\n\r\n")
    return tcp_server(handle)


def test_ollama_streaming_and_tool_calls(tcp_server, monkeypatch):
    seen = []
    server = fake_ollama(tcp_server, [
        {"message": {"role": "assistant", "content": "Checking "}, "done": False},
        {"message": {"role": "assistant", "content": "", "tool_calls": [
            {"function": {"name": "dns_lookup", "arguments": {"name": "example.com"}}},
            {"function": {"name": "echo", "arguments": "{\"x\": \"str-args\"}"}}]}, "done": False},
        {"done": True, "done_reason": "stop"},
    ], seen=seen)
    monkeypatch.setattr(llm, "OLLAMA_URL", server.url)
    provider = OllamaProvider("qwen2.5:3b")
    provider.reset("system prompt")
    provider.add_user("hi")
    streamed = []
    text, calls = provider.step([ToolSpec("echo", "d", {"type": "object"})], streamed.append)
    assert text == "Checking " and streamed == ["Checking "]
    assert [(c.name, c.args) for c in calls] == [("dns_lookup", {"name": "example.com"}), ("echo", {"x": "str-args"})]
    request = seen[0]
    assert request["messages"][0] == {"role": "system", "content": "system prompt"}
    assert request["tools"][0]["function"]["name"] == "echo" and request["stream"] is True
    provider.add_tool_results([(calls[0], "result", False), (calls[1], "bad", True)])
    assert provider.messages[-2] == {"role": "tool", "tool_name": "dns_lookup", "content": "result"}
    assert provider.messages[-1]["content"] == "ERROR: bad"


@pytest.mark.parametrize("error,expected", [
    ("invalid character '<' looking for beginning of value", "known bug with qwen3"),
    ('model "nope" not found, try pulling it first', "ollama pull"),
    ("registry.ollama.ai/library/gemma does not support tools", "doesn't support tool calling"),
])
def test_ollama_error_messages(tcp_server, monkeypatch, error, expected):
    server = fake_ollama(tcp_server, [{"error": error}])
    monkeypatch.setattr(llm, "OLLAMA_URL", server.url)
    provider = OllamaProvider("nope")
    provider.reset("s")
    provider.add_user("hi")
    with pytest.raises(LLMError, match=expected):
        provider.step([], lambda s: None)


def test_ollama_not_running(monkeypatch):
    from conftest import free_port
    monkeypatch.setattr(llm, "OLLAMA_URL", f"http://127.0.0.1:{free_port()}")
    assert llm.ollama_status(timeout=1) == (False, "", [])
    provider = OllamaProvider("x")
    provider.reset("s")
    with pytest.raises(LLMError, match="Can't reach Ollama"):
        provider.step([], lambda s: None)


def test_stream_lines_plain_body(tcp_server):
    def handle(h):
        while h.rfile.readline() not in (b"\r\n", b""):
            pass
        h.wfile.write(b"HTTP/1.1 200 OK\r\n\r\none\ntwo\nthree")

    lines = stream_lines(tcp_server(handle).url, "GET")
    assert next(lines).status_code == 200
    assert list(lines) == ["one", "two", "three"]


def test_default_model_prefers_tool_capable_qwen25():
    assert llm.default_ollama_model(["qwen3:4b", "llama3.2:3b", "qwen2.5:7b"]) == "qwen2.5:7b"
    assert llm.default_ollama_model(["something:1b"]) == "something:1b"


@pytest.mark.skipif(not llm.ollama_status(timeout=1)[0], reason="Ollama is not running")
def test_live_ollama_tool_call():
    running, _, models = llm.ollama_status()
    provider = OllamaProvider(llm.default_ollama_model(models))
    wires = []
    tools = build_tools(wires.append, lambda: "")
    answer = Agent(provider, {"dns_lookup": tools["dns_lookup"]}, lambda c, r: False).ask(
        "Use the dns_lookup tool to find the A records of example.com, then list the addresses.")
    assert wires, "the model should have called dns_lookup"
    assert answer.strip()
