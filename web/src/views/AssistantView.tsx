import { AnimatePresence, motion } from "motion/react";
import { ArrowUp, Bot, Check, ChevronRight, KeyRound, Loader2, Paperclip, Play, RotateCcw, ShieldQuestion, Square, X, XCircle } from "lucide-react";
import { useCallback, useEffect, useRef, useState, type FormEvent, type ReactNode } from "react";
import { api, persist, remember, type LLMStatus } from "../lib/api";
import { useStore, type Attachment } from "../lib/store";
import { Button, Card, cx, Input, Segmented, Select, ViewHeader } from "../components/ui";

type Part =
  | { kind: "text"; text: string }
  | { kind: "tool"; id: string; name: string; args: Record<string, unknown>; stage: string; info: string }
  | { kind: "approval"; id: string; tool: string; args: Record<string, unknown>; reason: string; decided?: boolean };

type Message =
  | { role: "user"; text: string; attachment?: string }
  | { role: "assistant"; model: string; parts: Part[]; done: boolean; error?: string };

const SUGGESTIONS = [
  "Does https://example.com support HTTP/2 and TLS 1.3?",
  "Is gmail.com's email setup healthy? What would you fix?",
  "Look up toolkit.test (A, MX, TXT) on 127.0.0.1:10325 and explain the records.",
  "Explain my last capture.",
];

/** Small Markdown renderer: headings, lists, code blocks, **bold** and `code`. */
function Markdown({ text }: { text: string }) {
  const out: ReactNode[] = [];
  const lines = text.split("\n");
  const inline = (s: string, key: string) => s.split(/(\*\*[^*]+\*\*|`[^`]+`)/g).map((p, i) =>
    p.startsWith("**") && p.endsWith("**") ? <strong key={`${key}-${i}`} className="font-semibold text-ink">{p.slice(2, -2)}</strong>
    : p.startsWith("`") && p.endsWith("`") ? <code key={`${key}-${i}`} className="rounded bg-raised px-1 py-px font-mono text-[12px] text-l-http">{p.slice(1, -1)}</code>
    : p);
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    if (line.trim().startsWith("```")) {
      const code: string[] = [];
      while (++i < lines.length && !lines[i].trim().startsWith("```")) code.push(lines[i]);
      out.push(<pre key={i} className="my-2 overflow-x-auto rounded-lg border border-line bg-void/60 p-3 font-mono text-[12px] text-ink/90">{code.join("\n")}</pre>);
      continue;
    }
    const heading = line.match(/^#{1,4}\s+(.*)/);
    if (heading) { out.push(<h4 key={i} className="mb-1 mt-3 text-[13.5px] font-semibold text-ink">{inline(heading[1], `h${i}`)}</h4>); continue; }
    const bullet = line.match(/^\s*(?:[-*]|\d+\.)\s+(.*)/);
    if (bullet) { out.push(<li key={i} className="ml-4 list-disc marker:text-faint">{inline(bullet[1], `l${i}`)}</li>); continue; }
    if (!line.trim()) { out.push(<div key={i} className="h-2" />); continue; }
    out.push(<p key={i}>{inline(line, `p${i}`)}</p>);
  }
  return <div className="space-y-0.5 text-[13.5px] leading-relaxed text-ink/90">{out}</div>;
}

function ToolCard({ part }: { part: Extract<Part, { kind: "tool" }> }) {
  const [open, setOpen] = useState(false);
  const running = part.stage === "start";
  const failed = ["error", "invalid", "denied"].includes(part.stage);
  const args = Object.entries(part.args).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(" ");
  return (
    <motion.div layout initial={{ opacity: 0, y: 4 }} animate={{ opacity: 1, y: 0 }}
      className={cx("my-2 overflow-hidden rounded-lg border bg-void/40", failed ? "border-bad/30" : running ? "border-tx/40" : "border-line")}>
      <button onClick={() => setOpen(!open)} className="flex w-full items-center gap-2.5 px-3 py-2 text-left">
        {running ? <Loader2 className="size-3.5 animate-spin text-tx" /> : failed ? <XCircle className="size-3.5 text-bad" /> : <Check className="size-3.5 text-ok" />}
        <span className="font-mono text-[12px] text-tx">{part.name}</span>
        <span className="min-w-0 flex-1 truncate font-mono text-[11.5px] text-faint">{args}</span>
        <ChevronRight className={cx("size-3.5 text-faint transition-transform", open && "rotate-90")} />
      </button>
      <AnimatePresence initial={false}>
        {open && part.info && (
          <motion.pre initial={{ height: 0 }} animate={{ height: "auto" }} exit={{ height: 0 }}
            className="scroll-thin max-h-60 overflow-auto border-t border-line px-3 py-2 font-mono text-[11.5px] leading-relaxed text-mute">
            {part.info}
          </motion.pre>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

export function AssistantView() {
  const { toast, wires, takePendingAsk, pendingAsk } = useStore();
  const [prefs, setPrefs] = useState(() => remember("assistant", { provider: "ollama", model: "" }));
  const [status, setStatus] = useState<LLMStatus | null>(null);
  const [messages, setMessages] = useState<Message[]>([]);
  const [input, setInput] = useState("");
  const [attachment, setAttachment] = useState<Attachment | null>(null);
  const [busy, setBusy] = useState(false);
  const [keyDraft, setKeyDraft] = useState("");
  const socket = useRef<WebSocket | null>(null);
  const bottom = useRef<HTMLDivElement>(null);
  const update = (patch: Partial<typeof prefs>) => setPrefs((p) => { const next = { ...p, ...patch }; persist("assistant", next); return next; });

  const refresh = useCallback(async () => {
    try {
      const s = await api.llmStatus();
      setStatus(s);
      setPrefs((p) => (p.provider === "ollama" && (!p.model || !s.ollama.models.includes(p.model)) ? { ...p, model: s.ollama.default } : p));
    } catch (err) {
      toast((err as Error).message);
    }
  }, [toast]);

  useEffect(() => { refresh(); }, [refresh]);

  // One websocket per visit to this view; events stream into the last assistant message
  useEffect(() => {
    const ws = new WebSocket(`${location.protocol === "https:" ? "wss" : "ws"}://${location.host}/api/assistant`);
    socket.current = ws;
    ws.onmessage = (msg) => {
      const e = JSON.parse(msg.data);
      setMessages((all) => {
        const next = [...all];
        const last = next[next.length - 1];
        if (!last || last.role !== "assistant") return all;
        const parts = [...last.parts];
        if (e.type === "text") {
          const tail = parts[parts.length - 1];
          if (tail?.kind === "text") parts[parts.length - 1] = { ...tail, text: tail.text + e.text };
          else parts.push({ kind: "text", text: e.text });
        } else if (e.type === "tool") {
          const i = parts.findIndex((p) => p.kind === "tool" && p.id === e.id);
          const part: Part = { kind: "tool", id: e.id, name: e.name, args: e.args, stage: e.stage, info: e.info };
          if (i >= 0) parts[i] = part; else parts.push(part);
        } else if (e.type === "approval") {
          parts.push({ kind: "approval", id: e.id, tool: e.tool, args: e.args, reason: e.reason });
        }
        next[next.length - 1] = { ...last, parts, done: e.type === "done" || e.type === "error" || last.done,
                                  error: e.type === "error" ? e.message : last.error };
        return next;
      });
      if (e.type === "done" || e.type === "error") setBusy(false);
    };
    ws.onclose = () => setBusy(false);
    return () => ws.close();
  }, []);

  useEffect(() => { bottom.current?.scrollIntoView({ behavior: "smooth", block: "end" }); }, [messages]);

  const send = useCallback((text: string, attach: Attachment | null) => {
    const ws = socket.current;
    if (!text.trim() || busy) return;
    if (!ws || ws.readyState !== WebSocket.OPEN) {
      if (ws?.readyState === WebSocket.CONNECTING) { setTimeout(() => send(text, attach), 250); return; }
      return toast("The assistant connection closed. Reload the page.");
    }
    if (!prefs.model) return toast("Pick a model first.");
    ws.send(JSON.stringify({ type: "ask", text, provider: prefs.provider, model: prefs.model, attachment: attach }));
    setMessages((m) => [...m, { role: "user", text, attachment: attach?.title },
                               { role: "assistant", model: prefs.model, parts: [], done: false }]);
    setBusy(true);
    setInput("");
    setAttachment(null);
  }, [busy, prefs, toast]);

  // "Explain" buttons elsewhere hand a question and capture over to this view
  useEffect(() => {
    if (!pendingAsk || !prefs.model) return;
    const ask = takePendingAsk();
    if (ask) send(ask.question, ask.attachment ?? null);
  }, [pendingAsk, prefs.model, takePendingAsk, send]);

  function decide(id: string, allow: boolean) {
    socket.current?.send(JSON.stringify({ type: "approval", id, allow }));
    setMessages((all) => all.map((m) => m.role !== "assistant" ? m
      : { ...m, parts: m.parts.map((p) => (p.kind === "approval" && p.id === id ? { ...p, decided: allow } : p)) }));
  }

  async function attachLatest() {
    const latest = wires[wires.length - 1];
    if (!latest) return toast("Nothing captured yet. Run a request first.", "info");
    const detail = await api.wire(latest.id);
    setAttachment({ title: detail.title, text: detail.transcript });
  }

  const submit = (e: FormEvent) => { e.preventDefault(); send(input, attachment); };
  const ollama = status?.ollama;
  const claude = status?.claude;
  const ready = prefs.provider === "ollama" ? ollama?.running && ollama.models.length > 0 : claude?.sdk;

  return (
    <div className="flex h-[calc(100vh-56px)] flex-col">
      <ViewHeader title="Assistant" subtitle="Ask in plain language. It runs DNS, HTTP, TLS and email checks itself, and asks before scanning, sending mail or changing data.">
        <Button tone="ghost" icon={<RotateCcw className="size-4" />} onClick={() => { socket.current?.send(JSON.stringify({ type: "reset" })); setMessages([]); }}>
          New chat
        </Button>
      </ViewHeader>

      <Card className="flex flex-wrap items-center gap-3 p-3">
        <Segmented layoutId="assistant-provider" value={prefs.provider}
          onChange={(v) => update({ provider: v, model: v === "claude" ? (claude?.model ?? "claude-opus-5") : (ollama?.default ?? "") })}
          options={[{ value: "ollama", label: "Local · Ollama", title: "Free, private, runs on this Mac" }, { value: "claude", label: "Claude", title: "Anthropic API, needs a key" }]} />
        {prefs.provider === "ollama" ? (
          <Select value={prefs.model} onChange={(e) => update({ model: e.target.value })} aria-label="Model" className="w-44 font-mono">
            {(ollama?.models ?? []).map((m) => <option key={m}>{m}</option>)}
          </Select>
        ) : <span className="font-mono text-[12.5px] text-mute">{claude?.model}</span>}
        <span className="flex items-center gap-2 text-[12px] text-mute">
          {prefs.provider === "ollama" ? (
            ollama?.running ? <><span className="size-2 rounded-full bg-ok" />Ollama {ollama.version} · free, stays on this Mac</>
            : ollama?.installed ? <><span className="size-2 rounded-full bg-warn" />Ollama isn't running
                <Button tone="plain" className="h-7" icon={<Play className="size-3.5" />}
                  onClick={async () => { await api.startOllama().catch((e) => toast(e.message)); setTimeout(refresh, 2500); }}>Start it</Button></>
            : <><span className="size-2 rounded-full bg-bad" />Install Ollama from ollama.com, then run: ollama pull qwen2.5:3b</>
          ) : !claude?.sdk ? <><span className="size-2 rounded-full bg-bad" />Needs the Anthropic SDK: pip install anthropic</>
            : <><span className={cx("size-2 rounded-full", claude.key_set ? "bg-ok" : "bg-warn")} />
                {claude.key_set ? "Key set for this session" : "Uses ANTHROPIC_API_KEY, or paste a key:"}
                {!claude.key_set && (
                  <form className="flex gap-1" onSubmit={async (e) => { e.preventDefault(); await api.settings(keyDraft); setKeyDraft(""); refresh(); }}>
                    <Input type="password" value={keyDraft} onChange={(e) => setKeyDraft(e.target.value)} className="h-7 w-40" placeholder="sk-ant-…" />
                    <Button tone="plain" className="h-7" icon={<KeyRound className="size-3.5" />} type="submit">Save</Button>
                  </form>
                )}</>}
        </span>
      </Card>

      <div className="scroll-thin mt-4 flex-1 overflow-y-auto pr-1">
        {messages.length === 0 ? (
          <div className="grid h-full place-items-center">
            <div className="max-w-xl text-center">
              <motion.div initial={{ scale: 0.8, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
                className="mx-auto mb-4 grid size-14 place-items-center rounded-2xl border border-line bg-raised shadow-[0_0_40px_-12px_var(--tx)]">
                <Bot className="size-6 text-tx" />
              </motion.div>
              <p className="text-[14px] text-ink">What should we look at?</p>
              <p className="mt-1 text-[12.5px] text-mute">Every request the assistant makes streams into the Wire column, so you can see exactly what it did.</p>
              <div className="mt-5 grid gap-2 sm:grid-cols-2">
                {SUGGESTIONS.map((s) => (
                  <button key={s} onClick={() => (s.startsWith("Explain my last") ? (attachLatest(), setInput(s)) : send(s, null))} disabled={!ready}
                    className="rounded-xl border border-line bg-panel/70 px-3.5 py-3 text-left text-[12.5px] text-ink/85 transition-colors hover:border-tx/50 hover:text-ink disabled:opacity-50">
                    {s}
                  </button>
                ))}
              </div>
            </div>
          </div>
        ) : (
          <div className="space-y-5 pb-4">
            {messages.map((m, i) => m.role === "user" ? (
              <motion.div key={i} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} className="flex justify-end">
                <div className="max-w-[80%] rounded-2xl rounded-br-md border border-tx/25 bg-tx/10 px-4 py-2.5 text-[13.5px] text-ink">
                  {m.attachment && <div className="mb-1 flex items-center gap-1.5 text-[11.5px] text-tx"><Paperclip className="size-3" />{m.attachment}</div>}
                  {m.text}
                </div>
              </motion.div>
            ) : (
              <motion.div key={i} initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex gap-3">
                <div className="mt-0.5 grid size-7 shrink-0 place-items-center rounded-lg border border-line bg-raised"><Bot className="size-3.5 text-tx" /></div>
                <div className="min-w-0 flex-1">
                  <div className="mb-1 font-mono text-[11px] text-faint">{m.model}</div>
                  {m.parts.map((p, j) =>
                    p.kind === "text" ? <Markdown key={j} text={p.text} />
                    : p.kind === "tool" ? <ToolCard key={p.id} part={p} />
                    : (
                      <motion.div key={p.id} initial={{ opacity: 0, scale: 0.98 }} animate={{ opacity: 1, scale: 1 }}
                        className="my-2 rounded-xl border border-warn/40 bg-warn/5 p-3.5">
                        <div className="flex items-center gap-2 text-[13px] font-medium text-ink"><ShieldQuestion className="size-4 text-warn" />Allow this action?</div>
                        <p className="mt-1 text-[12.5px] text-mute">{p.reason}</p>
                        <pre className="mt-2 overflow-x-auto rounded-md bg-void/50 p-2 font-mono text-[11.5px] text-ink/80">{p.tool} {JSON.stringify(p.args, null, 2)}</pre>
                        {p.decided === undefined ? (
                          <div className="mt-3 flex gap-2">
                            <Button tone="send" className="h-8" icon={<Check className="size-3.5" />} onClick={() => decide(p.id, true)}>Allow</Button>
                            <Button tone="plain" className="h-8" icon={<X className="size-3.5" />} onClick={() => decide(p.id, false)}>Deny</Button>
                          </div>
                        ) : <p className={cx("mt-2 text-[12px]", p.decided ? "text-ok" : "text-mute")}>{p.decided ? "Allowed" : "Denied"}</p>}
                      </motion.div>
                    ))}
                  {!m.done && m.parts.length === 0 && (
                    <div className="flex items-center gap-2 text-[12.5px] text-mute"><Loader2 className="size-3.5 animate-spin" />Thinking…</div>
                  )}
                  {!m.done && m.parts.length > 0 && m.parts[m.parts.length - 1].kind === "text" && (
                    <span className="ml-0.5 inline-block h-4 w-1.5 translate-y-0.5 animate-pulse rounded-sm bg-tx" />
                  )}
                  {m.error && <p className="mt-2 rounded-lg border border-bad/30 bg-bad/5 px-3 py-2 text-[12.5px] text-bad">{m.error}</p>}
                </div>
              </motion.div>
            ))}
            <div ref={bottom} />
          </div>
        )}
      </div>

      <form onSubmit={submit} className="mt-3">
        <AnimatePresence>
          {attachment && (
            <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
              className="mb-2 inline-flex items-center gap-2 rounded-lg border border-tx/30 bg-tx/10 px-3 py-1.5 text-[12px] text-tx">
              <Paperclip className="size-3.5" />{attachment.title}
              <span className="text-mute">· secrets removed before sending</span>
              <button type="button" onClick={() => setAttachment(null)} aria-label="Remove attachment"><X className="size-3.5" /></button>
            </motion.div>
          )}
        </AnimatePresence>
        <div className="flex items-center gap-2 rounded-2xl border border-line bg-panel/90 p-1.5 pl-2 focus-within:border-tx/60 focus-within:ring-2 focus-within:ring-tx/15">
          <button type="button" onClick={attachLatest} title="Attach the latest capture" aria-label="Attach the latest capture"
            className="rounded-lg p-2 text-mute hover:bg-raised hover:text-tx"><Paperclip className="size-4" /></button>
          <input value={input} onChange={(e) => setInput(e.target.value)} placeholder={ready ? "Ask about a site, a domain, an error, a capture…" : "Set up a model above to start"}
            className="h-9 flex-1 bg-transparent text-[13.5px] text-ink placeholder:text-faint focus:outline-none" aria-label="Message" />
          {busy ? (
            <Button tone="plain" type="button" className="rounded-xl" icon={<Square className="size-3.5" />}
              onClick={() => socket.current?.send(JSON.stringify({ type: "cancel" }))}>Stop</Button>
          ) : (
            <Button tone="send" type="submit" className="rounded-xl px-3" disabled={!input.trim() || !ready} aria-label="Send"><ArrowUp className="size-4" /></Button>
          )}
        </div>
      </form>
    </div>
  );
}
