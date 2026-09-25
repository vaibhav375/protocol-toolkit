import { motion } from "motion/react";
import { ArrowRight, Inbox, ScanSearch, Send, Server } from "lucide-react";
import { useState, type FormEvent } from "react";
import { api, persist, remember, type SMTPResult } from "../lib/api";
import { useStore } from "../lib/store";
import { Button, Card, cx, Empty, Field, Input, Segmented, TextArea, Toggle, ViewHeader } from "../components/ui";

const PRESETS: Record<string, { server: string; port: number; security: string }> = {
  "Built-in test server": { server: "127.0.0.1", port: 1025, security: "none" },
  Gmail: { server: "smtp.gmail.com", port: 587, security: "starttls" },
  "Outlook / Microsoft 365": { server: "smtp.office365.com", port: 587, security: "starttls" },
};

export function SmtpView() {
  const { toast, inspect, go, servers, setServers } = useStore();
  const [form, setForm] = useState(() => remember("smtp", {
    server: "127.0.0.1", port: 1025, security: "none", verify: true, username: "",
    from: "you@example.com", to: "friend@example.com", subject: "Hello from Protocol Toolkit",
    body: "This message was sent by a hand-written SMTP client.",
  }));
  const [password, setPassword] = useState("");  // never stored
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<SMTPResult | null>(null);
  const update = (patch: Partial<typeof form>) => setForm((f) => { const next = { ...f, ...patch }; persist("smtp", next); return next; });
  const local = ["127.0.0.1", "localhost", "::1"].includes(form.server.trim());

  async function applyPreset(name: string) {
    const p = PRESETS[name];
    update({ ...p, server: p.server || form.server });
    if (name === "Built-in test server") {
      try {
        const state = servers?.smtp.running ? servers : await api.startServer("smtp");
        setServers(state);
        update({ ...p, port: state.smtp.port });
        toast(`Test server listening on 127.0.0.1:${state.smtp.port}`, "ok");
      } catch (err) {
        toast((err as Error).message);
      }
    }
  }

  async function send(e: FormEvent) {
    e.preventDefault();
    const to = form.to.split(",").map((s) => s.trim()).filter(Boolean);
    if (!form.server.trim() || !form.from.trim() || !to.length) return toast("Fill in the server, From and To.");
    setBusy(true);
    try {
      setResult(await api.smtp({ server: form.server.trim(), port: Number(form.port), security: form.security,
        verify_tls: form.verify, username: form.username.trim(), password, from: form.from.trim(), to,
        subject: form.subject, body: form.body }));
    } catch (err) {
      toast((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <ViewHeader title="SMTP" subtitle="Send a real email and watch the whole SMTP conversation, including the switch to TLS.">
        <div className="flex flex-wrap gap-1">
          {Object.keys(PRESETS).map((name) => (
            <Button key={name} tone="ghost" className="h-8" icon={name.startsWith("Built") ? <Server className="size-3.5" /> : undefined}
              onClick={() => applyPreset(name)}>{name}</Button>
          ))}
        </div>
      </ViewHeader>

      <form onSubmit={send}>
        <Card className="space-y-4 p-4">
          <div className="grid grid-cols-[1fr_96px_auto] items-end gap-3">
            <Field label="Server"><Input value={form.server} onChange={(e) => update({ server: e.target.value })} className="font-mono" spellCheck={false} /></Field>
            <Field label="Port"><Input type="number" value={form.port} onChange={(e) => update({ port: Number(e.target.value) })} className="font-mono" /></Field>
            <Segmented layoutId="smtp-sec" value={form.security} onChange={(v) => update({ security: v, port: v === "implicit" ? 465 : v === "starttls" ? 587 : form.port })}
              options={[{ value: "none", label: "Plain" }, { value: "starttls", label: "STARTTLS" }, { value: "implicit", label: "TLS" }]} />
          </div>
          <div className="grid grid-cols-[1fr_1fr_auto] items-end gap-3">
            <Field label="Username" hint="optional"><Input value={form.username} onChange={(e) => update({ username: e.target.value })} autoComplete="off" /></Field>
            <Field label="Password" hint="kept in memory only"><Input type="password" value={password} onChange={(e) => setPassword(e.target.value)} autoComplete="off" /></Field>
            <Toggle checked={form.verify} onChange={(v) => update({ verify: v })} label="Verify TLS" />
          </div>
          {!local && form.security === "none" && form.username && (
            <p className="text-[12px] text-warn">Passwords are only sent over an encrypted connection. Choose STARTTLS or TLS for a remote server.</p>
          )}
          <div className="grid grid-cols-2 gap-3">
            <Field label="From"><Input value={form.from} onChange={(e) => update({ from: e.target.value })} /></Field>
            <Field label="To" hint="comma-separated"><Input value={form.to} onChange={(e) => update({ to: e.target.value })} /></Field>
          </div>
          <Field label="Subject"><Input value={form.subject} onChange={(e) => update({ subject: e.target.value })} /></Field>
          <TextArea rows={4} value={form.body} onChange={(e) => update({ body: e.target.value })} className="w-full font-sans text-[13px]" aria-label="Message" />
          <div className="flex items-center gap-3">
            <Button tone="send" type="submit" busy={busy} icon={<Send className="size-4" />}>Send email</Button>
            {local && <span className="text-[12px] text-mute">Mail to the built-in server is caught in Test servers and never delivered.</span>}
          </div>
        </Card>
      </form>

      {!result ? (
        <Empty icon={<Send className="size-8" />} title="No conversation yet">The client's commands and the server's replies will appear here, line by line.</Empty>
      ) : (
        <motion.div key={result.wire_id} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
          <Card className="mt-5">
            <div className="flex items-center gap-3 border-b border-line px-4 py-3">
              <span className={cx("size-2 rounded-full", result.error ? "bg-bad" : "bg-ok")} />
              <span className="text-[13px] text-ink">{result.error ? "Not sent" : "Accepted by the server"}</span>
              <span className="truncate font-mono text-[12px] text-mute">{result.error ?? result.result}</span>
              <div className="ml-auto flex gap-2">
                {local && !result.error && <Button tone="ghost" icon={<Inbox className="size-4" />} onClick={() => go("lab")}>Open inbox</Button>}
                <Button tone="plain" icon={<ScanSearch className="size-4" />} onClick={() => inspect(result.wire_id)}>Inspect wire</Button>
              </div>
            </div>
            {result.hint && <p className="border-b border-line px-4 py-2.5 text-[12.5px] text-warn">{result.hint}</p>}
            <ol className="scroll-thin max-h-[420px] overflow-y-auto px-4 py-3 font-mono text-[12px] leading-[1.7]">
              {result.log.map((line, i) => {
                const client = line.startsWith("C:");
                const server = line.startsWith("S:");
                return (
                  <motion.li key={i} initial={{ opacity: 0, x: client ? -6 : 6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: Math.min(i * 0.025, 0.8) }}
                    className={cx("flex gap-3", client ? "text-tx" : server ? "text-rx" : "text-faint italic")}>
                    <span className="w-4 shrink-0 text-center opacity-70">{client ? "→" : server ? "←" : "·"}</span>
                    <span className="break-all">{client || server ? line.slice(3) : line}</span>
                  </motion.li>
                );
              })}
              {result.error && <li className="mt-1 flex gap-3 text-bad"><ArrowRight className="mt-1 size-3" />{result.error}</li>}
            </ol>
          </Card>
        </motion.div>
      )}
    </>
  );
}
