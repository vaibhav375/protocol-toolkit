import { AnimatePresence, motion } from "motion/react";
import { ArrowRight, Bot, Cookie as CookieIcon, Globe, Lock, ScanSearch, ShieldAlert } from "lucide-react";
import { useState, type FormEvent } from "react";
import { api, EXPLAIN, formatBytes, formatMs, persist, remember, type HTTPResult } from "../lib/api";
import { useStore } from "../lib/store";
import { Button, Card, cx, Empty, Input, Segmented, Select, Tabs, TextArea, Toggle, ViewHeader } from "../components/ui";
import { Waterfall } from "../components/wire";

const METHODS = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
const DISPLAY_LIMIT = 150_000;

function statusTone(status: number): string {
  return status >= 500 ? "text-bad" : status >= 400 ? "text-warn" : status >= 300 ? "text-l-tcp" : "text-ok";
}

export function HttpView() {
  const { toast, inspect, askAssistant } = useStore();
  const [form, setForm] = useState(() => remember("http", {
    url: "https://example.com/", method: "GET", headers: "Accept: */*", body: "",
    version: "auto", verify: true, follow: true, cookies: true,
  }));
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<HTTPResult | null>(null);
  const [tab, setTab] = useState<"body" | "headers" | "tls" | "cookies">("body");
  const [showAll, setShowAll] = useState(false);
  const [editor, setEditor] = useState<"headers" | "body" | null>(null);
  const update = (patch: Partial<typeof form>) => setForm((f) => { const next = { ...f, ...patch }; persist("http", next); return next; });

  async function send(e?: FormEvent, override?: Partial<typeof form>) {
    e?.preventDefault();
    const f = { ...form, ...override };
    if (!f.url.trim()) return toast("Enter a URL to send the request to.");
    setBusy(true);
    setShowAll(false);
    const headers = Object.fromEntries(f.headers.split("\n").filter((l) => l.includes(":"))
      .map((l) => [l.slice(0, l.indexOf(":")).trim(), l.slice(l.indexOf(":") + 1).trim()]));
    try {
      const r = await api.http({
        url: f.url.trim(), method: f.method, headers,
        body: ["POST", "PUT", "PATCH", "DELETE"].includes(f.method) ? f.body : null,
        http_version: f.version, verify_tls: f.verify, follow_redirects: f.follow, use_cookies: f.cookies,
      });
      setResult(r);
      if (r.error) setTab("body");
    } catch (err) {
      toast((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  async function explainCapture(wireId: number) {
    try {
      const wire = await api.wire(wireId);
      askAssistant(EXPLAIN, { title: wire.title, text: wire.transcript });
    } catch (err) {
      toast((err as Error).message);
    }
  }

  const bodyText = result?.body ?? "";
  return (
    <>
      <ViewHeader title="HTTP" subtitle="Send a real request with a hand-written HTTP/1.1 and HTTP/2 client, and see how long each step took." />

      <Card className="p-4">
        <form onSubmit={send} className="flex gap-2">
          <Select value={form.method} onChange={(e) => update({ method: e.target.value })} aria-label="Method" className="w-[104px] font-mono">
            {METHODS.map((m) => <option key={m}>{m}</option>)}
          </Select>
          <Input value={form.url} onChange={(e) => update({ url: e.target.value })} placeholder="https://example.com/"
            aria-label="URL" className="flex-1 font-mono" spellCheck={false} />
          <Button tone="send" busy={busy} icon={<ArrowRight className="size-4" />} type="submit">Send</Button>
        </form>
        <div className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1">
          <Segmented layoutId="http-version" size="sm" value={form.version} onChange={(v) => update({ version: v })} options={[
            { value: "auto", label: "Auto", title: "HTTP/2 when the server offers it" },
            { value: "1.1", label: "HTTP/1.1" }, { value: "2", label: "HTTP/2" },
            { value: "3", label: "HTTP/3", title: "QUIC over UDP" }]} />
          <Toggle checked={form.verify} onChange={(v) => update({ verify: v })} label="Verify TLS" />
          <Toggle checked={form.follow} onChange={(v) => update({ follow: v })} label="Follow redirects" />
          <Toggle checked={form.cookies} onChange={(v) => update({ cookies: v })} label="Cookie jar" />
          <div className="ml-auto flex gap-1">
            <Button tone="ghost" className="h-8" onClick={() => setEditor(editor === "headers" ? null : "headers")}>Headers</Button>
            <Button tone="ghost" className="h-8" onClick={() => setEditor(editor === "body" ? null : "body")}>Body</Button>
          </div>
        </div>
        <AnimatePresence initial={false}>
          {editor && (
            <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: "auto", opacity: 1 }} exit={{ height: 0, opacity: 0 }}
              className="overflow-hidden">
              <TextArea className="mt-3 w-full" rows={5} spellCheck={false}
                placeholder={editor === "headers" ? "Name: value, one per line" : "Request body (sent for POST, PUT, PATCH and DELETE)"}
                value={editor === "headers" ? form.headers : form.body}
                onChange={(e) => update(editor === "headers" ? { headers: e.target.value } : { body: e.target.value })} />
            </motion.div>
          )}
        </AnimatePresence>
      </Card>

      <AnimatePresence mode="wait">
        {!result ? (
          <motion.div key="empty" exit={{ opacity: 0 }}>
            <Empty icon={<Globe className="size-8" />} title="No response yet">
              Try <button className="text-tx hover:underline" onClick={() => update({ url: "https://www.google.com/" })}>google.com</button> to see HTTP/2 negotiated during the TLS handshake.
            </Empty>
          </motion.div>
        ) : result.error ? (
          <motion.div key={`err-${result.wire_id}`} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }}>
            <Card className="mt-5 border-bad/30 p-5">
              <div className="flex items-start gap-3">
                <ShieldAlert className="mt-0.5 size-5 shrink-0 text-bad" />
                <div className="min-w-0 flex-1">
                  <p className="font-medium text-ink">The request didn't complete</p>
                  <p className="mt-1 text-[13px] text-mute">{result.error}</p>
                </div>
                <Button tone="plain" icon={<ScanSearch className="size-4" />} onClick={() => inspect(result.wire_id)}>Inspect wire</Button>
              </div>
            </Card>
          </motion.div>
        ) : (
          <motion.div key={`ok-${result.wire_id}`} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="mt-5 space-y-4">
            <Card className="p-5">
              <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
                <div className="flex items-baseline gap-3">
                  <motion.span initial={{ scale: 0.8, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
                    className={cx("font-display text-[40px] font-bold leading-none tracking-tight", statusTone(result.status!))}>
                    {result.status}
                  </motion.span>
                  <span className="text-[15px] text-ink">{result.reason}</span>
                </div>
                <dl className="flex flex-wrap gap-x-6 gap-y-1 text-[12.5px]">
                  {[["Protocol", result.version], ["Total", formatMs(result.elapsed_ms!)],
                    ["Body", formatBytes(result.body_size!) + (result.encoding ? ` · ${formatBytes(result.raw_size!)} ${result.encoding}` : "")],
                    ["Redirects", String(result.history!.length)]].map(([k, v]) => (
                    <div key={k}><dt className="text-[10.5px] uppercase tracking-[.1em] text-faint">{k}</dt><dd className="font-mono text-ink">{v}</dd></div>
                  ))}
                </dl>
                <div className="ml-auto flex gap-2">
                  <Button tone="plain" icon={<ScanSearch className="size-4" />} onClick={() => inspect(result.wire_id)}>Inspect wire</Button>
                  <Button tone="ghost" icon={<Bot className="size-4" />}
                    onClick={() => explainCapture(result.wire_id)}>Explain</Button>
                </div>
              </div>
              {result.offers_h3 && result.version !== "HTTP/3" && (
                <div className="mt-4 flex items-center gap-3 rounded-lg border border-l-http/30 bg-l-http/5 px-3 py-2 text-[12.5px]">
                  <span className="text-ink/90">This server also speaks HTTP/3 over QUIC (it said so in its Alt-Svc header).</span>
                  <Button tone="ghost" className="ml-auto h-7" onClick={() => { update({ version: "3" }); send(undefined, { version: "3" }); }}>
                    Try HTTP/3
                  </Button>
                </div>
              )}
              <div className="mt-5 border-t border-line pt-4">
                <Waterfall phases={result.phases!} />
              </div>
            </Card>

            <Card>
              <Tabs layoutId="http-tab" value={tab} onChange={setTab} tabs={[
                { value: "body", label: "Body" }, { value: "headers", label: "Headers", count: result.headers!.length },
                { value: "tls", label: "Connection" }, { value: "cookies", label: "Cookies", count: result.cookies!.length }]} />
              <div className="p-4">
                {tab === "body" && (
                  bodyText ? (
                    <>
                      <pre className="scroll-thin max-h-[520px] overflow-auto whitespace-pre-wrap break-all font-mono text-[12px] leading-relaxed text-ink/90">
                        {showAll ? bodyText : bodyText.slice(0, DISPLAY_LIMIT)}
                      </pre>
                      {(bodyText.length > DISPLAY_LIMIT && !showAll) && (
                        <Button tone="ghost" className="mt-2" onClick={() => setShowAll(true)}>
                          Show all {formatBytes(bodyText.length)}
                        </Button>
                      )}
                    </>
                  ) : <p className="text-[13px] text-mute">The response has no body.</p>
                )}
                {tab === "headers" && (
                  <table className="w-full text-[12.5px]"><tbody>
                    {result.headers!.map(([k, v], i) => (
                      <tr key={i} className="border-b border-line/50 last:border-0">
                        <td className="w-56 py-1.5 pr-4 align-top font-mono text-l-http">{k}</td>
                        <td className="break-all py-1.5 font-mono text-ink/90">{v}</td>
                      </tr>
                    ))}
                  </tbody></table>
                )}
                {tab === "tls" && (
                  <div className="grid gap-4 md:grid-cols-2">
                    <div>
                      <h3 className="mb-2 flex items-center gap-2 text-[12px] font-medium text-mute"><Lock className="size-3.5" /> TLS</h3>
                      {result.tls ? (
                        <dl className="space-y-1.5 text-[12.5px]">
                          {[["Version", result.tls.version], ["Cipher", result.tls.cipher], ["ALPN", result.tls.alpn ?? "none"],
                            ["Certificate", result.tls.subject || "not verified"], ["Issuer", result.tls.issuer], ["Expires", result.tls.expires]].map(([k, v]) => (
                            <div key={k} className="flex gap-3"><dt className="w-24 shrink-0 text-faint">{k}</dt><dd className="font-mono text-ink">{v}</dd></div>
                          ))}
                        </dl>
                      ) : <p className="text-[12.5px] text-mute">Plain HTTP: nothing on this connection was encrypted.</p>}
                    </div>
                    <div>
                      <h3 className="mb-2 text-[12px] font-medium text-mute">Redirects</h3>
                      {result.history!.length ? (
                        <ol className="space-y-1.5 font-mono text-[12px]">
                          {result.history!.map((h, i) => (
                            <li key={i}><span className="text-l-tcp">{h.status}</span> <span className="text-ink/80">{h.url}</span> <span className="text-faint">→ {h.location}</span></li>
                          ))}
                          <li><span className="text-ok">{result.status}</span> <span className="text-ink">{result.url}</span></li>
                        </ol>
                      ) : <p className="text-[12.5px] text-mute">None. The first response was final.</p>}
                    </div>
                  </div>
                )}
                {tab === "cookies" && (
                  result.cookies!.length ? (
                    <div>
                      <table className="w-full text-[12.5px]"><thead><tr className="text-left text-[10.5px] uppercase tracking-[.1em] text-faint">
                        <th className="pb-2">Name</th><th>Value</th><th>Domain</th><th>Flags</th></tr></thead><tbody>
                        {result.cookies!.map((c) => (
                          <tr key={`${c.domain}${c.path}${c.name}`} className="border-t border-line/50">
                            <td className="py-1.5 font-mono text-ink">{c.name}</td>
                            <td className="max-w-[260px] truncate font-mono text-mute">{c.value}</td>
                            <td className="font-mono text-mute">{c.domain}{c.path !== "/" ? c.path : ""}</td>
                            <td className="text-faint">{[c.secure && "Secure", c.http_only && "HttpOnly", !c.expires && "Session"].filter(Boolean).join(" · ")}</td>
                          </tr>))}
                      </tbody></table>
                      <Button tone="ghost" className="mt-3" icon={<CookieIcon className="size-4" />}
                        onClick={async () => { await api.clearCookies(); setResult({ ...result, cookies: [] }); toast("Cookie jar cleared", "ok"); }}>
                        Clear cookie jar
                      </Button>
                    </div>
                  ) : <p className="text-[13px] text-mute">No cookies stored. Sites that set cookies will show them here and get them back on the next request.</p>
                )}
              </div>
            </Card>
          </motion.div>
        )}
      </AnimatePresence>
    </>
  );
}
