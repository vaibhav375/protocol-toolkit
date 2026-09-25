import { AnimatePresence, motion } from "motion/react";
import { ArrowRight, Network, Route, ScanSearch, Server, ShieldCheck, ShieldAlert } from "lucide-react";
import { useState, type FormEvent } from "react";
import { api, formatMs, persist, remember, type DNSRecord, type DNSResult, type TraceResult } from "../lib/api";
import { useStore } from "../lib/store";
import { Button, Card, cx, Empty, Field, Input, Segmented, Select, Toggle, ViewHeader } from "../components/ui";

const TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR", "SRV", "CAA", "HTTPS", "DS", "DNSKEY"];
const TRANSPORT_NOTE: Record<string, string> = {
  UDP: "Classic DNS on port 53. Unencrypted: anyone on the network path can read or alter it.",
  TCP: "Port 53 over TCP, used for large answers. Still unencrypted.",
  DoT: "DNS-over-TLS on port 853. Encrypted, used by Android's Private DNS.",
  DoH: "DNS-over-HTTPS. Encrypted and indistinguishable from web traffic, used by browsers.",
};

function Records({ title, records }: { title: string; records: DNSRecord[] }) {
  if (!records.length) return null;
  return (
    <div>
      <h3 className="mb-2 text-[10.5px] font-medium uppercase tracking-[.12em] text-faint">{title}</h3>
      <table className="w-full text-[12.5px]"><tbody>
        {records.map((r, i) => (
          <motion.tr key={i} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.04 }}
            className="border-t border-line/50 first:border-0">
            <td className="py-1.5 pr-4 font-mono text-ink">{r.name}.</td>
            <td className="w-16 font-mono text-l-dns">{r.type}</td>
            <td className="w-20 font-mono text-faint">{r.ttl}s</td>
            <td className="break-all py-1.5 font-mono text-ink/90">{r.value}</td>
          </motion.tr>
        ))}
      </tbody></table>
    </div>
  );
}

export function DnsView() {
  const { toast, inspect, servers, setServers } = useStore();
  const [form, setForm] = useState(() => remember("dns", { name: "example.com", type: "A", server: "8.8.8.8", transport: "UDP", dnssec: false }));
  const [busy, setBusy] = useState<"query" | "trace" | null>(null);
  const [result, setResult] = useState<DNSResult | null>(null);
  const [trace, setTrace] = useState<TraceResult | null>(null);
  const update = (patch: Partial<typeof form>) => setForm((f) => { const next = { ...f, ...patch }; persist("dns", next); return next; });

  async function run(kind: "query" | "trace", override?: Partial<typeof form>) {
    const f = { ...form, ...override };
    if (!f.name.trim()) return toast("Enter a name to look up.");
    setBusy(kind);
    try {
      const body = { name: f.name.trim(), type: f.type, server: f.server.trim(), transport: f.transport, dnssec: f.dnssec };
      if (kind === "query") { setResult(await api.dns(body)); setTrace(null); }
      else { setTrace(await api.trace(body)); setResult(null); }
    } catch (err) {
      toast((err as Error).message);
    } finally {
      setBusy(null);
    }
  }

  async function useLocalServer() {
    try {
      const state = servers?.dns.running ? servers : await api.startServer("dns");
      setServers(state);
      const patch = { server: `127.0.0.1:${state.dns.port}`, transport: "UDP", name: form.name.endsWith(".test") ? form.name : "toolkit.test" };
      update(patch);
      run("query", patch);
    } catch (err) {
      toast((err as Error).message);
    }
  }

  const submit = (e: FormEvent) => { e.preventDefault(); run("query"); };
  const rcodeTone = (r?: string) => (r === "NOERROR" ? "text-ok border-ok/40 bg-ok/10" : r === "NXDOMAIN" ? "text-warn border-warn/40 bg-warn/10" : "text-bad border-bad/40 bg-bad/10");

  return (
    <>
      <ViewHeader title="DNS" subtitle="Ask any resolver directly over UDP, TCP, TLS or HTTPS, or follow a name down from the root servers.">
        <Button tone="ghost" icon={<Server className="size-4" />} onClick={useLocalServer}>Use local test server</Button>
      </ViewHeader>

      <Card className="p-4">
        <form onSubmit={submit} className="grid grid-cols-[1fr_120px_auto] gap-2">
          <Input value={form.name} onChange={(e) => update({ name: e.target.value })} className="font-mono" spellCheck={false}
            aria-label="Name" placeholder="example.com, or an IP address for PTR" />
          <Select value={form.type} onChange={(e) => update({ type: e.target.value })} aria-label="Record type" className="font-mono">
            {TYPES.map((t) => <option key={t}>{t}</option>)}
          </Select>
          <div className="flex gap-2">
            <Button tone="send" type="submit" busy={busy === "query"} icon={<ArrowRight className="size-4" />}>Query</Button>
            <Button tone="plain" type="button" busy={busy === "trace"} icon={<Route className="size-4" />} onClick={() => run("trace")}>Trace from root</Button>
          </div>
        </form>
        <div className="mt-3 flex flex-wrap items-end gap-3">
          <Field label="Resolver" className="w-52">
            <Input list="resolvers" value={form.server} onChange={(e) => update({ server: e.target.value })} className="font-mono" spellCheck={false} />
            <datalist id="resolvers">
              {["8.8.8.8", "1.1.1.1", "9.9.9.9", "8.8.4.4", "127.0.0.1:10325"].map((s) => <option key={s} value={s} />)}
            </datalist>
          </Field>
          <div>
            <div className="mb-1.5 text-[11px] font-medium uppercase tracking-[.08em] text-mute">Transport</div>
            <Segmented layoutId="dns-transport" value={form.transport} onChange={(v) => update({ transport: v })}
              options={["UDP", "TCP", "DoT", "DoH"].map((t) => ({ value: t, label: t }))} />
          </div>
          <Toggle checked={form.dnssec} onChange={(v) => update({ dnssec: v })} label="Ask for DNSSEC" />
        </div>
        <p className="mt-3 text-[12px] text-mute">{TRANSPORT_NOTE[form.transport]}</p>
      </Card>

      <AnimatePresence mode="wait">
        {result ? (
          <motion.div key={`q-${result.wire_id}`} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
            <Card className="mt-5 p-5">
              {result.error ? (
                <div className="flex items-start gap-3">
                  <ShieldAlert className="mt-0.5 size-5 text-bad" />
                  <p className="flex-1 text-[13px] text-ink">{result.error}</p>
                  <Button tone="plain" icon={<ScanSearch className="size-4" />} onClick={() => inspect(result.wire_id)}>Inspect wire</Button>
                </div>
              ) : (
                <>
                  <div className="flex flex-wrap items-center gap-3">
                    <span className={cx("rounded-md border px-2.5 py-1 font-mono text-[13px] font-medium", rcodeTone(result.rcode))}>{result.rcode}</span>
                    <div className="flex gap-1">
                      {result.flags!.map((f) => <span key={f} className="rounded bg-raised px-1.5 py-0.5 font-mono text-[11px] text-mute" title={FLAG_HELP[f]}>{f}</span>)}
                    </div>
                    <span className="font-mono text-[12px] text-mute">{result.transport} · {result.server} · {formatMs(result.elapsed_ms!)}</span>
                    {result.authenticated && <span className="flex items-center gap-1 text-[12px] text-ok"><ShieldCheck className="size-4" /> DNSSEC validated</span>}
                    <Button tone="plain" className="ml-auto" icon={<ScanSearch className="size-4" />} onClick={() => inspect(result.wire_id)}>Inspect wire</Button>
                  </div>
                  <div className="mt-5 space-y-5">
                    <Records title="Answer" records={result.answers!} />
                    <Records title="Authority" records={result.authority!} />
                    <Records title="Additional" records={result.additional!} />
                    {!result.answers!.length && (
                      <p className="text-[13px] text-mute">
                        {result.rcode === "NXDOMAIN" ? "This name doesn't exist." : `The name exists but has no ${form.type} records.`}
                      </p>
                    )}
                  </div>
                </>
              )}
            </Card>
          </motion.div>
        ) : trace ? (
          <motion.div key={`t-${trace.wire_id}`} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}>
            <Card className="mt-5 p-5">
              {trace.error ? <p className="text-[13px] text-bad">{trace.error}</p> : (
                <ol className="relative">
                  {trace.steps!.map((s, i) => (
                    <motion.li key={i} initial={{ opacity: 0, x: -10 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.18 }}
                      className="relative pb-6 pl-8 last:pb-0">
                      {i < trace.steps!.length - 1 && (
                        <motion.span className="absolute left-[7px] top-5 w-px bg-gradient-to-b from-tx to-line"
                          initial={{ height: 0 }} animate={{ height: "calc(100% - 12px)" }} transition={{ delay: i * 0.18 + 0.1, duration: 0.3 }} />
                      )}
                      <span className={cx("absolute left-0 top-1 size-[15px] rounded-full border-2",
                        s.answers.length ? "border-ok bg-ok/20" : "border-tx bg-tx/15")} />
                      <div className="flex flex-wrap items-baseline gap-x-3">
                        <span className="font-mono text-[13px] text-ink">{s.server}</span>
                        <span className="font-mono text-[11.5px] text-faint">{s.ip}</span>
                        <span className="font-mono text-[11.5px] text-mute">{formatMs(s.elapsed_ms)}</span>
                        <span className="text-[12px] text-mute">
                          {s.answers.length ? "answered" : s.rcode !== "NOERROR" ? s.rcode : `referred to ${s.referral[0]?.name ?? "?"}`}
                        </span>
                      </div>
                      <div className="mt-1.5 space-y-0.5 font-mono text-[12px] text-ink/80">
                        {(s.answers.length ? s.answers : s.referral.slice(0, 4)).map((r, j) => (
                          <div key={j}><span className="text-l-dns">{r.type}</span> {r.value}</div>
                        ))}
                        {!s.answers.length && s.referral.length > 4 && <div className="text-faint">+{s.referral.length - 4} more name servers</div>}
                      </div>
                    </motion.li>
                  ))}
                </ol>
              )}
              <Button tone="plain" className="mt-5" icon={<ScanSearch className="size-4" />} onClick={() => inspect(trace.wire_id)}>Inspect every packet</Button>
            </Card>
          </motion.div>
        ) : (
          <motion.div key="empty"><Empty icon={<Network className="size-8" />} title="No lookup yet">
            Query a resolver, or trace a name to watch root, TLD and authoritative servers hand it along.
          </Empty></motion.div>
        )}
      </AnimatePresence>
    </>
  );
}

const FLAG_HELP: Record<string, string> = {
  QR: "Response", AA: "Authoritative answer", TC: "Truncated", RD: "Recursion desired",
  RA: "Recursion available", AD: "Authenticated data (DNSSEC)", CD: "Checking disabled",
};
