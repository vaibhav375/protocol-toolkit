import { AnimatePresence, motion } from "motion/react";
import { Download, Play, Radar, Square } from "lucide-react";
import { useEffect, useRef, useState, type FormEvent } from "react";
import { api, persist, remember, type ScanRow } from "../lib/api";
import { useStore } from "../lib/store";
import { Button, Card, cx, Empty, Input, Segmented, Select, Toggle, ViewHeader } from "../components/ui";

function download(name: string, text: string, type: string) {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = Object.assign(document.createElement("a"), { href: url, download: name });
  a.click();
  URL.revokeObjectURL(url);
}

export function ScanView() {
  const { toast, subscribe, demo } = useStore();
  const targets = demo ? Object.keys(demo.scan_targets) : null;
  const [form, setForm] = useState(() => remember("scan", { host: "127.0.0.1", mode: "common", ports: "1-1024", timeout: 0.5, banners: true, closed: false }));
  const [job, setJob] = useState<{ id: string; total: number } | null>(null);
  const [rows, setRows] = useState<ScanRow[]>([]);
  const [done, setDone] = useState<string | null>(null);
  const jobRef = useRef<string | null>(null);
  const update = (patch: Partial<typeof form>) => setForm((f) => { const next = { ...f, ...patch }; persist("scan", next); return next; });

  useEffect(() => subscribe((event) => {
    if (event.job !== jobRef.current) return;
    if (event.type === "scan") setRows((r) => [...r, event.result as ScanRow]);
    if (event.type === "scan_done") {
      jobRef.current = null;
      setJob(null);
      setDone(event.error ? String(event.error)
        : `${event.open} open of ${event.scanned} scanned${event.stopped ? " (stopped)" : ""}`);
    }
  }), [subscribe]);

  async function start(e: FormEvent) {
    e.preventDefault();
    setRows([]);
    setDone(null);
    try {
      const host = targets && !targets.includes(form.host.trim()) ? targets[0] : form.host.trim();
      const r = await api.scan({ host, ports: form.mode === "common" ? "common" : form.ports,
        timeout: Number(form.timeout), banners: form.banners });
      jobRef.current = r.job;
      setJob({ id: r.job, total: r.total });
    } catch (err) {
      toast((err as Error).message);
    }
  }

  const visible = rows.filter((r) => r.status === "Open" || form.closed).sort((a, b) => a.port - b.port);
  const progress = job ? rows.length / job.total : done ? 1 : 0;

  function exportRows(kind: "csv" | "json") {
    const sorted = [...rows].sort((a, b) => a.port - b.port);
    if (kind === "json") return download("scan.json", JSON.stringify(sorted, null, 2), "application/json");
    const esc = (v: string | number) => `"${String(v).replace(/"/g, '""')}"`;
    download("scan.csv", ["port,status,service,banner,tls", ...sorted.map((r) => [r.port, r.status, r.service, r.banner, r.tls].map(esc).join(","))].join("\n"), "text/csv");
  }

  return (
    <>
      <ViewHeader title="Scanner" subtitle="Find open TCP ports and identify what's listening. Only scan machines you own or have permission to test." />
      <Card className="p-4">
        <form onSubmit={start} className="flex flex-wrap items-center gap-2">
          {targets ? (
            <Select value={targets.includes(form.host) ? form.host : targets[0]} onChange={(e) => update({ host: e.target.value })}
              className="w-56 font-mono" aria-label="Target host" title={demo!.scan_targets[targets[0]]}>
              {targets.map((t) => <option key={t}>{t}</option>)}
            </Select>
          ) : (
            <Input value={form.host} onChange={(e) => update({ host: e.target.value })} className="w-56 font-mono" aria-label="Target host" spellCheck={false} />
          )}
          <Segmented layoutId="scan-mode" value={form.mode} onChange={(v) => update({ mode: v })}
            options={[{ value: "common", label: "Common ports" }, { value: "custom", label: "Custom" }]} />
          {form.mode === "custom" && (
            <Input value={form.ports} onChange={(e) => update({ ports: e.target.value })} className="w-40 font-mono" aria-label="Ports" placeholder="22,80,8000-8100" />
          )}
          <Toggle checked={form.banners} onChange={(v) => update({ banners: v })} label="Identify services" />
          <Toggle checked={form.closed} onChange={(v) => update({ closed: v })} label="Show closed" />
          <div className="ml-auto flex gap-2">
            {job ? <Button tone="danger" icon={<Square className="size-3.5" />} onClick={() => api.stopScan(job.id)}>Stop</Button>
              : <Button tone="send" type="submit" icon={<Play className="size-4" />}>Scan</Button>}
          </div>
        </form>
        <div className="mt-4 h-1 overflow-hidden rounded-full bg-void/70">
          <motion.div className="h-full rounded-full bg-tx shadow-[0_0_12px_var(--tx)]" animate={{ width: `${progress * 100}%` }} transition={{ ease: "easeOut" }} />
        </div>
        <div className="mt-2 flex items-center justify-between text-[12px] text-mute">
          <span>{job ? `Scanning… ${rows.length} of ${job.total}` : done ?? "Ready"}</span>
          {rows.length > 0 && !job && (
            <span className="flex gap-1">
              <Button tone="ghost" className="h-7 px-2" icon={<Download className="size-3.5" />} onClick={() => exportRows("csv")}>CSV</Button>
              <Button tone="ghost" className="h-7 px-2" icon={<Download className="size-3.5" />} onClick={() => exportRows("json")}>JSON</Button>
            </span>
          )}
        </div>
      </Card>

      {visible.length === 0 && !job ? (
        <Empty icon={<Radar className="size-8" />} title={done ? "Nothing open" : "No scan yet"}>
          {done ? "No listening services were found on those ports."
            : targets ? `The demo scans ${targets.join(", ")}, a host whose owners invite scans. Run the app yourself to scan your own machines.`
            : "Scan 127.0.0.1 to see what's running on this Mac."}
        </Empty>
      ) : (
        <Card className="mt-5 overflow-hidden">
          <div className="grid grid-cols-[80px_90px_180px_1fr_120px] gap-3 border-b border-line px-4 py-2.5 text-[10.5px] font-medium uppercase tracking-[.1em] text-faint">
            <span>Port</span><span>State</span><span>Service</span><span>Banner</span><span>TLS</span>
          </div>
          <AnimatePresence initial={false}>
            {visible.map((r) => (
              <motion.div key={r.port} layout initial={{ opacity: 0, backgroundColor: "color-mix(in oklab, var(--tx) 18%, transparent)" }}
                animate={{ opacity: 1, backgroundColor: "rgba(0,0,0,0)" }} transition={{ duration: 0.8 }}
                className="grid grid-cols-[80px_90px_180px_1fr_120px] items-center gap-3 border-b border-line/50 px-4 py-2 text-[12.5px] last:border-0">
                <span className="font-mono text-ink">{r.port}</span>
                <span className={cx("font-medium", r.status === "Open" ? "text-ok" : "text-faint")}>{r.status}</span>
                <span className="truncate text-ink/90">{r.service}</span>
                <span className="truncate font-mono text-[12px] text-mute" title={r.banner}>{r.banner}</span>
                <span className="truncate font-mono text-[11.5px] text-l-tls">{r.tls}</span>
              </motion.div>
            ))}
          </AnimatePresence>
        </Card>
      )}
    </>
  );
}
