import { AnimatePresence, motion } from "motion/react";
import { ArrowDownLeft, ArrowUpRight, Binary, Bot, ChevronDown, Copy, Download, EyeOff, FileJson, Network, Trash2 } from "lucide-react";
import { useEffect, useMemo, useRef, useState } from "react";
import { api, b64ToBytes, EXPLAIN, formatBytes, formatMs, type WireDetail, type WireEvent, type WireField, type WireSummary } from "../lib/api";
import { useStore } from "../lib/store";
import { Button, Card, cx, Empty, LayerChip, Select, ViewHeader } from "../components/ui";
import { dirColor, Waterfall } from "../components/wire";

const ROW_H = 20;

function HexView({ bytes, range, direction }: { bytes: Uint8Array; range: [number, number] | null; direction: WireEvent["direction"] }) {
  const box = useRef<HTMLDivElement>(null);
  const [scroll, setScroll] = useState(0);
  const [height, setHeight] = useState(360);
  const [perRow, setPerRow] = useState(16);  // 8 when the panel is narrow, so the text column stays visible
  const rows = Math.ceil(bytes.length / perRow);
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    const ro = new ResizeObserver(() => { setHeight(el.clientHeight); setPerRow(el.clientWidth >= 660 ? 16 : 8); });
    ro.observe(el);
    return () => ro.disconnect();
  }, []);
  useEffect(() => {
    // Bring a newly selected field into view
    if (range && box.current) {
      const top = Math.floor(range[0] / perRow) * ROW_H;
      if (top < box.current.scrollTop || top > box.current.scrollTop + height - ROW_H * 2) box.current.scrollTop = Math.max(0, top - ROW_H * 2);
    }
  }, [range, height, perRow]);
  const first = Math.max(0, Math.floor(scroll / ROW_H) - 4);
  const last = Math.min(rows, first + Math.ceil(height / ROW_H) + 8);
  const inRange = (i: number) => range !== null && i >= range[0] && i < range[1];
  const hl = `color-mix(in oklab, ${dirColor(direction)} 30%, transparent)`;
  return (
    <div ref={box} onScroll={(e) => setScroll(e.currentTarget.scrollTop)} className="scroll-thin relative h-full overflow-auto font-mono text-[11.5px]">
      <div style={{ height: rows * ROW_H }} className="relative">
        {Array.from({ length: last - first }, (_, k) => {
          const r = first + k;
          const slice = Array.from(bytes.subarray(r * perRow, r * perRow + perRow));
          return (
            <div key={r} className="absolute left-0 flex gap-4 px-3" style={{ top: r * ROW_H, height: ROW_H, lineHeight: `${ROW_H}px` }}>
              <span className="w-16 text-faint">{(r * perRow).toString(16).padStart(8, "0")}</span>
              <span className="flex gap-[5px]" style={{ width: perRow * 24 - 5 }}>
                {slice.map((b, j) => (
                  <span key={j} className={cx("w-[19px] rounded-[3px] text-center", b === 0 ? "text-faint/60" : "text-ink/85")}
                    style={inRange(r * perRow + j) ? { background: hl, color: "var(--ink)" } : undefined}>
                    {b.toString(16).padStart(2, "0")}
                  </span>
                ))}
              </span>
              <span className="whitespace-pre text-mute">
                {slice.map((b, j) => (
                  <span key={j} style={inRange(r * perRow + j) ? { background: hl, color: "var(--ink)" } : undefined}>
                    {b >= 32 && b < 127 ? String.fromCharCode(b) : "·"}
                  </span>
                ))}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function FieldList({ fields, active, onHover, onPick }: {
  fields: WireField[]; active: number | null; onHover: (i: number | null) => void; onPick: (i: number) => void;
}) {
  if (!fields.length) return <p className="p-4 text-[12.5px] text-mute">No labelled fields for this frame.</p>;
  return (
    <ul className="scroll-thin h-full overflow-y-auto py-1" onMouseLeave={() => onHover(null)}>
      {fields.map((f, i) => (
        <li key={i}>
          <button onMouseEnter={() => onHover(i)} onClick={() => onPick(i)}
            className={cx("grid w-full grid-cols-[minmax(0,1fr)_minmax(0,1.2fr)] gap-3 px-3 py-1 text-left text-[12px] transition-colors",
              active === i ? "bg-raised" : "hover:bg-raised/50")}>
            <span className="truncate text-ink/90" style={{ paddingLeft: f.depth * 14 }}>
              {f.depth > 0 && <span className="mr-1.5 text-faint">└</span>}{f.label}
            </span>
            <span className="truncate font-mono text-[11.5px] text-mute" title={f.value}>{f.value}</span>
          </button>
        </li>
      ))}
    </ul>
  );
}

function ExportMenu({ wireId, summary, onDelete }: { wireId: number; summary?: WireSummary; onDelete: (all: boolean) => void }) {
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const close = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false); };
    document.addEventListener("mousedown", close);
    return () => document.removeEventListener("mousedown", close);
  }, []);
  const ex = summary?.exports;
  const item = "flex w-full items-start gap-3 rounded-lg px-3 py-2 text-left hover:bg-raised";
  return (
    <div ref={box} className="relative">
      <Button tone="plain" icon={<Download className="size-4" />} onClick={() => setOpen(!open)} aria-expanded={open}>
        Export <ChevronDown className="size-3.5" />
      </Button>
      <AnimatePresence>
        {open && (
          <motion.div initial={{ opacity: 0, y: -4, scale: 0.98 }} animate={{ opacity: 1, y: 0, scale: 1 }} exit={{ opacity: 0, y: -4 }}
            className="absolute right-0 top-11 z-30 w-80 rounded-xl border border-line bg-panel p-1.5 shadow-2xl" role="menu">
            {ex?.pcapng && (
              <>
                <a className={item} href={api.exportUrl(wireId, "pcapng")} download onClick={() => setOpen(false)}>
                  <Network className="mt-0.5 size-4 text-l-tls" />
                  <span><span className="block text-[13px] text-ink">Packet capture (.pcapng)</span>
                    <span className="block text-[11.5px] text-mute">{ex.keys ? "Includes TLS keys, so Wireshark shows the decrypted traffic." : "Opens in Wireshark."}</span></span>
                </a>
                {ex.keys && (
                  <a className={item} href={api.exportUrl(wireId, "pcapng", "?keys=false")} download onClick={() => setOpen(false)}>
                    <Network className="mt-0.5 size-4 text-faint" />
                    <span><span className="block text-[13px] text-ink">Packet capture without keys</span>
                      <span className="block text-[11.5px] text-mute">For sharing: encrypted traffic stays encrypted.</span></span>
                  </a>
                )}
              </>
            )}
            {ex?.har && (
              <>
                <a className={item} href={api.exportUrl(wireId, "har")} download onClick={() => setOpen(false)}>
                  <FileJson className="mt-0.5 size-4 text-l-http" />
                  <span><span className="block text-[13px] text-ink">HAR (.har)</span>
                    <span className="block text-[11.5px] text-mute">For browser dev tools. Cookies and auth headers hidden.</span></span>
                </a>
                <a className={item} href={api.exportUrl(wireId, "har", "?sanitize=false")} download onClick={() => setOpen(false)}>
                  <FileJson className="mt-0.5 size-4 text-faint" />
                  <span><span className="block text-[13px] text-ink">HAR with cookies and auth headers</span>
                    <span className="block text-[11.5px] text-mute">Contains secrets. Keep it private.</span></span>
                </a>
              </>
            )}
            <a className={item} href={api.exportUrl(wireId, "transcript")} download onClick={() => setOpen(false)}>
              <Download className="mt-0.5 size-4 text-mute" />
              <span className="text-[13px] text-ink">Text transcript (.txt)</span>
            </a>
            <div className="my-1 border-t border-line" />
            <button className={item} onClick={() => { setOpen(false); onDelete(false); }}>
              <Trash2 className="mt-0.5 size-4 text-bad" /><span className="text-[13px] text-ink">Delete this capture</span>
            </button>
            <button className={item} onClick={() => { setOpen(false); if (confirm("Delete every saved capture? This can't be undone.")) onDelete(true); }}>
              <Trash2 className="mt-0.5 size-4 text-bad" /><span className="text-[13px] text-ink">Clear all history</span>
            </button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

export function InspectorView() {
  const { wires, inspected, inspect, askAssistant, toast, forget } = useStore();
  const id = inspected ?? wires[wires.length - 1]?.id ?? null;
  const [detail, setDetail] = useState<WireDetail | null>(null);
  const [layer, setLayer] = useState<string>("all");
  const [selected, setSelected] = useState(0);
  const [picked, setPicked] = useState<number | null>(null);
  const [hovered, setHovered] = useState<number | null>(null);

  useEffect(() => {
    if (id === null) return;
    let alive = true;
    api.wire(id).then((d) => {
      if (!alive) return;
      setDetail(d);
      setLayer("all");
      setPicked(null);
      // Start on the first application-layer message: TLS records are mostly ciphertext
      const app = d.events.findIndex((e) => e.direction !== "info" && !["TLS", "TCP"].includes(e.layer));
      setSelected(app >= 0 ? app : Math.max(0, d.events.findIndex((e) => e.size > 0)));
    }).catch((err) => toast((err as Error).message));
    return () => { alive = false; };
  }, [id, toast]);

  const visible = useMemo(() => (detail?.events ?? []).filter((e) => layer === "all" || e.layer === layer || e.direction === "info"), [detail, layer]);
  const event = detail?.events[selected];
  const bytes = useMemo(() => (event ? b64ToBytes(event.data) : new Uint8Array()), [event]);
  const focus = hovered ?? picked;
  const range: [number, number] | null = event && focus !== null && event.fields[focus]
    ? [event.fields[focus].offset, event.fields[focus].offset + event.fields[focus].length] : null;

  if (id === null) {
    return <><ViewHeader title="Inspector" subtitle="Every byte of an exchange, labelled." />
      <Empty icon={<Binary className="size-8" />} title="Nothing captured yet">Run any request. Its bytes, timing and every labelled field will show up here.</Empty></>;
  }

  return (
    <div className="flex h-[calc(100vh-56px)] flex-col">
      <ViewHeader title="Inspector" subtitle="Hover a field to light up its bytes. Captures are saved on this Mac, and export to Wireshark (pcapng) or browser dev tools (HAR).">
        <div className="flex gap-2">
          <Select value={id} onChange={(e) => inspect(Number(e.target.value))} className="max-w-72" aria-label="Capture">
            {[...wires].reverse().map((w) => <option key={w.id} value={w.id}>{w.source} · {w.title}</option>)}
          </Select>
          <Button tone="ghost" icon={<Copy className="size-4" />} title="Copy the transcript"
            onClick={() => detail && navigator.clipboard.writeText(detail.transcript).then(() => toast("Transcript copied", "ok"))}>Copy</Button>
          <ExportMenu wireId={id} summary={wires.find((w) => w.id === id)} onDelete={async (all) => {
            try {
              if (all) { await api.clearWires(); toast("History cleared", "ok"); }
              else { await api.deleteWire(id); forget(id); toast("Capture deleted", "ok"); }
            } catch (err) { toast((err as Error).message); }
          }} />
          <Button tone="plain" icon={<Bot className="size-4" />} onClick={() => detail && askAssistant(EXPLAIN, { title: detail.title, text: detail.transcript })}>Explain</Button>
        </div>
      </ViewHeader>

      {detail && (
        <>
          <Card className="p-4">
            <div className="mb-3 flex items-center gap-3">
              <span className="font-mono text-[13px] text-ink">{detail.title}</span>
              <span className="font-mono text-[12px] text-mute">{formatMs(detail.total_ms)} · {detail.events.filter((e) => e.direction !== "info").length} frames</span>
              <div className="ml-auto flex gap-1">
                {["all", ...detail.layers].map((l) => (
                  <button key={l} onClick={() => setLayer(l)}
                    className={cx("rounded-md px-2 py-0.5 text-[11.5px] transition-colors", layer === l ? "bg-raised text-ink ring-1 ring-line" : "text-mute hover:text-ink")}>
                    {l === "all" ? "All layers" : l}
                  </button>
                ))}
              </div>
            </div>
            <Waterfall phases={detail.phases} compact />
          </Card>

          <div className="mt-4 grid min-h-0 flex-1 grid-cols-[minmax(0,0.85fr)_minmax(0,1.4fr)] gap-4">
            <Card className="flex min-h-0 flex-col overflow-hidden">
              <div className="border-b border-line px-3 py-2 text-[10.5px] font-medium uppercase tracking-[.12em] text-faint">Frames</div>
              <ul className="scroll-thin flex-1 overflow-y-auto py-1">
                {visible.map((e) => (
                  <li key={e.i}>
                    <button onClick={() => { setSelected(e.i); setPicked(null); }}
                      className={cx("grid w-full grid-cols-[52px_16px_minmax(0,1fr)_56px] items-center gap-2 px-3 py-1.5 text-left",
                        selected === e.i ? "bg-raised" : "hover:bg-raised/50")}>
                      <span className="text-right font-mono text-[10.5px] tabular-nums text-faint">{e.t.toFixed(1)}</span>
                      {e.direction === "out" ? <ArrowUpRight className="size-3.5 text-tx" />
                        : e.direction === "in" ? <ArrowDownLeft className="size-3.5 text-rx" /> : <span className="size-1.5 justify-self-center rounded-full bg-faint" />}
                      <span className="flex min-w-0 items-center gap-2">
                        {e.direction !== "info" && <LayerChip layer={e.layer} />}
                        <span className={cx("truncate text-[12px]", e.direction === "info" ? "italic text-faint" : "text-ink/90")}>{e.summary}</span>
                      </span>
                      <span className="text-right font-mono text-[10.5px] text-faint">{e.size ? formatBytes(e.size) : ""}</span>
                    </button>
                  </li>
                ))}
              </ul>
            </Card>

            <div className="grid min-h-0 grid-rows-[minmax(0,1fr)_minmax(0,1.3fr)] gap-4">
              <Card className="flex min-h-0 flex-col overflow-hidden">
                <div className="flex items-center gap-2 border-b border-line px-3 py-2 text-[10.5px] font-medium uppercase tracking-[.12em] text-faint">
                  Fields {event?.redacted && <span className="flex items-center gap-1 normal-case tracking-normal text-warn"><EyeOff className="size-3" />credentials hidden</span>}
                </div>
                <div className="min-h-0 flex-1">
                  {event && <FieldList fields={event.fields} active={focus} onHover={setHovered} onPick={setPicked} />}
                </div>
              </Card>
              <Card className="flex min-h-0 flex-col overflow-hidden">
                <div className="flex items-center gap-2 border-b border-line px-3 py-2 text-[10.5px] font-medium uppercase tracking-[.12em] text-faint">
                  Bytes
                  {event && <span className="ml-auto normal-case tracking-normal">{formatBytes(event.size)}{event.truncated ? " · first 64 KB" : ""}</span>}
                </div>
                <motion.div key={selected} initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="min-h-0 flex-1 py-1">
                  {event && event.size > 0 ? <HexView bytes={bytes} range={range} direction={event.direction} />
                    : <p className="p-4 text-[12.5px] text-mute">{event?.summary}</p>}
                </motion.div>
              </Card>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
