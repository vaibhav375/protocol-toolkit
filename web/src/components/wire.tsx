import { AnimatePresence, motion, useReducedMotion } from "motion/react";
import { ArrowDownLeft, ArrowUpRight, Radio, ScanSearch } from "lucide-react";
import { useMemo } from "react";
import { b64ToBytes, formatBytes, formatMs, type Direction, type Phase, type TapeEvent, type WireSummary } from "../lib/api";
import { useStore } from "../lib/store";
import { cx, LayerChip, StatusDot } from "./ui";

export function dirColor(direction: Direction): string {
  return direction === "out" ? "var(--tx)" : direction === "in" ? "var(--rx)" : "var(--faint)";
}

/** The first bytes of a frame drawn as a barcode: bar height = byte value. */
export function ByteStrip({ sample, direction, bars = 32 }: { sample: string; direction: Direction; bars?: number }) {
  const bytes = useMemo(() => b64ToBytes(sample).slice(0, bars), [sample, bars]);
  const color = dirColor(direction);
  if (direction === "info" || bytes.length === 0) {
    return <svg width={bars * 3} height={16} aria-hidden><line x1="0" x2={bars * 3} y1="8" y2="8" stroke="var(--faint)" strokeDasharray="2 3" /></svg>;
  }
  return (
    <svg width={bars * 3} height={16} aria-hidden>
      {Array.from(bytes).map((b, i) => {
        const h = 2 + (b / 255) * 14;
        return <rect key={i} x={i * 3} y={16 - h} width={2} height={h} rx={0.5} fill={color} opacity={0.35 + (b / 255) * 0.65} />;
      })}
    </svg>
  );
}

export function FrameRow({ event, index }: { event: TapeEvent; index: number }) {
  const reduce = useReducedMotion();
  const Arrow = event.direction === "out" ? ArrowUpRight : ArrowDownLeft;
  return (
    <motion.li
      layout="position"
      initial={reduce ? false : { opacity: 0, x: 28 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ delay: reduce ? 0 : Math.min(index * 0.035, 0.7), type: "spring", stiffness: 380, damping: 34 }}
      className="grid grid-cols-[46px_14px_1fr] items-center gap-x-2 gap-y-1 px-3 py-1.5"
    >
      <span className="text-right font-mono text-[10.5px] tabular-nums text-faint">{event.t.toFixed(1)}</span>
      {event.direction === "info"
        ? <span className="size-1.5 justify-self-center rounded-full bg-faint" />
        : <Arrow className="size-3.5" style={{ color: dirColor(event.direction) }} />}
      <div className="flex min-w-0 items-center gap-2">
        {event.direction !== "info" && <LayerChip layer={event.layer} />}
        <span className={cx("truncate text-[12px]", event.direction === "info" ? "text-faint italic" : "text-ink/85")}>{event.summary}</span>
      </div>
      {event.direction !== "info" && (
        <>
          <span />
          <span />
          <div className="flex items-center gap-2">
            <ByteStrip sample={event.sample} direction={event.direction} />
            <span className="font-mono text-[10px] text-faint">{formatBytes(event.size)}</span>
          </div>
        </>
      )}
    </motion.li>
  );
}

function Capture({ wire, latest }: { wire: WireSummary; latest: boolean }) {
  const { inspect } = useStore();
  const frames = wire.events.filter((e) => e.direction !== "info" || e.layer !== "TCP");
  const shown = frames.slice(0, latest ? 14 : 4);
  return (
    <motion.div layout initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
      className={cx("border-b border-line/70", latest ? "bg-raised/40" : "opacity-70 hover:opacity-100")}>
      <button onClick={() => inspect(wire.id)}
        className="group flex w-full items-center gap-2 px-3 pb-1 pt-3 text-left" title="Open in the Wire Inspector">
        <span className="font-mono text-[10px] uppercase tracking-[.1em] text-faint">{wire.source}</span>
        <span className="min-w-0 flex-1 truncate text-[12.5px] font-medium text-ink">{wire.title}</span>
        <span className="font-mono text-[10.5px] tabular-nums text-mute">{formatMs(wire.total_ms)}</span>
        <ScanSearch className="size-3.5 text-faint transition-colors group-hover:text-tx" />
      </button>
      <ul className="pb-2">
        {shown.map((e, i) => <FrameRow key={`${wire.id}-${i}`} event={e} index={latest ? i : 0} />)}
      </ul>
      {frames.length > shown.length && (
        <button onClick={() => inspect(wire.id)} className="mb-2 ml-[76px] text-[11.5px] text-mute hover:text-tx">
          +{frames.length - shown.length} more frames
        </button>
      )}
    </motion.div>
  );
}

/** The live column of captured frames shown next to every tool. */
export function WireTape() {
  const { wires, connected } = useStore();
  const recent = [...wires].reverse().slice(0, 8);
  return (
    <aside className="flex h-full w-[340px] shrink-0 flex-col border-l border-line bg-panel/60 backdrop-blur-md max-xl:hidden">
      <div className="flex items-center gap-2.5 border-b border-line px-4 py-3.5">
        <Radio className="size-4 text-tx" />
        <span className="font-display text-[13px] font-medium tracking-wide">Wire</span>
        <span className="ml-auto flex items-center gap-1.5 text-[11px] text-mute">
          <StatusDot on={connected} /> {connected ? "live" : "reconnecting"}
        </span>
      </div>
      <div className="flex gap-3 border-b border-line/70 px-4 py-2 text-[11px] text-mute">
        <span className="flex items-center gap-1"><ArrowUpRight className="size-3 text-tx" /> sent</span>
        <span className="flex items-center gap-1"><ArrowDownLeft className="size-3 text-rx" /> received</span>
        <span className="ml-auto">bars = byte values</span>
      </div>
      <div className="scroll-thin flex-1 overflow-y-auto">
        {recent.length === 0 ? (
          <p className="px-5 py-10 text-center text-[12.5px] leading-relaxed text-mute">
            Every byte the toolkit sends or receives streams in here. Send a request to see it.
          </p>
        ) : (
          <AnimatePresence initial={false}>
            {recent.map((w, i) => <Capture key={w.id} wire={w} latest={i === 0} />)}
          </AnimatePresence>
        )}
      </div>
    </aside>
  );
}

const PHASE_COLORS = ["var(--l-dns)", "var(--l-tcp)", "var(--l-tls)", "var(--rx)", "var(--l-http)", "var(--l-smtp)"];

/** Timing phases drawn in the order they happened. */
export function Waterfall({ phases, compact }: { phases: Phase[]; compact?: boolean }) {
  const reduce = useReducedMotion();
  if (!phases.length) return null;
  const total = Math.max(...phases.map((p) => p.start + p.ms), 0.001);
  return (
    <div className={cx("grid grid-cols-[130px_1fr_72px] items-center gap-x-3", compact ? "gap-y-1.5" : "gap-y-2")}>
      {phases.map((p, i) => (
        <div key={`${p.name}-${i}`} className="contents">
          <span className="truncate text-[12px] text-mute">{p.name}</span>
          <div className="relative h-2.5 rounded-full bg-void/60">
            <motion.div
              className="absolute top-0 h-full rounded-full"
              style={{ left: `${(p.start / total) * 100}%`, background: PHASE_COLORS[i % PHASE_COLORS.length],
                       boxShadow: `0 0 14px -2px ${PHASE_COLORS[i % PHASE_COLORS.length]}` }}
              initial={reduce ? false : { width: 0 }}
              animate={{ width: `max(${(p.ms / total) * 100}%, 3px)` }}
              transition={{ delay: reduce ? 0 : 0.08 + (p.start / total) * 0.6, duration: 0.45, ease: [0.2, 0.8, 0.2, 1] }}
            />
          </div>
          <span className="text-right font-mono text-[11.5px] tabular-nums text-ink/80">{formatMs(p.ms)}</span>
        </div>
      ))}
    </div>
  );
}
