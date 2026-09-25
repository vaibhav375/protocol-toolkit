import { motion } from "motion/react";
import { Loader2 } from "lucide-react";
import type { ButtonHTMLAttributes, InputHTMLAttributes, ReactNode, SelectHTMLAttributes, TextareaHTMLAttributes } from "react";

export function cx(...parts: (string | false | null | undefined)[]): string {
  return parts.filter(Boolean).join(" ");
}

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & {
  tone?: "send" | "plain" | "ghost" | "danger";
  busy?: boolean;
  icon?: ReactNode;
};

/** "send" is cyan: it is the button that puts bytes on the wire. */
export function Button({ tone = "plain", busy, icon, children, className, disabled, ...rest }: ButtonProps) {
  return (
    <button
      {...rest}
      disabled={disabled || busy}
      className={cx(
        "inline-flex h-9 shrink-0 items-center justify-center gap-2 rounded-lg px-3.5 text-[13px] font-medium",
        "transition-[background,border-color,color,box-shadow,transform] duration-150 active:scale-[.98] disabled:cursor-not-allowed disabled:opacity-50",
        tone === "send" && "bg-tx text-void shadow-[0_0_0_1px_var(--tx),0_8px_28px_-12px_var(--tx)] hover:brightness-110",
        tone === "plain" && "border border-line bg-raised text-ink hover:border-faint",
        tone === "ghost" && "text-mute hover:bg-raised hover:text-ink",
        tone === "danger" && "border border-bad/40 bg-bad/10 text-bad hover:bg-bad/20",
        className,
      )}
    >
      {busy ? <Loader2 className="size-4 animate-spin" /> : icon}
      {children}
    </button>
  );
}

export function Input({ className, ...rest }: InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...rest}
      className={cx(
        "h-9 min-w-0 rounded-lg border border-line bg-panel px-3 text-[13px] text-ink placeholder:text-faint",
        "transition-colors focus:border-tx/70 focus:outline-none focus:ring-2 focus:ring-tx/20",
        className,
      )}
    />
  );
}

export function TextArea({ className, ...rest }: TextareaHTMLAttributes<HTMLTextAreaElement>) {
  return (
    <textarea
      {...rest}
      className={cx(
        "min-h-24 rounded-lg border border-line bg-panel p-3 font-mono text-[12.5px] leading-relaxed text-ink placeholder:text-faint",
        "scroll-thin transition-colors focus:border-tx/70 focus:outline-none focus:ring-2 focus:ring-tx/20",
        className,
      )}
    />
  );
}

export function Select({ className, children, ...rest }: SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      {...rest}
      className={cx(
        "h-9 rounded-lg border border-line bg-panel px-2.5 text-[13px] text-ink focus:border-tx/70 focus:outline-none focus:ring-2 focus:ring-tx/20",
        className,
      )}
    >
      {children}
    </select>
  );
}

export function Label({ children, hint }: { children: ReactNode; hint?: string }) {
  return (
    <span className="mb-1.5 flex items-baseline gap-2 text-[11px] font-medium uppercase tracking-[.08em] text-mute">
      {children}
      {hint && <span className="normal-case tracking-normal text-faint">{hint}</span>}
    </span>
  );
}

export function Field({ label, hint, children, className }: { label: string; hint?: string; children: ReactNode; className?: string }) {
  return (
    <label className={cx("flex min-w-0 flex-col", className)}>
      <Label hint={hint}>{label}</Label>
      {children}
    </label>
  );
}

/** Segmented control with a sliding highlight */
export function Segmented<T extends string>({ value, options, onChange, layoutId, size = "md" }: {
  value: T; options: { value: T; label: string; title?: string }[]; onChange: (v: T) => void; layoutId: string; size?: "sm" | "md";
}) {
  return (
    <div className={cx("inline-flex rounded-lg border border-line bg-panel p-0.5", size === "sm" ? "h-8" : "h-9")} role="radiogroup">
      {options.map((o) => (
        <button
          key={o.value}
          type="button"
          role="radio"
          aria-checked={value === o.value}
          title={o.title}
          onClick={() => onChange(o.value)}
          className={cx("relative rounded-md px-3 text-[12.5px] font-medium transition-colors", value === o.value ? "text-ink" : "text-mute hover:text-ink")}
        >
          {value === o.value && (
            <motion.span layoutId={layoutId} className="absolute inset-0 rounded-md bg-raised shadow-[inset_0_0_0_1px_var(--line)]"
              transition={{ type: "spring", stiffness: 500, damping: 38 }} />
          )}
          <span className="relative">{o.label}</span>
        </button>
      ))}
    </div>
  );
}

export function Toggle({ checked, onChange, label }: { checked: boolean; onChange: (v: boolean) => void; label: string }) {
  return (
    <button type="button" role="switch" aria-checked={checked} onClick={() => onChange(!checked)}
      className="group inline-flex h-9 items-center gap-2 rounded-lg px-1.5 text-[13px] text-mute hover:text-ink">
      <span className={cx("relative h-[18px] w-8 rounded-full border transition-colors", checked ? "border-tx/60 bg-tx/25" : "border-line bg-panel")}>
        <motion.span layout transition={{ type: "spring", stiffness: 600, damping: 32 }}
          className={cx("absolute top-[2px] size-3 rounded-full", checked ? "right-[2px] bg-tx" : "left-[2px] bg-faint")} />
      </span>
      {label}
    </button>
  );
}

export function Card({ children, className }: { children: ReactNode; className?: string }) {
  return <section className={cx("rounded-xl border border-line bg-panel/80 backdrop-blur-sm", className)}>{children}</section>;
}

const LAYER_COLOR: Record<string, string> = {
  TCP: "var(--l-tcp)", TLS: "var(--l-tls)", "HTTP/1.1": "var(--l-http)", "HTTP/2": "var(--l-http)", HTTP: "var(--l-http)",
  DNS: "var(--l-dns)", UDP: "var(--l-dns)", SMTP: "var(--l-smtp)",
  QUIC: "var(--l-tls)", "HTTP/3": "var(--l-http)",
};

export function layerColor(layer: string): string {
  return LAYER_COLOR[layer] ?? "var(--mute)";
}

export function LayerChip({ layer }: { layer: string }) {
  const color = layerColor(layer);
  return (
    <span className="inline-flex h-5 items-center rounded-[5px] px-1.5 font-mono text-[10.5px] font-medium"
      style={{ color, background: `color-mix(in oklab, ${color} 14%, transparent)`, boxShadow: `inset 0 0 0 1px color-mix(in oklab, ${color} 30%, transparent)` }}>
      {layer}
    </span>
  );
}

export function StatusDot({ on, className }: { on: boolean; className?: string }) {
  return <span className={cx("inline-block size-2 rounded-full", on ? "bg-ok animate-pulse-dot" : "bg-faint", className)} />;
}

export function ViewHeader({ title, subtitle, children }: { title: string; subtitle: string; children?: ReactNode }) {
  return (
    <header className="mb-5 flex flex-wrap items-end justify-between gap-3">
      <div>
        <h1 className="font-display text-[22px] font-medium tracking-[-.01em] text-ink">{title}</h1>
        <p className="mt-1 max-w-2xl text-[13px] text-mute">{subtitle}</p>
      </div>
      {children}
    </header>
  );
}

export function Empty({ icon, title, children }: { icon: ReactNode; title: string; children?: ReactNode }) {
  return (
    <div className="flex flex-col items-center justify-center gap-2 py-16 text-center">
      <div className="text-faint">{icon}</div>
      <p className="text-[14px] text-ink">{title}</p>
      {children && <div className="max-w-md text-[13px] text-mute">{children}</div>}
    </div>
  );
}

export function Tabs<T extends string>({ value, onChange, tabs, layoutId }: {
  value: T; onChange: (v: T) => void; tabs: { value: T; label: string; count?: number }[]; layoutId: string;
}) {
  return (
    <div className="flex gap-1 border-b border-line px-2" role="tablist">
      {tabs.map((t) => (
        <button key={t.value} role="tab" aria-selected={value === t.value} onClick={() => onChange(t.value)}
          className={cx("relative px-3 py-2.5 text-[12.5px] font-medium transition-colors", value === t.value ? "text-ink" : "text-mute hover:text-ink")}>
          {t.label}
          {t.count !== undefined && <span className="ml-1.5 font-mono text-[11px] text-faint">{t.count}</span>}
          {value === t.value && <motion.span layoutId={layoutId} className="absolute inset-x-2 -bottom-px h-0.5 rounded-full bg-tx" />}
        </button>
      ))}
    </div>
  );
}
