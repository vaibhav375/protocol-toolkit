import { AnimatePresence, motion } from "motion/react";
import { ArrowUpRight, Binary, Bot, Globe, MailCheck, Moon, Network, Radar, Send, Server, Sun, X } from "lucide-react";
import { useEffect, type ComponentType } from "react";
import { cx } from "./components/ui";
import { WireTape } from "./components/wire";
import { useStore, type View } from "./lib/store";
import { AssistantView } from "./views/AssistantView";
import { DnsView } from "./views/DnsView";
import { HttpView } from "./views/HttpView";
import { InspectorView } from "./views/InspectorView";
import { LabView } from "./views/LabView";
import { MailView } from "./views/MailView";
import { ScanView } from "./views/ScanView";
import { SmtpView } from "./views/SmtpView";

const NAV: { view: View; label: string; icon: ComponentType<{ className?: string }>; group: string }[] = [
  { view: "http", label: "HTTP", icon: Globe, group: "Protocols" },
  { view: "dns", label: "DNS", icon: Network, group: "Protocols" },
  { view: "smtp", label: "SMTP", icon: Send, group: "Protocols" },
  { view: "mail", label: "Mail check", icon: MailCheck, group: "Diagnose" },
  { view: "scan", label: "Scanner", icon: Radar, group: "Diagnose" },
  { view: "lab", label: "Test servers", icon: Server, group: "Diagnose" },
  { view: "assistant", label: "Assistant", icon: Bot, group: "Understand" },
  { view: "inspector", label: "Inspector", icon: Binary, group: "Understand" },
];

const VIEWS: Record<View, ComponentType> = {
  http: HttpView, dns: DnsView, smtp: SmtpView, mail: MailView, scan: ScanView,
  lab: LabView, assistant: AssistantView, inspector: InspectorView,
};

function Logo() {
  return (
    <div className="flex items-center gap-2.5 px-4 pb-6 pt-5">
      <svg viewBox="0 0 32 32" className="size-8" aria-hidden>
        <rect width="32" height="32" rx="9" fill="var(--raised)" stroke="var(--line)" />
        <motion.path d="M5 20h5l3-9 4 13 3-8h7" fill="none" stroke="var(--tx)" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"
          initial={{ pathLength: 0 }} animate={{ pathLength: 1 }} transition={{ duration: 1.1, ease: "easeInOut" }} />
      </svg>
      <div className="leading-none">
        <div className="font-display text-[13px] font-bold tracking-[.02em]">Protocol</div>
        <div className="mt-1 font-display text-[10px] font-medium tracking-[.34em] text-mute">TOOLKIT</div>
      </div>
    </div>
  );
}

function Rail() {
  const { view, go, theme, toggleTheme, servers, demo } = useStore();
  const groups = [...new Set(NAV.map((n) => n.group))];
  const labRunning = servers && (servers.smtp.running || servers.dns.running);
  return (
    <nav className="flex w-[212px] shrink-0 flex-col border-r border-line bg-panel/70 backdrop-blur-md max-md:hidden" aria-label="Tools">
      <Logo />
      <div className="flex-1 space-y-5 px-2.5">
        {groups.map((group) => (
          <div key={group}>
            <div className="px-2.5 pb-1.5 text-[10.5px] font-medium uppercase tracking-[.14em] text-faint">{group}</div>
            {NAV.filter((n) => n.group === group).map(({ view: v, label, icon: Icon }) => (
              <button key={v} onClick={() => go(v)} aria-current={view === v ? "page" : undefined}
                className={cx("relative flex h-9 w-full items-center gap-3 rounded-lg px-2.5 text-[13px] transition-colors",
                  view === v ? "text-ink" : "text-mute hover:bg-raised/60 hover:text-ink")}>
                {view === v && (
                  <motion.span layoutId="rail-active" className="absolute inset-0 rounded-lg bg-raised shadow-[inset_0_0_0_1px_var(--line)]"
                    transition={{ type: "spring", stiffness: 500, damping: 40 }}>
                    <span className="absolute inset-y-2 -left-2.5 w-[3px] rounded-r-full bg-tx shadow-[0_0_12px_var(--tx)]" />
                  </motion.span>
                )}
                <Icon className={cx("relative size-4", view === v && "text-tx")} />
                <span className="relative">{label}</span>
                {v === "lab" && labRunning && <span className="relative ml-auto size-1.5 rounded-full bg-ok" title="Running" />}
              </button>
            ))}
          </div>
        ))}
      </div>
      <div className="flex items-center justify-between border-t border-line px-4 py-3">
        <span className="text-[11px] text-faint">{demo ? "Public demo" : "Runs on this Mac"}</span>
        <button onClick={toggleTheme} className="rounded-md p-1.5 text-mute hover:bg-raised hover:text-ink"
          aria-label={theme === "dark" ? "Switch to light theme" : "Switch to dark theme"}>
          {theme === "dark" ? <Sun className="size-4" /> : <Moon className="size-4" />}
        </button>
      </div>
    </nav>
  );
}

/** Phones: the rail becomes a scrolling strip of tools along the top */
function MobileNav() {
  const { view, go } = useStore();
  return (
    <nav className="flex shrink-0 items-center gap-1 overflow-x-auto border-b border-line bg-panel/80 px-2 py-2 backdrop-blur-md md:hidden"
      aria-label="Tools">
      {NAV.map(({ view: v, label, icon: Icon }) => (
        <button key={v} onClick={() => go(v)} aria-current={view === v ? "page" : undefined}
          className={cx("flex h-8 shrink-0 items-center gap-1.5 rounded-lg px-2.5 text-[12.5px]",
            view === v ? "bg-raised text-ink shadow-[inset_0_0_0_1px_var(--line)]" : "text-mute")}>
          <Icon className={cx("size-3.5", view === v && "text-tx")} />{label}
        </button>
      ))}
    </nav>
  );
}

const REPO = "https://github.com/vaibhav375/protocol-toolkit";

/** Public demo only: say where it runs and what it won't do */
function DemoBanner() {
  const { demo } = useStore();
  if (!demo) return null;
  return (
    <div className="flex flex-wrap items-center gap-x-3 gap-y-1 border-b border-line bg-tx/[.06] px-4 py-2 text-[12px] text-mute md:px-8">
      <span className="font-medium text-tx">Live demo</span>
      <span>
        Real traffic from a cloud server, in a private session only you can see. HTTP is limited to {demo.http_methods.join(" and ")}, mail
        goes to a test inbox, and scans only reach {Object.keys(demo.scan_targets).join(", ")}.
      </span>
      <a href={REPO} target="_blank" rel="noreferrer" className="ml-auto inline-flex items-center gap-1 text-tx hover:underline">
        Get the full app <ArrowUpRight className="size-3.5" />
      </a>
    </div>
  );
}

function Toasts() {
  const { toasts, dismiss } = useStore();
  return (
    <div className="pointer-events-none fixed bottom-5 left-1/2 z-50 flex -translate-x-1/2 flex-col items-center gap-2" aria-live="polite">
      <AnimatePresence>
        {toasts.map((t) => (
          <motion.div key={t.id} layout initial={{ opacity: 0, y: 16, scale: 0.97 }} animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 8 }}
            className={cx("pointer-events-auto flex max-w-lg items-start gap-3 rounded-xl border bg-raised px-4 py-3 text-[13px] shadow-2xl",
              t.kind === "error" ? "border-bad/40" : t.kind === "ok" ? "border-ok/40" : "border-line")}>
            <span className={cx("mt-1 size-2 shrink-0 rounded-full", t.kind === "error" ? "bg-bad" : t.kind === "ok" ? "bg-ok" : "bg-tx")} />
            <span className="text-ink">{t.text}</span>
            <button onClick={() => dismiss(t.id)} className="text-faint hover:text-ink" aria-label="Dismiss"><X className="size-4" /></button>
          </motion.div>
        ))}
      </AnimatePresence>
    </div>
  );
}

export function App() {
  const { view, go } = useStore();
  const Current = VIEWS[view];

  useEffect(() => {
    // Alt+1..8 jumps between tools
    const onKey = (e: KeyboardEvent) => {
      if (e.altKey && /^[1-8]$/.test(e.key)) { go(NAV[Number(e.key) - 1].view); e.preventDefault(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [go]);

  return (
    <div className="backdrop flex h-full overflow-hidden max-md:flex-col">
      <Rail />
      <MobileNav />
      <main className="scroll-thin min-w-0 flex-1 overflow-y-auto">
        <DemoBanner />
        <AnimatePresence mode="wait">
          <motion.div key={view} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0, y: -4 }}
            transition={{ duration: 0.18 }} className={cx("mx-auto px-4 py-5 md:px-8 md:py-7", view === "inspector" ? "max-w-[1500px]" : "max-w-[1100px]")}>
            <Current />
          </motion.div>
        </AnimatePresence>
      </main>
      {/* The Inspector is the full-size version of the tape, so the tape steps aside there */}
      {view !== "inspector" && <WireTape />}
      <Toasts />
    </div>
  );
}
