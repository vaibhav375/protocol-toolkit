import { motion } from "motion/react";
import { AlertTriangle, ArrowRight, Bot, CheckCircle2, Info, MailCheck, XCircle } from "lucide-react";
import { useState, type FormEvent } from "react";
import { api, persist, remember, type CheckStatus, type MailReport } from "../lib/api";
import { useStore } from "../lib/store";
import { Button, Card, cx, Empty, Input, Toggle, ViewHeader } from "../components/ui";

const STATUS: Record<CheckStatus, { icon: typeof CheckCircle2; tone: string; label: string }> = {
  pass: { icon: CheckCircle2, tone: "text-ok", label: "Pass" },
  warn: { icon: AlertTriangle, tone: "text-warn", label: "Warning" },
  fail: { icon: XCircle, tone: "text-bad", label: "Fail" },
  info: { icon: Info, tone: "text-faint", label: "Optional" },
};

const GRADE_TONE: Record<string, string> = { A: "text-ok", B: "text-ok", C: "text-warn", D: "text-bad", F: "text-bad" };

export function MailView() {
  const { toast, askAssistant } = useStore();
  const [form, setForm] = useState(() => remember("mail", { domain: "gmail.com", selectors: "", probe: false }));
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<MailReport | null>(null);
  const update = (patch: Partial<typeof form>) => setForm((f) => { const next = { ...f, ...patch }; persist("mail", next); return next; });

  async function run(e: FormEvent) {
    e.preventDefault();
    if (!form.domain.trim()) return toast("Enter a domain or email address.");
    setBusy(true);
    try {
      setReport(await api.mailcheck({ domain: form.domain.trim(), probe_smtp: form.probe,
        selectors: form.selectors.split(",").map((s) => s.trim()).filter(Boolean) }));
    } catch (err) {
      toast((err as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <>
      <ViewHeader title="Mail check" subtitle="Is this domain set up to send and receive email reliably? Reads its DNS records and, optionally, tests its mail server. Sends nothing." />
      <Card className="p-4">
        <form onSubmit={run} className="flex flex-wrap items-center gap-2">
          <Input value={form.domain} onChange={(e) => update({ domain: e.target.value })} className="min-w-64 flex-1 font-mono"
            placeholder="example.com or you@example.com" aria-label="Domain" spellCheck={false} />
          <Input value={form.selectors} onChange={(e) => update({ selectors: e.target.value })} className="w-44 font-mono"
            placeholder="DKIM selectors" aria-label="DKIM selectors" title="Comma-separated. Found in the s= tag of a DKIM-Signature header." />
          <Toggle checked={form.probe} onChange={(v) => update({ probe: v })} label="Test STARTTLS on port 25" />
          <Button tone="send" type="submit" busy={busy} icon={<ArrowRight className="size-4" />}>Check</Button>
        </form>
      </Card>

      {!report ? (
        <Empty icon={<MailCheck className="size-8" />} title="No report yet">
          Checks MX, SPF (including the 10-lookup limit), DMARC, DKIM key strength, MTA-STS, TLS-RPT and BIMI.
        </Empty>
      ) : (
        <motion.div key={report.domain + report.grade} initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="mt-5 space-y-3">
          <Card className="flex items-center gap-6 p-5">
            <motion.div initial={{ scale: 0.6, opacity: 0, rotate: -8 }} animate={{ scale: 1, opacity: 1, rotate: 0 }}
              transition={{ type: "spring", stiffness: 260, damping: 18 }}
              className={cx("grid size-20 place-items-center rounded-2xl border border-line bg-raised font-display text-[44px] font-bold", GRADE_TONE[report.grade])}>
              {report.grade}
            </motion.div>
            <div className="flex-1">
              <div className="font-mono text-[15px] text-ink">{report.domain}</div>
              <div className="mt-2 flex gap-4 text-[12.5px]">
                {(["pass", "warn", "fail"] as CheckStatus[]).map((s) => (
                  <span key={s} className={STATUS[s].tone}>{report.counts[s]} {STATUS[s].label.toLowerCase()}{report.counts[s] === 1 || s === "pass" ? "" : "s"}</span>
                ))}
              </div>
            </div>
            <Button tone="ghost" icon={<Bot className="size-4" />}
              onClick={() => askAssistant("Explain this email deliverability report in plain language and list what to fix first.",
                { title: `Mail check ${report.domain}`, text: report.text })}>Explain</Button>
          </Card>
          {report.checks.map((c, i) => {
            const S = STATUS[c.status];
            return (
              <motion.div key={c.area} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: 0.05 + i * 0.05 }}>
                <Card className="flex gap-4 p-4">
                  <S.icon className={cx("mt-0.5 size-5 shrink-0", S.tone)} />
                  <div className="min-w-0 flex-1">
                    <div className="flex items-baseline gap-3">
                      <span className="w-20 shrink-0 font-mono text-[12px] font-medium text-mute">{c.area}</span>
                      <span className="text-[13.5px] text-ink">{c.title}</span>
                    </div>
                    {c.detail && <p className="mt-1 pl-[92px] text-[12.5px] text-mute">{c.detail}</p>}
                    {c.records.length > 0 && (
                      <div className="mt-2 space-y-1 pl-[92px]">
                        {c.records.map((r, j) => <div key={j} className="break-all font-mono text-[11.5px] text-l-dns/90">{r}</div>)}
                      </div>
                    )}
                  </div>
                </Card>
              </motion.div>
            );
          })}
        </motion.div>
      )}
    </>
  );
}
