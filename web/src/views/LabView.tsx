import { AnimatePresence, motion } from "motion/react";
import { Check, Inbox, Mail, Network, Play, Square, Trash2 } from "lucide-react";
import { useEffect, useState } from "react";
import { api, type MailItem } from "../lib/api";
import { useStore } from "../lib/store";
import { Button, Card, cx, Input, StatusDot, TextArea, ViewHeader } from "../components/ui";

type Message = MailItem & { headers: string; body: string };

export function LabView() {
  const { servers, setServers, toast, subscribe, demo } = useStore();
  const locked = !!servers?.locked;
  const [smtpPort, setSmtpPort] = useState("1025");
  const [dnsPort, setDnsPort] = useState("10325");
  const [inbox, setInbox] = useState<MailItem[]>([]);
  const [open, setOpen] = useState<Message | null>(null);
  const [zone, setZone] = useState("");
  const [log, setLog] = useState<string[]>([]);

  useEffect(() => {
    api.inbox().then(setInbox).catch(() => undefined);
    api.servers().then((s) => setLog(s.dns.queries)).catch(() => undefined);
  }, []);
  useEffect(() => {
    if (servers && !zone) setZone(servers.dns.zone);
    if (servers?.smtp.running) setSmtpPort(String(servers.smtp.port));
    if (servers?.dns.running) setDnsPort(String(servers.dns.port));
  }, [servers, zone]);
  useEffect(() => subscribe((event) => {
    if (event.type === "mail") setInbox((m) => [...m, event.mail as MailItem]);
    if (event.type === "log" && event.source === "dns") setLog((l) => [...l.slice(-80), String(event.line)]);
  }), [subscribe]);

  async function toggle(kind: "smtp" | "dns") {
    try {
      const running = servers?.[kind].running;
      setServers(running ? await api.stopServer(kind) : await api.startServer(kind, Number(kind === "smtp" ? smtpPort : dnsPort)));
    } catch (err) {
      toast((err as Error).message);
    }
  }

  async function applyZone() {
    try {
      setServers(await api.setZone(zone));
      toast(servers?.dns.running ? "Zone applied. New queries use it immediately." : "Zone saved. It's used when the server starts.", "ok");
    } catch (err) {
      toast((err as Error).message);
    }
  }

  const smtp = servers?.smtp;
  const dns = servers?.dns;
  return (
    <>
      <ViewHeader title="Test servers" subtitle={demo
        ? "SMTP and DNS servers to practise against. In the demo they're always on and shared, but you only see the mail and queries you sent."
        : "Local SMTP and DNS servers to practise against. They only accept connections from this Mac and stop when the toolkit quits."} />
      <div className="grid gap-4 min-[1560px]:grid-cols-2">
        <Card className="flex flex-col p-5">
          <div className="flex items-center gap-3">
            <Mail className="size-5 text-l-smtp" />
            <div className="flex-1">
              <h2 className="text-[14px] font-medium text-ink">SMTP server</h2>
              <p className="text-[12px] text-mute">Catches every message and never delivers it, like Mailpit.</p>
            </div>
            <StatusDot on={!!smtp?.running} />
          </div>
          <div className="mt-4 flex items-center gap-2">
            <span className="whitespace-nowrap text-[12px] text-mute">127.0.0.1 :</span>
            <Input value={smtpPort} onChange={(e) => setSmtpPort(e.target.value)} disabled={smtp?.running} className="w-24 font-mono" aria-label="SMTP port" />
            {!locked && (
              <Button tone={smtp?.running ? "danger" : "send"} icon={smtp?.running ? <Square className="size-3.5" /> : <Play className="size-4" />}
                onClick={() => toggle("smtp")}>{smtp?.running ? "Stop" : "Start"}</Button>
            )}
            <Button tone="ghost" className="ml-auto" icon={<Trash2 className="size-4" />} disabled={!inbox.length}
              onClick={async () => { await api.clearInbox(); setInbox([]); setOpen(null); }}>Clear</Button>
          </div>
          <div className="mt-4 min-h-40 flex-1 rounded-lg border border-line bg-void/40">
            {inbox.length === 0 ? (
              <div className="flex h-full min-h-40 flex-col items-center justify-center gap-2 text-center text-[12.5px] text-mute">
                <Inbox className="size-6 text-faint" />
                {smtp?.running ? `Waiting for mail on port ${smtp.port}. Send one from the SMTP tool.` : "Start the server, then send to 127.0.0.1."}
              </div>
            ) : (
              <ul className="scroll-thin max-h-56 overflow-y-auto">
                <AnimatePresence initial={false}>
                  {[...inbox].reverse().map((m) => (
                    <motion.li key={m.id} initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }}>
                      <button onClick={async () => setOpen(await api.message(m.id))}
                        className={cx("grid w-full grid-cols-[84px_1fr] gap-x-3 border-b border-line/50 px-3 py-2 text-left hover:bg-raised/60",
                          open?.id === m.id && "bg-raised")}>
                        <span className="whitespace-nowrap font-mono text-[11px] text-faint">{new Date(m.received * 1000).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span>
                        <span className="truncate text-[13px] text-ink">{m.subject}</span>
                        <span />
                        <span className="truncate text-[11.5px] text-mute">{m.from} → {m.to.join(", ")}</span>
                      </button>
                    </motion.li>
                  ))}
                </AnimatePresence>
              </ul>
            )}
          </div>
          <AnimatePresence>
            {open && (
              <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
                className="mt-3 rounded-lg border border-line bg-void/40 p-3">
                <p className="mb-2 text-[11.5px] text-faint">
                  Envelope: {open.from} → {open.to.join(", ")}{open.authenticated_as && ` · logged in as ${open.authenticated_as}`}
                </p>
                <pre className="scroll-thin max-h-32 overflow-auto whitespace-pre-wrap font-mono text-[11.5px] text-l-dns/80">{open.headers}</pre>
                <pre className="mt-3 whitespace-pre-wrap text-[13px] text-ink">{open.body}</pre>
              </motion.div>
            )}
          </AnimatePresence>
        </Card>

        <Card className="flex flex-col p-5">
          <div className="flex items-center gap-3">
            <Network className="size-5 text-l-dns" />
            <div className="flex-1">
              <h2 className="text-[14px] font-medium text-ink">DNS server</h2>
              <p className="text-[12px] text-mute">Answers authoritatively for the zone below, over UDP and TCP.</p>
            </div>
            <StatusDot on={!!dns?.running} />
          </div>
          <div className="mt-4 flex items-center gap-2">
            <span className="whitespace-nowrap text-[12px] text-mute">127.0.0.1 :</span>
            <Input value={dnsPort} onChange={(e) => setDnsPort(e.target.value)} disabled={dns?.running} className="w-24 font-mono" aria-label="DNS port" />
            {!locked && (
              <>
                <Button tone={dns?.running ? "danger" : "send"} icon={dns?.running ? <Square className="size-3.5" /> : <Play className="size-4" />}
                  onClick={() => toggle("dns")}>{dns?.running ? "Stop" : "Start"}</Button>
                <Button tone="plain" className="ml-auto" icon={<Check className="size-4" />} onClick={applyZone}>Apply zone</Button>
              </>
            )}
          </div>
          <TextArea value={zone} onChange={(e) => setZone(e.target.value)} rows={10} spellCheck={false} readOnly={locked}
            className="mt-4 w-full whitespace-pre" aria-label="Zone records" />
          <p className="mt-2 text-[11.5px] text-faint">
            {locked ? "The demo's zone is shared, so it can't be edited here; the app you run yourself lets you change it."
              : "One record per line: name, type, value. Types: A AAAA CNAME MX TXT NS PTR SRV. *.name is a wildcard."}
          </p>
          <div className="mt-3 rounded-lg border border-line bg-void/40 p-3">
            <div className="mb-1 text-[10.5px] font-medium uppercase tracking-[.12em] text-faint">Queries received</div>
            <ul className="scroll-thin max-h-28 overflow-y-auto font-mono text-[11.5px] text-mute">
              {log.length === 0 ? <li className="text-faint">None yet. Point the DNS tool at 127.0.0.1:{dns?.port ?? 10325}.</li>
                : [...log].reverse().map((l, i) => <li key={log.length - i}>{l}</li>)}
            </ul>
          </div>
        </Card>
      </div>
    </>
  );
}
