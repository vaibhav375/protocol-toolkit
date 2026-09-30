import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { api, persist, remember, type DemoInfo, type ServersState, type WireSummary } from "./api";

export type View = "http" | "dns" | "smtp" | "mail" | "scan" | "lab" | "assistant" | "inspector";

export interface Toast { id: number; kind: "error" | "info" | "ok"; text: string }

export interface Attachment { title: string; text: string }

type LiveEvent = { type: string; [key: string]: unknown };
type Listener = (event: LiveEvent) => void;

interface Store {
  view: View;
  go: (view: View) => void;
  wires: WireSummary[];
  inspect: (wireId: number) => void;
  forget: (wireId: number) => void;
  inspected: number | null;
  servers: ServersState | null;
  setServers: (s: ServersState) => void;
  connected: boolean;
  theme: "dark" | "light";
  toggleTheme: () => void;
  toasts: Toast[];
  toast: (text: string, kind?: Toast["kind"]) => void;
  dismiss: (id: number) => void;
  subscribe: (fn: Listener) => () => void;
  askAssistant: (question: string, attachment?: Attachment) => void;
  pendingAsk: { question: string; attachment?: Attachment } | null;
  /** Limits of the public demo website; null in the desktop app */
  demo: DemoInfo | null;
  takePendingAsk: () => { question: string; attachment?: Attachment } | null;
}

const Ctx = createContext<Store | null>(null);

export function useStore(): Store {
  const store = useContext(Ctx);
  if (!store) throw new Error("useStore outside provider");
  return store;
}

export function StoreProvider({ children }: { children: ReactNode }) {
  const [view, setView] = useState<View>(() => remember("ui", { view: "http" as View }).view);
  const [wires, setWires] = useState<WireSummary[]>([]);
  const [inspected, setInspected] = useState<number | null>(null);
  const [servers, setServers] = useState<ServersState | null>(null);
  const [connected, setConnected] = useState(false);
  const [theme, setTheme] = useState<"dark" | "light">(() => remember("ui", { theme: "dark" as "dark" | "light" }).theme);
  const [toasts, setToasts] = useState<Toast[]>([]);
  const [pendingAsk, setPendingAsk] = useState<Store["pendingAsk"]>(null);
  const [demo, setDemo] = useState<DemoInfo | null>(null);
  const listeners = useRef(new Set<Listener>());
  const toastId = useRef(0);

  useEffect(() => { document.documentElement.dataset.theme = theme; }, [theme]);
  useEffect(() => { persist("ui", { view, theme }); }, [view, theme]);

  const toast = useCallback((text: string, kind: Toast["kind"] = "error") => {
    const id = ++toastId.current;
    setToasts((t) => [...t.slice(-3), { id, kind, text }]);
    setTimeout(() => setToasts((t) => t.filter((x) => x.id !== id)), kind === "error" ? 7000 : 3500);
  }, []);

  useEffect(() => {
    api.wires().then(setWires).catch(() => undefined);
    api.servers().then(setServers).catch(() => undefined);
    api.info().then((info) => setDemo(info.demo)).catch(() => undefined);
    // Live events: new captures, test-server activity, scan results
    const source = new EventSource("/api/events", { withCredentials: true });
    source.onopen = () => setConnected(true);
    source.onerror = () => setConnected(false);
    source.onmessage = (msg) => {
      const event = JSON.parse(msg.data) as LiveEvent;
      if (event.type === "wire") {
        setWires((w) => [...w.filter((x) => x.id !== (event.wire as WireSummary).id), event.wire as WireSummary].slice(-60));
      } else if (event.type === "wires_cleared") {
        setWires([]);
      } else if (event.type === "servers") {
        setServers(event.state as ServersState);
      }
      listeners.current.forEach((fn) => fn(event));
    };
    return () => source.close();
  }, []);

  const store = useMemo<Store>(() => ({
    view,
    go: setView,
    wires,
    inspected,
    inspect: (id) => { setInspected(id); setView("inspector"); },
    forget: (id) => { setWires((w) => w.filter((x) => x.id !== id)); setInspected(null); },
    servers,
    setServers,
    connected,
    theme,
    toggleTheme: () => setTheme((t) => (t === "dark" ? "light" : "dark")),
    toasts,
    toast,
    dismiss: (id) => setToasts((t) => t.filter((x) => x.id !== id)),
    subscribe: (fn) => { listeners.current.add(fn); return () => { listeners.current.delete(fn); }; },
    askAssistant: (question, attachment) => { setPendingAsk({ question, attachment }); setView("assistant"); },
    pendingAsk,
    demo,
    takePendingAsk: () => { const p = pendingAsk; setPendingAsk(null); return p; },
  }), [view, wires, inspected, servers, connected, theme, toasts, toast, pendingAsk, demo]);

  return <Ctx.Provider value={store}>{children}</Ctx.Provider>;
}
