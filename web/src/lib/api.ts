// Typed client for the local backend. Every call is same-origin; the session cookie
// set by the launch link authenticates it.

export type Direction = "out" | "in" | "info";

export interface Phase { name: string; start: number; ms: number }

export interface TapeEvent {
  t: number; direction: Direction; layer: string; size: number; summary: string; sample: string;
}

export interface WireSummary {
  id: number; title: string; source: string; created: number; total_ms: number;
  phases: Phase[]; events: TapeEvent[]; layers: string[];
  exports: { pcapng: boolean; har: boolean; keys: boolean };
}

export interface WireField { offset: number; length: number; label: string; value: string; depth: number }

export interface WireEvent extends TapeEvent {
  i: number; redacted: boolean; truncated: boolean; data: string; fields: WireField[];
}

export interface WireDetail extends Omit<WireSummary, "events"> { events: WireEvent[]; transcript: string }

export interface TLSInfo {
  version: string; cipher: string; alpn: string | null; subject: string; issuer: string;
  expires: string; san: string[]; verified: boolean;
}

export interface Cookie {
  name: string; value: string; domain: string; path: string; secure: boolean; http_only: boolean; expires: number | null;
}

export interface HTTPResult {
  error?: string; wire_id: number;
  status?: number; reason?: string; version?: string; url?: string; elapsed_ms?: number;
  headers?: [string, string][]; body?: string; body_truncated?: boolean; body_size?: number; raw_size?: number;
  encoding?: string; content_type?: string; tls?: TLSInfo | null;
  history?: { status: number; url: string; location: string }[]; phases?: Phase[]; cookies?: Cookie[];
  offers_h3?: boolean;
}

export interface DNSRecord { name: string; type: string; ttl: number; value: string }

export interface DNSResult {
  error?: string; wire_id: number;
  rcode?: string; flags?: string[]; transport?: string; server?: string; elapsed_ms?: number;
  authenticated?: boolean; id?: number; edns?: number | null;
  answers?: DNSRecord[]; authority?: DNSRecord[]; additional?: DNSRecord[]; text?: string;
}

export interface TraceResult {
  error?: string; wire_id: number;
  steps?: { server: string; ip: string; rcode: string; elapsed_ms: number; answers: DNSRecord[]; referral: DNSRecord[] }[];
}

export interface SMTPResult { error?: string; hint?: string; result?: string; log: string[]; wire_id: number }

export type CheckStatus = "pass" | "warn" | "fail" | "info";

export interface MailReport {
  domain: string; grade: string; counts: Record<CheckStatus, number>;
  checks: { area: string; status: CheckStatus; title: string; detail: string; records: string[] }[];
  text: string;
}

export interface ScanRow { port: number; status: "Open" | "Closed" | "Filtered"; service: string; banner: string; tls: string }

export interface ServersState {
  smtp: { running: boolean; port: number; messages: number };
  dns: { running: boolean; port: number; zone: string; queries: string[] };
}

export interface MailItem { id: number; received: number; from: string; to: string[]; subject: string; authenticated_as: string }

export interface LLMStatus {
  ollama: { running: boolean; version: string; models: string[]; installed: boolean; default: string };
  claude: { sdk: boolean; model: string; key_set: boolean };
}

export interface Info { version: string; http2: boolean; query_types: string[]; transports: string[]; common_ports: number[] }

export const EXPLAIN = "Explain the attached capture: what happened step by step, anything unusual, and what to check next.";

export class ApiError extends Error {}

async function call<T>(method: string, path: string, body?: unknown): Promise<T> {
  let res: Response;
  try {
    res = await fetch(path, {
      method,
      headers: body === undefined ? {} : { "Content-Type": "application/json" },
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: "same-origin",
    });
  } catch {
    throw new ApiError("Lost contact with the toolkit. Is it still running in the terminal?");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new ApiError(typeof data.detail === "string" ? data.detail : `Request failed (${res.status})`);
  return data as T;
}

export const api = {
  info: () => call<Info>("GET", "/api/info"),
  wires: () => call<WireSummary[]>("GET", "/api/wires"),
  wire: (id: number) => call<WireDetail>("GET", `/api/wires/${id}`),
  deleteWire: (id: number) => call<unknown>("DELETE", `/api/wires/${id}`),
  clearWires: () => call<unknown>("DELETE", "/api/wires"),
  exportUrl: (id: number, kind: "pcapng" | "har" | "transcript", opts = "") => `/api/wires/${id}/export/${kind}${opts}`,
  http: (req: object) => call<HTTPResult>("POST", "/api/http", req),
  clearCookies: () => call<Cookie[]>("DELETE", "/api/http/cookies"),
  dns: (req: object) => call<DNSResult>("POST", "/api/dns", req),
  trace: (req: object) => call<TraceResult>("POST", "/api/dns/trace", req),
  smtp: (req: object) => call<SMTPResult>("POST", "/api/smtp", req),
  mailcheck: (req: object) => call<MailReport>("POST", "/api/mailcheck", req),
  scan: (req: object) => call<{ job: string; total: number }>("POST", "/api/scan", req),
  stopScan: (job: string) => call<unknown>("POST", `/api/scan/${job}/stop`),
  servers: () => call<ServersState>("GET", "/api/servers"),
  startServer: (kind: "smtp" | "dns", port?: number) => call<ServersState>("POST", `/api/servers/${kind}/start`, { port }),
  stopServer: (kind: "smtp" | "dns") => call<ServersState>("POST", `/api/servers/${kind}/stop`),
  setZone: (zone: string) => call<ServersState>("PUT", "/api/servers/dns/zone", { zone }),
  inbox: () => call<MailItem[]>("GET", "/api/servers/inbox"),
  message: (id: number) => call<MailItem & { headers: string; body: string }>("GET", `/api/servers/inbox/${id}`),
  clearInbox: () => call<unknown>("DELETE", "/api/servers/inbox"),
  llmStatus: () => call<LLMStatus>("GET", "/api/llm/status"),
  startOllama: () => call<unknown>("POST", "/api/llm/start-ollama"),
  settings: (apiKey: string) => call<{ key_set: boolean }>("POST", "/api/settings", { api_key: apiKey }),
};

export function b64ToBytes(b64: string): Uint8Array {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function formatBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / 1024 / 1024).toFixed(2)} MB`;
}

export function formatMs(ms: number): string {
  return ms < 10 ? `${ms.toFixed(1)} ms` : ms < 1000 ? `${Math.round(ms)} ms` : `${(ms / 1000).toFixed(2)} s`;
}

/** Remember form inputs per view; storage can be unavailable, so never throw. */
export function remember<T>(key: string, fallback: T): T {
  try {
    const raw = localStorage.getItem(`pt:${key}`);
    return raw ? { ...fallback, ...JSON.parse(raw) } : fallback;
  } catch {
    return fallback;
  }
}

export function persist(key: string, value: unknown): void {
  try {
    localStorage.setItem(`pt:${key}`, JSON.stringify(value));
  } catch {
    /* private mode or storage disabled: inputs just won't be remembered */
  }
}
