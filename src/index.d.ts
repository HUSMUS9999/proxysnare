import type * as http from "node:http";

export type ProxySnareMode = "off" | "monitor" | "observe" | "balanced" | "strict";
export type NormalizedProxySnareMode = "off" | "monitor" | "balanced" | "strict";

export interface ProxySnareReason {
  code: string;
  weight: number;
  detail: string;
}

export interface ProxySnareVerdict {
  ok: boolean;
  blocked: boolean;
  score: number;
  threshold: number;
  mode: NormalizedProxySnareMode;
  reasons: ProxySnareReason[];
  nextCanary: string | null;
}

export interface ProxySnareEngineOptions {
  mode?: ProxySnareMode;
  secret?: Buffer | string;
  threshold?: number;
  freshnessMs?: number;
  nonceTtlMs?: number;
  sessionTtlMs?: number;
  maxSessions?: number;
  maxNonces?: number;
  maxHandshakesPerMin?: number;
  protectedPaths?: Array<string | RegExp>;
  trustProxy?: string | string[];
  onDetect?: (event: ProxySnareVerdict & { ip: string; method: string; path: string; sessionId: string | null }) => void;
}

export interface ProxySnareSession {
  sessionId: string;
  sessionKeyHex: string;
  canary: string;
  freshnessMs: number;
  serverNowMs: number;
  protectedPaths: string[];
  protectedRules: Array<string | { regex: string; flags: string }>;
}

export interface ProxySnareEngine {
  mode: NormalizedProxySnareMode;
  threshold: number;
  freshnessMs: number;
  protectedPaths: Array<string | RegExp>;
  isPathProtected(pathname: string): boolean;
  allowHandshake(ip: string, now?: number): boolean;
  issueSession(opts?: { ip?: string; userAgent?: string; origin?: string }): ProxySnareSession | null;
  signRequest(opts: {
    sessionKeyHex: string;
    method: string;
    pathWithQuery: string;
    body?: Buffer | string;
    seq: number | string;
    ts: number | string;
    nonce: string;
    canary: string;
  }): string;
  inspectRequest(opts: {
    method?: string;
    url?: string;
    headers?: Record<string, string | string[] | undefined>;
    body?: Buffer | string;
    ip?: string;
    now?: number;
    rawHeaderLines?: string[] | null;
  }): ProxySnareVerdict;
  serializeProtectedPathsForClient(): Array<string | { regex: string; flags: string }>;
  extractClientIp(req: { socket?: { remoteAddress?: string }; ip?: string; headers?: Record<string, string | string[] | undefined> }): string;
}

export interface ProxySnareMiddlewareOptions extends ProxySnareEngineOptions {
  basePath?: string;
  exposeDebugHeaders?: boolean;
  maxBodyBytes?: number;
}

export interface ProxySnareServerOptions extends ProxySnareMiddlewareOptions {
  target?: string;
  injectGuard?: boolean;
  maxHtmlBytes?: number;
  upstreamTimeoutMs?: number;
}

export interface ProxySnareMiddleware {
  (req: http.IncomingMessage, res: http.ServerResponse, next?: (err?: unknown) => void): Promise<boolean>;
  engine: ProxySnareEngine;
}

export interface ProxySnareServer {
  server: http.Server;
  engine: ProxySnareEngine;
  listen(port?: number, host?: string): Promise<string>;
  close(): Promise<void>;
}

export function normalizeMode(mode?: string): NormalizedProxySnareMode;
export function normalizePathname(rawUrl: string): string;
export function sha256Hex(input: Buffer | string): string;
export function hmacSha256Hex(keyBuf: Buffer | string, data: Buffer | string): string;
export function createProxySnareEngine(options?: ProxySnareEngineOptions): ProxySnareEngine;
export function createProxySnareMiddleware(options?: ProxySnareMiddlewareOptions): ProxySnareMiddleware;
export function createProxySnareServer(options?: ProxySnareServerOptions): ProxySnareServer;
export function buildBrowserGuardScript(options?: { basePath?: string; protectedRules?: Array<string | { regex: string; flags: string }> }): string;
export function compileNaturalLanguage(prompt: string): { intent: string; options: Record<string, unknown>; summary: string };
