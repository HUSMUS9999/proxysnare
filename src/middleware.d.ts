import type * as http from "node:http";
import type { NormalizedProxySnareMode, ProxySnareBootChallenge, ProxySnareEngine, ProxySnareEngineOptions, ProxySnareVerdict } from "./detector.js";

export interface ProxySnareRequest extends http.IncomingMessage {
  rawBody?: Buffer;
  body?: unknown;
  _body?: boolean;
  originalUrl?: string;
  proxySnareBody?: Buffer;
  proxySnare?: ProxySnareVerdict;
}

export interface BrowserIntegrityContext {
  req: ProxySnareRequest;
  ip: string;
  userAgent: string;
  headers: http.IncomingHttpHeaders;
  challenge: string;
  bootToken: string;
  browserProof: unknown;
  cdpActive?: boolean;
  mode: NormalizedProxySnareMode;
}

export interface BrowserIntegrityVerdict {
  ok?: boolean;
  blocked?: boolean;
  score?: number;
  reasons?: string[];
}

export interface ProxySnareStore {
  get(key: string): unknown | Promise<unknown>;
  set(key: string, value: unknown, ttlMs?: number): unknown | Promise<unknown>;
  setIfNotExists?(key: string, value: unknown, ttlMs?: number): boolean | Promise<boolean>;
  take?(key: string): unknown | Promise<unknown>;
  delete?(key: string): unknown | Promise<unknown>;
  del?(key: string): unknown | Promise<unknown>;
}

export interface ProxySnareMiddlewareOptions extends ProxySnareEngineOptions {
  basePath?: string;
  exposeDebugHeaders?: boolean;
  maxBodyBytes?: number;
  bodyReadTimeoutMs?: number;
  parseReqBody?: boolean;
  requireVeilBreak?: boolean;
  collectConsoleEvalTelemetry?: boolean;
  embeddedVeilBreakScript?: string;
  store?: ProxySnareStore;
  verifyBrowserIntegrity?: (ctx: BrowserIntegrityContext) => BrowserIntegrityVerdict | Promise<BrowserIntegrityVerdict>;
}

export interface ProxySnareServerOptions extends ProxySnareMiddlewareOptions {
  target?: string;
  injectGuard?: boolean;
  sriOnPublicCache?: boolean;
  maxHtmlBytes?: number;
  upstreamTimeoutMs?: number;
}

export interface ProxySnareMiddleware {
  (req: ProxySnareRequest, res: http.ServerResponse, next?: (err?: unknown) => void): Promise<boolean>;
  engine: ProxySnareEngine;
  basePath: string;
  guardSri: string;
  guardVersion: string;
  guardHash: string;
  captureRawBody(req: ProxySnareRequest, res: http.ServerResponse, buf: Buffer): void;
}

export interface ProxySnareServer {
  server: http.Server;
  engine: ProxySnareEngine;
  middleware: ProxySnareMiddleware;
  guardSri: string;
  guardVersion: string;
  guardHash: string;
  listen(port?: number, host?: string): Promise<string>;
  close(): Promise<void>;
}

export function createProxySnareMiddleware(options?: ProxySnareMiddlewareOptions): ProxySnareMiddleware;
export function createProxySnareServer(options?: ProxySnareServerOptions): ProxySnareServer;
export function injectGuardIntoHtml(
  html: string,
  basePath: string,
  opts?: {
    sri?: string;
    version?: string;
    boot?: ProxySnareBootChallenge | null;
    requireVeilBreak?: boolean;
    unifiedBundle?: boolean;
    blockPage?: boolean;
    prependTags?: string;
    prependSrc?: string;
    bridgeToken?: string;
    stripScriptSrc?: string;
  }
): string;
