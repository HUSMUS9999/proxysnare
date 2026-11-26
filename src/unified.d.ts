import type * as http from "node:http";
import type { NormalizedProxySnareMode, ProxySnareBootChallenge, ProxySnareEngine } from "./detector.js";
import type { ProxySnareMiddleware, ProxySnareRequest, ProxySnareServerOptions } from "./middleware.js";

export interface UnifiedShieldOptions extends Omit<ProxySnareServerOptions, "verifyBrowserIntegrity" | "requireVeilBreak"> {
  veilbreak?: unknown;
  veilbreakBasePath?: string;
  veilbreakOptions?: Record<string, unknown>;
  antiCdp?: boolean;
  allowDevTools?: boolean;
  autoBlockPage?: boolean;
  enablePlayground?: boolean;
  enableVeilBreakTickets?: boolean;
  onVeilBreakDetect?: (event: unknown) => void;
}

export interface UnifiedMiddleware {
  (req: ProxySnareRequest, res: http.ServerResponse, next?: (err?: unknown) => void): Promise<boolean>;
  engine: ProxySnareEngine;
  proxysnare: ProxySnareMiddleware;
  veilbreak: unknown;
  mode: NormalizedProxySnareMode;
  guardSri: string;
  guardVersion: string;
  guardHash: string;
  gateSri: string;
  gateVersion: string;
  captureRawBody(req: ProxySnareRequest, res: http.ServerResponse, buf: Buffer): void;
  headTags(boot?: ProxySnareBootChallenge | null): string;
}

export interface UnifiedShieldServer {
  server: http.Server;
  engine: ProxySnareEngine;
  middleware: ProxySnareMiddleware;
  veilbreak: unknown;
  mode: NormalizedProxySnareMode;
  guardSri: string;
  guardVersion: string;
  guardHash: string;
  gateSri: string;
  gateVersion: string;
  listen(port?: number, host?: string): Promise<string>;
  close(): Promise<void>;
}

export function createUnifiedMiddleware(options?: Omit<UnifiedShieldOptions, "target" | "injectGuard" | "sriOnPublicCache" | "maxHtmlBytes" | "upstreamTimeoutMs">): UnifiedMiddleware;
export function createUnifiedShield(options?: UnifiedShieldOptions): UnifiedShieldServer;
