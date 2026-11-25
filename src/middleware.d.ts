import type * as http from "node:http";
import type { ProxySnareEngine, ProxySnareEngineOptions, ProxySnareVerdict } from "./detector.js";

export interface ProxySnareRequest extends http.IncomingMessage {
  rawBody?: Buffer;
  body?: unknown;
  _body?: boolean;
  originalUrl?: string;
  proxySnareBody?: Buffer;
  proxySnare?: ProxySnareVerdict;
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
  (req: ProxySnareRequest, res: http.ServerResponse, next?: (err?: unknown) => void): Promise<boolean>;
  engine: ProxySnareEngine;
}

export interface ProxySnareServer {
  server: http.Server;
  engine: ProxySnareEngine;
  listen(port?: number, host?: string): Promise<string>;
  close(): Promise<void>;
}

export function createProxySnareMiddleware(options?: ProxySnareMiddlewareOptions): ProxySnareMiddleware;
export function createProxySnareServer(options?: ProxySnareServerOptions): ProxySnareServer;
