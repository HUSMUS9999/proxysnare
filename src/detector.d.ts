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
  rehandshakeRecommended: boolean;
}

export interface ProxySnareTrustedProxies {
  size: number;
  has(ip: string): boolean;
}

export interface ProxySnareBootChallenge {
  bootToken: string;
  challenge: string;
  difficulty: number;
  exp: number;
}

export interface ProxySnareEngineOptions {
  mode?: ProxySnareMode;
  secret?: Buffer | string;
  threshold?: number;
  freshnessMs?: number;
  nonceTtlMs?: number;
  sessionTtlMs?: number;
  bootTokenTtlMs?: number;
  maxSessions?: number;
  maxNonces?: number;
  maxBootTokens?: number;
  maxHandshakesPerMin?: number;
  handshakePowBits?: number;
  requireBootToken?: boolean;
  bindIp?: boolean;
  protectedPaths?: Array<string | RegExp>;
  trustProxy?: string | string[];
  onDetect?: (event: ProxySnareVerdict & { ip: string; method: string; path: string; sessionId: string | null }) => void;
}

export interface ProxySnareLocalSession {
  protocol: "PS_LOCAL_V1";
  sessionId: string;
  sessionKeyHex: string;
  canary: string;
  freshnessMs: number;
  serverNowMs: number;
  protectedPaths: string[];
  protectedRules: Array<string | { regex: string; flags: string }>;
}

export interface ProxySnareEcdhSession {
  protocol: "PS_ECDH_V2";
  sessionId: string;
  serverPubB64: string;
  saltB64: string;
  canary: string;
  freshnessMs: number;
  serverNowMs: number;
  protectedPaths: string[];
  protectedRules: Array<string | { regex: string; flags: string }>;
}

export type ProxySnareSession = ProxySnareLocalSession | ProxySnareEcdhSession | { error: string };

export interface ProxySnareEngine {
  mode: NormalizedProxySnareMode;
  threshold: number;
  freshnessMs: number;
  handshakePowBits: number;
  requireBootToken: boolean;
  bindIp: boolean;
  protectedPaths: Array<string | RegExp>;
  trustedProxies: ProxySnareTrustedProxies;
  isPathProtected(pathname: string): boolean;
  allowHandshake(ip: string, now?: number): boolean;
  issueBootChallenge(opts?: { ip?: string; userAgent?: string }): ProxySnareBootChallenge | null;
  consumeBootChallenge(opts?: { bootToken?: string; powNonce?: string; ip?: string; userAgent?: string }): { ok: boolean; error?: string };
  issueSession(opts?: { ip?: string; userAgent?: string; origin?: string; clientPubB64?: string | null }): ProxySnareSession | null;
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
    fromTrustedProxy?: boolean;
  }): ProxySnareVerdict;
  serializeProtectedPathsForClient(): Array<string | { regex: string; flags: string }>;
  extractClientIp(req: { socket?: { remoteAddress?: string }; ip?: string; headers?: Record<string, string | string[] | undefined> }): string;
}

export function normalizeMode(mode?: ProxySnareMode | (string & {})): NormalizedProxySnareMode;
export function normalizePathname(rawUrl: string): string;
export function stripSchemeAndAuthority(rawUrl: string): string;
export function isCliOrProxyUa(ua: string, secChUa?: string): boolean;
export function verifyPowSolution(prefix: string, challenge: string, powNonce: string, difficulty: number): boolean;
export function solvePowChallenge(prefix: string, challenge: string, difficulty: number): string;
export function sha256Hex(input: Buffer | string): string;
export function hmacSha256Hex(keyBuf: Buffer | string, data: Buffer | string): string;
export function createProxySnareEngine(options?: ProxySnareEngineOptions): ProxySnareEngine;
