import type * as crypto from "node:crypto";
import type { NormalizedProxySnareMode, ProxySnareMode, ProxySnarePreset } from "./presets.js";
export type { NormalizedProxySnareMode, ProxySnareMode, ProxySnarePreset } from "./presets.js";

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
  canaryAck: string | null;
  rehandshakeRecommended: boolean;
  redirectGetHint?: boolean;
}

export interface ProxySnareSessionSnapshot {
  sessionId: string;
  keyB64: string;
  lastSeq: number;
  canary: string;
  ua?: string;
  uaHash: string;
  ip: string;
  origin: string;
  exp: number;
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
  signingKeyPair?: { privateKey: crypto.KeyObject | Buffer | string; publicKey?: crypto.KeyObject | Buffer | string };
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
  blockAiCrawlers?: boolean;
  blockConsoleEval?: boolean;
  blockCdpActive?: boolean;
  allowDevTools?: boolean;
  blockAutomationOnAllRoutes?: boolean;
  requireUserGestureOnMutate?: boolean;
  gestureExemptPaths?: Array<string | RegExp>;
  gestureProtectedPaths?: Array<string | RegExp>;
  requireSignedContext?: boolean;
  requireGuardIntegrity?: boolean;
  ecdsaHandshakeAuth?: boolean;
  sri?: boolean;
  userGestureWindowMs?: number;
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
  serverSigB64?: string;
  canary: string;
  freshnessMs: number;
  serverNowMs: number;
  protectedPaths: string[];
  protectedRules: Array<string | { regex: string; flags: string }>;
}

export type ProxySnareSession = ProxySnareLocalSession | ProxySnareEcdhSession | { error: string };

export interface ProxySnareEngine {
  mode: NormalizedProxySnareMode;
  preset: ProxySnarePreset;
  threshold: number;
  freshnessMs: number;
  handshakePowBits: number;
  requireBootToken: boolean;
  bindIp: boolean;
  blockAiCrawlers: boolean;
  blockConsoleEval: boolean;
  blockCdpActive: boolean;
  allowDevTools: boolean;
  blockAutomationOnAllRoutes: boolean;
  requireUserGestureOnMutate: boolean;
  requireSignedContext: boolean;
  requireGuardIntegrity: boolean;
  ecdsaHandshakeAuth: boolean;
  sri: boolean;
  hasPersistentSecret: boolean;
  sessionTtlMs: number;
  nonceTtlMs: number;
  bootTokenTtlMs: number;
  userGestureWindowMs: number;
  serverVerifyPubB64: string;
  protectedPaths: Array<string | RegExp>;
  trustedProxies: ProxySnareTrustedProxies;
  isPathProtected(pathname: string): boolean;
  allowHandshake(ip: string, now?: number): boolean;
  allowBoot(ip: string, now?: number): boolean;
  allowHtmlBoot(ip: string, now?: number): boolean;
  issueBootChallenge(opts?: { ip?: string; userAgent?: string }): ProxySnareBootChallenge | null;
  consumeBootChallenge(opts?: {
    bootToken?: string;
    powNonce?: string;
    ip?: string;
    userAgent?: string;
  }): { ok: boolean; error?: string; tokenId?: string; challenge?: string; difficulty?: number };
  issueSession(opts?: {
    ip?: string;
    userAgent?: string;
    origin?: string;
    clientPubB64?: string | null;
    bootToken?: string;
    hsBind?: string;
  }): ProxySnareSession | null;
  verifyHandshakeSignature(opts: {
    sessionId: string;
    clientPubB64: string;
    serverPubB64: string;
    saltB64: string;
    bootToken?: string | undefined;
    serverNowMs?: number | string | undefined;
    canary: string;
    hsBind?: string | undefined;
    serverSigB64?: string | undefined;
  }): boolean;
  signRequest(opts: {
    sessionKeyHex: string;
    method: string;
    pathWithQuery: string;
    body?: Buffer | string;
    seq: number | string;
    ts: number | string;
    nonce: string;
    canary: string;
    ctx?: string;
  }): string;
  inspectRequest(opts: {
    method?: string;
    url?: string;
    headers?: Record<string, string | string[] | undefined>;
    body?: Buffer | string;
    ip?: string;
    now?: number;
    rawHeaderLines?: string[] | null;
    rawHeaderNames?: string[] | null;
    rawHeaders?: string[] | null;
    fromTrustedProxy?: boolean;
    precheckedProtected?: boolean | null;
    precomputedOverrideProtected?: boolean | null;
    precomputedPathname?: string | null;
  }): ProxySnareVerdict;
  hasActiveSession(sid: string, now?: number): boolean;
  exportSessionRecord(sid: string): ProxySnareSessionSnapshot | null;
  importSessionRecord(snap: ProxySnareSessionSnapshot): boolean;
  serializeProtectedPathsForClient(): Array<string | { regex: string; flags: string }>;
  extractClientIp(
    req: { socket?: { remoteAddress?: string }; ip?: string; app?: { get?(k: string): unknown }; headers?: Record<string, string | string[] | undefined> },
    expressTrustsProxy?: boolean | null,
    precheckedTrustedProxy?: boolean | null
  ): string;
}

export const PROXY_LEAK_HEADERS: readonly string[];
export { normalizeMode, resolvePreset } from "./presets.js";
export function normalizePathname(rawUrl: string): string;
export function stripSchemeAndAuthority(rawUrl: string): string;
export function normalizeHostDefaultPort(hostRaw: string, protocol?: string): string;
export function parseHttpOriginHost(originRaw: string): string;
export function isCliOrProxyUa(ua: string, secChUa?: string): boolean;
export function isAiCrawlerRequest(headers?: Record<string, string | string[] | undefined>): boolean;
export function verifyPowSolution(prefix: string, challenge: string, powNonce: string, difficulty: number): boolean;
export function solvePowChallenge(prefix: string, challenge: string, difficulty: number): string;
export function sha256Hex(input: Buffer | string): string;
export function safeEqualHex(a: string, b: string): boolean;
export function hmacSha256Hex(keyBuf: Buffer | string, data: Buffer | string): string;
export function createProxySnareEngine(options?: ProxySnareEngineOptions): ProxySnareEngine;
