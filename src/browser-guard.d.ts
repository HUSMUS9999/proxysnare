import type { ProxySnareBootChallenge, ProxySnareMode } from "./detector.js";

export interface BuildBrowserGuardOptions {
  basePath?: string;
  mode?: ProxySnareMode;
  protectedPaths?: Array<string | RegExp | { regex: string; flags: string }>;
  protectedRules?: Array<string | RegExp | { regex: string; flags: string }> | null;
  initialBoot?: ProxySnareBootChallenge | null;
  serverVerifyPubB64?: string;
  userGestureWindowMs?: number;
  requireVeilBreak?: boolean;
  allowDevTools?: boolean;
  blockCdpActive?: boolean;
  blockConsoleEval?: boolean;
  collectConsoleEvalTelemetry?: boolean;
  requireGuardIntegrity?: boolean;
  failClosedOnTamper?: boolean;
  embeddedVeilBreakScript?: string;
}

export interface GuardIntegrityDigests {
  sri: string;
  guardHash: string;
  version: string;
}

export function buildBrowserGuardScript(options?: BuildBrowserGuardOptions): string;
export function computeGuardIntegrity(scriptSource: string): GuardIntegrityDigests;
