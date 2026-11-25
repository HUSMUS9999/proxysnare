import type { ProxySnareBootChallenge } from "./detector.js";

export interface BuildBrowserGuardOptions {
  basePath?: string;
  protectedPaths?: Array<string | RegExp | { regex: string; flags: string }>;
  protectedRules?: Array<string | RegExp | { regex: string; flags: string }> | null;
  initialBoot?: ProxySnareBootChallenge | null;
}

export function buildBrowserGuardScript(options?: BuildBrowserGuardOptions): string;
