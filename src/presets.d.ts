export type ProxySnareMode = "off" | "monitor" | "observe" | "balanced" | "strict" | "paranoid";
export type NormalizedProxySnareMode = "off" | "monitor" | "balanced" | "strict" | "paranoid";

export interface ProxySnarePreset {
  readonly mode: NormalizedProxySnareMode;
  readonly threshold: number;
  readonly freshnessMs: number;
  readonly handshakePowBits: number;
  readonly bindIp: boolean;
  readonly blockAiCrawlers: boolean;
  readonly blockConsoleEval: boolean;
  readonly blockCdpActive: boolean;
  readonly allowDevTools: boolean;
  readonly requireUserGestureOnMutate: boolean;
  readonly requireSignedContext: boolean;
  readonly requireGuardIntegrity: boolean;
  readonly ecdsaHandshakeAuth: boolean;
  readonly sri: boolean;
  readonly userGestureWindowMs: number;
}

export const VALID_MODES: ReadonlySet<ProxySnareMode>;
export const SECURITY_PRESETS: Readonly<Record<NormalizedProxySnareMode, Readonly<ProxySnarePreset>>>;
export function normalizeMode(mode?: ProxySnareMode | (string & {})): NormalizedProxySnareMode;
export function resolvePreset(
  mode?: ProxySnareMode | (string & {}),
  overrides?: Partial<Omit<ProxySnarePreset, "mode" | "threshold" | "freshnessMs" | "handshakePowBits">>
): ProxySnarePreset;
