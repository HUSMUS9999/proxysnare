"use strict";

const VALID_MODES = new Set(["off", "monitor", "observe", "balanced", "strict", "paranoid"]);

const SECURITY_PRESETS = Object.freeze({
  off: Object.freeze({
    mode: "off",
    threshold: 6,
    freshnessMs: 15_000,
    handshakePowBits: 0,
    bindIp: false,
    blockAiCrawlers: false,
    blockConsoleEval: false,
    blockCdpActive: false,
    allowDevTools: true,
    requireUserGestureOnMutate: false,
    requireSignedContext: false,
    requireGuardIntegrity: false,
    ecdsaHandshakeAuth: false,
    sri: false,
    userGestureWindowMs: 15_000,
  }),
  monitor: Object.freeze({
    mode: "monitor",
    threshold: 6,
    freshnessMs: 15_000,
    handshakePowBits: 0,
    bindIp: false,
    blockAiCrawlers: true,
    blockConsoleEval: false,
    blockCdpActive: false,
    allowDevTools: true,
    requireUserGestureOnMutate: false,
    requireSignedContext: false,
    requireGuardIntegrity: false,
    ecdsaHandshakeAuth: true,
    sri: true,
    userGestureWindowMs: 15_000,
  }),
  balanced: Object.freeze({
    mode: "balanced",
    threshold: 6,
    freshnessMs: 15_000,
    handshakePowBits: 10,
    bindIp: false,
    blockAiCrawlers: true,
    blockConsoleEval: false,
    blockCdpActive: false,
    allowDevTools: true,
    requireUserGestureOnMutate: false,
    requireSignedContext: false,
    requireGuardIntegrity: false,
    ecdsaHandshakeAuth: true,
    sri: true,
    userGestureWindowMs: 15_000,
  }),
  strict: Object.freeze({
    mode: "strict",
    threshold: 4,
    freshnessMs: 8_000,
    handshakePowBits: 12,
    bindIp: true,
    blockAiCrawlers: true,
    blockConsoleEval: true,
    blockCdpActive: true,
    allowDevTools: false,
    requireUserGestureOnMutate: false,
    requireSignedContext: false,
    requireGuardIntegrity: true,
    ecdsaHandshakeAuth: true,
    sri: true,
    userGestureWindowMs: 15_000,
  }),
  paranoid: Object.freeze({
    mode: "paranoid",
    threshold: 4,
    freshnessMs: 5_000,
    handshakePowBits: 14,
    bindIp: true,
    blockAiCrawlers: true,
    blockConsoleEval: true,
    blockCdpActive: true,
    allowDevTools: false,
    requireUserGestureOnMutate: true,
    requireSignedContext: true,
    requireGuardIntegrity: true,
    ecdsaHandshakeAuth: true,
    sri: true,
    userGestureWindowMs: 15_000,
  }),
});

function normalizeMode(mode = "strict") {
  const raw = String(mode ?? "strict").trim().toLowerCase();
  if (!VALID_MODES.has(raw)) {
    throw new Error(
      `Invalid ProxySnare mode '${mode}': expected 'off', 'monitor', 'observe', 'balanced', 'strict', or 'paranoid'`
    );
  }
  return raw === "observe" ? "monitor" : raw;
}

function resolvePreset(mode = "strict", overrides = {}) {
  const norm = normalizeMode(mode);
  const base = SECURITY_PRESETS[norm];
  const explicitBlockCdp = overrides.blockCdpActive !== undefined;
  const explicitBlockCe = overrides.blockConsoleEval !== undefined;
  const allowDevTools =
    overrides.allowDevTools !== undefined
      ? Boolean(overrides.allowDevTools)
      : (explicitBlockCdp && Boolean(overrides.blockCdpActive)
          ? false
          : base.allowDevTools);
  const blockCdpActive = explicitBlockCdp
    ? Boolean(overrides.blockCdpActive)
    : (allowDevTools || norm === "off" || norm === "monitor" ? false : true);
  const blockConsoleEval = explicitBlockCe
    ? Boolean(overrides.blockConsoleEval)
    : (allowDevTools ? false : base.blockConsoleEval);
  return {
    ...base,
    bindIp: overrides.bindIp !== undefined ? Boolean(overrides.bindIp) : base.bindIp,
    blockAiCrawlers:
      overrides.blockAiCrawlers !== undefined ? Boolean(overrides.blockAiCrawlers) : base.blockAiCrawlers,
    blockConsoleEval,
    blockCdpActive,
    allowDevTools,
    requireUserGestureOnMutate:
      overrides.requireUserGestureOnMutate !== undefined
        ? Boolean(overrides.requireUserGestureOnMutate)
        : base.requireUserGestureOnMutate,
    requireSignedContext:
      overrides.requireSignedContext !== undefined
        ? Boolean(overrides.requireSignedContext)
        : base.requireSignedContext,
    requireGuardIntegrity:
      overrides.requireGuardIntegrity !== undefined
        ? Boolean(overrides.requireGuardIntegrity)
        : base.requireGuardIntegrity,
    ecdsaHandshakeAuth:
      overrides.ecdsaHandshakeAuth !== undefined
        ? Boolean(overrides.ecdsaHandshakeAuth)
        : base.ecdsaHandshakeAuth,
    sri: overrides.sri !== undefined ? Boolean(overrides.sri) : base.sri,
    userGestureWindowMs:
      Number.isFinite(overrides.userGestureWindowMs) && overrides.userGestureWindowMs > 0
        ? overrides.userGestureWindowMs
        : base.userGestureWindowMs,
  };
}

module.exports = {
  VALID_MODES,
  SECURITY_PRESETS,
  normalizeMode,
  resolvePreset,
};
