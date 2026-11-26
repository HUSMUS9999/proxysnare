"use strict";

const { SECURITY_PRESETS, VALID_MODES, resolvePreset } = require("./presets.js");
const {
  PROXY_LEAK_HEADERS,
  createProxySnareEngine,
  normalizeMode,
  normalizePathname,
  stripSchemeAndAuthority,
  normalizeHostDefaultPort,
  parseHttpOriginHost,
  isCliOrProxyUa,
  isAiCrawlerRequest,
  verifyPowSolution,
  solvePowChallenge,
  sha256Hex,
  safeEqualHex,
  hmacSha256Hex,
} = require("./detector.js");
const { buildBrowserGuardScript, computeGuardIntegrity } = require("./browser-guard.js");
const { createProxySnareMiddleware, createProxySnareServer, injectGuardIntoHtml } = require("./middleware.js");
const { createUnifiedMiddleware, createUnifiedShield } = require("./unified.js");
const { compileNaturalLanguage } = require("./nl.js");

module.exports = {
  PROXY_LEAK_HEADERS,
  SECURITY_PRESETS,
  VALID_MODES,
  resolvePreset,
  createProxySnareEngine,
  createProxySnareMiddleware,
  createProxySnareServer,
  createUnifiedMiddleware,
  createUnifiedShield,
  buildBrowserGuardScript,
  computeGuardIntegrity,
  injectGuardIntoHtml,
  compileNaturalLanguage,
  normalizeMode,
  normalizePathname,
  stripSchemeAndAuthority,
  normalizeHostDefaultPort,
  parseHttpOriginHost,
  isCliOrProxyUa,
  isAiCrawlerRequest,
  verifyPowSolution,
  solvePowChallenge,
  sha256Hex,
  safeEqualHex,
  hmacSha256Hex,
};
