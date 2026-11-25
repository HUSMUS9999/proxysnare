"use strict";

const { createProxySnareEngine, normalizeMode, normalizePathname, sha256Hex, hmacSha256Hex } = require("./detector.js");
const { buildBrowserGuardScript } = require("./browser-guard.js");
const { createProxySnareMiddleware, createProxySnareServer } = require("./middleware.js");
const { compileNaturalLanguage } = require("./nl.js");

module.exports = {
  createProxySnareEngine,
  createProxySnareMiddleware,
  createProxySnareServer,
  buildBrowserGuardScript,
  compileNaturalLanguage,
  normalizeMode,
  normalizePathname,
  sha256Hex,
  hmacSha256Hex,
};
