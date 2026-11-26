"use strict";

const path = require("node:path");
const { normalizePathname } = require("./detector.js");
const { createProxySnareMiddleware, createProxySnareServer, injectGuardIntoHtml, stripScriptBySrc } = require("./middleware.js");

function escapeHtmlAttr(s) {
  return String(s).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function loadVeilBreakModule(customMod) {
  if (customMod && typeof customMod.createVeilBreakMiddleware === "function") {
    return customMod;
  }
  try {
    return require("veilbreak");
  } catch {
    try {
      return require(path.resolve(__dirname, "../../veilbreak/src/index.js"));
    } catch {
      throw new Error(
        "createUnifiedShield requires the 'veilbreak' package. Install it (`npm i veilbreak`) or pass `{ veilbreak }` explicitly."
      );
    }
  }
}

function initUnifiedParts(options = {}) {
  const vb = loadVeilBreakModule(options.veilbreak);
  const mode = options.mode ?? "strict";
  const protectedPaths =
    Array.isArray(options.protectedPaths) && options.protectedPaths.length > 0
      ? options.protectedPaths
      : ["/api"];
  const vbBasePath = String(options.veilbreakBasePath || "/__veilbreak").replace(/\/+$/, "") || "/__veilbreak";
  const psBasePath = String(options.basePath || "/__proxysnare").replace(/\/+$/, "") || "/__proxysnare";
  const enablePlayground = Boolean(options.enablePlayground);
  // Prioritize explicit blockCdpActive over allowDevTools for VeilBreak (since VeilBreak's allowDevTools solely governs CDP blocking,
  // while ProxySnare's allowDevTools:false + blockCdpActive:false keeps blockConsoleEval:true with passive DevTools allowed!)
  const vbAllowDevTools =
    options.blockCdpActive !== undefined
      ? !Boolean(options.blockCdpActive)
      : (options.allowDevTools !== undefined ? Boolean(options.allowDevTools) : undefined);
  const enableTickets = Boolean(options.enableVeilBreakTickets);
  const vbMiddleware = vb.createVeilBreakMiddleware({
    ...(options.veilbreakOptions || {}),
    mode,
    basePath: vbBasePath,
    protectedPaths,
    trustProxy: options.trustProxy,
    bindIp: options.bindIp,
    // Only forward external store to VeilBreak when standalone VeilBreak /ticket routes are explicitly enabled
    // (unified playground authenticates via /__proxysnare/handshake and does not require VeilBreak ticket deletion primitives).
    ...(enableTickets && options.store ? { store: options.store } : {}),
    exposeDebugHeaders: options.exposeDebugHeaders,
    ...(options.blockAiCrawlers !== undefined ? { blockAiCrawlers: options.blockAiCrawlers } : {}),
    ...(options.antiCdp !== undefined ? { antiCdp: options.antiCdp } : {}),
    ...(vbAllowDevTools !== undefined ? { allowDevTools: vbAllowDevTools } : {}),
    ...(options.autoBlockPage !== undefined ? { autoBlockPage: options.autoBlockPage } : {}),
    ...(options.sri !== undefined ? { sri: options.sri } : {}),
    unified: true,
    includeTicketPow: enableTickets,
    _lazyGateScript: !enableTickets,
    ...(options.userGestureWindowMs !== undefined ? { userGestureWindowMs: options.userGestureWindowMs } : {}),
    // unified.js serves its own single-bundle playground HTML so vbMiddleware does not allocate an unused playgroundHtmlBuf
    enablePlayground: false,
    _allowBlockPageOverridePath: enablePlayground ? `${vbBasePath}/playground` : "",
    ...(options.onVeilBreakDetect !== undefined ? { onDetect: options.onVeilBreakDetect } : {}),
  });

  const vbControlPaths = new Set([
    `${vbBasePath}/gate.js`,
    `${vbBasePath}/health`,
  ]);
  if (enableTickets) {
    vbControlPaths.add(`${vbBasePath}/ticket`);
  }
  if (enablePlayground) {
    vbControlPaths.add(`${vbBasePath}/playground`);
  }

  // Derive ProxySnare DevTools/CDP knobs from final resolved vbMiddleware.preset (honoring veilbreakOptions in BOTH directions!)
  // Disabling antiCdp alone disables ProxySnare blockCdpActive WITHOUT silently disabling blockConsoleEval!
  const explicitVbAllowDt = options.veilbreakOptions && options.veilbreakOptions.allowDevTools !== undefined
    ? Boolean(options.veilbreakOptions.allowDevTools)
    : undefined;
  const effectiveAllowDevTools =
    options.allowDevTools !== undefined
      ? Boolean(options.allowDevTools)
      : (explicitVbAllowDt !== undefined
          ? explicitVbAllowDt
          : (options.blockCdpActive === undefined && vbMiddleware.preset.allowDevTools === true ? true : undefined));
  const effectiveBlockCdp =
    options.blockCdpActive !== undefined
      ? Boolean(options.blockCdpActive)
      : (vbMiddleware.preset.antiCdp === false || effectiveAllowDevTools === true ? false : undefined);

  const embeddedVbScript =
    vbMiddleware.mode !== "off"
      ? (typeof vb.buildBrowserGateScript === "function"
          ? vb.buildBrowserGateScript({
              ...(options.veilbreakOptions || {}),
              basePath: vbBasePath,
              defaultMode: vbMiddleware.mode,
              protectedPaths,
              autoBlockPage: vbMiddleware.preset.autoBlockPage,
              antiCdp: vbMiddleware.preset.antiCdp,
              allowDevTools: vbMiddleware.preset.allowDevTools,
              sri: vbMiddleware.preset.sri,
              unified: true,
              embedded: true,
              _shareBaseRealm: true,
              includeTicketPow: false,
              userGestureWindowMs: options.userGestureWindowMs,
              allowBlockPageOverridePath: enablePlayground ? `${vbBasePath}/playground` : "",
            })
          : vbMiddleware.gateJs)
      : "";

  const sharedPsOptions = {
    ...options,
    mode,
    basePath: psBasePath,
    protectedPaths,
    requireVeilBreak: vbMiddleware.mode !== "off",
    embeddedVeilBreakScript: embeddedVbScript,
    _stripScriptSrc: embeddedVbScript ? `${vbBasePath}/gate.js` : "",
    blockAutomationOnAllRoutes:
      options.blockAutomationOnAllRoutes !== undefined ? Boolean(options.blockAutomationOnAllRoutes) : true,
    ...(effectiveAllowDevTools !== undefined ? { allowDevTools: effectiveAllowDevTools } : {}),
    ...(effectiveBlockCdp !== undefined ? { blockCdpActive: effectiveBlockCdp } : {}),
    verifyBrowserIntegrity: ({ headers, challenge, browserProof }) =>
      vbMiddleware.verifyHandshakeProof({
        headers,
        proof: browserProof,
        expectedChallenge: challenge,
        skipHeaderChecks: vbMiddleware.mode !== "monitor",
        _headersPrevalidated: vbMiddleware.mode !== "monitor",
      }),
  };

  let unifiedPlaygroundBuf = null;
  const vbPrefixSlash = `${vbBasePath}/`;
  const handleVbControl = (req, res, next, psRef = null) => {
    if (req.method === "GET" || req.method === "HEAD" || (enableTickets && req.method === "POST")) {
      const rawUrl = String(req.originalUrl || req.url || "/");
      const qIdx = rawUrl.indexOf("?");
      const rawPathOnly = qIdx >= 0 ? rawUrl.slice(0, qIdx) : rawUrl;
      // Zero-alloc fast-path: clean paths without normalization hazards can only match vbControlPaths if prefixed by vbBasePath/
      if (
        !rawPathOnly.startsWith(vbPrefixSlash) &&
        !rawPathOnly.includes("%") &&
        !rawPathOnly.includes("..") &&
        !rawPathOnly.includes("\\") &&
        !rawPathOnly.includes("//") &&
        !rawPathOnly.includes("/.") &&
        !rawPathOnly.includes(";")
      ) {
        return false;
      }
      const pathname = normalizePathname(rawUrl);
      if (enablePlayground && (req.method === "GET" || req.method === "HEAD") && pathname === `${vbBasePath}/playground` && psRef) {
        if (!unifiedPlaygroundBuf && typeof vb.buildPlaygroundHtml === "function") {
          const baseHtml = vb.buildPlaygroundHtml({
            basePath: vbBasePath,
            mode: vbMiddleware.mode,
            antiCdp: vbMiddleware.preset.antiCdp,
          });
          // Strip standalone gate.js tag ONLY when embeddedVbScript is active (mode !== "off"), so mode:"off" playground renders cleanly!
          const strippedHtml = embeddedVbScript ? stripScriptBySrc(baseHtml, `${vbBasePath}/gate.js`) : baseHtml;
          const withGuard = injectGuardIntoHtml(strippedHtml, psBasePath, {
            sri: psRef.engine.sri ? psRef.guardSri : "",
            version: psRef.engine.sri ? psRef.guardVersion : "",
            requireVeilBreak: vbMiddleware.mode !== "off",
            unifiedBundle: Boolean(embeddedVbScript),
            blockPage: false,
          });
          unifiedPlaygroundBuf = Buffer.from(withGuard, "utf8");
        }
        if (unifiedPlaygroundBuf) {
          res.writeHead(200, {
            "Content-Type": "text/html; charset=utf-8",
            "Cache-Control": "no-store",
            "Content-Length": unifiedPlaygroundBuf.length,
          });
          if (req.method === "HEAD") res.end();
          else res.end(unifiedPlaygroundBuf);
          return true;
        }
      }
      if (
        vbControlPaths.has(pathname) &&
        (req.method === "GET" ||
          (req.method === "HEAD" && pathname !== `${vbBasePath}/ticket`) ||
          (req.method === "POST" && pathname === `${vbBasePath}/ticket`))
      ) {
        return vbMiddleware(req, res, next);
      }
      // Cache normalized pathname in psRef's WeakMap so psMiddleware never normalizes this URL twice (zero IncomingMessage mutation!)
      if (psRef && typeof psRef._setPrePath === "function") psRef._setPrePath(req, pathname);
    }
    return false;
  };

  return { vbBasePath, psBasePath, vbMiddleware, sharedPsOptions, handleVbControl };
}

/**
 * Combined ProxySnare + VeilBreak Express/Connect/raw-Node middleware.
 */
function createUnifiedMiddleware(options = {}) {
  const { psBasePath, vbMiddleware, sharedPsOptions, handleVbControl } = initUnifiedParts(options);
  const psMiddleware = createProxySnareMiddleware(sharedPsOptions);

  function handle(req, res, next) {
    const vbRes = handleVbControl(req, res, next, psMiddleware);
    if (vbRes) return Promise.resolve(vbRes);
    return psMiddleware(req, res, next);
  }

  handle.engine = psMiddleware.engine;
  handle.proxysnare = psMiddleware;
  handle.veilbreak = vbMiddleware;
  handle.mode = psMiddleware.engine.mode;
  handle.guardSri = psMiddleware.guardSri;
  handle.guardVersion = psMiddleware.guardVersion;
  handle.guardHash = psMiddleware.guardHash;
  Object.defineProperties(handle, {
    gateSri: { enumerable: true, get: () => vbMiddleware.gateSri },
    gateVersion: { enumerable: true, get: () => vbMiddleware.gateVersion },
  });
  handle.captureRawBody = psMiddleware.captureRawBody;
  handle.headTags = (boot = null) => {
    const baseGuardSrc = `${psBasePath}/guard.js`;
    const guardWithVer = psMiddleware.engine.sri && psMiddleware.guardVersion
      ? `${baseGuardSrc}?v=${encodeURIComponent(psMiddleware.guardVersion)}`
      : baseGuardSrc;
    const safeGuardSrc = escapeHtmlAttr(guardWithVer);
    const sriAttr = psMiddleware.engine.sri && psMiddleware.guardSri
      ? ` integrity="${escapeHtmlAttr(psMiddleware.guardSri)}"`
      : "";
    const bootAttr = boot
      ? ` data-ps-boot="${escapeHtmlAttr(Buffer.from(JSON.stringify(boot), "utf8").toString("base64url"))}"`
      : "";
    const vbReqAttr = vbMiddleware.mode !== "off" ? ' data-require-vb="true" data-unified-bundle="true"' : "";
    return `<script src="${safeGuardSrc}"${sriAttr}${bootAttr}${vbReqAttr}></script>`;
  };
  return handle;
}

/**
 * Unified single-pass reverse-proxy shield combining ProxySnare + VeilBreak.
 * Serves ONE SRI-pinned combined bundle (`/__proxysnare/guard.js`) so VeilBreak & ProxySnare
 * communicate exclusively over a private lexical closure (unreachable from window / Symbol.for / MutationObserver).
 */
function createUnifiedShield(options = {}) {
  const { vbMiddleware, sharedPsOptions, handleVbControl } = initUnifiedParts(options);
  let shieldRef = null;
  const shield = createProxySnareServer({
    ...sharedPsOptions,
    // Synchronous fast-path: returns false directly (zero Promise allocation) for 99.9% of requests
    _preMiddleware: (req, res) => handleVbControl(req, res, undefined, shieldRef ? shieldRef.middleware : null),
  });
  shieldRef = shield;

  const out = {
    ...shield,
    veilbreak: vbMiddleware,
    mode: shield.engine.mode,
  };
  Object.defineProperties(out, {
    gateSri: { enumerable: true, get: () => vbMiddleware.gateSri },
    gateVersion: { enumerable: true, get: () => vbMiddleware.gateVersion },
  });
  return out;
}

module.exports = {
  createUnifiedMiddleware,
  createUnifiedShield,
};
