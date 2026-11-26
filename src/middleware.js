"use strict";

const crypto = require("node:crypto");
const http = require("node:http");
const https = require("node:https");
const querystring = require("node:querystring");
const { Readable } = require("node:stream");
const zlib = require("node:zlib");
const {
  PROXY_LEAK_HEADERS,
  createProxySnareEngine,
  normalizePathname,
  CLEAN_ASCII_PATH_RE,
  stripSchemeAndAuthority,
  normalizeHostDefaultPort,
  parseHttpOriginHost,
  parseBrowserMajorChrome,
  parseBrowserMajorFirefox,
  isCliOrProxyUa,
  isAiCrawlerRequest,
  countDuplicateSensitiveHeaders,
  evaluatePreBodyMinScore,
  sha256Hex,
  safeEqualHex,
} = require("./detector.js");
const { buildBrowserGuardScript, computeGuardIntegrity } = require("./browser-guard.js");

const EMPTY_BUF = Buffer.alloc(0);

const HOP_BY_HOP_HEADERS = new Set([
  "connection",
  "keep-alive",
  "proxy-authenticate",
  "proxy-authorization",
  "proxy-connection",
  "te",
  "trailer",
  "trailers",
  "transfer-encoding",
  "upgrade",
]);

const PROTECTED_FROM_CONN_STRIP = new Set([
  "host",
  "authorization",
  "cookie",
  "forwarded",
  "x-forwarded-for",
  "x-forwarded-host",
  "x-forwarded-proto",
  "x-real-ip",
  "cf-connecting-ip",
  "true-client-ip",
]);

const PROXY_HANDSHAKE_LEAK_HEADERS = PROXY_LEAK_HEADERS;

function stripHopByHop(headers, { isRequest = false } = {}) {
  const out = {};
  if (!headers || typeof headers !== "object") return out;
  let connTokens = null;
  const connVal = !isRequest ? headers.connection : undefined;
  if (typeof connVal === "string" && connVal) {
    for (const tok of connVal.split(",")) {
      const t = tok.trim().toLowerCase();
      if (t && !PROTECTED_FROM_CONN_STRIP.has(t) && !t.startsWith("x-auth-") && !t.startsWith("cf-")) {
        if (!connTokens) connTokens = new Set();
        connTokens.add(t);
      }
    }
  }
  for (const k in headers) {
    if (!Object.prototype.hasOwnProperty.call(headers, k)) continue;
    const kl = k.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(kl) || (connTokens && connTokens.has(kl))) continue;
    out[k] = headers[k];
  }
  return out;
}

function escapeHtmlAttr(s) {
  return String(s).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function readRequestBody(req, maxBytes = 1024 * 1024, timeoutMs = 15_000) {
  if (req.readableEnded) {
    return Promise.resolve(Buffer.alloc(0));
  }
  if (req.aborted || (req.destroyed && !req.complete) || req.errored) {
    return Promise.reject(Object.assign(new Error("REQUEST_ABORTED"), { statusCode: 400 }));
  }
  const clRaw = req.headers && req.headers["content-length"];
  if (typeof clRaw === "string" && /^\d+$/.test(clRaw.trim())) {
    const clNum = Number(clRaw.trim());
    if (Number.isFinite(clNum) && clNum > maxBytes) {
      return Promise.reject(Object.assign(new Error("BODY_TOO_LARGE"), { statusCode: 413 }));
    }
  }
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let settled = false;
    let timer = null;

    const finish = (err, val) => {
      if (settled) return;
      settled = true;
      if (timer) {
        clearTimeout(timer);
        timer = null;
      }
      req.removeListener("data", onData);
      req.removeListener("end", onEnd);
      req.removeListener("error", onError);
      req.removeListener("aborted", onAborted);
      req.removeListener("close", onClose);
      if (err) reject(err);
      else resolve(val);
    };

    if (Number.isFinite(timeoutMs) && timeoutMs > 0) {
      timer = setTimeout(() => {
        req.pause();
        finish(Object.assign(new Error("REQUEST_BODY_TIMEOUT"), { statusCode: 408 }));
      }, timeoutMs);
      if (typeof timer.unref === "function") timer.unref();
    }

    const onData = (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        req.pause();
        finish(Object.assign(new Error("BODY_TOO_LARGE"), { statusCode: 413 }));
        return;
      }
      chunks.push(chunk);
    };
    const onEnd = () => finish(null, chunks.length === 0 ? Buffer.alloc(0) : chunks.length === 1 ? chunks[0] : Buffer.concat(chunks, total));
    const onError = (err) => finish(err);
    const onAborted = () => finish(Object.assign(new Error("REQUEST_ABORTED"), { statusCode: 400 }));
    const onClose = () => {
      if (!req.complete) finish(Object.assign(new Error("REQUEST_ABORTED"), { statusCode: 400 }));
    };

    req.on("data", onData);
    req.on("end", onEnd);
    req.on("error", onError);
    req.on("aborted", onAborted);
    req.on("close", onClose);
  });
}

function sendJson(res, status, obj, extraHeaders = {}, isHead = false, req = null) {
  if (res.headersSent || res.writableEnded) return;
  const closeUnread =
    status >= 400 &&
    req &&
    (req.httpVersionMajor === undefined || req.httpVersionMajor < 2) &&
    !req.complete &&
    !req.readableEnded &&
    hasRequestBodyHeader(req.headers);
  const payload = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(payload),
    ...(closeUnread ? { Connection: "close" } : {}),
    ...extraHeaders,
  });
  if (isHead) res.end();
  else res.end(payload);
}

function validateHandshakeClientHeaders(
  req,
  mode,
  { requireScriptDest = false, fromTrustedProxy = undefined, blockAiCrawlers = true } = {}
) {
  const headers = req.headers || {};
  const sfs = String(headers["sec-fetch-site"] || "").trim().toLowerCase();
  const sfm = String(headers["sec-fetch-mode"] || "").trim().toLowerCase();
  const sfd = String(headers["sec-fetch-dest"] || "").trim().toLowerCase();
  const conn = String(headers["connection"] || "").trim().toLowerCase();
  const acceptLang = String(headers["accept-language"] || "").trim();
  const ua = String(headers["user-agent"] || "");
  const secChUa = String(headers["sec-ch-ua"] || "");
  const origin = String(headers["origin"] || "").trim();
  const host = String(headers["host"] || "").trim().toLowerCase();

  const remoteRaw = String(req?.socket?.remoteAddress || req?.ip || "").trim();
  // Respect explicit fromTrustedProxy computed from engine.trustedProxies allowlist (never override allowlist with coarse Express trust proxy!)
  const effectiveTrustedProxy =
    fromTrustedProxy !== undefined
      ? Boolean(fromTrustedProxy)
      : Boolean(req?.app && typeof req.app.get === "function" && req.app.get("trust proxy"));

  if (hasDuplicateHostOrCl(req.rawHeaders)) {
    return { ok: false, status: 403, error: "DUPLICATE_HEADER_SMUGGLING" };
  }
  if (sfs.includes("cross-site")) {
    return { ok: false, status: 403, error: "CROSS_SITE_HANDSHAKE_DENIED" };
  }
  if (origin) {
    const originHost = parseHttpOriginHost(origin);
    if (!originHost) {
      return { ok: false, status: 403, error: "INVALID_ORIGIN_DENIED" };
    }
    const normHost = host ? normalizeHostDefaultPort(host) : "";
    const xfhFirst = effectiveTrustedProxy
      ? normalizeHostDefaultPort(String(headers["x-forwarded-host"] || "").split(",")[0] || "")
      : "";
    if ((!normHost || originHost !== normHost) && (!xfhFirst || originHost !== xfhFirst)) {
      return { ok: false, status: 403, error: "CROSS_ORIGIN_HANDSHAKE_DENIED" };
    }
  }

  if (mode === "strict" || mode === "balanced" || mode === "paranoid") {
    if (headers["content-length"] && headers["transfer-encoding"]) {
      return { ok: false, status: 403, error: "CL_TE_SMUGGLING" };
    }
    if (
      String(headers["x-http-method-override"] || "").trim() ||
      String(headers["x-method-override"] || "").trim() ||
      String(headers["x-http-method"] || "").trim()
    ) {
      return { ok: false, status: 403, error: "METHOD_OVERRIDE_DENIED" };
    }
    for (const ph of PROXY_HANDSHAKE_LEAK_HEADERS) {
      if (headers[ph] !== undefined) {
        return { ok: false, status: 403, error: "PROXY_HEADER_DENIED" };
      }
    }
    if (blockAiCrawlers && isAiCrawlerRequest(headers)) {
      return { ok: false, status: 403, error: "AI_CRAWLER_OR_SCRAPER_DENIED" };
    }
    if (isCliOrProxyUa(ua, secChUa)) {
      return { ok: false, status: 403, error: "NON_BROWSER_HANDSHAKE_DENIED" };
    }
    const secChPlat = String(headers["sec-ch-ua-platform"] || "").replace(/"/g, "").toLowerCase();
    if (secChPlat) {
      const uaLinux = ua.includes("Linux") && !ua.includes("Android");
      const uaWin = ua.includes("Windows NT");
      const uaMac = ua.includes("Macintosh");
      if (
        (uaLinux && (secChPlat === "windows" || secChPlat === "macos")) ||
        (uaWin && (secChPlat === "linux" || secChPlat === "macos")) ||
        (uaMac && (secChPlat === "windows" || secChPlat === "linux"))
      ) {
        return { ok: false, status: 403, error: "OS_HEADER_CONTRADICTION" };
      }
    }
    const claimsModern = parseBrowserMajorChrome(ua) >= 80 || parseBrowserMajorFirefox(ua) >= 90;
    if (claimsModern) {
      if (!sfs || (sfs !== "same-origin" && sfs !== "same-site") || !sfm) {
        return { ok: false, status: 403, error: "FETCH_METADATA_REQUIRED" };
      }
      if (requireScriptDest && sfd !== "script") {
        return { ok: false, status: 403, error: "SCRIPT_FETCH_DEST_REQUIRED" };
      }
      if (!acceptLang) {
        return { ok: false, status: 403, error: "ACCEPT_LANGUAGE_REQUIRED" };
      }
      if (mode !== "balanced" && !effectiveTrustedProxy && conn === "close" && remoteRaw) {
        return { ok: false, status: 403, error: "REPEATER_CONNECTION_CLOSE" };
      }
    }
  }

  return { ok: true };
}

function hasDuplicateHostOrCl(rawHeaders) {
  if (!Array.isArray(rawHeaders) || rawHeaders.length === 0) return false;
  const { hostCount, clCount } = countDuplicateSensitiveHeaders(rawHeaders, null, null);
  return hostCount > 1 || clCount > 1;
}

function hasRequestBodyHeader(headers) {
  if (!headers) return false;
  if (headers["transfer-encoding"]) return true;
  const clRaw = headers["content-length"];
  const clTrim = Array.isArray(clRaw) ? clRaw.join(",").trim() : String(clRaw ?? "").trim();
  return clTrim !== "" && !/^0+$/.test(clTrim);
}

function isHtmlBootstrapNavigation(
  req,
  { blockAiCrawlers = true, fromTrustedProxy = false, strictConnectionCheck = true, precheckedClean = false, skipCliCheck = false } = {}
) {
  const headers = req.headers || {};
  if (req.method !== "GET") return false;
  const accept = String(headers["accept"] || "").toLowerCase();
  const sfm = String(headers["sec-fetch-mode"] || "").trim().toLowerCase();
  const sfd = String(headers["sec-fetch-dest"] || "").trim().toLowerCase();
  const sfs = String(headers["sec-fetch-site"] || "").trim().toLowerCase();
  const ua = String(headers["user-agent"] || "");
  if (!accept.includes("text/html")) return false;
  if (hasRequestBodyHeader(headers)) return false;
  if (headers["x-original-url"] || headers["x-rewrite-url"]) return false;
  const claimsModern = parseBrowserMajorChrome(ua) >= 80 || parseBrowserMajorFirefox(ua) >= 90;
  if (claimsModern || sfm || sfd) {
    const validDest = sfd === "document" || (sfd === "iframe" && (sfs === "same-origin" || sfs === "same-site"));
    if (sfm !== "navigate" || !validDest) return false;
  }
  if (claimsModern && strictConnectionCheck && !fromTrustedProxy && String(headers["connection"] || "").trim().toLowerCase() === "close") return false;
  if (!precheckedClean && hasDuplicateHostOrCl(req.rawHeaders)) return false;
  if (!skipCliCheck && isCliOrProxyUa(ua, headers["sec-ch-ua"])) return false;
  if (!precheckedClean && blockAiCrawlers && isAiCrawlerRequest(headers)) return false;
  if (!precheckedClean && PROXY_HANDSHAKE_LEAK_HEADERS.some((h) => headers[h] !== undefined)) return false;
  return true;
}

/**
 * Plug-and-play middleware for raw Node `http.createServer`, Express, or Connect.
 * Serves static SRI-pinned `/__proxysnare/guard.js`, `/__proxysnare/boot`,
 * ECDSA-authenticated `/__proxysnare/handshake` (`PS_ECDH_V2`), and `/__proxysnare/health`.
 */
function createProxySnareMiddleware(options = {}) {
  const basePath = String(options.basePath || "/__proxysnare").replace(/\/+$/, "") || "/__proxysnare";
  const guardRoutePath = `${basePath}/guard.js`;
  const healthRoutePath = `${basePath}/health`;
  const bootRoutePath = `${basePath}/boot`;
  const handshakeRoutePath = `${basePath}/handshake`;
  const exposeDebugHeaders = options.exposeDebugHeaders !== false;
  const verifyBrowserIntegrity =
    typeof options.verifyBrowserIntegrity === "function" ? options.verifyBrowserIntegrity : null;
  const requireVeilBreak =
    options.requireVeilBreak !== undefined
      ? Boolean(options.requireVeilBreak)
      : typeof options.verifyBrowserIntegrity === "function";
  const isReverseProxy = Boolean(options._reverseProxy);
  const bodyReadTimeoutMs = Number.isFinite(options.bodyReadTimeoutMs) && options.bodyReadTimeoutMs > 0 ? options.bodyReadTimeoutMs : 15_000;
  const parseReqBody = options.parseReqBody !== false;
  const extStore = options.store && typeof options.store.get === "function" && typeof options.store.set === "function" ? options.store : null;
  const engine = createProxySnareEngine(options);
  if (extStore && !engine.hasPersistentSecret) {
    throw new Error(
      "ProxySnare options.store requires a shared persistent 'secret' (or PROXYSNARE_SECRET / signingKeyPair) across workers"
    );
  }
  const clientRules = engine.serializeProtectedPathsForClient();
  const useStaticSri = engine.sri;
  const serverVerifyPubB64 = engine.ecdsaHandshakeAuth ? engine.serverVerifyPubB64 : "";

  const embeddedVbSrc = typeof options.embeddedVeilBreakScript === "string" ? options.embeddedVeilBreakScript : "";
  const collectCeTelemetry =
    options.collectConsoleEvalTelemetry !== undefined
      ? Boolean(options.collectConsoleEvalTelemetry)
      : (engine.blockConsoleEval || !engine.allowDevTools || engine.mode === "monitor");
  const staticGuardJs = buildBrowserGuardScript({
    basePath,
    mode: engine.mode,
    protectedRules: clientRules,
    initialBoot: null,
    serverVerifyPubB64,
    userGestureWindowMs: engine.userGestureWindowMs,
    requireVeilBreak,
    allowDevTools: engine.allowDevTools,
    blockCdpActive: engine.blockCdpActive,
    blockConsoleEval: engine.blockConsoleEval,
    collectConsoleEvalTelemetry: collectCeTelemetry,
    requireGuardIntegrity: engine.requireGuardIntegrity,
    failClosedOnTamper: engine.mode !== "off" && engine.mode !== "monitor",
    embeddedVeilBreakScript: embeddedVbSrc,
  });
  const staticGuardBuf = Buffer.from(staticGuardJs, "utf8");
  const { sri: guardSri, version: guardVersion, guardHash: expectedGuardHash } = computeGuardIntegrity(staticGuardJs);
  const guardVerQueryRe = new RegExp(`(?:^|&)v=${guardVersion}(?:&|$)`);
  let staticGuardBr = null;
  let staticGuardGz = null;
  const pickStaticGuardEncoding = (req) => {
    const ae = String(req?.headers?.["accept-encoding"] || "").toLowerCase();
    if (/\bbr\b(?!\s*;\s*q\s*=\s*0(?:\.0+)?(?![.\d]))/.test(ae)) {
      if (!staticGuardBr) {
        staticGuardBr = zlib.brotliCompressSync(staticGuardBuf, {
          params: { [zlib.constants.BROTLI_PARAM_QUALITY]: 5 },
        });
      }
      return { buf: staticGuardBr, enc: "br", etag: `"${guardVersion}-br"` };
    }
    if (/\bgzip\b(?!\s*;\s*q\s*=\s*0(?:\.0+)?(?![.\d]))/.test(ae)) {
      if (!staticGuardGz) staticGuardGz = zlib.gzipSync(staticGuardBuf, { level: 6 });
      return { buf: staticGuardGz, enc: "gzip", etag: `"${guardVersion}-gzip"` };
    }
    return { buf: staticGuardBuf, enc: "", etag: `"${guardVersion}"` };
  };
  const needDynamicBoot = !useStaticSri && engine.mode !== "off";
  const bootPlaceholder = "const INITIAL_BOOT_INLINE = null;";
  const bootSplitIdx = needDynamicBoot ? staticGuardJs.indexOf(bootPlaceholder) : -1;
  const guardPrefixBuf =
    bootSplitIdx >= 0
      ? Buffer.from(staticGuardJs.slice(0, bootSplitIdx + "const INITIAL_BOOT_INLINE = ".length), "utf8")
      : null;
  const guardSuffixBuf =
    bootSplitIdx >= 0 ? Buffer.from(staticGuardJs.slice(bootSplitIdx + bootPlaceholder.length - 1), "utf8") : null;
  const encodeDynamicBootParts = needDynamicBoot
    ? (bootObj) => {
        if (guardPrefixBuf && guardSuffixBuf) {
          const bootLit = JSON.stringify(bootObj || null)
            .replace(/</g, "\\u003c")
            .replace(/>/g, "\\u003e")
            .replace(/&/g, "\\u0026")
            .replace(/[\u0080-\uffff]/g, (ch) => "\\u" + ch.charCodeAt(0).toString(16).padStart(4, "0"));
          const midBuf = Buffer.from(bootLit, "utf8");
          return { parts: [guardPrefixBuf, midBuf, guardSuffixBuf], byteLength: guardPrefixBuf.length + midBuf.length + guardSuffixBuf.length };
        }
        const fullBuf = Buffer.from(
          buildBrowserGuardScript({
            basePath,
            mode: engine.mode,
            protectedRules: clientRules,
            initialBoot: bootObj,
            serverVerifyPubB64,
            userGestureWindowMs: engine.userGestureWindowMs,
            requireVeilBreak,
            allowDevTools: engine.allowDevTools,
            blockCdpActive: engine.blockCdpActive,
            blockConsoleEval: engine.blockConsoleEval,
            collectConsoleEvalTelemetry: collectCeTelemetry,
            requireGuardIntegrity: engine.requireGuardIntegrity,
            failClosedOnTamper: engine.mode !== "monitor" && engine.mode !== "off",
            embeddedVeilBreakScript: embeddedVbSrc,
          }),
          "utf8"
        );
        return { parts: [fullBuf], byteLength: fullBuf.length };
      }
    : null;

  function restoreRequestStream(req, buf) {
    if (!req || typeof req.on !== "function") return;
    const payload = Buffer.isBuffer(buf) ? buf : Buffer.from(buf || "");
    if (req instanceof Readable) {
      // Clear stale body-consumption listeners (notably "readable", which blocks
      // Readable.prototype.resume() used by Readable.toWeb() in Node 18-24) while
      // preserving HTTP socket/lifecycle listeners such as "close" and "error".
      if (typeof req.removeAllListeners === "function") {
        for (const ev of ["data", "end", "readable", "pause", "resume"]) {
          req.removeAllListeners(ev);
        }
      }
      let pushed = false;
      // autoDestroy: false & emitClose: false prevent duplicate 'close' emission when downstream (e.g. for-await)
      // consumes/destroys the replayed stream, and leaving req.complete untouched preserves HTTP abort checks.
      Readable.call(req, { autoDestroy: false, emitClose: false });
      req._read = function _psReplayRead() {
        if (pushed) return;
        pushed = true;
        if (payload.length > 0) this.push(payload);
        this.push(null);
      };
      req._destroy = function _psReplayDestroy(err, cb) {
        if (typeof cb === "function") cb(err || null);
      };
      return;
    }
    // Minimal fallback for non-Readable mock request objects in unit tests.
    let consumed = false;
    const origOn = req.on.bind(req);
    const origEmit = typeof req.emit === "function" ? req.emit.bind(req) : () => {};
    req.on = function replayMockOn(ev, listener) {
      const r = origOn(ev, listener);
      if (ev === "data" && !consumed) {
        consumed = true;
        queueMicrotask(() => {
          if (payload.length > 0) origEmit("data", payload);
          origEmit("end");
        });
      }
      return r;
    };
    req[Symbol.asyncIterator] = async function* replayMockIter() {
      if (!consumed) {
        consumed = true;
        if (payload.length > 0) yield payload;
      }
    };
  }

  // Private WeakMaps carry precomputed normalized/clean-ASCII pathnames between unified/server probes and middleware
  // without mutating IncomingMessage hidden classes or re-running CLEAN_ASCII_PATH_RE during reverse-proxy forwarding!
  const prePathCache = new WeakMap();
  const cleanRawPathCache = new WeakMap();

  async function handleInner(req, res, next) {
    const reqArrivalMs = Date.now();
    const urlStr = req.originalUrl || req.url || "/";
    const cachedPath = prePathCache.get(req);
    const qIdxUrl = urlStr.indexOf("?");
    let isCleanAscii = false;
    let pathname;
    if (typeof cachedPath === "string") {
      pathname = cachedPath;
    } else {
      const rawPathOnly = qIdxUrl >= 0 ? urlStr.slice(0, qIdxUrl) : urlStr;
      if (CLEAN_ASCII_PATH_RE.test(rawPathOnly)) {
        isCleanAscii = true;
        cleanRawPathCache.set(req, rawPathOnly);
        pathname = rawPathOnly.length > 1 && rawPathOnly.endsWith("/") ? rawPathOnly.slice(0, -1) : rawPathOnly || "/";
      } else {
        pathname = normalizePathname(urlStr);
      }
    }

    // Lazily evaluate trustedProxies CIDR / Express trust-proxy lookup so static SRI guard.js, health,
    // and mode:"off" fast-exits pay zero CIDR/Express lookup overhead!
    let _trustCache = null;
    const getTrustInfo = () => {
      if (!_trustCache) {
        const remoteRaw = String(req?.socket?.remoteAddress || req?.ip || "").trim();
        const expressTrustsProxy = Boolean(req?.app && typeof req.app.get === "function" && req.app.get("trust proxy"));
        const remoteInTrustedProxies = Boolean(remoteRaw && engine.trustedProxies.size > 0 && engine.trustedProxies.has(remoteRaw));
        const fromTrustedProxy = engine.trustedProxies.size > 0 ? remoteInTrustedProxies : expressTrustsProxy;
        _trustCache = { expressTrustsProxy, remoteInTrustedProxies, fromTrustedProxy };
      }
      return _trustCache;
    };

    if ((req.method === "GET" || req.method === "HEAD") && pathname === guardRoutePath) {
      const isHead = req.method === "HEAD";
      if (useStaticSri || engine.mode === "off") {
        const query = qIdxUrl >= 0 ? urlStr.slice(qIdxUrl + 1) : "";
        const hasMatchingVer = guardVerQueryRe.test(query);
        const ccVal = hasMatchingVer
          ? "public, max-age=31536000, immutable, no-transform"
          : "public, no-cache, no-transform";
        const asset = pickStaticGuardEncoding(req);
        const inm = String(req.headers["if-none-match"] || "").trim();
        const inmMatches =
          Boolean(inm) &&
          (inm === "*" ||
            inm === asset.etag ||
            inm === `W/${asset.etag}` ||
            (inm.includes(",") && inm.split(",").some((t) => { const s = t.trim(); return s === "*" || s === asset.etag || s === `W/${asset.etag}`; })));
        if (inmMatches) {
          res.writeHead(304, {
            ETag: asset.etag,
            "Cache-Control": ccVal,
            Vary: "Accept-Encoding",
          });
          res.end();
          return true;
        }
        res.writeHead(200, {
          "Content-Type": "application/javascript; charset=utf-8",
          "Cache-Control": ccVal,
          ETag: asset.etag,
          Vary: "Accept-Encoding",
          ...(asset.enc ? { "Content-Encoding": asset.enc } : {}),
          "X-Content-Type-Options": "nosniff",
          "Content-Length": asset.buf.length,
        });
        if (isHead) res.end();
        else res.end(asset.buf);
        return true;
      }
      let boot = null;
      if (!isHead) {
        const { expressTrustsProxy, remoteInTrustedProxies, fromTrustedProxy } = getTrustInfo();
        const ip = engine.extractClientIp(req, expressTrustsProxy, remoteInTrustedProxies);
        const ua = String(req.headers["user-agent"] || "");
        const bootEligible =
          engine.mode !== "off" &&
          validateHandshakeClientHeaders(req, engine.mode, {
            requireScriptDest: true,
            fromTrustedProxy,
            blockAiCrawlers: engine.blockAiCrawlers,
          }).ok;
        boot = bootEligible && engine.allowBoot(ip) ? engine.issueBootChallenge({ ip, userAgent: ua }) : null;
      }
      const dyn = encodeDynamicBootParts(boot);
      res.writeHead(200, {
        "Content-Type": "application/javascript; charset=utf-8",
        "Cache-Control": "no-store, private, no-transform",
        "Vary": "User-Agent",
        "X-Content-Type-Options": "nosniff",
        "Content-Length": dyn.byteLength,
      });
      if (isHead) {
        res.end();
      } else if (typeof res.write === "function" && dyn.parts.length > 1) {
        for (let i = 0; i < dyn.parts.length - 1; i++) res.write(dyn.parts[i]);
        res.end(dyn.parts[dyn.parts.length - 1]);
      } else {
        res.end(dyn.parts.length === 1 ? dyn.parts[0] : Buffer.concat(dyn.parts, dyn.byteLength));
      }
      return true;
    }

    if ((req.method === "GET" || req.method === "HEAD") && pathname === healthRoutePath) {
      sendJson(res, 200, { ok: true, mode: engine.mode }, {}, req.method === "HEAD");
      return true;
    }

    if (req.method === "GET" && pathname === bootRoutePath) {
      const { expressTrustsProxy, remoteInTrustedProxies, fromTrustedProxy } = getTrustInfo();
      const hdrCheck = validateHandshakeClientHeaders(req, engine.mode, {
        fromTrustedProxy,
        blockAiCrawlers: engine.blockAiCrawlers,
      });
      if (!hdrCheck.ok) {
        sendJson(res, hdrCheck.status, { ok: false, error: hdrCheck.error });
        return true;
      }
      const ip = engine.extractClientIp(req, expressTrustsProxy, remoteInTrustedProxies);
      if (!engine.allowBoot(ip)) {
        sendJson(res, 429, { ok: false, error: "HANDSHAKE_RATE_LIMITED" });
        return true;
      }
      const boot = engine.issueBootChallenge({
        ip,
        userAgent: req.headers["user-agent"] || "",
      });
      if (!boot) {
        sendJson(res, 503, { ok: false, error: "BOOT_CAPACITY_EXCEEDED" });
        return true;
      }
      sendJson(res, 200, { ok: true, ...boot }, { "Vary": "Origin, User-Agent" });
      return true;
    }

    if (req.method === "POST" && pathname === handshakeRoutePath) {
      const { expressTrustsProxy, remoteInTrustedProxies, fromTrustedProxy } = getTrustInfo();
      const hdrCheck = validateHandshakeClientHeaders(req, engine.mode, {
        fromTrustedProxy,
        blockAiCrawlers: engine.blockAiCrawlers,
      });
      if (!hdrCheck.ok) {
        sendJson(res, hdrCheck.status, { ok: false, error: hdrCheck.error }, {}, false, req);
        return true;
      }
      const ip = engine.extractClientIp(req, expressTrustsProxy, remoteInTrustedProxies);
      if (!engine.allowHandshake(ip)) {
        sendJson(res, 429, { ok: false, error: "HANDSHAKE_RATE_LIMITED" }, {}, false, req);
        return true;
      }

      let hsBody = {};
      if (req.rawBody && Buffer.isBuffer(req.rawBody)) {
        try {
          hsBody = req.rawBody.length > 0 ? JSON.parse(req.rawBody.toString("utf8")) : {};
        } catch {
          sendJson(res, 400, { ok: false, error: "BAD_HANDSHAKE_JSON" }, {}, false, req);
          return true;
        }
      } else if (Buffer.isBuffer(req.body)) {
        try {
          hsBody = req.body.length > 0 ? JSON.parse(req.body.toString("utf8")) : {};
        } catch {
          sendJson(res, 400, { ok: false, error: "BAD_HANDSHAKE_JSON" }, {}, false, req);
          return true;
        }
      } else if (typeof req.body === "string") {
        try {
          hsBody = req.body.length > 0 ? JSON.parse(req.body) : {};
        } catch {
          sendJson(res, 400, { ok: false, error: "BAD_HANDSHAKE_JSON" }, {}, false, req);
          return true;
        }
      } else if ((req._body || req.readableEnded) && req.body && typeof req.body === "object") {
        hsBody = req.body;
      } else if (!req.readableEnded) {
        try {
          const raw = await readRequestBody(req, 8192, Math.min(bodyReadTimeoutMs, 10_000));
          hsBody = raw.length > 0 ? JSON.parse(raw.toString("utf8")) : {};
        } catch (e) {
          sendJson(res, e.statusCode || 400, { ok: false, error: e.message === "REQUEST_BODY_TIMEOUT" ? "REQUEST_BODY_TIMEOUT" : "BAD_HANDSHAKE" }, {}, false, req);
          return true;
        }
      }

      if (!hsBody || typeof hsBody !== "object" || Array.isArray(hsBody)) {
        sendJson(res, 400, { ok: false, error: "BAD_HANDSHAKE" }, {}, false, req);
        return true;
      }

      const ua = req.headers["user-agent"] || "";
      const enforcing = engine.mode === "strict" || engine.mode === "balanced" || engine.mode === "paranoid";
      let bootChallenge = "";
      // Enforce boot-token challenge binding whenever requireBootToken is true OR verifyBrowserIntegrity (unified VeilBreak) is active in enforcing modes!
      if (engine.mode !== "off" && (engine.requireBootToken || (verifyBrowserIntegrity && enforcing))) {
        const bootRes = engine.consumeBootChallenge({
          bootToken: hsBody.bootToken,
          powNonce: hsBody.powNonce,
          ip,
          userAgent: ua,
        });
        if (!bootRes.ok) {
          sendJson(res, bootRes.error === "BOOT_CAPACITY_EXCEEDED" ? 503 : 403, { ok: false, error: bootRes.error }, {}, false, req);
          return true;
        }
        if (extStore && bootRes.tokenId) {
          const bKey = `ps:bt:${bootRes.tokenId}`;
          const seen = typeof extStore.setIfNotExists === "function"
            ? !(await extStore.setIfNotExists(bKey, 1, Math.max(60_000, engine.bootTokenTtlMs)))
            : Boolean(await extStore.get(bKey));
          if (seen) {
            sendJson(res, 403, { ok: false, error: "BOOT_TOKEN_REPLAYED_OR_INVALID" }, {}, false, req);
            return true;
          }
          if (typeof extStore.setIfNotExists !== "function") {
            await extStore.set(bKey, 1, Math.max(60_000, engine.bootTokenTtlMs));
          }
        }
        bootChallenge = bootRes.challenge || "";
      }

      // Bypass 2 guard: verify runtime function integrity hash (strict/paranoid enforce exact match; balanced still rejects explicit tamper sentinels!)
      const suppliedHash = typeof hsBody.guardHash === "string" ? hsBody.guardHash.trim().toLowerCase() : "";
      const isTamperSentinel = suppliedHash === "tampered_subtle" || suppliedHash === "tampered_guard" || suppliedHash === "tampered_console";
      if (enforcing) {
        if (isTamperSentinel) {
          sendJson(res, 403, { ok: false, error: "GUARD_INTEGRITY_MISMATCH" });
          return true;
        }
        if (engine.requireGuardIntegrity) {
          if (!suppliedHash || !safeEqualHex(suppliedHash, expectedGuardHash)) {
            sendJson(res, 403, { ok: false, error: "GUARD_INTEGRITY_MISMATCH" });
            return true;
          }
        }
      }

      // Active CDP gate at handshake strictly honors engine.blockCdpActive (so explicit blockCdpActive:false / unified antiCdp:false is never overridden!)
      if (enforcing && engine.blockCdpActive && hsBody.cdpActive === true) {
        sendJson(res, 403, { ok: false, error: "CDP_ACTIVE_DENIED" });
        return true;
      }

      // Bypass 4 & Unified VeilBreak bridge: optional browser-integrity verification at handshake!
      if (verifyBrowserIntegrity && engine.mode !== "off") {
        let bv;
        try {
          bv = await verifyBrowserIntegrity({
            req,
            ip,
            userAgent: ua,
            headers: req.headers,
            challenge: bootChallenge,
            bootToken: typeof hsBody.bootToken === "string" ? hsBody.bootToken : "",
            browserProof: hsBody.browserProof ?? null,
            cdpActive: hsBody.cdpActive === true,
            mode: engine.mode,
          });
        } catch {
          bv = { ok: false, blocked: true, reasons: ["BROWSER_INTEGRITY_ERROR"] };
        }
        if (bv && (bv.blocked || bv.ok === false) && engine.mode !== "monitor") {
          const errPayload = exposeDebugHeaders
            ? { ok: false, error: "BROWSER_INTEGRITY_FAILED", reasons: bv.reasons || [] }
            : { ok: false, error: "BROWSER_INTEGRITY_FAILED" };
          sendJson(res, 403, errPayload);
          return true;
        }
      }

      // HTTP /handshake ALWAYS enforces ephemeral ECDH P-256 (PS_ECDH_V2) — ZERO plaintext sessionKeyHex on the wire!
      if (typeof hsBody.clientPubB64 !== "string" || !hsBody.clientPubB64.trim()) {
        sendJson(res, 400, { ok: false, error: "ECDH_KEY_REQUIRED" });
        return true;
      }

      const bpDigest =
        hsBody.browserProof && typeof hsBody.browserProof === "object" && typeof hsBody.browserProof.d === "string"
          ? hsBody.browserProof.d
          : "";
      const hasClientAttest =
        hsBody.guardHash !== undefined || hsBody.cdpActive !== undefined || hsBody.browserProof !== undefined;
      const hsBind = hasClientAttest
        ? sha256Hex(`${typeof hsBody.guardHash === "string" ? hsBody.guardHash : ""}|${hsBody.cdpActive === true ? "1" : "0"}|${bpDigest}`)
        : "";

      const sess = engine.issueSession({
        ip,
        userAgent: ua,
        origin: req.headers["origin"] || "",
        clientPubB64: hsBody.clientPubB64,
        bootToken: typeof hsBody.bootToken === "string" ? hsBody.bootToken : "",
        hsBind,
      });
      if (!sess) {
        sendJson(res, 503, { ok: false, error: "SESSION_CAPACITY_EXCEEDED" });
        return true;
      }
      if (sess.error) {
        sendJson(res, 400, { ok: false, error: sess.error });
        return true;
      }
      if (extStore && sess.sessionId) {
        const snap = engine.exportSessionRecord(sess.sessionId);
        if (snap) await extStore.set(`ps:sess:${sess.sessionId}`, snap, engine.sessionTtlMs);
      }
      sendJson(res, 200, { ok: true, ...sess }, { "Vary": "Origin, User-Agent" });
      return true;
    }

    if (engine.mode === "off") {
      if (typeof next === "function") next();
      return false;
    }

    const overrideProtected = engine.hasProtectedOverrideHeader(req.headers);
    const pathProt = engine.inspectPathProtection(urlStr, isCleanAscii ? pathname : null);
    const isProtected = pathProt.protected || overrideProtected;

    const hasBodyHdr = hasRequestBodyHeader(req.headers);
    const isCorsPreflight =
      req.method === "OPTIONS" &&
      Boolean(String(req.headers?.["access-control-request-method"] || "").trim()) &&
      Boolean(String(req.headers?.["origin"] || "").trim()) &&
      !hasBodyHdr &&
      !req.headers?.["x-ps-session"];
    const methodHasBody =
      req.method !== "GET" &&
      req.method !== "HEAD" &&
      !(req.method === "OPTIONS" && isCorsPreflight);

    // Reject unsigned body smuggling on protected GET/HEAD requests (unless CL+TE smuggling which inspectRequest scores)
    if (
      isProtected &&
      (req.method === "GET" || req.method === "HEAD") &&
      engine.mode !== "monitor" &&
      !((req.headers?.["content-length"] && req.headers?.["transfer-encoding"]))
    ) {
      if (hasBodyHdr) {
        sendJson(res, 400, { ok: false, error: "BODY_NOT_ALLOWED_ON_GET_HEAD" }, {}, false, req);
        return true;
      }
    }

    const enforcingMode = engine.mode === "strict" || engine.mode === "balanced" || engine.mode === "paranoid";
    const isOptionsAcrm = req.method === "OPTIONS" && !hasBodyHdr && Boolean(String(req.headers?.["access-control-request-method"] || "").trim());
    const NONCE_BURN_MAX_BYTES = Math.min(options.maxBodyBytes || 1024 * 1024, 65536);
    const clRawBurn = req.headers?.["content-length"];
    const clBurnStr = Array.isArray(clRawBurn) ? clRawBurn.join(",").trim() : String(clRawBurn ?? "").trim();
    const clWithinBurnCap = clBurnStr === "" || (/^\d+$/.test(clBurnStr) && Number(clBurnStr) <= NONCE_BURN_MAX_BYTES);
    // Single-pass header pre-evaluation BEFORE distributed extStore.get() and body buffering:
    // skips extStore.get() on unsigned CORS preflights, malformed X-PS-* headers, and unauthenticated CLI/crawler/large-body floods,
    // while allowing live-session nonce burning on <=64KB requests across workers!
    let psSidHdr = "";
    let preBodyHdrInfo = null;
    let psSyntaxOk = false;
    let preGuaranteedLocal = 0;
    let awaitedExtStore = false;
    const mayNeedExtStore = Boolean(extStore && req.headers?.["x-ps-session"]);
    const mayNeedUnprotPsCheck = !isProtected && methodHasBody && Boolean(req.headers?.["x-ps-session"]);
    if (mayNeedExtStore || mayNeedUnprotPsCheck) {
      const preLocal = evaluatePreBodyMinScore(req.headers, {
        mode: engine.mode,
        blockAiCrawlers: engine.blockAiCrawlers,
        blockAutomationOnAllRoutes: engine.blockAutomationOnAllRoutes,
        hasSession: null,
        isProtected,
        overrideProtected,
        method: req.method,
        rawHeaders: Array.isArray(req.rawHeaders) ? req.rawHeaders : null,
        skipOverrides: true,
        now: reqArrivalMs,
      });
      preBodyHdrInfo = preLocal.hdrInfo;
      psSyntaxOk = Boolean(preBodyHdrInfo.psSyntaxOk);
      preGuaranteedLocal = preLocal.guaranteed;
      if (mayNeedExtStore && psSyntaxOk) {
        psSidHdr = String(preBodyHdrInfo.map["x-ps-session"] || "").trim();
        const allowBurnLookup = !preBodyHdrInfo.cliUa && !preBodyHdrInfo.isAiCrawler && (!methodHasBody || clWithinBurnCap);
        if (!(enforcingMode && preGuaranteedLocal >= engine.threshold) || allowBurnLookup) {
          const snap = await extStore.get(`ps:sess:${psSidHdr}`);
          awaitedExtStore = true;
          if (snap) engine.importSessionRecord(snap);
        }
      }
    }

    // On unprotected routes, ONLY buffer the request body when all 6 required X-PS-* proof headers are
    // present AND syntactically valid (prevents 413 DoS on streaming upload routes via a single dummy X-PS-* header!).
    const hasPsHeader = !isProtected && methodHasBody && psSyntaxOk;

    let bodyBuf = EMPTY_BUF;
    let readFromStream = false;
    let bodySkipped = false;
    const needBodyForInspection = isProtected || hasPsHeader;
    const reqCt = String(req.headers?.["content-type"] || "").toLowerCase();

    // Evaluate enforcing-mode pre-body flood gate BEFORE both Express pre-parsed req.body re-serialization and raw-stream buffering,
    // while reading <=64KB bodies when the caller proves possession of the live 96-bit rotating canary so blocked valid-HMAC nonces are always burned!
    let preBodyGateBlocked = false;
    let preBodyHasLiveCanary = false;
    if (enforcingMode && needBodyForInspection && methodHasBody && !isOptionsAcrm && !(req.rawBody && Buffer.isBuffer(req.rawBody))) {
      if (!preBodyHdrInfo) {
        const preEval = evaluatePreBodyMinScore(req.headers, {
          mode: engine.mode,
          blockAiCrawlers: engine.blockAiCrawlers,
          blockAutomationOnAllRoutes: engine.blockAutomationOnAllRoutes,
          hasSession: null,
          isProtected,
          overrideProtected,
          method: req.method,
          rawHeaders: Array.isArray(req.rawHeaders) ? req.rawHeaders : null,
          skipOverrides: true,
          now: reqArrivalMs,
        });
        preBodyHdrInfo = preEval.hdrInfo;
        psSyntaxOk = Boolean(preBodyHdrInfo.psSyntaxOk);
        preGuaranteedLocal = preEval.guaranteed;
      }
      let g = preGuaranteedLocal;
      if (psSyntaxOk) {
        const preSessRes = engine.precheckSessionHeaders(preBodyHdrInfo, reqArrivalMs);
        g += preSessRes.pen;
        preBodyHasLiveCanary = preSessRes.hasLiveCanaryNonce;
      }
      preBodyGateBlocked = g >= engine.threshold;
    }

    const skipPreAuthBody = preBodyGateBlocked && !(preBodyHasLiveCanary && clWithinBurnCap);
    if (req.rawBody && Buffer.isBuffer(req.rawBody)) {
      bodyBuf = req.rawBody;
    } else if (skipPreAuthBody) {
      bodySkipped = true;
    } else if (needBodyForInspection && methodHasBody && Buffer.isBuffer(req.body)) {
      bodyBuf = req.body;
    } else if (needBodyForInspection && methodHasBody && typeof req.body === "string") {
      bodyBuf = Buffer.from(req.body, "utf8");
    } else if (needBodyForInspection && methodHasBody && (req._body || req.readableEnded) && req.body && typeof req.body === "object") {
      if (
        (!req.headers?.["content-length"] || String(req.headers?.["content-length"] || "").trim() === "0") &&
        !req.headers?.["transfer-encoding"] &&
        Object.keys(req.body).length === 0
      ) {
        bodyBuf = EMPTY_BUF;
      } else if (reqCt.includes("application/x-www-form-urlencoded")) {
        const usp = new URLSearchParams();
        for (const [k, v] of Object.entries(req.body)) {
          if (Array.isArray(v)) {
            for (const item of v) {
              if (item !== undefined && item !== null) usp.append(k, String(item));
            }
          } else if (v !== undefined && v !== null) {
            usp.append(k, String(v));
          }
        }
        bodyBuf = Buffer.from(usp.toString(), "utf8");
      } else {
        bodyBuf = Buffer.from(JSON.stringify(req.body), "utf8");
      }
    } else if (needBodyForInspection && methodHasBody) {
      const readLimit = preBodyGateBlocked ? NONCE_BURN_MAX_BYTES : (options.maxBodyBytes || 1024 * 1024);
      try {
        bodyBuf = await readRequestBody(req, readLimit, bodyReadTimeoutMs);
        readFromStream = true;
      } catch (e) {
        sendJson(res, e.statusCode || 400, { ok: false, error: e.message || "BAD_BODY" }, {}, false, req);
        return true;
      }
      req.rawBody = bodyBuf;
    }
    req.proxySnareBody = bodyBuf;

    let _clientIpCache = null;
    const getClientIpLazy = () => {
      if (_clientIpCache === null) {
        const t = getTrustInfo();
        _clientIpCache = engine.extractClientIp(req, t.expressTrustsProxy, t.remoteInTrustedProxies);
      }
      return _clientIpCache;
    };
    // Always re-sample Date.now() after async body read / extStore I/O so held bodies cannot bypass freshnessMs and usedNonces stays strictly expiry-ordered!
    const inspectNowMs = readFromStream || awaitedExtStore ? Date.now() : reqArrivalMs;
    const verdict = engine.inspectRequest({
      method: req.method,
      url: urlStr,
      headers: req.headers,
      body: bodyBuf,
      now: inspectNowMs,
      rawHeaders: Array.isArray(req.rawHeaders) ? req.rawHeaders : null,
      getFromTrustedProxy: () => getTrustInfo().fromTrustedProxy,
      precheckedProtected: isProtected,
      precomputedOverrideProtected: overrideProtected,
      precomputedPathname: pathname,
      precomputedPathCands: pathProt.cands,
      getNormIp: getClientIpLazy,
      precomputedHdrInfo: preBodyHdrInfo,
      bodySkipped,
    });

    // Multi-worker atomic single-use nonce claim to eliminate concurrent signed-request & blocked-valid-HMAC header-fixup replay races!
    if (extStore && psSidHdr && (verdict.nextCanary || verdict._nonceBurned)) {
      const psNonceHdr = String((preBodyHdrInfo && preBodyHdrInfo.map["x-ps-nonce"]) || req.headers?.["x-ps-nonce"] || "").trim();
      if (/^[A-Za-z0-9_-]{8,64}$/.test(psNonceHdr)) {
        const nKey = `ps:nonce:${psSidHdr}:${psNonceHdr}`;
        const claimed = typeof extStore.setIfNotExists === "function"
          ? Boolean(await extStore.setIfNotExists(nKey, 1, engine.nonceTtlMs))
          : !(await extStore.get(nKey)) && (await extStore.set(nKey, 1, engine.nonceTtlMs), true);
        if (!claimed && !verdict.reasons.some((r) => r.code === "REPEATER_NONCE_REPLAYED")) {
          verdict.reasons.push({ code: "REPEATER_NONCE_REPLAYED", weight: 10, detail: "Distributed single-use nonce already claimed on another worker" });
          verdict.score += 10;
          verdict.nextCanary = null;
          verdict.canaryAck = null;
          if (engine.mode !== "monitor") {
            verdict.blocked = true;
            verdict.ok = false;
          }
          if (typeof options.onDetect === "function") {
            try {
              options.onDetect({ ...verdict, ip: getClientIpLazy(), method: req.method, path: pathname, sessionId: psSidHdr });
            } catch {}
          }
        }
      }
      if (!verdict.blocked && verdict.nextCanary) {
        const updated = engine.exportSessionRecord(psSidHdr);
        if (updated) await extStore.set(`ps:sess:${psSidHdr}`, updated, engine.sessionTtlMs);
      }
    }
    req.proxySnare = verdict;

    if (exposeDebugHeaders) {
      if (!isReverseProxy) res.setHeader("X-ProxySnare-Score", String(verdict.score));
      res.setHeader("X-ProxySnare-Mode", verdict.mode);
    }
    if (verdict.nextCanary) {
      res.setHeader("X-PS-Next-Canary", verdict.nextCanary);
      if (verdict.canaryAck) res.setHeader("X-PS-Canary-Ack", verdict.canaryAck);
      if (!isReverseProxy) {
        const curVary = res.getHeader ? String(res.getHeader("Vary") || "") : "";
        if (!curVary.toLowerCase().includes("x-ps-session")) {
          res.setHeader("Vary", curVary ? `${curVary}, X-PS-Session, X-PS-Seq` : "X-PS-Session, X-PS-Seq");
        }
      }
    }
    if (verdict.rehandshakeRecommended) {
      res.setHeader("X-PS-Rehandshake", "1");
    }

    if (verdict.blocked) {
      const extra = {};
      if (verdict.rehandshakeRecommended) extra["X-PS-Rehandshake"] = "1";
      if (verdict.redirectGetHint) extra["X-PS-Redirect-Get"] = "1";
      const body = exposeDebugHeaders
        ? {
            ok: false,
            error: "REPEATER_OR_PROXY_BLOCKED",
            score: verdict.score,
            threshold: verdict.threshold,
            reasons: verdict.reasons.map((r) => r.code),
          }
        : { ok: false, error: "REPEATER_OR_PROXY_BLOCKED" };
      sendJson(res, 403, body, extra, req.method === "HEAD", req);
      return true;
    }

    // Lazily parse req.body ONLY when accessed (raw Node handlers work seamlessly; Express 4 users mounting express.json() downstream can pass parseReqBody: false!)
    if (readFromStream && !isReverseProxy) {
      if (parseReqBody) {
        const origBodyVal = req.body;
        const isEmptyPlaceholder =
          origBodyVal &&
          typeof origBodyVal === "object" &&
          !Array.isArray(origBodyVal) &&
          !Buffer.isBuffer(origBodyVal) &&
          Object.keys(origBodyVal).length === 0;
        if (origBodyVal === undefined || isEmptyPlaceholder) {
          const isJsonCt = /\bapplication\/(?:[a-z0-9.+-]+\+)?json\b/.test(reqCt);
          const isFormCt = !isJsonCt && reqCt.includes("application/x-www-form-urlencoded");
          const isTextCt = !isJsonCt && !isFormCt && reqCt.startsWith("text/");
          if (isJsonCt || isFormCt || isTextCt) {
            Object.defineProperty(req, "body", {
              configurable: true,
              enumerable: true,
              get() {
                let parsed = origBodyVal;
                if (isJsonCt) {
                  if (bodyBuf.length === 0) {
                    parsed = {};
                  } else {
                    try {
                      parsed = JSON.parse(bodyBuf.toString("utf8"));
                    } catch {
                      parsed = origBodyVal;
                    }
                  }
                } else if (isFormCt) {
                  parsed = querystring.parse(bodyBuf.toString("utf8"));
                } else {
                  parsed = bodyBuf.toString("utf8");
                }
                Object.defineProperty(req, "body", { value: parsed, writable: true, enumerable: true, configurable: true });
                return parsed;
              },
              set(v) {
                Object.defineProperty(req, "body", { value: v, writable: true, enumerable: true, configurable: true });
              },
            });
          }
        }
      }
      restoreRequestStream(req, bodyBuf);
    }

    if (typeof next === "function") {
      next();
    }
    return false;
  }

  function handle(req, res, next) {
    return handleInner(req, res, next).catch((err) => {
      if (typeof next === "function") {
        next(err);
        return true;
      }
      sendJson(res, 500, { ok: false, error: "INTERNAL_ERROR" }, {}, false, req);
      return true;
    });
  }

  handle.engine = engine;
  handle.basePath = basePath;
  handle.guardSri = guardSri;
  handle.guardVersion = guardVersion;
  handle.guardHash = expectedGuardHash;
  handle._setPrePath = (req, p) => { prePathCache.set(req, p); };
  handle._getPrePath = (req) => prePathCache.get(req);
  handle._setCleanRawPath = (req, p) => { cleanRawPathCache.set(req, p); };
  handle._getCleanRawPath = (req) => cleanRawPathCache.get(req);
  handle.captureRawBody = (req, _res, buf) => {
    if (buf) req.rawBody = Buffer.from(buf);
  };
  return handle;
}

function decodeHtmlBodyAsync(rawBuf, contentEncoding, maxOutputLength = 5 * 1024 * 1024) {
  const enc = String(contentEncoding || "").trim().toLowerCase();
  if (!enc || enc === "identity") return Promise.resolve(rawBuf);
  const opts = { maxOutputLength };
  const fn =
    enc === "gzip"
      ? zlib.gunzip
      : enc === "deflate"
        ? zlib.inflate
        : enc === "br"
          ? zlib.brotliDecompress
          : null;
  if (!fn) return Promise.resolve(null);
  return new Promise((resolve) => {
    fn(rawBuf, opts, (err, out) => resolve(err ? null : out));
  });
}

function asciiLower(s) {
  const str = String(s);
  if (str.indexOf("\u0130") < 0 && str.indexOf("\u212A") < 0) return str.toLowerCase();
  return str.replace(/[A-Z]+/g, (m) => m.toLowerCase());
}

function findTagInsertIndex(html, tagName, lowHtml) {
  const low = lowHtml || asciiLower(html);
  const needle = `<${tagName}`;
  let idx = 0;
  let nextCommentStart = low.indexOf("<!--", 0);
  while (idx < low.length) {
    const pos = low.indexOf(needle, idx);
    if (pos < 0) return -1;
    // Advance comment pointer forward in strictly O(N) amortized time
    while (nextCommentStart >= 0 && nextCommentStart < pos) {
      const cEnd = low.indexOf("-->", nextCommentStart + 4);
      if (cEnd < 0) return -1;
      if (cEnd > pos) {
        idx = cEnd + 3;
        nextCommentStart = low.indexOf("<!--", idx);
        break;
      }
      nextCommentStart = low.indexOf("<!--", cEnd + 3);
    }
    if (idx > pos) continue;
    const nextCh = low[pos + needle.length];
    if (nextCh === ">" || nextCh === " " || nextCh === "\t" || nextCh === "\r" || nextCh === "\n" || nextCh === "/") {
      const gt = low.indexOf(">", pos + needle.length);
      if (gt >= 0) return gt + 1;
      return -1;
    }
    idx = pos + needle.length;
  }
  return -1;
}

const SCRIPT_SRC_RE_CACHE = new Map();
function hasScriptSrc(html, baseSrc, lowHtml) {
  if (lowHtml && !lowHtml.includes(asciiLower(baseSrc))) return false;
  let entry = SCRIPT_SRC_RE_CACHE.get(baseSrc);
  if (!entry) {
    if (SCRIPT_SRC_RE_CACHE.size > 64) SCRIPT_SRC_RE_CACHE.clear();
    const esc = escapeHtmlAttr(baseSrc).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    entry = {
      fastRe: new RegExp(esc, "i"),
      tagRe: new RegExp(`<script\\b[^<>]*\\bsrc=["']${esc}(?:\\?[^"']*)?["']`, "i"),
    };
    SCRIPT_SRC_RE_CACHE.set(baseSrc, entry);
  }
  if (!lowHtml && !entry.fastRe.test(html)) return false;
  return entry.tagRe.test(html);
}

const EMPTY_SCRIPT_TAG_RE = /<script\b[^<>]*>\s*<\/script>\s*/gi;
const STRIP_SRC_RE_CACHE = new Map();
function stripScriptBySrc(html, targetSrc, lowHtml) {
  if (!targetSrc) return html;
  if (lowHtml && !lowHtml.includes(asciiLower(targetSrc))) return html;
  let entry = STRIP_SRC_RE_CACHE.get(targetSrc);
  if (!entry) {
    if (STRIP_SRC_RE_CACHE.size > 64) STRIP_SRC_RE_CACHE.clear();
    const esc = escapeHtmlAttr(targetSrc).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    entry = {
      fastRe: new RegExp(esc, "i"),
      tagRe: new RegExp(`^<script\\b[^<>]*\\bsrc=["']${esc}(?:\\?[^"']*)?["']`, "i"),
    };
    STRIP_SRC_RE_CACHE.set(targetSrc, entry);
  }
  if (!lowHtml && !entry.fastRe.test(html)) return html;
  return html.replace(EMPTY_SCRIPT_TAG_RE, (tag) => (entry.tagRe.test(tag) ? "" : tag));
}

function injectGuardIntoHtml(
  html,
  basePath,
  { sri = "", version = "", boot = null, requireVeilBreak = false, unifiedBundle = false, blockPage = undefined, prependTags = "", prependSrc = "", bridgeToken = "", stripScriptSrc = "", lowHtml = null, alreadyHasGuard = null, alreadyHasPrepend = null } = {}
) {
  let workingHtml = stripScriptSrc ? stripScriptBySrc(html, stripScriptSrc, lowHtml) : html;
  const fullLow = workingHtml === html && lowHtml ? lowHtml : null;
  const baseSrc = `${basePath}/guard.js`;
  const srcWithVer = version ? `${baseSrc}?v=${encodeURIComponent(version)}` : baseSrc;
  const safeSrc = escapeHtmlAttr(srcWithVer);
  const sriAttr = sri ? ` integrity="${escapeHtmlAttr(sri)}"` : "";
  const bootAttr = boot
    ? ` data-ps-boot="${escapeHtmlAttr(Buffer.from(JSON.stringify(boot), "utf8").toString("base64url"))}"`
    : "";
  const vbAttr = requireVeilBreak ? ' data-require-vb="true"' : "";
  const uniAttr = unifiedBundle ? ' data-unified-bundle="true"' : "";
  const bpAttr = blockPage === false ? ' data-block-page="false"' : "";
  const hasPre = alreadyHasPrepend !== null ? Boolean(alreadyHasPrepend) : (Boolean(prependSrc) && hasScriptSrc(workingHtml, prependSrc, fullLow));
  const hasGrd = alreadyHasGuard !== null ? Boolean(alreadyHasGuard) : hasScriptSrc(workingHtml, baseSrc, fullLow);
  const needPrepend = Boolean(prependTags) && !hasPre;
  const needGuard = !hasGrd;
  if (!needPrepend && !needGuard) return workingHtml;
  // Only stamp data-vb-bridge onto guard.js when the paired gate.js tag carrying that exact bridgeToken is also being injected!
  const brAttr = bridgeToken && needPrepend ? ` data-vb-bridge="${escapeHtmlAttr(bridgeToken)}"` : "";
  const guardTag = needGuard ? `<script src="${safeSrc}"${sriAttr}${bootAttr}${vbAttr}${uniAttr}${bpAttr}${brAttr}></script>` : "";
  const combined = `${needPrepend ? prependTags : ""}${guardTag}`;

  // Fast-path 4KB -> 64KB -> full document using length-preserving asciiLower() (avoids 5MB stalls & U+0130 index shifts!)
  const tryInsertWithLower = (lowStr) => {
    const headAfter = findTagInsertIndex(workingHtml, "head", lowStr);
    if (headAfter >= 0) {
      const metaMatch = /^(\s*<meta\b[^<>]*\bcharset\b[^<>]*>)/i.exec(workingHtml.slice(headAfter, headAfter + 256));
      const insertAt = metaMatch ? headAfter + metaMatch[0].length : headAfter;
      return `${workingHtml.slice(0, insertAt)}${combined}${workingHtml.slice(insertAt)}`;
    }
    const closeHead = lowStr.indexOf("</head>");
    if (closeHead >= 0) {
      return `${workingHtml.slice(0, closeHead)}${combined}${workingHtml.slice(closeHead)}`;
    }
    const bodyAfter = findTagInsertIndex(workingHtml, "body", lowStr);
    if (bodyAfter >= 0) {
      return `${workingHtml.slice(0, bodyAfter)}${combined}${workingHtml.slice(bodyAfter)}`;
    }
    return null;
  };
  if (fullLow) {
    const res = tryInsertWithLower(fullLow);
    if (res !== null) return res;
  } else {
    const res4k = tryInsertWithLower(asciiLower(workingHtml.length > 4096 ? workingHtml.slice(0, 4096) : workingHtml));
    if (res4k !== null) return res4k;
    if (workingHtml.length > 4096) {
      const res64k = tryInsertWithLower(asciiLower(workingHtml.length > 65536 ? workingHtml.slice(0, 65536) : workingHtml));
      if (res64k !== null) return res64k;
    }
    if (workingHtml.length > 65536) {
      const resAll = tryInsertWithLower(asciiLower(workingHtml));
      if (resAll !== null) return resAll;
    }
  }
  return `${combined}${workingHtml}`;
}

const STATIC_SUBRESOURCE_DESTS = new Set([
  "style", "image", "font", "script", "manifest", "audio", "video", "track", "worker", "serviceworker", "sharedworker",
]);
const EXTENSIONLESS_MEDIA_DESTS = new Set(["image", "font", "style", "audio", "video"]);
const STATIC_ASSET_EXT_RE = /\.(?:css|m?js|cjs|tsx?|jsx|vue|svelte|astro|png|jpe?g|gif|webp|avif|svg|ico|woff2?|ttf|otf|eot|webmanifest|wasm|mp4|webm|mp3|ogg|wav|vtt)$/i;
const VITE_DEV_PREFIX_RE = /(?:^|\/)@(?:vite|id|fs|react-refresh)(?:\/|$)/;
function inferStaticDest(headers, sfd, claimsModern) {
  if (sfd) return sfd;
  if (claimsModern) return "";
  const accept = String(headers?.accept || "").toLowerCase();
  if (!accept || accept.includes("text/html")) return "";
  if (accept.includes("image/")) return "image";
  if (accept.includes("text/css")) return "style";
  if (accept.includes("font/")) return "font";
  if (accept.includes("audio/")) return "audio";
  if (accept.includes("video/")) return "video";
  return "";
}

function isStaticSubresourceProbe(req, { blockAiCrawlers = true, fromTrustedProxy = false, pathname = "", strictConnectionCheck = true } = {}) {
  if (req.method !== "GET" && req.method !== "HEAD") return false;
  const headers = req.headers || {};
  const ua = String(headers["user-agent"] || "");
  const claimsModern = parseBrowserMajorChrome(ua) >= 80 || parseBrowserMajorFirefox(ua) >= 90;
  const sfd = String(headers["sec-fetch-dest"] || "").trim().toLowerCase();
  const sfs = String(headers["sec-fetch-site"] || "").trim().toLowerCase();
  // Match isHtmlBootstrapNavigation: only enforce Sec-Fetch-Dest when sent OR browser claims modern Chrome>=80 / Firefox>=90 (0-FP on Safari < 16.4!)
  if (sfd || claimsModern) {
    if (!STATIC_SUBRESOURCE_DESTS.has(sfd)) return false;
  }
  if (sfs && sfs !== "same-origin" && sfs !== "same-site" && sfs !== "none") return false;
  const p = pathname || normalizePathname(req.url || "/");
  // Allow extensionless same-origin/same-site media/font/style routes (e.g., Next.js /_next/image) including Safari < 16.4 via Accept inference,
  // because isAllowedStaticMime strictly binds upstream MIME to the exact dest!
  const effDest = inferStaticDest(headers, sfd, claimsModern);
  const allowExtensionlessMedia =
    EXTENSIONLESS_MEDIA_DESTS.has(effDest) && (!sfs || sfs === "same-origin" || sfs === "same-site");
  if (!STATIC_ASSET_EXT_RE.test(p) && !p.endsWith("/manifest.json") && !VITE_DEV_PREFIX_RE.test(p) && !allowExtensionlessMedia) {
    return false;
  }
  if (hasRequestBodyHeader(headers)) return false;
  if (hasDuplicateHostOrCl(req.rawHeaders)) return false;
  if (isCliOrProxyUa(ua, headers["sec-ch-ua"] || "")) return false;
  if (blockAiCrawlers && isAiCrawlerRequest(headers)) return false;
  if (PROXY_HANDSHAKE_LEAK_HEADERS.some((h) => headers[h] !== undefined)) return false;
  if (headers["x-original-url"] || headers["x-rewrite-url"]) return false;
  if (strictConnectionCheck && claimsModern && !fromTrustedProxy && String(headers["connection"] || "").trim().toLowerCase() === "close") return false;
  return true;
}

function isAllowedStaticMime(ct, pathname = "", sfd = "") {
  // On extensionless media/style/font routes (e.g. Next.js /_next/image), strictly bind upstream MIME to Sec-Fetch-Dest so JS/JSONP cannot leak under Sec-Fetch-Dest: image!
  const isExtMediaOnly =
    EXTENSIONLESS_MEDIA_DESTS.has(sfd) &&
    !STATIC_ASSET_EXT_RE.test(pathname) &&
    !pathname.endsWith("/manifest.json") &&
    !VITE_DEV_PREFIX_RE.test(pathname);
  if (isExtMediaOnly) {
    if (sfd === "image") return ct.startsWith("image/");
    if (sfd === "style") return ct.startsWith("text/css");
    if (sfd === "font") {
      return (
        ct.startsWith("font/") ||
        ct.startsWith("application/font") ||
        ct.startsWith("application/x-font-") ||
        ct.startsWith("application/vnd.ms-fontobject")
      );
    }
    if (sfd === "audio") return ct.startsWith("audio/");
    if (sfd === "video") return ct.startsWith("video/");
    return false;
  }
  return (
    ct.startsWith("text/css") ||
    ct.startsWith("image/") ||
    ct.startsWith("font/") ||
    ct.startsWith("audio/") ||
    ct.startsWith("video/") ||
    ct.startsWith("text/vtt") ||
    ct.startsWith("application/font") ||
    ct.startsWith("application/x-font-") ||
    ct.startsWith("application/vnd.ms-fontobject") ||
    ct.startsWith("application/wasm") ||
    ct.startsWith("application/javascript") ||
    ct.startsWith("application/x-javascript") ||
    ct.startsWith("text/javascript") ||
    ct.startsWith("application/manifest+json") ||
    ((!sfd || sfd === "manifest") && (pathname.endsWith("/manifest.json") || pathname.endsWith(".webmanifest")) && ct.startsWith("application/json"))
  );
}

function sanitizeForwardPathname(rawPath) {
  if (typeof rawPath === "string" && rawPath.length > 0 && rawPath !== "//" && CLEAN_ASCII_PATH_RE.test(rawPath)) {
    return rawPath;
  }
  let s = String(rawPath || "/").replace(/\\/g, "/");
  const nul = s.indexOf("\0");
  if (nul >= 0) s = s.slice(0, nul);
  const hash = s.indexOf("#");
  if (hash >= 0) s = s.slice(0, hash);
  if (!s.startsWith("/")) s = "/" + s;
  const hadTrailingSlash = s.length > 1 && s.endsWith("/");
  const out = [];
  for (const seg of s.split("/")) {
    if (!seg || seg === ".") continue;
    if (seg === "..") {
      if (out.length > 0) out.pop();
      continue;
    }
    const safeSeg = seg.replace(/[^A-Za-z0-9\-._~!$&'()*+,;=:@%]|%(?![0-9a-fA-F]{2})/g, (ch) => encodeURIComponent(ch));
    out.push(safeSeg);
  }
  const joined = "/" + out.join("/");
  return hadTrailingSlash && joined !== "/" ? `${joined}/` : joined;
}

function isSharedCacheDirective(headerVal) {
  const cc = String(headerVal || "").toLowerCase();
  if (!cc) return false;
  // RFC 9111 §5.2.2.4/§5.2.2.7: field-qualified private="..." / no-cache="..." still allow shared caching of the HTML body!
  if (/\b(?:no-store|(?:no-cache|private)(?!\s*=))\b/.test(cc)) return false;
  return /\b(?:public|s-maxage\s*=\s*[1-9]\d*|max-age\s*=\s*[1-9]\d*|stale-while-revalidate\s*=\s*[1-9]\d*|stale-if-error\s*=\s*[1-9]\d*)\b/.test(cc);
}

function classifyHtmlCaching(headersOrCc) {
  if (typeof headersOrCc === "string") {
    const isPublicCacheable = isSharedCacheDirective(headersOrCc);
    const cc = headersOrCc.toLowerCase();
    const isBrowserCached =
      !/\b(?:no-store|no-cache(?!\s*=))\b/.test(cc) &&
      /\b(?:max-age|s-maxage|stale-while-revalidate|stale-if-error)\s*=\s*[1-9]\d*\b/.test(cc);
    return { isPublicCacheable, isBrowserCached };
  }
  if (!headersOrCc || typeof headersOrCc !== "object") {
    return { isPublicCacheable: false, isBrowserCached: false };
  }
  let ccRaw = "";
  let expiresRaw = "";
  let isPublicCacheable = false;
  for (const k in headersOrCc) {
    if (!Object.prototype.hasOwnProperty.call(headersOrCc, k)) continue;
    const kl = k.toLowerCase();
    if (kl === "cache-control") ccRaw = String(headersOrCc[k] || "").toLowerCase();
    else if (kl === "expires") expiresRaw = String(headersOrCc[k] || "").trim();
    if (
      !isPublicCacheable &&
      (kl === "cache-control" ||
        kl === "surrogate-control" ||
        kl === "cdn-cache-control" ||
        kl.endsWith("-cdn-cache-control"))
    ) {
      if (isSharedCacheDirective(headersOrCc[k])) isPublicCacheable = true;
    }
  }
  const hasFutureExpires = Boolean(expiresRaw) && (() => {
    const expMs = Date.parse(expiresRaw);
    return Number.isFinite(expMs) && expMs > Date.now();
  })();
  // RFC 9111 §5.3: future Expires without private/no-store/no-cache/max-age=0/s-maxage=0 is shared-cacheable!
  if (!isPublicCacheable && hasFutureExpires && !/\b(?:no-store|(?:no-cache|private)(?!\s*=)|(?:s-maxage|max-age)\s*=\s*0)\b/.test(ccRaw)) {
    isPublicCacheable = true;
  }
  const isBrowserCached =
    !/\b(?:no-store|no-cache(?!\s*=))\b/.test(ccRaw) &&
    (/\b(?:max-age|s-maxage|stale-while-revalidate|stale-if-error)\s*=\s*[1-9]\d*\b/.test(ccRaw) ||
      (hasFutureExpires && !/\bmax-age\s*=\s*0\b/.test(ccRaw)));
  return { isPublicCacheable, isBrowserCached };
}

/**
 * Standalone reverse-proxy shield that sits in front of ANY backend (`target`),
 * auto-injects `/__proxysnare/guard.js` into HTML responses, and blocks curl & Caido/Burp Repeater.
 */
function createProxySnareServer(options = {}) {
  const targetUrl = new URL(options.target || "http://127.0.0.1:3000");
  if (targetUrl.protocol !== "http:" && targetUrl.protocol !== "https:") {
    throw new Error(`Unsupported target protocol '${targetUrl.protocol}': expected http: or https:`);
  }
  const basePath = String(options.basePath || "/__proxysnare").replace(/\/+$/, "") || "/__proxysnare";
  const exposeDebugHeaders = options.exposeDebugHeaders !== false;
  const maxHtmlBytes = Number.isFinite(options.maxHtmlBytes) && options.maxHtmlBytes > 0 ? options.maxHtmlBytes : 5 * 1024 * 1024;
  const upstreamTimeoutMs = Number.isFinite(options.upstreamTimeoutMs) && options.upstreamTimeoutMs > 0 ? options.upstreamTimeoutMs : 30_000;
  const middleware = createProxySnareMiddleware({ ...options, basePath, exposeDebugHeaders, _reverseProxy: true });
  const injectGuard = options.injectGuard !== false && middleware.engine.mode !== "off";
  const preMiddleware = typeof options._preMiddleware === "function" ? options._preMiddleware : null;
  const requireVeilBreak =
    options.requireVeilBreak !== undefined
      ? Boolean(options.requireVeilBreak)
      : typeof options.verifyBrowserIntegrity === "function";
  const unifiedBundle = Boolean(options.embeddedVeilBreakScript);
  const stripScriptSrc = typeof options._stripScriptSrc === "string" ? options._stripScriptSrc : "";
  const sriOnPublicCache = Boolean(options.sriOnPublicCache);
  const rootProtected = middleware.engine.isPathProtected("/");
  const clientMod = targetUrl.protocol === "https:" ? https : http;
  const baseTargetPath = targetUrl.pathname && targetUrl.pathname !== "/" ? targetUrl.pathname.replace(/\/+$/, "") : "";

  const server = http.createServer((req, res) => {
    let htmlBootstrapProbe = false;
    let staticAssetProbe = false;
    let fromTpCached;
    const getFromTp = () => {
      if (fromTpCached === undefined) {
        const remoteRaw = String(req?.socket?.remoteAddress || req?.ip || "").trim();
        fromTpCached = Boolean(remoteRaw && middleware.engine.trustedProxies.size > 0 && middleware.engine.trustedProxies.has(remoteRaw));
      }
      return fromTpCached;
    };

    const runPipeline = async () => {
      if (preMiddleware) {
        const preRes = preMiddleware(req, res);
        const preHandled = preRes && typeof preRes.then === "function" ? await preRes : preRes;
        if (preHandled) return true;
      }
      if (
        rootProtected &&
        middleware.engine.mode !== "off" &&
        middleware.engine.mode !== "monitor" &&
        (req.method === "GET" || req.method === "HEAD")
      ) {
        const hdrs = req.headers || {};
        // Check canonical lowercase x-ps-* keys BEFORE calling normalizePathname (zero allocation on signed API GETs!)
        const hasPsHdr = Boolean(
          hdrs["x-ps-session"] || hdrs["x-ps-seq"] || hdrs["x-ps-ts"] ||
          hdrs["x-ps-nonce"] || hdrs["x-ps-canary"] || hdrs["x-ps-proof"] || hdrs["x-ps-ctx"]
        );
        if (!hasPsHdr) {
          const cachedPre = middleware._getPrePath(req);
          let reqNormPath;
          if (typeof cachedPre === "string") {
            reqNormPath = cachedPre;
          } else {
            const rawUrl = req.url || "/";
            const qIdx = rawUrl.indexOf("?");
            const rawPathOnly = qIdx >= 0 ? rawUrl.slice(0, qIdx) : rawUrl;
            if (CLEAN_ASCII_PATH_RE.test(rawPathOnly)) {
              middleware._setCleanRawPath(req, rawPathOnly);
              reqNormPath = rawPathOnly.length > 1 && rawPathOnly.endsWith("/") ? rawPathOnly.slice(0, -1) : rawPathOnly || "/";
            } else {
              reqNormPath = normalizePathname(rawUrl);
            }
          }
          middleware._setPrePath(req, reqNormPath);
          if (!reqNormPath.startsWith(`${basePath}/`)) {
            const fromTp = getFromTp();
            const strictConn = middleware.engine.mode !== "balanced";
            htmlBootstrapProbe = isHtmlBootstrapNavigation(req, {
              blockAiCrawlers: middleware.engine.blockAiCrawlers,
              fromTrustedProxy: fromTp,
              strictConnectionCheck: strictConn,
            });
            if (!htmlBootstrapProbe) {
              staticAssetProbe = isStaticSubresourceProbe(req, {
                blockAiCrawlers: middleware.engine.blockAiCrawlers,
                fromTrustedProxy: fromTp,
                pathname: reqNormPath,
                strictConnectionCheck: strictConn,
              });
            }
          }
        }
      }
      if (htmlBootstrapProbe || staticAssetProbe) return false;
      return Boolean(await middleware(req, res));
    };

    runPipeline()
      .then((handled) => {
        if (handled) return;
        if (res.destroyed || res.closed || res.writableEnded || req.aborted || (req.destroyed && !req.complete)) return;

        let rawFwd = stripSchemeAndAuthority(req.url || "/");
        let fwdSearch = "";
        const qIdx = rawFwd.indexOf("?");
        if (qIdx >= 0) {
          fwdSearch = rawFwd.slice(qIdx);
          rawFwd = rawFwd.slice(0, qIdx);
        }
        const safeSearch = fwdSearch
          ? fwdSearch.replace(/[^A-Za-z0-9\-._~!$&'()*+,;=:@/?%]|%(?![0-9a-fA-F]{2})/g, (ch) => encodeURIComponent(ch))
          : "";
        const preCleanRaw = middleware._getCleanRawPath(req);
        const safeFwdPath = preCleanRaw && rawFwd === preCleanRaw && rawFwd !== "//" ? rawFwd : sanitizeForwardPathname(rawFwd);
        let fwdPath = `${safeFwdPath}${safeSearch}`;
        if (baseTargetPath) fwdPath = `${baseTargetPath}${fwdPath}`;

        const fwdHeaders = stripHopByHop(req.headers, { isRequest: true });
        delete fwdHeaders["x-original-url"];
        delete fwdHeaders["x-rewrite-url"];
        delete fwdHeaders["x-http-method-override"];
        delete fwdHeaders["x-method-override"];
        delete fwdHeaders["x-http-method"];
        fwdHeaders.host = targetUrl.host;
        const remoteIp = String(req.socket?.remoteAddress || "").replace(/^::ffff:/, "");
        if (remoteIp) {
          fwdHeaders["x-forwarded-for"] = fwdHeaders["x-forwarded-for"]
            ? `${fwdHeaders["x-forwarded-for"]}, ${remoteIp}`
            : remoteIp;
        }

        const hasBufferedBody = Boolean(req._body || req.rawBody);
        if (hasBufferedBody) {
          const len = req.proxySnareBody ? req.proxySnareBody.length : 0;
          fwdHeaders["content-length"] = String(len);
          delete fwdHeaders["transfer-encoding"];
        }
        const acceptHdr = String(req.headers["accept"] || "").toLowerCase();
        if (injectGuard && acceptHdr.includes("text/html")) {
          fwdHeaders["accept-encoding"] = "identity";
        }
        if (htmlBootstrapProbe || staticAssetProbe) {
          delete fwdHeaders["if-modified-since"];
          delete fwdHeaders["if-none-match"];
        }

        let responded = false;
        const upstreamReq = clientMod.request(
          {
            protocol: targetUrl.protocol,
            hostname: targetUrl.hostname,
            port: targetUrl.port || (targetUrl.protocol === "https:" ? 443 : 80),
            method: req.method,
            path: fwdPath,
            headers: fwdHeaders,
            timeout: upstreamTimeoutMs,
          },
          (upRes) => {
            upRes.on("error", () => {
              if (responded) return;
              responded = true;
              if (!res.headersSent) sendJson(res, 502, { ok: false, error: "UPSTREAM_ERROR" });
              else res.destroy();
            });

            const statusCode = upRes.statusCode || 200;
            const ct = String(upRes.headers["content-type"] || "").toLowerCase();
            const mimeEssence = ct.split(";", 1)[0].trim();
            const isHtmlMime = mimeEssence === "text/html";
            const reqSfdRaw = String(req.headers["sec-fetch-dest"] || "").trim().toLowerCase();
            const reqUaStatic = staticAssetProbe && !reqSfdRaw ? String(req.headers["user-agent"] || "") : "";
            const reqSfd = staticAssetProbe
              ? inferStaticDest(req.headers, reqSfdRaw, reqUaStatic ? (parseBrowserMajorChrome(reqUaStatic) >= 80 || parseBrowserMajorFirefox(reqUaStatic) >= 90) : false)
              : reqSfdRaw;
            const reqPathForMime = staticAssetProbe
              ? (middleware._getPrePath(req) || normalizePathname(req.url || "/"))
              : "";

            // For wildcard HTML-bootstrap & static-subresource probes, strictly verify upstream MIME essence before leaking any body bytes!
            if ((htmlBootstrapProbe && !isHtmlMime) || (staticAssetProbe && !isAllowedStaticMime(ct, reqPathForMime, reqSfd))) {
              if ((htmlBootstrapProbe || staticAssetProbe) && statusCode >= 301 && statusCode <= 308 && statusCode !== 304 && Boolean(upRes.headers["location"])) {
                responded = true;
                const redirHeaders = stripHopByHop(upRes.headers);
                delete redirHeaders["content-length"];
                delete redirHeaders["content-encoding"];
                delete redirHeaders["content-type"];
                redirHeaders["content-length"] = "0";
                res.writeHead(statusCode, redirHeaders);
                res.end();
                upRes.destroy();
                return;
              }
              responded = true;
              if (typeof options.onDetect === "function") {
                try {
                  const enforceScore = middleware.engine.mode === "strict" || middleware.engine.mode === "paranoid" ? 8 : 6;
                  options.onDetect({
                    ok: false,
                    blocked: true,
                    score: enforceScore,
                    threshold: middleware.engine.threshold,
                    mode: middleware.engine.mode,
                    reasons: [{ code: "REPEATER_PROOF_MISSING", weight: enforceScore, detail: "Non-HTML protected response rejected on wildcard HTML bootstrap probe" }],
                    nextCanary: null,
                    canaryAck: null,
                    rehandshakeRecommended: false,
                    method: req.method,
                    path: normalizePathname(req.url || "/"),
                    ip: middleware.engine.extractClientIp(req),
                    sessionId: null,
                  });
                } catch {}
              }
              const errBody = exposeDebugHeaders
                ? { ok: false, error: "REPEATER_OR_PROXY_BLOCKED", reasons: ["REPEATER_PROOF_MISSING"] }
                : { ok: false, error: "REPEATER_OR_PROXY_BLOCKED" };
              sendJson(res, 403, errBody);
              upRes.destroy();
              return;
            }

            // Never let an unauthenticated CORS OPTIONS preflight leak body from a non-CORS upstream route!
            if (
              req.method === "OPTIONS" &&
              Boolean(String(req.headers["access-control-request-method"] || "").trim()) &&
              !req.proxySnare?.nextCanary &&
              middleware.engine.mode !== "off" &&
              middleware.engine.mode !== "monitor" &&
              middleware.engine.isPathProtected(req.url || "/") &&
              !upRes.headers["access-control-allow-origin"]
            ) {
              responded = true;
              if (typeof options.onDetect === "function") {
                try {
                  options.onDetect({
                    ok: false,
                    blocked: true,
                    score: 8,
                    threshold: middleware.engine.threshold,
                    mode: middleware.engine.mode,
                    reasons: [{ code: "CORS_PREFLIGHT_NOT_ENABLED", weight: 8, detail: "Unauthenticated OPTIONS preflight targeting non-CORS protected route" }],
                    nextCanary: null,
                    canaryAck: null,
                    rehandshakeRecommended: false,
                    method: req.method,
                    path: normalizePathname(req.url || "/"),
                    ip: middleware.engine.extractClientIp(req),
                    sessionId: null,
                  });
                } catch {}
              }
              sendJson(res, 403, { ok: false, error: "CORS_PREFLIGHT_NOT_ENABLED" });
              upRes.destroy();
              return;
            }

            const outHeaders = stripHopByHop(upRes.headers);
            if (req.proxySnare?.nextCanary) {
              outHeaders["x-ps-next-canary"] = req.proxySnare.nextCanary;
              if (req.proxySnare.canaryAck) outHeaders["x-ps-canary-ack"] = req.proxySnare.canaryAck;
              const vHdr = String(outHeaders["vary"] || "");
              if (!vHdr.toLowerCase().includes("x-ps-session")) {
                outHeaders["vary"] = vHdr ? `${vHdr}, X-PS-Session, X-PS-Seq` : "X-PS-Session, X-PS-Seq";
              }
            }
            if (req.proxySnare?.rehandshakeRecommended) {
              outHeaders["x-ps-rehandshake"] = "1";
            }
            if (exposeDebugHeaders) {
              outHeaders["x-proxysnare-score"] = String(req.proxySnare?.score ?? 0);
            }

            const canHaveBody = req.method !== "HEAD" && statusCode !== 204 && statusCode !== 304;
            if (injectGuard && canHaveBody && isHtmlMime) {
              const chunks = [];
              let totalBytes = 0;
              let overflowed = false;
              const onData = (c) => {
                totalBytes += c.length;
                if (totalBytes > maxHtmlBytes) {
                  overflowed = true;
                  upRes.removeListener("data", onData);
                  upRes.removeListener("end", onEnd);
                  if (responded || res.headersSent || res.writableEnded) {
                    chunks.length = 0;
                    return;
                  }
                  responded = true;
                  res.writeHead(statusCode, outHeaders);
                  for (const prev of chunks) res.write(prev);
                  chunks.length = 0;
                  res.write(c);
                  upRes.pipe(res);
                  return;
                }
                chunks.push(c);
              };
              const onEnd = async () => {
                try {
                  if (overflowed || responded || res.headersSent || res.writableEnded) return;
                  const rawBuf = chunks.length === 1 ? chunks[0] : Buffer.concat(chunks, totalBytes);
                  chunks.length = 0;
                  const ce = outHeaders["content-encoding"];
                  let decoded = rawBuf;
                  if (ce) {
                    const maybe = await decodeHtmlBodyAsync(rawBuf, ce, maxHtmlBytes);
                    if (overflowed || responded || res.headersSent || res.writableEnded) return;
                    if (!maybe) {
                      responded = true;
                      res.writeHead(statusCode, outHeaders);
                      res.end(rawBuf);
                      return;
                    }
                    decoded = maybe;
                    delete outHeaders["content-encoding"];
                  }
                  if (overflowed || responded || res.headersSent || res.writableEnded) return;
                  const rawHtml = decoded.toString("utf8");
                  const isFullHtmlDoc = /<(?:!doctype\s+html|html|head|body)\b/i.test(rawHtml.slice(0, 4096));
                  if (!isFullHtmlDoc) {
                    responded = true;
                    outHeaders["content-length"] = String(decoded.length);
                    res.writeHead(statusCode, outHeaders);
                    res.end(decoded);
                    return;
                  }
                  const { isPublicCacheable, isBrowserCached } = classifyHtmlCaching(outHeaders);
                  const alreadyHasGuard = hasScriptSrc(rawHtml, `${basePath}/guard.js`);
                  // Avoid pinning SRI into public CDN-cacheable HTML (which would break after rolling deploys/upgrades) unless explicitly opted-in!
                  const useGuardSri = middleware.engine.sri && (!isPublicCacheable || (sriOnPublicCache && middleware.engine.hasPersistentSecret));
                  let htmlBoot = null;
                  if (
                    middleware.engine.sri &&
                    middleware.engine.mode !== "off" &&
                    req.method === "GET" &&
                    statusCode >= 200 &&
                    statusCode < 300 &&
                    !isPublicCacheable &&
                    !alreadyHasGuard &&
                    Boolean(String(req.headers["accept-language"] || "").trim())
                  ) {
                    const htmlFromTp = getFromTp();
                    const psClean = Boolean(req.proxySnare && req.proxySnare.score === 0);
                    const eligibleForBoot =
                      htmlBootstrapProbe ||
                      ((!req.proxySnare || req.proxySnare.score === 0) &&
                        isHtmlBootstrapNavigation(req, {
                          blockAiCrawlers: middleware.engine.blockAiCrawlers,
                          fromTrustedProxy: htmlFromTp,
                          strictConnectionCheck: middleware.engine.mode !== "balanced",
                          precheckedClean: psClean,
                          skipCliCheck: psClean && middleware.engine.blockAutomationOnAllRoutes,
                        }));
                    if (eligibleForBoot) {
                      const ip = middleware.engine.extractClientIp(req, false, htmlFromTp);
                      if (middleware.engine.allowHtmlBoot(ip)) {
                        htmlBoot = middleware.engine.issueBootChallenge({
                          ip,
                          userAgent: String(req.headers["user-agent"] || ""),
                        });
                      }
                    }
                  }
                  const html = injectGuardIntoHtml(rawHtml, basePath, {
                    sri: useGuardSri ? middleware.guardSri : "",
                    version: useGuardSri ? middleware.guardVersion : "",
                    boot: htmlBoot,
                    requireVeilBreak,
                    unifiedBundle,
                    stripScriptSrc,
                    alreadyHasGuard,
                  });
                  const htmlModified = html !== rawHtml;
                  const buf = htmlModified ? Buffer.from(html, "utf8") : decoded;
                  outHeaders["content-length"] = String(buf.length);
                  if (htmlBoot) {
                    outHeaders["cache-control"] = "private, no-store";
                    for (const hk of Object.keys(outHeaders)) {
                      const hkl = hk.toLowerCase();
                      if (hkl === "cdn-cache-control" || hkl.endsWith("-cdn-cache-control") || hkl === "surrogate-control" || hkl === "expires") {
                        delete outHeaders[hk];
                      }
                    }
                    outHeaders["vary"] = outHeaders["vary"] ? `${outHeaders["vary"]}, User-Agent` : "User-Agent";
                    delete outHeaders["etag"];
                    delete outHeaders["last-modified"];
                  } else if (htmlModified) {
                    if (useGuardSri && isBrowserCached && !isPublicCacheable) {
                      outHeaders["cache-control"] = "private, no-cache";
                      delete outHeaders["expires"];
                    }
                    delete outHeaders["etag"];
                    delete outHeaders["last-modified"];
                  }
                  responded = true;
                  res.writeHead(statusCode, outHeaders);
                  res.end(buf);
                } catch (_) {
                  if (!responded && !res.headersSent && !res.writableEnded) {
                    responded = true;
                    sendJson(res, 502, { ok: false, error: "UPSTREAM_DECODE_ERROR" });
                  }
                }
              };
              upRes.on("data", onData);
              upRes.on("end", onEnd);
              return;
            }

            responded = true;
            res.writeHead(statusCode, outHeaders);
            upRes.pipe(res);
          }
        );

        upstreamReq.on("timeout", () => {
          upstreamReq.destroy(new Error("UPSTREAM_TIMEOUT"));
        });
        upstreamReq.on("error", () => {
          if (responded) return;
          responded = true;
          if (!res.headersSent) {
            sendJson(res, 502, { ok: false, error: "UPSTREAM_UNREACHABLE" });
          } else {
            res.destroy();
          }
        });
        res.on("close", () => {
          if (!res.writableEnded) upstreamReq.destroy();
        });

        if (hasBufferedBody) {
          if (req.proxySnareBody && req.proxySnareBody.length > 0) {
            upstreamReq.write(req.proxySnareBody);
          }
          upstreamReq.end();
        } else {
          req.pipe(upstreamReq);
        }
      })
      .catch(() => {
        if (!res.headersSent) sendJson(res, 500, { ok: false, error: "INTERNAL_ERROR" });
      });
  });

  return {
    server,
    engine: middleware.engine,
    middleware,
    guardSri: middleware.guardSri,
    guardVersion: middleware.guardVersion,
    guardHash: middleware.guardHash,
    listen(port = 8080, host = "127.0.0.1") {
      return new Promise((resolve, reject) => {
        const onErr = (err) => reject(err);
        server.once("error", onErr);
        server.listen(port, host, () => {
          server.removeListener("error", onErr);
          const addr = server.address();
          resolve(`http://${host}:${addr.port}`);
        });
      });
    },
    close() {
      return new Promise((resolve) => {
        if (typeof server.closeIdleConnections === "function") server.closeIdleConnections();
        server.close(() => resolve());
        if (typeof server.closeAllConnections === "function") server.closeAllConnections();
      });
    },
  };
}

module.exports = {
  createProxySnareMiddleware,
  createProxySnareServer,
  injectGuardIntoHtml,
  stripScriptBySrc,
};
