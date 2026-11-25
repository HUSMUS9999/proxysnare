"use strict";

const http = require("node:http");
const https = require("node:https");
const querystring = require("node:querystring");
const zlib = require("node:zlib");
const {
  createProxySnareEngine,
  normalizePathname,
  stripSchemeAndAuthority,
  isCliOrProxyUa,
} = require("./detector.js");
const { buildBrowserGuardScript } = require("./browser-guard.js");

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

const PROXY_HANDSHAKE_LEAK_HEADERS = [
  "proxy-connection",
  "x-burp-header",
  "x-burp-collaborator",
  "x-caido-id",
  "x-caido-replay",
  "x-mitmproxy",
];

function stripHopByHop(headers, { isRequest = false } = {}) {
  const out = {};
  const connTokens = new Set();
  const connVal = headers?.connection;
  if (!isRequest && typeof connVal === "string") {
    for (const tok of connVal.split(",")) {
      const t = tok.trim().toLowerCase();
      if (t && !PROTECTED_FROM_CONN_STRIP.has(t) && !t.startsWith("x-auth-") && !t.startsWith("cf-")) {
        connTokens.add(t);
      }
    }
  }
  for (const [k, v] of Object.entries(headers || {})) {
    const kl = k.toLowerCase();
    if (HOP_BY_HOP_HEADERS.has(kl) || connTokens.has(kl)) continue;
    out[k] = v;
  }
  return out;
}

function escapeHtmlAttr(s) {
  return String(s).replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
}

function readRequestBody(req, maxBytes = 1024 * 1024) {
  if (req.readableEnded) {
    return Promise.resolve(Buffer.alloc(0));
  }
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    let settled = false;

    const finish = (err, val) => {
      if (settled) return;
      settled = true;
      req.removeListener("data", onData);
      req.removeListener("end", onEnd);
      req.removeListener("error", onError);
      req.removeListener("aborted", onAborted);
      if (err) reject(err);
      else resolve(val);
    };

    const onData = (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        req.pause();
        finish(Object.assign(new Error("BODY_TOO_LARGE"), { statusCode: 413 }));
        return;
      }
      chunks.push(chunk);
    };
    const onEnd = () => finish(null, Buffer.concat(chunks));
    const onError = (err) => finish(err);
    const onAborted = () => finish(Object.assign(new Error("REQUEST_ABORTED"), { statusCode: 400 }));

    req.on("data", onData);
    req.on("end", onEnd);
    req.on("error", onError);
    req.on("aborted", onAborted);
  });
}

function sendJson(res, status, obj, extraHeaders = {}) {
  if (res.headersSent || res.writableEnded) return;
  const payload = JSON.stringify(obj);
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
    "Content-Length": Buffer.byteLength(payload),
    ...extraHeaders,
  });
  res.end(payload);
}

function validateHandshakeClientHeaders(req, mode, { requireScriptDest = false, fromTrustedProxy = false } = {}) {
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

  if (sfs.includes("cross-site")) {
    return { ok: false, status: 403, error: "CROSS_SITE_HANDSHAKE_DENIED" };
  }
  if (origin && host) {
    try {
      const u = new URL(origin);
      if ((u.protocol !== "http:" && u.protocol !== "https:") || u.username || u.password) {
        return { ok: false, status: 403, error: "INVALID_ORIGIN_DENIED" };
      }
      const normHost = host.endsWith(":80") && u.protocol === "http:" ? host.slice(0, -3) : (host.endsWith(":443") && u.protocol === "https:" ? host.slice(0, -4) : host);
      if (u.host.toLowerCase() !== normHost) {
        return { ok: false, status: 403, error: "CROSS_ORIGIN_HANDSHAKE_DENIED" };
      }
    } catch {
      return { ok: false, status: 403, error: "INVALID_ORIGIN_DENIED" };
    }
  }

  if (mode === "strict" || mode === "balanced") {
    for (const ph of PROXY_HANDSHAKE_LEAK_HEADERS) {
      if (headers[ph] !== undefined) {
        return { ok: false, status: 403, error: "PROXY_HEADER_DENIED" };
      }
    }
    if (isCliOrProxyUa(ua, secChUa)) {
      return { ok: false, status: 403, error: "NON_BROWSER_HANDSHAKE_DENIED" };
    }
    const cm = /Chrome\/(\d+)/i.exec(ua);
    const fm = /Firefox\/(\d+)/i.exec(ua);
    const claimsModern = (cm && Number(cm[1]) >= 80) || (fm && Number(fm[1]) >= 90);
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
      if (!fromTrustedProxy && conn === "close") {
        return { ok: false, status: 403, error: "REPEATER_CONNECTION_CLOSE" };
      }
    }
  }

  return { ok: true };
}

function isHtmlBootstrapNavigation(req) {
  const headers = req.headers || {};
  if (req.method !== "GET") return false;
  const accept = String(headers["accept"] || "").toLowerCase();
  const sfm = String(headers["sec-fetch-mode"] || "").trim().toLowerCase();
  const sfd = String(headers["sec-fetch-dest"] || "").trim().toLowerCase();
  const ua = String(headers["user-agent"] || "");
  if (!accept.includes("text/html")) return false;
  if (isCliOrProxyUa(ua, headers["sec-ch-ua"])) return false;
  if (headers["content-length"] && headers["transfer-encoding"]) return false;
  if (PROXY_HANDSHAKE_LEAK_HEADERS.some((h) => headers[h] !== undefined)) return false;
  if (headers["x-original-url"] || headers["x-rewrite-url"]) return false;
  const cm = /Chrome\/(\d+)/i.exec(ua);
  const fm = /Firefox\/(\d+)/i.exec(ua);
  const claimsModern = (cm && Number(cm[1]) >= 80) || (fm && Number(fm[1]) >= 90);
  if (claimsModern && (sfm !== "navigate" || sfd !== "document")) return false;
  return true;
}

/**
 * Plug-and-play middleware for raw Node `http.createServer`, Express, or Connect.
 * Serves `/__proxysnare/guard.js`, `/__proxysnare/boot`, `/__proxysnare/handshake` (PS_ECDH_V2),
 * and `/__proxysnare/health`, and inspects protected requests.
 */
function createProxySnareMiddleware(options = {}) {
  const basePath = String(options.basePath || "/__proxysnare").replace(/\/+$/, "") || "/__proxysnare";
  const exposeDebugHeaders = options.exposeDebugHeaders !== false;
  const engine = createProxySnareEngine(options);
  const clientRules = engine.serializeProtectedPathsForClient();

  async function handleInner(req, res, next) {
    const urlStr = req.originalUrl || req.url || "/";
    const pathname = normalizePathname(urlStr);
    const remoteRaw = String(req?.socket?.remoteAddress || req?.ip || "").trim();
    const fromTrustedProxy = Boolean(remoteRaw && engine.trustedProxies.size > 0 && engine.trustedProxies.has(remoteRaw));

    if (req.method === "GET" && pathname === `${basePath}/guard.js`) {
      const ip = engine.extractClientIp(req);
      const ua = String(req.headers["user-agent"] || "");
      const bootEligible =
        engine.mode !== "off" &&
        validateHandshakeClientHeaders(req, engine.mode, { requireScriptDest: true, fromTrustedProxy }).ok;
      // Gate boot-token stamping on per-IP rate limit so /guard.js cannot exhaust maxBootTokens!
      const boot = bootEligible && engine.allowHandshake(ip) ? engine.issueBootChallenge({ ip, userAgent: ua }) : null;
      const script = buildBrowserGuardScript({
        basePath,
        protectedRules: clientRules,
        initialBoot: boot,
      });
      res.writeHead(200, {
        "Content-Type": "application/javascript; charset=utf-8",
        "Cache-Control": "no-store, private",
        "Vary": "User-Agent",
        "X-Content-Type-Options": "nosniff",
        "Content-Length": Buffer.byteLength(script),
      });
      res.end(script);
      return true;
    }

    if (req.method === "GET" && pathname === `${basePath}/health`) {
      sendJson(res, 200, { ok: true, mode: engine.mode });
      return true;
    }

    if (req.method === "GET" && pathname === `${basePath}/boot`) {
      const hdrCheck = validateHandshakeClientHeaders(req, engine.mode, { fromTrustedProxy });
      if (!hdrCheck.ok) {
        sendJson(res, hdrCheck.status, { ok: false, error: hdrCheck.error });
        return true;
      }
      const ip = engine.extractClientIp(req);
      if (!engine.allowHandshake(ip)) {
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

    if (req.method === "POST" && pathname === `${basePath}/handshake`) {
      const hdrCheck = validateHandshakeClientHeaders(req, engine.mode, { fromTrustedProxy });
      if (!hdrCheck.ok) {
        sendJson(res, hdrCheck.status, { ok: false, error: hdrCheck.error });
        return true;
      }
      const ip = engine.extractClientIp(req);
      if (!engine.allowHandshake(ip)) {
        sendJson(res, 429, { ok: false, error: "HANDSHAKE_RATE_LIMITED" });
        return true;
      }

      let hsBody = {};
      if (req.rawBody && Buffer.isBuffer(req.rawBody)) {
        try {
          hsBody = req.rawBody.length > 0 ? JSON.parse(req.rawBody.toString("utf8")) : {};
        } catch {
          sendJson(res, 400, { ok: false, error: "BAD_HANDSHAKE_JSON" });
          return true;
        }
      } else if (req._body && req.body && typeof req.body === "object" && !Buffer.isBuffer(req.body)) {
        hsBody = req.body;
      } else if (!req.readableEnded) {
        try {
          const raw = await readRequestBody(req, 4096);
          hsBody = raw.length > 0 ? JSON.parse(raw.toString("utf8")) : {};
        } catch (e) {
          sendJson(res, e.statusCode || 400, { ok: false, error: "BAD_HANDSHAKE" });
          return true;
        }
      }

      if (!hsBody || typeof hsBody !== "object" || Array.isArray(hsBody)) {
        sendJson(res, 400, { ok: false, error: "BAD_HANDSHAKE" });
        return true;
      }

      const ua = req.headers["user-agent"] || "";
      if (engine.mode !== "off" && engine.requireBootToken) {
        const bootRes = engine.consumeBootChallenge({
          bootToken: hsBody.bootToken,
          powNonce: hsBody.powNonce,
          ip,
          userAgent: ua,
        });
        if (!bootRes.ok) {
          sendJson(res, 403, { ok: false, error: bootRes.error });
          return true;
        }
      }

      // HTTP /handshake ALWAYS enforces ephemeral ECDH P-256 (PS_ECDH_V2) — ZERO plaintext sessionKeyHex on the wire!
      if (typeof hsBody.clientPubB64 !== "string" || !hsBody.clientPubB64.trim()) {
        sendJson(res, 400, { ok: false, error: "ECDH_KEY_REQUIRED" });
        return true;
      }

      const sess = engine.issueSession({
        ip,
        userAgent: ua,
        origin: req.headers["origin"] || "",
        clientPubB64: hsBody.clientPubB64,
      });
      if (!sess) {
        sendJson(res, 503, { ok: false, error: "SESSION_CAPACITY_EXCEEDED" });
        return true;
      }
      if (sess.error) {
        sendJson(res, 400, { ok: false, error: sess.error });
        return true;
      }
      sendJson(res, 200, { ok: true, ...sess }, { "Vary": "Origin, User-Agent" });
      return true;
    }

    const overrideUrls = [req.headers?.["x-original-url"], req.headers?.["x-rewrite-url"]]
      .flat()
      .filter((u) => typeof u === "string" && u.trim() !== "");
    const isProtected =
      engine.isPathProtected(urlStr) || overrideUrls.some((u) => engine.isPathProtected(u));
    const hasPsHeader = Object.keys(req.headers || {}).some((k) => k.toLowerCase().startsWith("x-ps-"));

    const isCorsPreflight =
      req.method === "OPTIONS" &&
      req.headers?.["access-control-request-method"] &&
      req.headers?.["origin"] &&
      !req.headers?.["content-length"] &&
      !req.headers?.["transfer-encoding"];
    const methodHasBody =
      req.method !== "GET" &&
      req.method !== "HEAD" &&
      !(req.method === "OPTIONS" && isCorsPreflight);

    let bodyBuf = Buffer.alloc(0);
    const reqCt = String(req.headers?.["content-type"] || "").toLowerCase();
    if (req.rawBody && Buffer.isBuffer(req.rawBody)) {
      bodyBuf = req.rawBody;
    } else if (methodHasBody && Buffer.isBuffer(req.body)) {
      bodyBuf = req.body;
    } else if (methodHasBody && typeof req.body === "string") {
      bodyBuf = Buffer.from(req.body, "utf8");
    } else if (methodHasBody && req._body && req.body && typeof req.body === "object") {
      if (
        String(req.headers?.["content-length"] || "").trim() === "0" &&
        !req.headers?.["transfer-encoding"] &&
        Object.keys(req.body).length === 0
      ) {
        bodyBuf = Buffer.alloc(0);
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
    } else if ((isProtected || hasPsHeader) && methodHasBody) {
      try {
        bodyBuf = await readRequestBody(req, options.maxBodyBytes || 1024 * 1024);
      } catch (e) {
        sendJson(res, e.statusCode || 400, { ok: false, error: e.message || "BAD_BODY" });
        return true;
      }
      req.rawBody = bodyBuf;
      req._body = true;
      const ct = String(req.headers["content-type"] || "").toLowerCase();
      const isEmptyPlaceholder =
        req.body &&
        typeof req.body === "object" &&
        !Array.isArray(req.body) &&
        !Buffer.isBuffer(req.body) &&
        Object.keys(req.body).length === 0;
      if (req.body === undefined || isEmptyPlaceholder) {
        if (/\bapplication\/(?:[a-z0-9.+-]+\+)?json\b/.test(ct)) {
          if (bodyBuf.length === 0) {
            req.body = {};
          } else {
            try {
              req.body = JSON.parse(bodyBuf.toString("utf8"));
            } catch {
              // leave req.body undefined for downstream handler
            }
          }
        } else if (ct.includes("application/x-www-form-urlencoded")) {
          req.body = querystring.parse(bodyBuf.toString("utf8"));
        } else if (ct.startsWith("text/")) {
          req.body = bodyBuf.toString("utf8");
        }
      }
    }
    req.proxySnareBody = bodyBuf;

    const rawHeaderLines = Array.isArray(req.rawHeaders)
      ? req.rawHeaders.reduce((acc, val, idx) => {
          if (idx % 2 === 0) acc.push(`${val}: ${req.rawHeaders[idx + 1] || ""}`);
          return acc;
        }, [])
      : null;

    const verdict = engine.inspectRequest({
      method: req.method,
      url: urlStr,
      headers: req.headers,
      body: bodyBuf,
      ip: engine.extractClientIp(req),
      rawHeaderLines,
      fromTrustedProxy,
    });
    req.proxySnare = verdict;

    if (exposeDebugHeaders) {
      res.setHeader("X-ProxySnare-Score", String(verdict.score));
      res.setHeader("X-ProxySnare-Mode", verdict.mode);
    }
    if (verdict.nextCanary) {
      res.setHeader("X-PS-Next-Canary", verdict.nextCanary);
    }
    if (verdict.rehandshakeRecommended) {
      res.setHeader("X-PS-Rehandshake", "1");
    }

    if (verdict.blocked) {
      const extra = verdict.rehandshakeRecommended ? { "X-PS-Rehandshake": "1" } : {};
      const body = exposeDebugHeaders
        ? {
            ok: false,
            error: "REPEATER_OR_PROXY_BLOCKED",
            score: verdict.score,
            threshold: verdict.threshold,
            reasons: verdict.reasons.map((r) => r.code),
          }
        : { ok: false, error: "REPEATER_OR_PROXY_BLOCKED" };
      sendJson(res, 403, body, extra);
      return true;
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
      sendJson(res, 500, { ok: false, error: "INTERNAL_ERROR" });
      return true;
    });
  }

  handle.engine = engine;
  return handle;
}

function decodeHtmlBody(rawBuf, contentEncoding, maxOutputLength = 5 * 1024 * 1024) {
  const enc = String(contentEncoding || "").trim().toLowerCase();
  if (!enc || enc === "identity") return rawBuf;
  const opts = { maxOutputLength };
  if (enc === "gzip") return zlib.gunzipSync(rawBuf, opts);
  if (enc === "deflate") return zlib.inflateSync(rawBuf, opts);
  if (enc === "br") return zlib.brotliDecompressSync(rawBuf, opts);
  return null;
}

function injectGuardIntoHtml(html, basePath) {
  const safeSrc = escapeHtmlAttr(`${basePath}/guard.js`);
  const tag = `<script src="${safeSrc}"></script>`;
  if (new RegExp(`<script\\b[^>]*\\bsrc=["']${safeSrc.replace(/[.*+?^${}()|[\]\\]/g, "\\$&")}["']`, "i").test(html)) {
    return html;
  }
  if (/<head(?:\s[^>]*)?>/i.test(html)) {
    return html.replace(/<head(?:\s[^>]*)?>/i, (m) => `${m}${tag}`);
  }
  if (/<\/head>/i.test(html)) {
    return html.replace(/<\/head>/i, (m) => `${tag}${m}`);
  }
  if (/<body(?:\s[^>]*)?>/i.test(html)) {
    return html.replace(/<body(?:\s[^>]*)?>/i, (m) => `${m}${tag}`);
  }
  return `${tag}${html}`;
}

function encodeForwardPathname(normPath) {
  return normPath
    .split("/")
    .map((seg) => encodeURIComponent(seg.replace(/%3F/gi, "?")))
    .join("/");
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
  const injectGuard = options.injectGuard !== false;
  const exposeDebugHeaders = options.exposeDebugHeaders !== false;
  const maxHtmlBytes = Number.isFinite(options.maxHtmlBytes) && options.maxHtmlBytes > 0 ? options.maxHtmlBytes : 5 * 1024 * 1024;
  const upstreamTimeoutMs = Number.isFinite(options.upstreamTimeoutMs) && options.upstreamTimeoutMs > 0 ? options.upstreamTimeoutMs : 30_000;
  const middleware = createProxySnareMiddleware({ ...options, basePath, exposeDebugHeaders });
  const clientMod = targetUrl.protocol === "https:" ? https : http;
  const baseTargetPath = targetUrl.pathname && targetUrl.pathname !== "/" ? targetUrl.pathname.replace(/\/+$/, "") : "";

  const server = http.createServer((req, res) => {
    const htmlBootstrapProbe =
      injectGuard &&
      middleware.engine.mode !== "off" &&
      middleware.engine.mode !== "monitor" &&
      middleware.engine.isPathProtected("/") &&
      !Object.keys(req.headers || {}).some((k) => k.toLowerCase().startsWith("x-ps-")) &&
      isHtmlBootstrapNavigation(req) &&
      !normalizePathname(req.url || "/").startsWith(`${basePath}/`);

    const middlewareStep = htmlBootstrapProbe ? Promise.resolve(false) : Promise.resolve(middleware(req, res));

    middlewareStep
      .then((handled) => {
        if (handled) return;

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
        const normFwd = normalizePathname(rawFwd);
        const trailingSlash = rawFwd.length > 1 && rawFwd.endsWith("/") && normFwd !== "/" ? "/" : "";
        let fwdPath = `${encodeForwardPathname(normFwd)}${trailingSlash}${safeSearch}`;
        if (baseTargetPath) fwdPath = `${baseTargetPath}${fwdPath}`;

        const fwdHeaders = stripHopByHop(req.headers, { isRequest: true });
        delete fwdHeaders["x-original-url"];
        delete fwdHeaders["x-rewrite-url"];
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
        if (htmlBootstrapProbe) {
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

            // For wildcard HTML-bootstrap probes, ONLY allow genuine text/html responses (or header-only 3xx redirects without forwarding any non-HTML body!)
            if (htmlBootstrapProbe && !ct.includes("text/html")) {
              if (statusCode >= 301 && statusCode <= 308 && statusCode !== 304 && Boolean(upRes.headers["location"])) {
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
                  options.onDetect({
                    ok: false,
                    blocked: true,
                    score: middleware.engine.mode === "strict" ? 8 : 6,
                    threshold: middleware.engine.mode === "strict" ? 4 : 6,
                    mode: middleware.engine.mode,
                    reasons: [{ code: "REPEATER_PROOF_MISSING", weight: middleware.engine.mode === "strict" ? 8 : 6, detail: "Non-HTML protected response rejected on wildcard HTML bootstrap probe" }],
                    nextCanary: null,
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
              Boolean(req.headers["access-control-request-method"]) &&
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
                    threshold: middleware.engine.mode === "strict" ? 4 : 6,
                    mode: middleware.engine.mode,
                    reasons: [{ code: "CORS_PREFLIGHT_NOT_ENABLED", weight: 8, detail: "Unauthenticated OPTIONS preflight targeting non-CORS protected route" }],
                    nextCanary: null,
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
            }
            if (req.proxySnare?.rehandshakeRecommended) {
              outHeaders["x-ps-rehandshake"] = "1";
            }
            if (exposeDebugHeaders) {
              outHeaders["x-proxysnare-score"] = String(req.proxySnare?.score ?? 0);
            }

            const canHaveBody = req.method !== "HEAD" && statusCode !== 204 && statusCode !== 304;
            if (injectGuard && canHaveBody && ct.includes("text/html")) {
              const chunks = [];
              let totalBytes = 0;
              let overflowed = false;
              upRes.on("data", (c) => {
                if (overflowed) {
                  res.write(c);
                  return;
                }
                totalBytes += c.length;
                if (totalBytes > maxHtmlBytes) {
                  overflowed = true;
                  res.writeHead(statusCode, outHeaders);
                  for (const prev of chunks) res.write(prev);
                  chunks.length = 0;
                  res.write(c);
                  return;
                }
                chunks.push(c);
              });
              upRes.on("end", () => {
                if (overflowed) {
                  res.end();
                  return;
                }
                const rawBuf = Buffer.concat(chunks);
                const ce = outHeaders["content-encoding"];
                let decoded = rawBuf;
                if (ce) {
                  try {
                    const maybe = decodeHtmlBody(rawBuf, ce, maxHtmlBytes);
                    if (!maybe) {
                      res.writeHead(statusCode, outHeaders);
                      res.end(rawBuf);
                      return;
                    }
                    decoded = maybe;
                    delete outHeaders["content-encoding"];
                  } catch {
                    res.writeHead(statusCode, outHeaders);
                    res.end(rawBuf);
                    return;
                  }
                }
                const html = injectGuardIntoHtml(decoded.toString("utf8"), basePath);
                const buf = Buffer.from(html, "utf8");
                outHeaders["content-length"] = String(buf.length);
                delete outHeaders["etag"];
                delete outHeaders["last-modified"];
                res.writeHead(statusCode, outHeaders);
                res.end(buf);
              });
              return;
            }

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
};
