"use strict";

const http = require("node:http");
const https = require("node:https");
const zlib = require("node:zlib");
const { createProxySnareEngine, normalizePathname } = require("./detector.js");
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

function stripHopByHop(headers) {
  const out = {};
  const connTokens = new Set();
  const connVal = headers?.connection;
  if (typeof connVal === "string") {
    for (const tok of connVal.split(",")) {
      const t = tok.trim().toLowerCase();
      if (t) connTokens.add(t);
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
  if (req.readableEnded || req.complete) {
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
        // Pause rather than destroy so caller can write HTTP 413 cleanly
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

/**
 * Plug-and-play middleware for raw Node `http.createServer`, Express, or Connect.
 * Serves `/__proxysnare/guard.js` and `/__proxysnare/handshake`, and inspects requests.
 */
function createProxySnareMiddleware(options = {}) {
  const basePath = String(options.basePath || "/__proxysnare").replace(/\/+$/, "") || "/__proxysnare";
  const exposeDebugHeaders = options.exposeDebugHeaders !== false;
  const engine = createProxySnareEngine(options);
  const guardJs = buildBrowserGuardScript({
    basePath,
    protectedRules: engine.serializeProtectedPathsForClient(),
  });

  async function handleInner(req, res, next) {
    const urlStr = req.originalUrl || req.url || "/";
    const pathname = normalizePathname(urlStr);

    if (req.method === "GET" && pathname === `${basePath}/guard.js`) {
      res.writeHead(200, {
        "Content-Type": "application/javascript; charset=utf-8",
        "Cache-Control": "no-store",
        "X-Content-Type-Options": "nosniff",
        "Content-Length": Buffer.byteLength(guardJs),
      });
      res.end(guardJs);
      return true;
    }

    if (req.method === "GET" && pathname === `${basePath}/health`) {
      sendJson(res, 200, { ok: true, mode: engine.mode });
      return true;
    }

    if (req.method === "POST" && pathname === `${basePath}/handshake`) {
      // Reject cross-site CSRF handshakes and enforce per-IP handshake rate limiting
      const sfs = String(req.headers["sec-fetch-site"] || "").toLowerCase();
      if (sfs.includes("cross-site")) {
        sendJson(res, 403, { ok: false, error: "CROSS_SITE_HANDSHAKE_DENIED" });
        return true;
      }
      const ip = engine.extractClientIp(req);
      if (!engine.allowHandshake(ip)) {
        sendJson(res, 429, { ok: false, error: "HANDSHAKE_RATE_LIMITED" });
        return true;
      }
      // Safe whether express.json() ran before or after this middleware!
      if (!req.rawBody && !req._body && !req.readableEnded) {
        try {
          await readRequestBody(req, 4096);
        } catch (e) {
          sendJson(res, e.statusCode || 400, { ok: false, error: "BAD_HANDSHAKE" });
          return true;
        }
      }
      const sess = engine.issueSession({
        ip,
        userAgent: req.headers["user-agent"] || "",
        origin: req.headers["origin"] || "",
      });
      sendJson(res, 200, { ok: true, ...sess }, { "Vary": "Origin, User-Agent" });
      return true;
    }

    const isProtected = engine.isPathProtected(pathname);
    const hasPsHeader = Object.keys(req.headers || {}).some((k) => k.toLowerCase().startsWith("x-ps-"));

    // Only buffer body on protected paths or when Proof-of-Freshness headers are present
    // (never breaks large file uploads or streaming endpoints on unprotected routes).
    let bodyBuf = Buffer.alloc(0);
    if (req.rawBody && Buffer.isBuffer(req.rawBody)) {
      bodyBuf = req.rawBody;
    } else if (Buffer.isBuffer(req.body)) {
      bodyBuf = req.body;
    } else if (typeof req.body === "string") {
      bodyBuf = Buffer.from(req.body, "utf8");
    } else if (req.body && typeof req.body === "object") {
      bodyBuf = Buffer.from(JSON.stringify(req.body), "utf8");
    } else if ((isProtected || hasPsHeader) && req.method !== "GET" && req.method !== "HEAD" && req.method !== "OPTIONS") {
      try {
        bodyBuf = await readRequestBody(req, options.maxBodyBytes || 1024 * 1024);
      } catch (e) {
        sendJson(res, e.statusCode || 400, { ok: false, error: e.message || "BAD_BODY" });
        return true;
      }
      req.rawBody = bodyBuf;
      req._body = true; // prevents downstream express.json() from hanging on consumed stream
      const ct = String(req.headers["content-type"] || "").toLowerCase();
      if (ct.includes("application/json") && bodyBuf.length > 0 && req.body === undefined) {
        try {
          req.body = JSON.parse(bodyBuf.toString("utf8"));
        } catch {
          // leave req.body undefined for downstream handler to reject malformed JSON
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
    });
    req.proxySnare = verdict;

    if (exposeDebugHeaders) {
      res.setHeader("X-ProxySnare-Score", String(verdict.score));
      res.setHeader("X-ProxySnare-Mode", verdict.mode);
    }
    if (verdict.nextCanary) {
      res.setHeader("X-PS-Next-Canary", verdict.nextCanary);
    }

    if (verdict.blocked) {
      const body = exposeDebugHeaders
        ? {
            ok: false,
            error: "REPEATER_OR_PROXY_BLOCKED",
            score: verdict.score,
            threshold: verdict.threshold,
            reasons: verdict.reasons.map((r) => r.code),
          }
        : { ok: false, error: "REPEATER_OR_PROXY_BLOCKED" };
      sendJson(res, 403, body);
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

function decodeHtmlBody(rawBuf, contentEncoding) {
  const enc = String(contentEncoding || "").trim().toLowerCase();
  if (!enc || enc === "identity") return rawBuf;
  if (enc === "gzip") return zlib.gunzipSync(rawBuf);
  if (enc === "deflate") return zlib.inflateSync(rawBuf);
  if (enc === "br") return zlib.brotliDecompressSync(rawBuf);
  return null;
}

function injectGuardIntoHtml(html, basePath) {
  const safeSrc = escapeHtmlAttr(`${basePath}/guard.js`);
  const tag = `<script src="${safeSrc}"></script>`;
  if (html.includes(`${basePath}/guard.js`)) return html;
  // Inject early in <head> (so guard instruments fetch/XHR before inline scripts run) or before </head>
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

/**
 * Standalone reverse-proxy shield that sits in front of ANY backend (`target`),
 * auto-injects `/__proxysnare/guard.js` into HTML responses, and blocks Caido/Burp Repeater.
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
    Promise.resolve(middleware(req, res))
      .then((handled) => {
        if (handled) return;

        // Sanitize request-target so absolute-form URIs cannot abuse upstream as an open proxy
        let fwdPath = req.url || "/";
        if (/^https?:\/\//i.test(fwdPath)) {
          try {
            const parsed = new URL(fwdPath);
            fwdPath = `${parsed.pathname}${parsed.search}`;
          } catch {
            fwdPath = "/";
          }
        }
        if (!fwdPath.startsWith("/")) fwdPath = "/" + fwdPath;
        if (baseTargetPath) fwdPath = `${baseTargetPath}${fwdPath}`;

        const fwdHeaders = stripHopByHop(req.headers);
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
        // Only ask for identity encoding when client asks for HTML (preserves compression on JS/CSS/API!)
        const acceptHdr = String(req.headers["accept"] || "").toLowerCase();
        if (injectGuard && acceptHdr.includes("text/html")) {
          fwdHeaders["accept-encoding"] = "identity";
        }

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
              if (!res.headersSent) sendJson(res, 502, { ok: false, error: "UPSTREAM_ERROR" });
              else res.destroy();
            });

            const statusCode = upRes.statusCode || 200;
            const ct = String(upRes.headers["content-type"] || "").toLowerCase();
            const outHeaders = stripHopByHop(upRes.headers);
            if (req.proxySnare?.nextCanary) {
              outHeaders["x-ps-next-canary"] = req.proxySnare.nextCanary;
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
                    const maybe = decodeHtmlBody(rawBuf, ce);
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
      return new Promise((resolve) => server.close(() => resolve()));
    },
  };
}

module.exports = {
  createProxySnareMiddleware,
  createProxySnareServer,
};
