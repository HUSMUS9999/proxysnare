"use strict";

const http = require("node:http");
const https = require("node:https");
const { createProxySnareEngine } = require("./detector.js");
const { buildBrowserGuardScript } = require("./browser-guard.js");

function readRequestBody(req, maxBytes = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let total = 0;
    req.on("data", (chunk) => {
      total += chunk.length;
      if (total > maxBytes) {
        reject(Object.assign(new Error("BODY_TOO_LARGE"), { statusCode: 413 }));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function sendJson(res, status, obj, extraHeaders = {}) {
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
 * Serves `/__proxysnare/guard.js` and `/__proxysnare/handshake`, and inspects every request.
 */
function createProxySnareMiddleware(options = {}) {
  const basePath = options.basePath || "/__proxysnare";
  const engine = createProxySnareEngine(options);
  const guardJs = buildBrowserGuardScript({
    basePath,
    protectedPaths: engine.protectedPaths.filter((p) => typeof p === "string"),
  });

  async function handle(req, res, next) {
    const urlStr = req.url || "/";
    const pathname = urlStr.split("?")[0] || "/";

    if (req.method === "GET" && pathname === `${basePath}/guard.js`) {
      res.writeHead(200, {
        "Content-Type": "application/javascript; charset=utf-8",
        "Cache-Control": "no-store",
        "Content-Length": Buffer.byteLength(guardJs),
      });
      res.end(guardJs);
      return true;
    }

    if (req.method === "GET" && pathname === `${basePath}/health`) {
      sendJson(res, 200, { ok: true, mode: engine.mode, threshold: engine.threshold });
      return true;
    }

    if (req.method === "POST" && pathname === `${basePath}/handshake`) {
      try {
        await readRequestBody(req, 4096);
      } catch {
        sendJson(res, 400, { ok: false, error: "BAD_HANDSHAKE" });
        return true;
      }
      const ip = engine.extractClientIp(req);
      const sess = engine.issueSession({
        ip,
        userAgent: req.headers["user-agent"] || "",
        origin: req.headers["origin"] || "",
      });
      sendJson(res, 200, { ok: true, ...sess });
      return true;
    }

    // Read body once; reuse `req.rawBody` if already captured (e.g. via express.json({ verify }))
    let bodyBuf = Buffer.alloc(0);
    if (req.rawBody && Buffer.isBuffer(req.rawBody)) {
      bodyBuf = req.rawBody;
    } else if (req.body && typeof req.body === "object" && !Buffer.isBuffer(req.body)) {
      bodyBuf = Buffer.from(JSON.stringify(req.body), "utf8");
    } else if (req.method !== "GET" && req.method !== "HEAD") {
      try {
        bodyBuf = await readRequestBody(req, options.maxBodyBytes || 1024 * 1024);
      } catch (e) {
        sendJson(res, e.statusCode || 400, { ok: false, error: e.message || "BAD_BODY" });
        return true;
      }
      req.rawBody = bodyBuf;
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

    res.setHeader("X-ProxySnare-Score", String(verdict.score));
    res.setHeader("X-ProxySnare-Mode", verdict.mode);
    if (verdict.nextCanary) {
      res.setHeader("X-PS-Next-Canary", verdict.nextCanary);
    }

    if (verdict.blocked) {
      sendJson(res, 403, {
        ok: false,
        error: "REPEATER_OR_PROXY_BLOCKED",
        score: verdict.score,
        threshold: verdict.threshold,
        reasons: verdict.reasons.map((r) => r.code),
      });
      return true;
    }

    if (typeof next === "function") {
      next();
    }
    return false;
  }

  handle.engine = engine;
  return handle;
}

/**
 * Standalone reverse-proxy shield that sits in front of ANY backend (`target`),
 * auto-injects `/__proxysnare/guard.js` into HTML responses, and blocks Caido/Burp Repeater.
 */
function createProxySnareServer(options = {}) {
  const targetUrl = new URL(options.target || "http://127.0.0.1:3000");
  const basePath = options.basePath || "/__proxysnare";
  const injectGuard = options.injectGuard !== false;
  const middleware = createProxySnareMiddleware({ ...options, basePath });
  const clientMod = targetUrl.protocol === "https:" ? https : http;

  const server = http.createServer(async (req, res) => {
    const handled = await middleware(req, res);
    if (handled) return;

    const fwdHeaders = { ...req.headers, host: targetUrl.host };
    if (req.proxySnareBody && req.proxySnareBody.length > 0) {
      fwdHeaders["content-length"] = String(req.proxySnareBody.length);
      delete fwdHeaders["transfer-encoding"];
    }
    if (injectGuard) {
      delete fwdHeaders["accept-encoding"]; // keep HTML uncompressed for clean script injection
    }

    const upstreamReq = clientMod.request(
      {
        protocol: targetUrl.protocol,
        hostname: targetUrl.hostname,
        port: targetUrl.port || (targetUrl.protocol === "https:" ? 443 : 80),
        method: req.method,
        path: req.url,
        headers: fwdHeaders,
      },
      (upRes) => {
        const ct = String(upRes.headers["content-type"] || "").toLowerCase();
        const outHeaders = { ...upRes.headers };
        if (req.proxySnare?.nextCanary) {
          outHeaders["x-ps-next-canary"] = req.proxySnare.nextCanary;
        }
        outHeaders["x-proxysnare-score"] = String(req.proxySnare?.score ?? 0);

        if (injectGuard && ct.includes("text/html")) {
          const chunks = [];
          upRes.on("data", (c) => chunks.push(c));
          upRes.on("end", () => {
            let html = Buffer.concat(chunks).toString("utf8");
            const tag = `<script src="${basePath}/guard.js"></script>`;
            if (!html.includes(`${basePath}/guard.js`)) {
              html = html.includes("</head>")
                ? html.replace("</head>", `${tag}</head>`)
                : html.includes("<body")
                  ? html.replace(/<body[^>]*>/i, (m) => `${m}${tag}`)
                  : `${tag}${html}`;
            }
            const buf = Buffer.from(html, "utf8");
            outHeaders["content-length"] = String(buf.length);
            delete outHeaders["transfer-encoding"];
            res.writeHead(upRes.statusCode || 200, outHeaders);
            res.end(buf);
          });
          return;
        }

        res.writeHead(upRes.statusCode || 200, outHeaders);
        upRes.pipe(res);
      }
    );

    upstreamReq.on("error", (err) => {
      if (!res.headersSent) {
        sendJson(res, 502, { ok: false, error: "UPSTREAM_UNREACHABLE", detail: err.message });
      }
    });

    if (req.proxySnareBody && req.proxySnareBody.length > 0) {
      upstreamReq.write(req.proxySnareBody);
    }
    upstreamReq.end();
  });

  return {
    server,
    engine: middleware.engine,
    listen(port = 8080, host = "127.0.0.1") {
      return new Promise((resolve) => {
        server.listen(port, host, () => {
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
