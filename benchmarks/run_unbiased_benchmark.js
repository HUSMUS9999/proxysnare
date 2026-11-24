#!/usr/bin/env node
"use strict";

/**
 * ProxySnare — Multi-Defense Live HTTP Benchmark Suite.
 *
 * Compares ProxySnare (balanced & strict) head-to-head against 6 standard HTTP
 * defense baselines over real local TCP/HTTP sockets:
 *   1. Unprotected Node.js HTTP API (baseline control)
 *   2. Double-Submit CSRF Token Guard (standard CSRF pattern)
 *   3. Sliding-Window Rate Limiter (60 req/min per IP)
 *   4. OWASP Fetch Metadata + Origin Guard (Sec-Fetch-Site + Origin)
 *   5. Stateless Short-TTL HMAC Signing (static key + 30s TTL, no nonce)
 *   6. Stateless HMAC (8s TTL) + Single-Use Nonce Cache (fair replay-resistant baseline)
 *   7. ProxySnare (balanced, 15s freshness)
 *   8. ProxySnare (strict, 8s freshness)
 *
 * Methodology:
 *   - 100 warmup requests per defense before timing so V8 JIT is hot for every row.
 *   - Client only computes HMAC for HMAC-based defenses (no crypto work billed to baseline/CSRF/RL/Fetch).
 *   - Burst Flood sends 75 UNIQUE fresh valid requests (NOT replaying an old nonce!) so it genuinely tests
 *     flood throttling rather than exact replay.
 *   - 300 sequential live POSTs measured per defense for median / p95 latency and throughput.
 */

const crypto = require("node:crypto");
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { performance } = require("node:perf_hooks");

const { createProxySnareMiddleware } = require("../src/index.js");

const STATIC_HMAC_KEY = "bench-static-client-signing-key-32b";
const CSRF_TOKEN = "csrf-tok-9f8e7d6c5b4a3210";
const BROWSER_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36";

function sha256Hex(buf) {
  return crypto.createHash("sha256").update(buf).digest("hex");
}

function hmacHex(key, msg) {
  return crypto.createHmac("sha256", key).update(msg, "utf8").digest("hex");
}

function readBody(req) {
  return new Promise((resolve) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", () => resolve(Buffer.concat(chunks)));
  });
}

function startServer(handler) {
  return new Promise((resolve) => {
    const srv = http.createServer(handler);
    srv.listen(0, "127.0.0.1", () => {
      resolve({
        server: srv,
        port: srv.address().port,
        base: `http://127.0.0.1:${srv.address().port}`,
        close: () => new Promise((r) => srv.close(r)),
      });
    });
  });
}

const keepAliveAgent = new http.Agent({ keepAlive: true, maxSockets: 8 });

function httpPost({ port, reqPath = "/api/transfer", headers = {}, body = '{"amount":42}', agent = keepAliveAgent }) {
  return new Promise((resolve, reject) => {
    const buf = Buffer.from(body, "utf8");
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port,
        path: reqPath,
        method: "POST",
        agent,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": buf.length,
          ...headers,
        },
      },
      (res) => {
        const chunks = [];
        res.on("data", (c) => chunks.push(c));
        res.on("end", () => {
          resolve({
            status: res.statusCode,
            headers: res.headers,
            body: Buffer.concat(chunks).toString("utf8"),
          });
        });
      }
    );
    req.on("error", reject);
    req.end(buf);
  });
}

async function buildDefenses() {
  const defs = [];

  // 1. Baseline: Unprotected Node.js HTTP API
  defs.push({
    id: "baseline",
    name: "Unprotected Node.js HTTP API",
    clientKind: "plain",
    clientJsRequired: false,
    worksForNonBrowserApis: true,
    srv: await startServer(async (req, res) => {
      await readBody(req);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"ok":true}');
    }),
  });

  // 2. Double-Submit CSRF Token Guard
  defs.push({
    id: "csrf_double_submit",
    name: "Double-Submit CSRF Guard",
    clientKind: "csrf",
    clientJsRequired: false,
    worksForNonBrowserApis: false,
    srv: await startServer(async (req, res) => {
      await readBody(req);
      const cookie = String(req.headers["cookie"] || "");
      const m = cookie.match(/csrf_tok=([^;]+)/);
      const hdr = String(req.headers["x-csrf-token"] || "");
      if (!m || !hdr || m[1] !== hdr) {
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end('{"error":"CSRF_MISMATCH"}');
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"ok":true}');
    }),
  });

  // 3. Sliding-Window Rate Limiter (60 req/min per IP)
  const rlHits = new Map();
  defs.push({
    id: "rate_limiter",
    name: "Rate Limiter (60 req/min/IP)",
    clientKind: "plain",
    clientJsRequired: false,
    worksForNonBrowserApis: true,
    resetState: () => rlHits.clear(),
    srv: await startServer(async (req, res) => {
      await readBody(req);
      const ip = req.socket.remoteAddress || "127.0.0.1";
      const now = Date.now();
      const arr = (rlHits.get(ip) || []).filter((t) => now - t < 60_000);
      arr.push(now);
      rlHits.set(ip, arr);
      if (arr.length > 60) {
        res.writeHead(429, { "Content-Type": "application/json" });
        res.end('{"error":"RATE_LIMITED"}');
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"ok":true}');
    }),
  });

  // 4. OWASP Fetch Metadata + Origin Guard
  defs.push({
    id: "fetch_metadata",
    name: "Fetch Metadata + Origin Guard",
    clientKind: "plain",
    clientJsRequired: false,
    worksForNonBrowserApis: false,
    srv: await startServer(async (req, res) => {
      await readBody(req);
      const sfs = String(req.headers["sec-fetch-site"] || "");
      const sfm = String(req.headers["sec-fetch-mode"] || "");
      const orig = String(req.headers["origin"] || "");
      if (sfs !== "same-origin" || !sfm || !orig.startsWith("http://127.0.0.1:")) {
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end('{"error":"FETCH_METADATA_BLOCKED"}');
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"ok":true}');
    }),
  });

  // 5. Stateless Short-TTL HMAC Signing (static key + 30s TTL, no nonce)
  defs.push({
    id: "stateless_hmac",
    name: "Stateless HMAC (30s TTL)",
    clientKind: "hmac",
    clientJsRequired: true,
    worksForNonBrowserApis: true,
    srv: await startServer(async (req, res) => {
      const body = await readBody(req);
      const ts = Number(req.headers["x-sig-ts"] || 0);
      const sig = String(req.headers["x-sig-hmac"] || "");
      if (!ts || Math.abs(Date.now() - ts) > 30_000) {
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end('{"error":"SIG_EXPIRED"}');
        return;
      }
      const expected = hmacHex(STATIC_HMAC_KEY, `${req.method}|${req.url}|${sha256Hex(body)}|${ts}`);
      if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end('{"error":"SIG_INVALID"}');
        return;
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"ok":true}');
    }),
  });

  // 6. Fair Replay-Resistant Baseline: Stateless HMAC (8s TTL) + Single-Use Nonce Cache
  const hmacNonces = new Map();
  defs.push({
    id: "hmac_8s_nonce",
    name: "HMAC (8s TTL) + Nonce Cache",
    clientKind: "hmac_nonce",
    clientJsRequired: true,
    worksForNonBrowserApis: true,
    resetState: () => hmacNonces.clear(),
    srv: await startServer(async (req, res) => {
      const body = await readBody(req);
      const ts = Number(req.headers["x-sig-ts"] || 0);
      const nonce = String(req.headers["x-sig-nonce"] || "");
      const sig = String(req.headers["x-sig-hmac"] || "");
      const now = Date.now();
      if (!ts || !nonce || now - ts > 8_000 || ts - now > 3_000) {
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end('{"error":"SIG_EXPIRED"}');
        return;
      }
      if (hmacNonces.has(nonce)) {
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end('{"error":"NONCE_REPLAYED"}');
        return;
      }
      const expected = hmacHex(STATIC_HMAC_KEY, `${req.method}|${req.url}|${sha256Hex(body)}|${ts}|${nonce}`);
      if (sig.length !== expected.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(expected))) {
        res.writeHead(403, { "Content-Type": "application/json" });
        res.end('{"error":"SIG_INVALID"}');
        return;
      }
      hmacNonces.set(nonce, now + 300_000);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"ok":true}');
    }),
  });

  // 7 & 8. ProxySnare (balanced & strict)
  for (const mode of ["balanced", "strict"]) {
    const mw = createProxySnareMiddleware({
      mode,
      protectedPaths: ["/api"],
      freshnessMs: mode === "strict" ? 8000 : 15000,
    });
    defs.push({
      id: `proxysnare_${mode}`,
      name: `ProxySnare (${mode})`,
      clientKind: "proxysnare",
      clientJsRequired: true,
      worksForNonBrowserApis: false,
      srv: await startServer(async (req, res) => {
        const handled = await mw(req, res);
        if (handled) return;
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end('{"ok":true}');
      }),
    });
  }

  return defs;
}

async function createClientHelper(def) {
  const port = def.srv.port;
  const baseHeaders = {
    "User-Agent": BROWSER_UA,
    "Origin": `http://127.0.0.1:${port}`,
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
    "Sec-CH-UA": '"Chromium";v="158", "Not.A/Brand";v="24", "Google Chrome";v="158"',
    "Sec-CH-UA-Platform": '"Linux"',
  };
  if (def.clientKind === "csrf") {
    baseHeaders["Cookie"] = `csrf_tok=${CSRF_TOKEN}`;
    baseHeaders["X-CSRF-Token"] = CSRF_TOKEN;
  }

  let psState = null;
  if (def.clientKind === "proxysnare") {
    const hs = await httpPost({ port, reqPath: "/__proxysnare/handshake", headers: baseHeaders, body: "{}" });
    const parsed = JSON.parse(hs.body);
    psState = {
      sid: parsed.sessionId,
      keyHex: parsed.sessionKeyHex,
      canary: parsed.canary,
      seq: 0,
    };
  }

  function buildSignedHeaders(body, reqPath = "/api/transfer") {
    const hdr = { ...baseHeaders };
    if (def.clientKind === "hmac") {
      const ts = Date.now();
      hdr["X-Sig-Ts"] = String(ts);
      hdr["X-Sig-Hmac"] = hmacHex(STATIC_HMAC_KEY, `POST|${reqPath}|${sha256Hex(Buffer.from(body))}|${ts}`);
    } else if (def.clientKind === "hmac_nonce") {
      const ts = Date.now();
      const nonce = crypto.randomBytes(12).toString("hex");
      hdr["X-Sig-Ts"] = String(ts);
      hdr["X-Sig-Nonce"] = nonce;
      hdr["X-Sig-Hmac"] = hmacHex(STATIC_HMAC_KEY, `POST|${reqPath}|${sha256Hex(Buffer.from(body))}|${ts}|${nonce}`);
    } else if (psState) {
      psState.seq += 1;
      const ts = Date.now();
      const nonce = crypto.randomBytes(12).toString("hex");
      const bh = sha256Hex(Buffer.from(body));
      const msg = `PS1|POST|${reqPath}|${bh}|${psState.seq}|${ts}|${nonce}|${psState.canary}`;
      const proof = hmacHex(Buffer.from(psState.keyHex, "hex"), msg);
      hdr["X-PS-Session"] = psState.sid;
      hdr["X-PS-Seq"] = String(psState.seq);
      hdr["X-PS-Ts"] = String(ts);
      hdr["X-PS-Nonce"] = nonce;
      hdr["X-PS-Canary"] = psState.canary;
      hdr["X-PS-Proof"] = proof;
    }
    return hdr;
  }

  async function sendClean(body = '{"amount":42}') {
    const headers = buildSignedHeaders(body);
    const resp = await httpPost({ port, headers, body });
    if (psState && resp.headers["x-ps-next-canary"]) {
      psState.canary = String(resp.headers["x-ps-next-canary"]);
    }
    return { resp, headers, body };
  }

  return { buildSignedHeaders, sendClean, baseHeaders };
}

function percentile(sorted, p) {
  if (!sorted.length) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

async function main() {
  const defs = await buildDefenses();
  const report = [];

  try {
    // Global V8 HTTP parser & loopback TCP warmup before measuring any row
    const warmBaseline = await createClientHelper(defs[0]);
    for (let g = 0; g < 400; g++) {
      await warmBaseline.sendClean('{"prewarm":1}');
    }

    for (const def of defs) {
      // === PART 1: SECURITY & FALSE-POSITIVE MATRIX (6 real scenarios) ===
      const client = await createClientHelper(def);

      // 1-2. Genuine Browser Click #1 & #2
      const c1 = await client.sendClean('{"amount":42}');
      const c2 = await client.sendClean('{"amount":43}');

      // 3. Exact Repeater Replay of Click #1 verbatim
      const replay = await httpPost({ port: def.srv.port, headers: c1.headers, body: c1.body });

      // 4. Body-Tampered Repeater Request (edit amount 42 -> 999999 on captured headers)
      const tamper = await httpPost({ port: def.srv.port, headers: c1.headers, body: '{"amount":999999}' });

      // 5. Intercept-Hold & Release: capture a fresh valid request, hold 8.3s, then release unmodified
      const heldHeaders = client.buildSignedHeaders('{"amount":55}');
      await new Promise((r) => setTimeout(r, 8300));
      const interceptHold = await httpPost({ port: def.srv.port, headers: heldHeaders, body: '{"amount":55}' });

      // 6. Cross-Origin CSRF Probe
      const csrfProbe = await httpPost({
        port: def.srv.port,
        headers: {
          "User-Agent": BROWSER_UA,
          "Origin": "https://evil.example",
          "Sec-Fetch-Site": "cross-site",
          "Sec-Fetch-Mode": "cors",
          "Cookie": `csrf_tok=${CSRF_TOKEN}`,
        },
        body: '{"amount":42}',
      });

      // 7. Stripped Proof + Proxy Header + Connection: close Replay
      const strippedHeaders = {
        "User-Agent": BROWSER_UA,
        "Cookie": `csrf_tok=${CSRF_TOKEN}`,
        "X-CSRF-Token": CSRF_TOKEN,
        "Proxy-Connection": "keep-alive",
        "Connection": "close",
      };
      const proxyStripped = await httpPost({ port: def.srv.port, headers: strippedHeaders, body: '{"amount":42}', agent: false });

      // 8. Genuine Burst Flood: 75 UNIQUE fresh valid requests (tests rate limiting, NOT duplicate nonce replay!)
      let burstBlocked = false;
      if (def.resetState) def.resetState();
      const burstClient = await createClientHelper(def);
      for (let b = 0; b < 75; b++) {
        const br = await burstClient.sendClean(`{"burst":${b}}`);
        if (br.resp.status === 429 || br.resp.status === 403) {
          burstBlocked = true;
          break;
        }
      }

      // === PART 2: WARM THROUGHPUT & LATENCY BENCHMARK (100 warmup + 300 measured sequential POSTs) ===
      if (def.resetState) def.resetState();
      const perfClient = await createClientHelper(def);
      for (let w = 0; w < 100; w++) {
        if (def.resetState && w % 50 === 0) def.resetState();
        const wr = await perfClient.sendClean(`{"warm":${w}}`);
        if (wr.resp.status !== 200) {
          throw new Error(`Warmup failed on ${def.id} at w=${w}: HTTP ${wr.resp.status} ${wr.resp.body}`);
        }
      }

      const N = 300;
      const latencies = [];
      let totalMeasuredMs = 0;
      for (let i = 0; i < N; i++) {
        if (def.resetState && i % 50 === 0) def.resetState();
        const t0 = performance.now();
        const r = await perfClient.sendClean(`{"amount":${i}}`);
        const dt = performance.now() - t0;
        latencies.push(dt);
        totalMeasuredMs += dt;
        if (r.resp.status !== 200) {
          throw new Error(`Perf run failed on ${def.id} at i=${i}: HTTP ${r.resp.status} ${r.resp.body}`);
        }
      }
      latencies.sort((a, b) => a - b);

      const attacks = {
        crossOriginCsrfBlocked: csrfProbe.status >= 400,
        exactReplayBlocked: replay.status >= 400,
        bodyTamperBlocked: tamper.status >= 400,
        interceptHold8sBlocked: interceptHold.status >= 400,
        proxyStrippedBlocked: proxyStripped.status >= 400,
        uniqueBurstFloodBlocked: burstBlocked,
      };
      const attacksBlockedCount = Object.values(attacks).filter(Boolean).length;

      const row = {
        id: def.id,
        name: def.name,
        clientJsRequired: def.clientJsRequired,
        worksForNonBrowserApis: def.worksForNonBrowserApis,
        genuineClick1Ok: c1.resp.status === 200,
        genuineClick2Ok: c2.resp.status === 200,
        falsePositives: (c1.resp.status === 200 ? 0 : 1) + (c2.resp.status === 200 ? 0 : 1),
        attacks,
        attacksBlocked: `${attacksBlockedCount}/6`,
        statuses: {
          click1: c1.resp.status,
          click2: c2.resp.status,
          crossOriginCsrf: csrfProbe.status,
          exactReplay: replay.status,
          bodyTamper: tamper.status,
          interceptHold8s: interceptHold.status,
          proxyStripped: proxyStripped.status,
          uniqueBurstFloodBlocked: burstBlocked,
        },
        perf: {
          requests: N,
          warmupRequests: 100,
          medianMs: Number(percentile(latencies, 50).toFixed(3)),
          p95Ms: Number(percentile(latencies, 95).toFixed(3)),
          reqPerSec: Math.round((N / totalMeasuredMs) * 1000),
        },
      };
      report.push(row);
      console.log(
        `${row.name.padEnd(32)} | FP=${row.falsePositives}/2 | Blocked=${row.attacksBlocked} | ` +
        `CSRF=${csrfProbe.status} Replay=${replay.status} Tamper=${tamper.status} Hold8s=${interceptHold.status} Proxy=${proxyStripped.status} UniqueBurst=${burstBlocked ? "429" : "200"} | ` +
        `med=${row.perf.medianMs}ms p95=${row.perf.p95Ms}ms (${row.perf.reqPerSec} req/s)`
      );
    }

    const outPath = path.join(__dirname, "results.json");
    fs.writeFileSync(
      outPath,
      JSON.stringify(
        {
          version: "1.0.0",
          timestamp: new Date().toISOString(),
          nodeVersion: process.version,
          methodology:
            "Real local TCP/HTTP keep-alive sockets; 100 warmup + 300 measured sequential POSTs per defense (no client HMAC billed to non-HMAC baselines); 2 genuine browser requests + 6 live attack scenarios (Burst Flood uses 75 unique fresh requests, not nonce replays).",
          results: report,
        },
        null,
        2
      ) + "\n"
    );
    console.log(`\nSaved ProxySnare benchmark results to ${outPath}`);
  } finally {
    keepAliveAgent.destroy();
    for (const d of defs) await d.srv.close();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
