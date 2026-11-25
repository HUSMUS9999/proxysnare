#!/usr/bin/env node
"use strict";

/**
 * ProxySnare — Multi-Defense Live HTTP Benchmark Suite (PS_ECDH_V2).
 *
 * Compares ProxySnare (balanced & strict) head-to-head against 6 standard HTTP
 * defense baselines over real local TCP/HTTP sockets:
 *   1. Unprotected Node.js HTTP API (baseline control)
 *   2. Double-Submit CSRF Token Guard (standard CSRF pattern)
 *   3. Sliding-Window Rate Limiter (60 req/min per IP)
 *   4. OWASP Fetch Metadata + Origin Guard (Sec-Fetch-Site + Origin)
 *   5. Stateless Short-TTL HMAC Signing (static key + 30s TTL, no nonce)
 *   6. Stateless HMAC (8s TTL) + Single-Use Nonce Cache (fair replay-resistant baseline)
 *   7. ProxySnare (balanced, 15s freshness, PS_ECDH_V2 + PoW)
 *   8. ProxySnare (strict, 8s freshness, PS_ECDH_V2 + PoW)
 *
 * Methodology:
 *   - 400-request global pre-warmup + 100 warmup + 300 measured sequential POSTs per defense
 *     interleaved across 3 rounds to eliminate row-order JIT/frequency bias.
 *   - Client only computes HMAC for HMAC-based defenses; ProxySnare uses full ephemeral ECDH P-256
 *     + HKDF-SHA256 + boot-token PoW handshake (handshake time reported separately).
 *   - Unique Flood sends 75 UNIQUE fresh valid requests (NOT replaying an old nonce!).
 *   - Pass `--write` (or `--out <path>`) to write results JSON without clobbering tracked baselines by default.
 */

const crypto = require("node:crypto");
const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");
const { performance } = require("node:perf_hooks");

const { createProxySnareMiddleware, solvePowChallenge } = require("../src/index.js");
const pkg = require("../package.json");

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
        close: () =>
          new Promise((r) => {
            if (typeof srv.closeAllConnections === "function") srv.closeAllConnections();
            srv.close(r);
          }),
      });
    });
  });
}

const keepAliveAgent = new http.Agent({ keepAlive: true, maxSockets: 16 });

function httpReq({ port, method = "POST", reqPath = "/api/transfer", headers = {}, body = null, agent = keepAliveAgent }) {
  return new Promise((resolve, reject) => {
    const buf = body !== null ? Buffer.from(body, "utf8") : null;
    const reqHeaders = { ...headers };
    if (buf !== null) {
      if (!reqHeaders["Content-Type"]) reqHeaders["Content-Type"] = "application/json";
      reqHeaders["Content-Length"] = buf.length;
    }
    const req = http.request(
      {
        hostname: "127.0.0.1",
        port,
        path: reqPath,
        method,
        agent,
        headers: reqHeaders,
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
    if (buf !== null) req.end(buf);
    else req.end();
  });
}

function httpPost(opts) {
  return httpReq({ method: "POST", body: '{"amount":42}', ...opts });
}

async function buildDefenses() {
  const defs = [];

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
    "Accept-Language": "en-US,en;q=0.9",
  };
  if (def.clientKind === "csrf") {
    baseHeaders["Cookie"] = `csrf_tok=${CSRF_TOKEN}`;
    baseHeaders["X-CSRF-Token"] = CSRF_TOKEN;
  }

  let psState = null;
  let handshakeMs = null;
  if (def.clientKind === "proxysnare") {
    const t0 = performance.now();
    const bootRes = await httpReq({ port, method: "GET", reqPath: "/__proxysnare/boot", headers: baseHeaders });
    if (bootRes.status !== 200) throw new Error(`Boot failed on ${def.id}: HTTP ${bootRes.status} ${bootRes.body}`);
    const boot = JSON.parse(bootRes.body);
    const powNonce = solvePowChallenge("PS_POW_V2", boot.challenge, boot.difficulty || 0);
    const ecdh = crypto.createECDH("prime256v1");
    ecdh.generateKeys();
    const clientPubB64 = ecdh.getPublicKey().toString("base64");

    const hs = await httpPost({
      port,
      reqPath: "/__proxysnare/handshake",
      headers: baseHeaders,
      body: JSON.stringify({ protocol: "PS_ECDH_V2", clientPubB64, bootToken: boot.bootToken, powNonce }),
    });
    if (hs.status !== 200) throw new Error(`Handshake failed on ${def.id}: HTTP ${hs.status} ${hs.body}`);
    const parsed = JSON.parse(hs.body);
    const shared = ecdh.computeSecret(Buffer.from(parsed.serverPubB64, "base64"));
    const info = Buffer.from(`PS_ECDH_V2|${parsed.sessionId}|${clientPubB64}|${parsed.serverPubB64}`, "utf8");
    const keyBuf = Buffer.from(crypto.hkdfSync("sha256", shared, Buffer.from(parsed.saltB64, "base64"), info, 32));
    handshakeMs = Number((performance.now() - t0).toFixed(3));
    psState = {
      sid: parsed.sessionId,
      keyBuf,
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
      const proof = hmacHex(psState.keyBuf, msg);
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

  return { buildSignedHeaders, sendClean, baseHeaders, handshakeMs };
}

function percentile(sorted, p) {
  if (!sorted.length) return 0;
  const idx = Math.min(sorted.length - 1, Math.floor((p / 100) * sorted.length));
  return sorted[idx];
}

async function main() {
  const args = process.argv.slice(2);
  const shouldWrite = args.includes("--write") || args.includes("--out");
  const outIdx = args.indexOf("--out");
  const outPath = outIdx >= 0 && args[outIdx + 1] ? path.resolve(args[outIdx + 1]) : path.join(__dirname, "results.json");

  const defs = await buildDefenses();
  const report = [];

  try {
    const warmBaseline = await createClientHelper(defs[0]);
    for (let g = 0; g < 400; g++) {
      await warmBaseline.sendClean('{"prewarm":1}');
    }

    // Prepare security tests & capture held requests simultaneously across all 8 servers (saves ~58s!)
    const secClients = [];
    for (const def of defs) {
      const client = await createClientHelper(def);
      const c1 = await client.sendClean('{"amount":42}');
      const c2 = await client.sendClean('{"amount":43}');
      const replay = await httpPost({ port: def.srv.port, headers: c1.headers, body: c1.body });
      const tamper = await httpPost({ port: def.srv.port, headers: c1.headers, body: '{"amount":999999}' });
      const heldHeaders = client.buildSignedHeaders('{"amount":55}');
      secClients.push({ def, client, c1, c2, replay, tamper, heldHeaders });
    }

    await new Promise((r) => setTimeout(r, 8300));

    for (const item of secClients) {
      const { def, client, c1, c2, replay, tamper, heldHeaders } = item;
      const interceptHold = await httpPost({ port: def.srv.port, headers: heldHeaders, body: '{"amount":55}' });

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

      const proxyStripped = await httpPost({
        port: def.srv.port,
        headers: {
          "User-Agent": BROWSER_UA,
          "Cookie": `csrf_tok=${CSRF_TOKEN}`,
          "X-CSRF-Token": CSRF_TOKEN,
          "Proxy-Connection": "keep-alive",
          "Connection": "close",
        },
        body: '{"amount":42}',
        agent: false,
      });

      let burstStatus = 200;
      if (def.resetState) def.resetState();
      const burstClient = await createClientHelper(def);
      for (let b = 0; b < 75; b++) {
        const br = await burstClient.sendClean(`{"burst":${b}}`);
        if (br.resp.status >= 400) {
          burstStatus = br.resp.status;
          break;
        }
      }

      item.sec = {
        handshakeMs: client.handshakeMs,
        c1: c1.resp.status,
        c2: c2.resp.status,
        csrf: csrfProbe.status,
        replay: replay.status,
        tamper: tamper.status,
        hold8s: interceptHold.status,
        proxy: proxyStripped.status,
        uniqueFloodStatus: burstStatus,
      };
    }

    // Interleaved 3-round warm perf measurement (100 warmup + 3x100 measured = 300 POSTs per defense)
    const perfClients = new Map();
    const perfLatencies = new Map();
    for (const def of defs) {
      if (def.resetState) def.resetState();
      const pc = await createClientHelper(def);
      for (let w = 0; w < 100; w++) {
        if (def.id === "rate_limiter" && w % 50 === 0) def.resetState();
        const wr = await pc.sendClean(`{"warm":${w}}`);
        if (wr.resp.status !== 200) throw new Error(`Warmup failed on ${def.id}: HTTP ${wr.resp.status}`);
      }
      if (def.resetState) def.resetState();
      perfClients.set(def.id, pc);
      perfLatencies.set(def.id, []);
    }

    for (let round = 0; round < 3; round++) {
      const order = round % 2 === 0 ? defs : [...defs].reverse();
      for (const def of order) {
        const pc = perfClients.get(def.id);
        const lats = perfLatencies.get(def.id);
        for (let i = 0; i < 100; i++) {
          if (def.id === "rate_limiter" && i % 50 === 0) def.resetState();
          const t0 = performance.now();
          const r = await pc.sendClean(`{"round":${round},"amount":${i}}`);
          lats.push(performance.now() - t0);
          if (r.resp.status !== 200) throw new Error(`Perf failed on ${def.id}: HTTP ${r.resp.status}`);
        }
      }
    }

    for (const item of secClients) {
      const { def, sec } = item;
      const latencies = perfLatencies.get(def.id);
      const totalMeasuredMs = latencies.reduce((a, b) => a + b, 0);
      latencies.sort((a, b) => a - b);

      const attacks = {
        crossOriginCsrfBlocked: sec.csrf >= 400,
        exactReplayBlocked: sec.replay >= 400,
        bodyTamperBlocked: sec.tamper >= 400,
        interceptHold8sBlocked: sec.hold8s >= 400,
        proxyStrippedBlocked: sec.proxy >= 400,
        uniqueBurstFloodBlocked: sec.uniqueFloodStatus >= 400,
      };
      const blockedCount = Object.values(attacks).filter(Boolean).length;
      const row = {
        id: def.id,
        name: def.name,
        clientJsRequired: def.clientJsRequired,
        worksForNonBrowserApis: def.worksForNonBrowserApis,
        genuineClick1Ok: sec.c1 === 200,
        genuineClick2Ok: sec.c2 === 200,
        falsePositives: (sec.c1 === 200 ? 0 : 1) + (sec.c2 === 200 ? 0 : 1),
        attacks,
        attacksBlocked: `${blockedCount}/6`,
        statuses: {
          click1: sec.c1,
          click2: sec.c2,
          crossOriginCsrf: sec.csrf,
          exactReplay: sec.replay,
          bodyTamper: sec.tamper,
          interceptHold8s: sec.hold8s,
          proxyStripped: sec.proxy,
          uniqueFlood: sec.uniqueFloodStatus,
        },
        perf: {
          requests: latencies.length,
          warmupRequests: 100,
          handshakeMs: sec.handshakeMs,
          medianMs: Number(percentile(latencies, 50).toFixed(3)),
          p95Ms: Number(percentile(latencies, 95).toFixed(3)),
          reqPerSec: Math.round((latencies.length / totalMeasuredMs) * 1000),
        },
      };
      report.push(row);
      console.log(
        `${row.name.padEnd(32)} | FP=${row.falsePositives}/2 | Blocked=${row.attacksBlocked} | ` +
          `CSRF=${sec.csrf} Replay=${sec.replay} Tamper=${sec.tamper} Hold8s=${sec.hold8s} Proxy=${sec.proxy} UniqueFlood=${sec.uniqueFloodStatus} | ` +
          `med=${row.perf.medianMs}ms p95=${row.perf.p95Ms}ms (${row.perf.reqPerSec} req/s)` +
          (sec.handshakeMs !== null ? ` [hs+pow=${sec.handshakeMs}ms]` : "")
      );
    }

    if (shouldWrite) {
      fs.writeFileSync(
        outPath,
        JSON.stringify(
          {
            version: pkg.version,
            timestamp: new Date().toISOString(),
            nodeVersion: process.version,
            methodology:
              "Real local TCP/HTTP keep-alive sockets; 400-request global pre-warmup + 100 warmup + 300 measured sequential POSTs interleaved across 3 rounds per defense (no client HMAC billed to non-HMAC baselines; ProxySnare uses full PS_ECDH_V2 + PoW handshake); 2 genuine browser requests + 6 live attack scenarios (Unique Flood uses 75 unique fresh requests, not nonce replays).",
            results: report,
          },
          null,
          2
        ) + "\n"
      );
      console.log(`\nSaved ProxySnare benchmark results to ${outPath}`);
    }
  } finally {
    keepAliveAgent.destroy();
    for (const d of defs) await d.srv.close();
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
