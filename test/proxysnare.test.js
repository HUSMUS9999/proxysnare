"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const http = require("node:http");
const vm = require("node:vm");
const zlib = require("node:zlib");
const { execFileSync } = require("node:child_process");
const path = require("node:path");

const {
  SECURITY_PRESETS,
  resolvePreset,
  createProxySnareEngine,
  createProxySnareMiddleware,
  createProxySnareServer,
  createUnifiedMiddleware,
  createUnifiedShield,
  buildBrowserGuardScript,
  computeGuardIntegrity,
  compileNaturalLanguage,
  solvePowChallenge,
} = require("../src/index.js");

const CHROME_UA =
  "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/158.0.0.0 Safari/537.36";

function makeBrowserHeaders(overrides = {}) {
  return {
    "user-agent": CHROME_UA,
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
    "sec-ch-ua-platform": '"Linux"',
    "accept-language": "en-US,en;q=0.9",
    connection: "keep-alive",
    ...overrides,
  };
}

/**
 * Performs a full genuine browser PS_ECDH_V2 handshake using Node's WebCrypto (subtle)
 * matching browser-guard.js byte-for-byte — including runtime guardHash AND pinned
 * ECDSA P-256 serverSigB64 verification!
 */
async function performBrowserEcdhHandshake(baseUrl, extraHeaders = {}, { browserProof = null, guardHashOverride = null } = {}) {
  const subtle = crypto.webcrypto.subtle;
  const guardResp = await fetch(`${baseUrl}/__proxysnare/guard.js`, {
    method: "GET",
    headers: makeBrowserHeaders({ "sec-fetch-dest": "script", "sec-fetch-mode": "no-cors", ...extraHeaders }),
  });
  assert.equal(guardResp.status, 200, `guard.js failed: ${guardResp.status}`);
  const guardSrc = await guardResp.text();
  const { guardHash } = computeGuardIntegrity(guardSrc);
  const pubMatch = /const SERVER_ECDSA_PUB = "([^"]*)";/.exec(guardSrc);
  const pinnedPubB64 = pubMatch ? pubMatch[1] : "";

  const bootResp = await fetch(`${baseUrl}/__proxysnare/boot`, {
    method: "GET",
    headers: makeBrowserHeaders(extraHeaders),
  });
  assert.equal(bootResp.status, 200, `boot failed: ${bootResp.status}`);
  const boot = await bootResp.json();
  assert.ok(boot.bootToken && boot.challenge);
  const powNonce = solvePowChallenge("PS_POW_V2", boot.challenge, boot.difficulty || 0);

  const kp = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const clientPubRaw = Buffer.from(await subtle.exportKey("raw", kp.publicKey));
  const clientPubB64 = clientPubRaw.toString("base64");

  const hsPayload = {
    protocol: "PS_ECDH_V2",
    clientPubB64,
    bootToken: boot.bootToken,
    powNonce,
    guardHash: guardHashOverride !== null ? guardHashOverride : guardHash,
    cdpActive: false,
    t: Date.now(),
  };
  if (browserProof !== null) {
    hsPayload.browserProof = typeof browserProof === "function" ? browserProof(boot.challenge) : browserProof;
  }
  const bpDigest = hsPayload.browserProof && typeof hsPayload.browserProof.d === "string" ? hsPayload.browserProof.d : "";
  const hsBind = crypto
    .createHash("sha256")
    .update(`${hsPayload.guardHash}|${hsPayload.cdpActive ? "1" : "0"}|${bpDigest}`, "utf8")
    .digest("hex");

  const hsResp = await fetch(`${baseUrl}/__proxysnare/handshake`, {
    method: "POST",
    headers: makeBrowserHeaders({ "Content-Type": "application/json", ...extraHeaders }),
    body: JSON.stringify(hsPayload),
  });
  assert.equal(hsResp.status, 200, `handshake failed: ${hsResp.status}`);
  const hs = await hsResp.json();
  assert.equal(hs.protocol, "PS_ECDH_V2");
  assert.equal(hs.sessionKeyHex, undefined, "MUST NEVER expose plaintext sessionKeyHex over HTTP!");
  assert.ok(hs.serverPubB64 && hs.saltB64 && hs.sessionId && hs.canary);

  if (pinnedPubB64) {
    assert.ok(hs.serverSigB64, "server MUST return ECDSA P-256 serverSigB64");
    const verifyKey = await subtle.importKey(
      "raw",
      Buffer.from(pinnedPubB64, "base64"),
      { name: "ECDSA", namedCurve: "P-256" },
      false,
      ["verify"]
    );
    const transcript = Buffer.from(
      `PS_HS_AUTH_V1|${hs.sessionId}|${clientPubB64}|${hs.serverPubB64}|${hs.saltB64}|${boot.bootToken}|${hs.serverNowMs}|${hs.canary}|${hsBind}`,
      "utf8"
    );
    const okSig = await subtle.verify(
      { name: "ECDSA", hash: "SHA-256" },
      verifyKey,
      Buffer.from(hs.serverSigB64, "base64"),
      transcript
    );
    assert.equal(okSig, true, "WebCrypto ECDSA P-256 handshake signature MUST verify against pinned SERVER_ECDSA_PUB!");
  }

  const serverPubKey = await subtle.importKey(
    "raw",
    Buffer.from(hs.serverPubB64, "base64"),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  const sharedBits = await subtle.deriveBits({ name: "ECDH", public: serverPubKey }, kp.privateKey, 256);
  const hkdfKey = await subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  const info = Buffer.from(`PS_ECDH_V2|${hs.sessionId}|${clientPubB64}|${hs.serverPubB64}|${hsBind}`, "utf8");
  const hmacKey = await subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: Buffer.from(hs.saltB64, "base64"), info },
    hkdfKey,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    true,
    ["sign"]
  );
  const derivedHex = Buffer.from(await subtle.exportKey("raw", hmacKey)).toString("hex");
  return { hs, boot, powNonce, clientPubB64, guardHash, pinnedPubB64, sessionKeyHex: derivedHex };
}

test("1. Legitimate browser sequence passes with score=0 and rotates honey-canary every request", () => {
  const engine = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api"] });
  const sess = engine.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });

  let canary = sess.canary;
  for (let seq = 1; seq <= 3; seq++) {
    const body = JSON.stringify({ step: seq, amount: 100 });
    const ts = Date.now();
    const nonce = crypto.randomBytes(12).toString("hex");
    const proof = engine.signRequest({
      sessionKeyHex: sess.sessionKeyHex,
      method: "POST",
      pathWithQuery: "/api/checkout",
      body,
      seq,
      ts,
      nonce,
      canary,
    });
    const r = engine.inspectRequest({
      method: "POST",
      url: "/api/checkout",
      body,
      headers: makeBrowserHeaders({
        "x-ps-session": sess.sessionId,
        "x-ps-seq": String(seq),
        "x-ps-ts": String(ts),
        "x-ps-nonce": nonce,
        "x-ps-canary": canary,
        "x-ps-proof": proof,
      }),
    });
    assert.equal(r.ok, true);
    assert.equal(r.blocked, false);
    assert.equal(r.score, 0);
    assert.ok(r.nextCanary && r.nextCanary !== canary);
    canary = r.nextCanary;
  }
});

test("2. Caido / Burp Repeater exact replay, body edit, intercept hold, IP theft, stale canary & balanced strip are blocked", () => {
  const engine = createProxySnareEngine({ mode: "strict", freshnessMs: 5000, protectedPaths: ["/api"] });
  const sess = engine.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const body = JSON.stringify({ amount: 10 });
  const ts = Date.now();
  const nonce = crypto.randomBytes(12).toString("hex");
  const proof = engine.signRequest({
    sessionKeyHex: sess.sessionKeyHex,
    method: "POST",
    pathWithQuery: "/api/pay",
    body,
    seq: 1,
    ts,
    nonce,
    canary: sess.canary,
  });
  const headers = makeBrowserHeaders({
    "x-ps-session": sess.sessionId,
    "x-ps-seq": "1",
    "x-ps-ts": String(ts),
    "x-ps-nonce": nonce,
    "x-ps-canary": sess.canary,
    "x-ps-proof": proof,
  });

  const r1 = engine.inspectRequest({ method: "POST", url: "/api/pay", body, headers });
  assert.equal(r1.ok, true);

  // Attack A: Exact Replay -> REPEATER_NONCE_REPLAYED + SEQ + STALE_CANARY
  const rReplay = engine.inspectRequest({ method: "POST", url: "/api/pay", body, headers });
  assert.equal(rReplay.blocked, true);
  assert.ok(rReplay.reasons.some((x) => x.code === "REPEATER_NONCE_REPLAYED"));
  assert.ok(rReplay.reasons.some((x) => x.code === "REPEATER_STALE_CANARY"));

  // Attack B: Edit 1 byte in Repeater (amount: 10 -> 999999) with fresh nonce/seq
  const rTamper = engine.inspectRequest({
    method: "POST",
    url: "/api/pay",
    body: JSON.stringify({ amount: 999999 }),
    headers: {
      ...headers,
      "x-ps-seq": "2",
      "x-ps-nonce": crypto.randomBytes(12).toString("hex"),
      "x-ps-canary": r1.nextCanary,
    },
  });
  assert.equal(rTamper.blocked, true);
  assert.ok(rTamper.reasons.some((x) => x.code === "REPEATER_BODY_OR_PATH_TAMPERED"));

  // Attack C: Request paused in Intercept past freshnessMs
  const oldTs = Date.now() - 12_000;
  const holdNonce = crypto.randomBytes(12).toString("hex");
  const holdProof = engine.signRequest({
    sessionKeyHex: sess.sessionKeyHex,
    method: "POST",
    pathWithQuery: "/api/pay",
    body,
    seq: 2,
    ts: oldTs,
    nonce: holdNonce,
    canary: r1.nextCanary,
  });
  const rHold = engine.inspectRequest({
    method: "POST",
    url: "/api/pay",
    body,
    headers: makeBrowserHeaders({
      "x-ps-session": sess.sessionId,
      "x-ps-seq": "2",
      "x-ps-ts": String(oldTs),
      "x-ps-nonce": holdNonce,
      "x-ps-canary": r1.nextCanary,
      "x-ps-proof": holdProof,
    }),
  });
  assert.equal(rHold.blocked, true);
  assert.ok(rHold.reasons.some((x) => x.code === "INTERCEPT_HOLD_OR_STALE_REPLAY"));

  // Attack D: Session stolen to another IP
  const ipNonce = crypto.randomBytes(12).toString("hex");
  const ipTs = Date.now();
  const ipProof = engine.signRequest({
    sessionKeyHex: sess.sessionKeyHex,
    method: "POST",
    pathWithQuery: "/api/pay",
    body,
    seq: 2,
    ts: ipTs,
    nonce: ipNonce,
    canary: r1.nextCanary,
  });
  const rIpTheft = engine.inspectRequest({
    method: "POST",
    url: "/api/pay",
    body,
    ip: "198.51.100.88",
    headers: makeBrowserHeaders({
      "x-ps-session": sess.sessionId,
      "x-ps-seq": "2",
      "x-ps-ts": String(ipTs),
      "x-ps-nonce": ipNonce,
      "x-ps-canary": r1.nextCanary,
      "x-ps-proof": ipProof,
    }),
  });
  assert.equal(rIpTheft.blocked, true);
  assert.ok(rIpTheft.reasons.some((x) => x.code === "REPEATER_IP_SESSION_MISMATCH"));

  // Attack E: Balanced mode stripping X-PS-* headers MUST still block
  const bal = createProxySnareEngine({ mode: "balanced", protectedPaths: ["/api"] });
  const rBalStrip = bal.inspectRequest({
    method: "POST",
    url: "/api/pay",
    body,
    headers: makeBrowserHeaders(),
  });
  assert.equal(rBalStrip.blocked, true);
  assert.ok(rBalStrip.reasons.some((x) => x.code === "REPEATER_PROOF_MISSING"));
});

test("3. Proxy leakage headers, path traversal/desync bypasses, rightmost XFF, strict CORS preflight, and CL+TE smuggling", () => {
  const engine = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api/"], trustProxy: "127.0.0.1" });

  const rProxy = engine.inspectRequest({
    method: "GET",
    url: "/public",
    headers: {
      "user-agent": CHROME_UA,
      "proxy-connection": "keep-alive",
      connection: "close",
    },
  });
  assert.equal(rProxy.blocked, true);
  assert.ok(rProxy.reasons.some((x) => x.code === "PROXY_HEADER_LEAK"));
  assert.ok(rProxy.reasons.some((x) => x.code === "FETCH_METADATA_MISSING"));
  assert.ok(rProxy.reasons.some((x) => x.code === "REPEATER_CONNECTION_CLOSE"));

  // Unprotected plain LAN HTTP GET / without Sec-Fetch-* must NOT false-positive
  const rPlainPublic = engine.inspectRequest({
    method: "GET",
    url: "/",
    headers: { "user-agent": CHROME_UA },
  });
  assert.equal(rPlainPublic.blocked, false);

  // Path normalization defeats case, percent-encoding, double-slash, traversal, %2e%2e, %00, backslash authority, trailing slash
  for (const bypassUrl of [
    "/api",
    "/API/transfer",
    "/%61pi/transfer",
    "//api/transfer",
    "/public/../api/transfer",
    "/api;v=1/transfer",
    "http://victim.example/api/transfer",
    "http://127.0.0.1\\api\\secret",
    "/api/%2e%2e/secret",
    "/api/secret/../../public",
    "/api%00/secret",
  ]) {
    const r = engine.inspectRequest({ method: "POST", url: bypassUrl, headers: makeBrowserHeaders(), body: "{}" });
    assert.equal(r.blocked, true, `Path bypass should be blocked: ${bypassUrl}`);
    assert.ok(r.reasons.some((x) => x.code === "REPEATER_PROOF_MISSING"));
  }

  // X-Original-URL targeting protected route on unprotected path must be blocked!
  const rOverride = engine.inspectRequest({
    method: "POST",
    url: "/public",
    headers: makeBrowserHeaders({ "x-original-url": "/api/secret" }),
    body: "{}",
  });
  assert.equal(rOverride.blocked, true);
  assert.ok(rOverride.reasons.some((x) => x.code === "PROXY_PATH_OVERRIDE_HEADER"));

  // Legitimate cross-origin CORS preflight OPTIONS passes cleanly; same-origin or bogus OPTIONS is BLOCKED!
  const rOpts = engine.inspectRequest({
    method: "OPTIONS",
    url: "/api/transfer",
    headers: {
      "user-agent": CHROME_UA,
      host: "api.victim.example",
      origin: "https://app.example",
      "access-control-request-method": "POST",
      "sec-fetch-mode": "cors",
    },
  });
  assert.equal(rOpts.blocked, false);

  const rSameOrigOpts = engine.inspectRequest({
    method: "OPTIONS",
    url: "/api/transfer",
    headers: {
      "user-agent": CHROME_UA,
      host: "api.victim.example",
      origin: "https://api.victim.example",
      "access-control-request-method": "POST",
      "sec-fetch-mode": "cors",
    },
  });
  assert.equal(rSameOrigOpts.blocked, true);

  const rBadOpts = engine.inspectRequest({
    method: "OPTIONS",
    url: "/api/transfer",
    headers: { "access-control-request-method": "POST" },
  });
  assert.equal(rBadOpts.blocked, true);

  // Rightmost untrusted X-Forwarded-For extraction (defeats leftmost spoofing)
  const ip = engine.extractClientIp({
    socket: { remoteAddress: "::ffff:127.0.0.1" },
    headers: { "x-forwarded-for": "1.2.3.4, 198.51.100.7, 127.0.0.1" },
  });
  assert.equal(ip, "198.51.100.7");

  const rSmug = engine.inspectRequest({
    method: "POST",
    url: "/public",
    headers: { "content-length": "5", "transfer-encoding": "chunked" },
  });
  assert.equal(rSmug.blocked, true);
  assert.ok(rSmug.reasons.some((x) => x.code === "CL_TE_SMUGGLING"));
});

test("4. Monitor mode logs & scores Repeater traffic without blocking", () => {
  const seen = [];
  const engine = createProxySnareEngine({
    mode: "monitor",
    protectedPaths: ["/api"],
    onDetect: (ev) => seen.push(ev),
  });
  const r = engine.inspectRequest({
    method: "POST",
    url: "/api/login",
    body: '{"u":"admin"}',
    headers: { "user-agent": "curl/8.5.0" },
  });
  assert.equal(r.ok, true);
  assert.equal(r.blocked, false);
  assert.ok(r.score >= 8);
  assert.equal(seen.length, 1);
});

test("5. PS_ECDH_V2 Reverse-Proxy Shield blocks curl & Caido Repeater, emits X-PS-Rehandshake even with debug headers off, and handles gzip/HEAD/Express", async () => {
  const backend = http.createServer((req, res) => {
    if (req.url === "/api/secret" && req.method === "POST") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true, received: body }));
      });
      return;
    }
    const html = "<!doctype html><html><head><title>App</title></head><body>Hello</body></html>";
    if (req.url === "/gzip") {
      const gz = zlib.gzipSync(Buffer.from(html, "utf8"));
      res.writeHead(200, { "Content-Type": "text/html", "Content-Encoding": "gzip", "Content-Length": gz.length });
      res.end(gz);
      return;
    }
    if (req.method === "HEAD") {
      res.writeHead(200, { "Content-Type": "text/html", "Content-Length": Buffer.byteLength(html) });
      res.end();
      return;
    }
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end(html);
  });
  await new Promise((r) => backend.listen(0, "127.0.0.1", r));
  const bPort = backend.address().port;

  const shield = createProxySnareServer({
    target: `http://127.0.0.1:${bPort}`,
    mode: "strict",
    protectedPaths: ["/api"],
    exposeDebugHeaders: false,
  });
  const baseUrl = await shield.listen(0, "127.0.0.1");
  try {
    const htmlResp = await new Promise((resolve, reject) => {
      const r = http.request(
        {
          host: "127.0.0.1",
          port: shield.server.address().port,
          method: "GET",
          path: "/",
          headers: makeBrowserHeaders({
            accept: "text/html,application/xhtml+xml,*/*;q=0.8",
            "sec-fetch-mode": "navigate",
            "sec-fetch-dest": "document",
            "sec-fetch-site": "none",
          }),
        },
        (resp) => {
          let body = "";
          resp.on("data", (c) => (body += c));
          resp.on("end", () => resolve({ status: resp.statusCode, text: async () => body }));
        }
      );
      r.on("error", reject);
      r.end();
    });
    assert.equal(htmlResp.status, 200);
    const htmlBody = await htmlResp.text();
    assert.ok(htmlBody.includes(`src="/__proxysnare/guard.js?v=${shield.guardVersion}"`));
    assert.ok(htmlBody.includes(`integrity="${shield.guardSri}"`), "injected guard.js tag must include sha384 SRI");
    assert.ok(htmlBody.includes('data-ps-boot="'), "HTML tag must deliver per-request boot token via data-ps-boot");

    const gzResp = await fetch(`${baseUrl}/gzip`, { headers: makeBrowserHeaders() });
    assert.equal(gzResp.status, 200);
    const gzBody = await gzResp.text();
    assert.ok(gzBody.includes(`src="/__proxysnare/guard.js?v=${shield.guardVersion}"`));
    assert.ok(gzBody.includes(`integrity="${shield.guardSri}"`));

    const headResp = await fetch(`${baseUrl}/`, { method: "HEAD", headers: makeBrowserHeaders() });
    assert.equal(headResp.status, 200);
    assert.equal((await headResp.text()).length, 0);

    // Raw curl / CLI UA blocked on /boot AND /handshake!
    const curlBoot = await fetch(`${baseUrl}/__proxysnare/boot`, {
      headers: { "User-Agent": "curl/8.5.0" },
    });
    assert.equal(curlBoot.status, 403);

    const curlHs = await fetch(`${baseUrl}/__proxysnare/handshake`, {
      method: "POST",
      headers: { "User-Agent": "curl/8.5.0", "Content-Type": "application/json" },
      body: "{}",
    });
    assert.equal(curlHs.status, 403);

    // Spoofed Chrome UA without Sec-Fetch-* blocked on /boot AND /handshake!
    const spoofBoot = await fetch(`${baseUrl}/__proxysnare/boot`, {
      headers: { "User-Agent": CHROME_UA },
    });
    assert.equal(spoofBoot.status, 403);

    // Cross-site handshake rejected
    const csrfHs = await fetch(`${baseUrl}/__proxysnare/handshake`, {
      method: "POST",
      headers: makeBrowserHeaders({ "sec-fetch-site": "cross-site", "content-type": "application/json" }),
      body: "{}",
    });
    assert.equal(csrfHs.status, 403);

    // Direct handshake without bootToken / ECDH key rejected
    const noBootHs = await fetch(`${baseUrl}/__proxysnare/handshake`, {
      method: "POST",
      headers: makeBrowserHeaders({ "Content-Type": "application/json" }),
      body: "{}",
    });
    assert.equal(noBootHs.status, 403);

    // Full WebCrypto PS_ECDH_V2 handshake succeeds with ZERO plaintext sessionKeyHex on wire!
    const { hs, boot, powNonce, clientPubB64, sessionKeyHex } = await performBrowserEcdhHandshake(baseUrl);

    // Replaying the exact same bootToken in Caido Repeater MUST fail 403!
    const replayHs = await fetch(`${baseUrl}/__proxysnare/handshake`, {
      method: "POST",
      headers: makeBrowserHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        protocol: "PS_ECDH_V2",
        clientPubB64,
        bootToken: boot.bootToken,
        powNonce,
      }),
    });
    assert.equal(replayHs.status, 403);

    // Legitimate signed POST using ECDH-derived key succeeds!
    const body = '{"x":42}';
    const ts = Date.now();
    const nonce = crypto.randomBytes(12).toString("hex");
    const proof = shield.engine.signRequest({
      sessionKeyHex,
      method: "POST",
      pathWithQuery: "/api/secret",
      body,
      seq: 1,
      ts,
      nonce,
      canary: hs.canary,
    });
    const okResp = await fetch(`${baseUrl}/api/secret`, {
      method: "POST",
      headers: makeBrowserHeaders({
        "Content-Type": "application/json",
        "X-PS-Session": hs.sessionId,
        "X-PS-Seq": "1",
        "X-PS-Ts": String(ts),
        "X-PS-Nonce": nonce,
        "X-PS-Canary": hs.canary,
        "X-PS-Proof": proof,
      }),
      body,
    });
    assert.equal(okResp.status, 200);
    assert.ok(okResp.headers.get("x-ps-next-canary"));
    assert.equal((await okResp.json()).received, body);

    // Replaying exact same signed request -> 403
    const repResp = await fetch(`${baseUrl}/api/secret`, {
      method: "POST",
      headers: makeBrowserHeaders({
        "Content-Type": "application/json",
        "X-PS-Session": hs.sessionId,
        "X-PS-Seq": "1",
        "X-PS-Ts": String(ts),
        "X-PS-Nonce": nonce,
        "X-PS-Canary": hs.canary,
        "X-PS-Proof": proof,
      }),
      body,
    });
    assert.equal(repResp.status, 403);
    assert.equal(repResp.headers.get("x-ps-rehandshake"), null);

    // Unknown/expired session MUST emit X-PS-Rehandshake: 1 even when exposeDebugHeaders is FALSE!
    const expResp = await fetch(`${baseUrl}/api/secret`, {
      method: "POST",
      headers: makeBrowserHeaders({
        "Content-Type": "application/json",
        "X-PS-Session": "deadbeefdeadbeefdeadbeefdeadbeef",
        "X-PS-Seq": "1",
        "X-PS-Ts": String(ts),
        "X-PS-Nonce": nonce,
        "X-PS-Canary": hs.canary,
        "X-PS-Proof": proof,
      }),
      body,
    });
    assert.equal(expResp.status, 403);
    assert.equal(expResp.headers.get("x-ps-rehandshake"), "1");
    assert.equal((await expResp.json()).reasons, undefined, "debug reasons remain hidden");
  } finally {
    await shield.close();
    await new Promise((r) => backend.close(r));
  }

  // Express-style pre-parsed body on /handshake works without hanging!
  const mw = createProxySnareMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  const expressSim = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      req.rawBody = Buffer.concat(chunks);
      req._body = true;
      await mw(req, res, () => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end('{"ok":true}');
      });
    });
  });
  await new Promise((r) => expressSim.listen(0, "127.0.0.1", r));
  try {
    const port = expressSim.address().port;
    const { hs } = await performBrowserEcdhHandshake(`http://127.0.0.1:${port}`);
    assert.ok(hs.sessionId);
  } finally {
    await new Promise((r) => expressSim.close(r));
  }
});

test("6. NL CLI compiler fixes, browser guard syntax, and Node <-> Python pure-stdlib PS_ECDH_V2 + PoW + parity", async () => {
  // Slashes in English prose ("caido/burp") must NOT hijack --paths!
  const pSlash = compileNaturalLanguage("block caido/burp repeater on http://localhost:3000 on port 8099 behind nginx");
  assert.equal(pSlash.intent, "protect");
  assert.equal(pSlash.options.mode, "strict");
  assert.equal(pSlash.options.port, 8099);
  assert.deepEqual(pSlash.options.protectedPaths, ["/api"]);
  assert.equal(pSlash.options.trustProxy, "127.0.0.1");

  // Negated block & observe mode compile safely to monitor (NEVER strict!)
  assert.equal(compileNaturalLanguage("don't block burp, observe http://localhost:3000").options.mode, "monitor");
  assert.equal(compileNaturalLanguage("start monitoring http://localhost:3000").options.mode, "monitor");
  assert.equal(compileNaturalLanguage("audit and block burp on http://localhost:3000").options.mode, "strict");
  assert.equal(compileNaturalLanguage("protect /api in balanced mode and audit replays on http://localhost:3000").options.mode, "balanced");
  assert.equal(compileNaturalLanguage("block reverse proxy on http://localhost:3000").options.trustProxy, "");
  assert.equal(compileNaturalLanguage("protect my app (http://localhost:3000)").options.target, "http://localhost:3000");
  assert.throws(() => compileNaturalLanguage("protect ftp://127.0.0.1:21"));
  assert.throws(() => compileNaturalLanguage("demo on port 99999"));

  // Browser guard parses cleanly as valid JS even with RegExp in protectedPaths and initialBoot
  new Function(
    buildBrowserGuardScript({
      protectedPaths: ["/api", /^\/v\d+\/pay/i],
      initialBoot: { bootToken: "a".repeat(32) + "." + "b".repeat(32), challenge: "c".repeat(32), difficulty: 10, exp: Date.now() + 60_000 },
    })
  );

  // Cross-language Node WebCrypto ECDH <-> Python pure-stdlib P-256 ECDH + HKDF-SHA256 exact parity!
  const subtle = crypto.webcrypto.subtle;
  const kp = await subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const clientPubB64 = Buffer.from(await subtle.exportKey("raw", kp.publicKey)).toString("base64");

  const pyOut = execFileSync(
    "python3",
    [
      "-c",
      `import sys, time, json; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v = ProxySnareVerifier(mode="strict", protected_paths=["/api/"])
# Verify pure-stdlib P-256 ECDH session has NO plaintext sessionKeyHex
s = v.issue_session(user_agent="Mozilla/5.0 Chrome/158.0", client_pub_b64=${JSON.stringify(clientPubB64)})
assert s["protocol"] == "PS_ECDH_V2" and "sessionKeyHex" not in s
# Verify boot challenge + PoW consume & replay rejection
boot = v.issue_boot_challenge(ip="127.0.0.1", user_agent="Mozilla/5.0 Chrome/158.0")
import hashlib
def solve(ch, diff):
    for i in range(5000000):
        n = str(i)
        d = hashlib.sha256(f"PS_POW_V2|{ch}|{n}".encode()).digest()
        bits = 0
        for b in d:
            if b == 0: bits += 8
            else: bits += 8 - b.bit_length(); break
        if bits >= diff: return n
pn = solve(boot["challenge"], boot["difficulty"])
ok1, err1 = v.consume_boot_challenge(boot_token=boot["bootToken"], pow_nonce=pn, ip="127.0.0.1", user_agent="Mozilla/5.0 Chrome/158.0")
ok2, err2 = v.consume_boot_challenge(boot_token=boot["bootToken"], pow_nonce=pn, ip="127.0.0.1", user_agent="Mozilla/5.0 Chrome/158.0")
assert ok1 and err1 is None
assert (not ok2) and err2 == "BOOT_TOKEN_REPLAYED_OR_INVALID"
# Short nonce (<8 chars) rejected matching Node.js parity
r_short = v.inspect_request(method="POST", url="/api/go", headers={
    "User-Agent": "Mozilla/5.0 Chrome/158.0", "Sec-Fetch-Site": "same-origin",
    "X-PS-Session": s["sessionId"], "X-PS-Seq": "1", "X-PS-Ts": str(int(time.time()*1000)),
    "X-PS-Nonce": "n1", "X-PS-Canary": s["canary"], "X-PS-Proof": "a"*64
}, body=b'{"a":1}')
assert r_short.blocked and any(x["code"]=="REPEATER_BODY_OR_PATH_TAMPERED" for x in r_short.reasons)
# Path traversal / %2e%2e / %00 / backslash authority checks
for bad in ("/api/%2e%2e/secret", "/api%00/secret", "http://127.0.0.1\\\\api\\\\secret", "/api"):
    assert v.is_path_protected(bad), f"missed {bad}"
print(json.dumps({"sid": s["sessionId"], "spub": s["serverPubB64"], "salt": s["saltB64"], "canary": s["canary"], "keyHex": v._sessions[s["sessionId"]]["key"].hex()}))`,
    ],
    { encoding: "utf8" }
  ).trim();
  const pyData = JSON.parse(pyOut);

  // Derive the SAME key in Node WebCrypto and verify byte-for-byte equality with Python pure-stdlib P-256!
  const serverPubKey = await subtle.importKey(
    "raw",
    Buffer.from(pyData.spub, "base64"),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  const sharedBits = await subtle.deriveBits({ name: "ECDH", public: serverPubKey }, kp.privateKey, 256);
  const hkdfKey = await subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  const info = Buffer.from(`PS_ECDH_V2|${pyData.sid}|${clientPubB64}|${pyData.spub}`, "utf8");
  const hmacKey = await subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: Buffer.from(pyData.salt, "base64"), info },
    hkdfKey,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    true,
    ["sign"]
  );
  const nodeDerivedHex = Buffer.from(await subtle.exportKey("raw", hmacKey)).toString("hex");
  assert.equal(nodeDerivedHex, pyData.keyHex, "Node WebCrypto P-256 ECDH+HKDF MUST match Python pure-stdlib P-256 byte-for-byte!");
});

test("7. v2 CIDR trustProxy, observe alias monitor canary rotation, and modular subpath exports with .d.ts", () => {
  const { createProxySnareEngine } = require("../src/detector.js");
  const engine = createProxySnareEngine({
    mode: "observe",
    trustProxy: ["10.0.0.0/8", "172.16.0.0/12"],
    protectedPaths: ["/api"],
  });
  assert.equal(engine.mode, "monitor");

  const realIp = engine.extractClientIp({
    socket: { remoteAddress: "::ffff:10.24.5.9" },
    headers: { "x-forwarded-for": "1.2.3.4, 203.0.113.77, 172.20.1.5" },
  });
  assert.equal(realIp, "203.0.113.77");

  const sess = engine.issueSession({
    ip: "203.0.113.77",
    userAgent: "Mozilla/5.0 Chrome/130.0.0.0",
  });
  const ts = String(Date.now());
  const nonce = "nonce-observe-1";
  const proof = engine.signRequest({
    sessionKeyHex: sess.sessionKeyHex,
    method: "POST",
    pathWithQuery: "/api/order",
    body: '{"item":1}',
    seq: "1",
    ts,
    nonce,
    canary: sess.canary,
  });
  const v = engine.inspectRequest({
    method: "POST",
    url: "/api/order",
    body: '{"item":1}',
    ip: "203.0.113.77",
    headers: {
      "user-agent": "Mozilla/5.0 Chrome/130.0.0.0",
      "x-ps-session": sess.sessionId,
      "x-ps-seq": "1",
      "x-ps-ts": ts,
      "x-ps-nonce": nonce,
      "x-ps-canary": sess.canary,
      "x-ps-proof": proof,
    },
  });
  assert.equal(v.blocked, false);
  assert.ok(v.nextCanary && v.nextCanary !== sess.canary, "monitor mode must rotate valid canary");

  const pkg = require("../package.json");
  assert.equal(pkg.exports["./detector"].default, "./src/detector.js");
  assert.equal(pkg.exports["./detector"].types, "./src/detector.d.ts");
  assert.equal(pkg.exports["./middleware"].types, "./src/middleware.d.ts");
  assert.equal(pkg.exports["."].types, "./src/index.d.ts");
  assert.ok(pkg.files.includes("!python/__pycache__/**"));
});

test("8. Security regressions: ['*'] wildcard, '|' injection, #/%ff/%2e%2e/%00 bypasses, IPv6 CIDR, Connection strip, capacity 503", async () => {
  const starEngine = createProxySnareEngine({ mode: "strict", protectedPaths: ["*"] });
  assert.equal(starEngine.isPathProtected("/anything/here"), true);
  assert.equal(starEngine.isPathProtected("/"), true);

  const apiEngine = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api"] });
  for (const bypass of [
    "/%61pi/%ff/secret",
    "/%ff%2f../api/secret",
    "/%61%70%69%3b%ff",
    "/api%3F",
    "/api%3Ffoo=1",
    "/api#public",
    "/api#/../../public",
    "/api%23/../../public",
    "/x#/../api/secret",
    "http://example.com/public#/../../api/secret",
    "/api/%2e%2e/secret",
    "/api%00/secret",
    "/api./secret",
    "/api%20/secret",
    "http://127.0.0.1\\api\\secret",
  ]) {
    assert.equal(apiEngine.isPathProtected(bypass), true, `Must protect bypass path: ${bypass}`);
  }

  const badCidrEngine = createProxySnareEngine({ mode: "strict", trustProxy: ["10.0.0.1/", "::1/128"] });
  assert.equal(badCidrEngine.trustedProxies.has("203.0.113.99"), false);
  assert.equal(badCidrEngine.trustedProxies.has("::1"), true);
  assert.equal(
    badCidrEngine.extractClientIp({ socket: { remoteAddress: "::1" }, headers: { "x-forwarded-for": "203.0.113.42" } }),
    "203.0.113.42"
  );

  const sess = apiEngine.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const rInj = apiEngine.inspectRequest({
    method: "POST",
    url: "/api/pay",
    body: "{}",
    headers: makeBrowserHeaders({
      "x-ps-session": sess.sessionId,
      "x-ps-seq": "1",
      "x-ps-ts": String(Date.now()),
      "x-ps-nonce": "abc|def12345",
      "x-ps-canary": sess.canary,
      "x-ps-proof": "a".repeat(64),
    }),
  });
  assert.equal(rInj.blocked, true);
  assert.ok(rInj.reasons.some((x) => x.code === "REPEATER_BODY_OR_PATH_TAMPERED"));

  const v6Engine = createProxySnareEngine({
    mode: "strict",
    trustProxy: ["2001:db8:abcd::/48"],
    protectedPaths: ["/api"],
  });
  const realClient = v6Engine.extractClientIp({
    socket: { remoteAddress: "2001:db8:abcd:0012::5" },
    headers: { "x-forwarded-for": "198.51.100.55, 2001:db8:abcd::9" },
  });
  assert.equal(realClient, "198.51.100.55");

  const capEngine = createProxySnareEngine({ mode: "strict", maxSessions: 2 });
  assert.ok(capEngine.issueSession({ ip: "127.0.0.1" }));
  assert.ok(capEngine.issueSession({ ip: "127.0.0.2" }));
  assert.equal(capEngine.issueSession({ ip: "127.0.0.3" }), null);

  let seenAuth = null;
  let seenXff = null;
  let seenUrl = null;
  const backend = http.createServer((req, res) => {
    seenAuth = req.headers.authorization || null;
    seenXff = req.headers["x-forwarded-for"] || null;
    seenUrl = req.url;
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end('{"ok":true}');
  });
  await new Promise((r) => backend.listen(0, "127.0.0.1", r));
  const shield = createProxySnareServer({
    target: `http://127.0.0.1:${backend.address().port}`,
    mode: "strict",
    protectedPaths: ["/api"],
  });
  const baseUrl = await shield.listen(0, "127.0.0.1");
  try {
    const spaceRes = await fetch(`${baseUrl}/public/my%20doc.pdf?q=hello%20world`, { headers: { "User-Agent": CHROME_UA } });
    assert.equal(spaceRes.status, 200);
    assert.equal(seenUrl, "/public/my%20doc.pdf?q=hello%20world");

    const rawAbs = await new Promise((resolve, reject) => {
      const req = http.request(
        { host: "127.0.0.1", port: shield.server.address().port, method: "GET", path: "http://example.com?x=/api/secret", headers: { "User-Agent": CHROME_UA } },
        (r) => { r.resume(); r.on("end", () => resolve(r.statusCode)); }
      );
      req.on("error", reject);
      req.end();
    });
    assert.equal(rawAbs, 200);
    assert.equal(seenUrl, "/?x=/api/secret");

    const resStatus = await new Promise((resolve, reject) => {
      const req = http.request(
        {
          host: "127.0.0.1",
          port: shield.server.address().port,
          method: "GET",
          path: "/public",
          headers: {
            "User-Agent": CHROME_UA,
            Authorization: "Bearer keep-me",
            Connection: "keep-alive, authorization, x-forwarded-for",
          },
        },
        (r) => { r.resume(); r.on("end", () => resolve(r.statusCode)); }
      );
      req.on("error", reject);
      req.end();
    });
    assert.equal(resStatus, 200);
    assert.equal(seenAuth, "Bearer keep-me");
    assert.ok(seenXff && seenXff.includes("127.0.0.1"));
  } finally {
    await shield.close();
    await new Promise((r) => backend.close(r));
  }
});

test("9. Loop B hardening: /guard.js boot rate-limit, trustProxy Connection:close, ['*'] HTML-only probe, trailing slash, monitor rehandshake, OPTIONS, Express body, NL & Python concurrency", async () => {
  // 1) /guard.js per-IP rate limiting gates legacy inline boot-token stamping (sri: false) while default sri: true serves static SRI-pinned bundle!
  const rlMw = createProxySnareMiddleware({ mode: "strict", maxHandshakesPerMin: 2, sri: false });
  function fetchGuardJs(mwInst, headers) {
    return new Promise((resolve) => {
      let status = 200;
      mwInst(
        { method: "GET", url: "/__proxysnare/guard.js", socket: { remoteAddress: "127.0.0.1" }, headers },
        {
          headersSent: false,
          writableEnded: false,
          setHeader() {},
          writeHead(code) { status = code; this.headersSent = true; },
          end(body) { this.writableEnded = true; resolve({ status, body: String(body) }); },
        }
      );
    });
  }
  const scriptHdrs = makeBrowserHeaders({ "sec-fetch-dest": "script", "sec-fetch-mode": "no-cors" });
  const g1 = await fetchGuardJs(rlMw, scriptHdrs);
  const g2 = await fetchGuardJs(rlMw, scriptHdrs);
  const g3 = await fetchGuardJs(rlMw, scriptHdrs);
  assert.equal(g1.status, 200);
  assert.equal(g2.status, 200);
  assert.equal(g3.status, 200);
  assert.ok(g1.body.includes('"bootToken":"'), "first /guard.js stamps initialBoot");
  assert.ok(g2.body.includes('"bootToken":"'), "second /guard.js stamps initialBoot");
  assert.ok(!g3.body.includes('"bootToken":"'), "third /guard.js skips boot-token mint once rate-limited");

  // 2) Nginx trustProxy + Connection: close, trailing-slash preservation, ['*'] HTML-only probe, monitor X-PS-Rehandshake, OPTIONS
  let lastSeenUrl = null;
  let lastSeenMethod = null;
  const detectEvents = [];
  const backend = http.createServer((req, res) => {
    lastSeenUrl = req.url;
    lastSeenMethod = req.method;
    if (req.url === "/" || req.url === "/docs/") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
      res.end("<html><head></head><body><h1>Home</h1></body></html>");
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ secret: "top-secret", path: req.url, method: req.method }));
  });
  await new Promise((r) => backend.listen(0, "127.0.0.1", r));

  try {
  // Server A: protectedPaths: ["*"] with trustProxy: ["127.0.0.1"]
  const starShield = createProxySnareServer({
    target: `http://127.0.0.1:${backend.address().port}`,
    mode: "strict",
    protectedPaths: ["*"],
    trustProxy: ["127.0.0.1"],
    onDetect: (ev) => detectEvents.push(ev),
  });
  const starUrl = await starShield.listen(0, "127.0.0.1");
  try {
    // HTML root navigation succeeds & injects guard script (raw http.request so undici fetch doesn't overwrite sec-fetch-mode: navigate -> cors)
    const rawGet = (reqPath, headers) =>
      new Promise((resolve, reject) => {
        const req = http.request(
          { host: "127.0.0.1", port: starShield.server.address().port, method: "GET", path: reqPath, headers },
          (r) => {
            let data = "";
            r.on("data", (c) => (data += c));
            r.on("end", () => resolve({ status: r.statusCode, body: data, headers: r.headers }));
          }
        );
        req.on("error", reject);
        req.end();
      });
    const navHdrs = makeBrowserHeaders({
      accept: "text/html,application/xhtml+xml",
      "sec-fetch-mode": "navigate",
      "sec-fetch-dest": "document",
      "sec-fetch-site": "none",
      "x-forwarded-for": "203.0.113.10",
    });
    const htmlRes = await rawGet("/", navHdrs);
    assert.equal(htmlRes.status, 200);
    assert.ok(htmlRes.body.includes("/__proxysnare/guard.js"), "injects guard script on HTML root");

    // Trailing slash preserved on forwarded path
    const docsRes = await rawGet("/docs/", navHdrs);
    assert.equal(docsRes.status, 200);
    assert.equal(lastSeenUrl, "/docs/", "trailing slash MUST be preserved when proxying upstream");

    // Spoofed navigation headers targeting JSON API under ["*"] MUST be blocked (no JSON leak!)
    const leakRes = await rawGet("/api/secret", navHdrs);
    assert.equal(leakRes.status, 403);
    assert.ok(!leakRes.body.includes("top-secret"), "non-HTML upstream response MUST NOT leak under ['*']");

    // trustProxy + Connection: close allowed on /boot, /handshake, and signed /api/*
    const rawBootStatus = await new Promise((resolve, reject) => {
      const req = http.request(
        {
          host: "127.0.0.1",
          port: starShield.server.address().port,
          method: "GET",
          path: "/__proxysnare/boot",
          headers: {
            ...makeBrowserHeaders({ "x-forwarded-for": "203.0.113.20" }),
            connection: "close",
          },
        },
        (r) => { r.resume(); r.on("end", () => resolve(r.statusCode)); }
      );
      req.on("error", reject);
      req.end();
    });
    assert.equal(rawBootStatus, 200, "trustProxy + Connection: close must succeed on /boot");

    const { hs, sessionKeyHex } = await performBrowserEcdhHandshake(starUrl, { "x-forwarded-for": "203.0.113.21" });
    const ts = String(Date.now());
    const nonce = "nonce-loopb-opt-1";
    const proof = starShield.engine.signRequest({
      sessionKeyHex,
      method: "OPTIONS",
      pathWithQuery: "/api/secret",
      body: "",
      seq: "1",
      ts,
      nonce,
      canary: hs.canary,
    });
    // Signed same-origin OPTIONS succeeds even when backend sets NO Access-Control-Allow-Origin
    const signedOpt = await new Promise((resolve, reject) => {
      const req = http.request(
        {
          host: "127.0.0.1",
          port: starShield.server.address().port,
          method: "OPTIONS",
          path: "/api/secret",
          headers: {
            ...makeBrowserHeaders({
              "x-forwarded-for": "203.0.113.21",
              "x-ps-session": hs.sessionId,
              "x-ps-seq": "1",
              "x-ps-ts": ts,
              "x-ps-nonce": nonce,
              "x-ps-canary": hs.canary,
              "x-ps-proof": proof,
            }),
            connection: "close",
          },
        },
        (r) => {
          let data = "";
          r.on("data", (c) => (data += c));
          r.on("end", () => resolve({ status: r.statusCode, body: data }));
        }
      );
      req.on("error", reject);
      req.end();
    });
    assert.equal(signedOpt.status, 200, "signed OPTIONS + Connection: close from trusted proxy must pass");
    assert.equal(lastSeenMethod, "OPTIONS");

    // Unauthenticated cross-origin OPTIONS to non-CORS backend -> 403 and no JSON leak
    const unauthOpt = await fetch(`${starUrl}/api/secret`, {
      method: "OPTIONS",
      headers: makeBrowserHeaders({
        origin: "https://other.example",
        "access-control-request-method": "POST",
        "x-forwarded-for": "203.0.113.22",
      }),
    });
    assert.equal(unauthOpt.status, 403);
    assert.ok(!(await unauthOpt.text()).includes("top-secret"), "unauthenticated OPTIONS must not leak non-CORS body");
    assert.ok(detectEvents.length > 0, "onDetect must fire for blocked requests");
  } finally {
    await starShield.close();
  }

  // Server B: monitor mode emits X-PS-Rehandshake: 1 on expired/unknown session without blocking
  const monShield = createProxySnareServer({
    target: `http://127.0.0.1:${backend.address().port}`,
    mode: "monitor",
    protectedPaths: ["/api"],
  });
  const monUrl = await monShield.listen(0, "127.0.0.1");
  try {
    const monRes = await fetch(`${monUrl}/api/secret`, {
      method: "GET",
      headers: makeBrowserHeaders({
        "x-ps-session": "deadbeefdeadbeefdeadbeefdeadbeef",
        "x-ps-seq": "1",
        "x-ps-ts": String(Date.now()),
        "x-ps-nonce": "nonce-monitor-123",
        "x-ps-canary": "a".repeat(32),
        "x-ps-proof": "b".repeat(64),
      }),
    });
    assert.equal(monRes.status, 200);
    assert.equal(monRes.headers.get("x-ps-rehandshake"), "1", "monitor mode must emit X-PS-Rehandshake: 1");
  } finally {
    await monShield.close();
  }
  } finally {
    backend.closeAllConnections?.();
    await new Promise((r) => backend.close(r));
  }

  // 3) Express pre-drained body parsing for urlencoded, text/plain, application/vnd.api+json, and empty JSON
  const expMw = createProxySnareMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  const expServer = http.createServer((req, res) => {
    const chunks = [];
    req.on("data", (c) => chunks.push(c));
    req.on("end", async () => {
      const raw = Buffer.concat(chunks).toString("utf8");
      const ct = String(req.headers["content-type"] || "").toLowerCase();
      req._body = true;
      if (ct.includes("json")) {
        req.body = raw ? JSON.parse(raw) : {};
      } else if (ct.includes("x-www-form-urlencoded")) {
        req.body = Object.fromEntries(new URLSearchParams(raw));
      } else {
        req.body = raw;
      }
      await expMw(req, res, () => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end('{"ok":true}');
      });
    });
  });
  await new Promise((r) => expServer.listen(0, "127.0.0.1", r));
  try {
    const expUrl = `http://127.0.0.1:${expServer.address().port}`;
    const { hs, sessionKeyHex } = await performBrowserEcdhHandshake(expUrl);
    let canary = hs.canary;
    let seq = 1;
    for (const [ct, body] of [
      ["application/x-www-form-urlencoded", "a=1&b=hello"],
      ["text/plain", "raw plain body"],
      ["application/vnd.api+json", '{"data":{"id":"1"}}'],
      ["application/json", ""],
    ]) {
      const ts = String(Date.now());
      const nonce = `nonce-exp-body-${seq}`;
      const proof = expMw.engine.signRequest({
        sessionKeyHex,
        method: "POST",
        pathWithQuery: "/api/form",
        body,
        seq: String(seq),
        ts,
        nonce,
        canary,
      });
      const resp = await fetch(`${expUrl}/api/form`, {
        method: "POST",
        headers: makeBrowserHeaders({
          "Content-Type": ct,
          "X-PS-Session": hs.sessionId,
          "X-PS-Seq": String(seq),
          "X-PS-Ts": ts,
          "X-PS-Nonce": nonce,
          "X-PS-Canary": canary,
          "X-PS-Proof": proof,
        }),
        body,
      });
      assert.equal(resp.status, 200, `Express pre-drained ${ct} (len=${body.length}) must verify cleanly`);
      canary = resp.headers.get("x-ps-next-canary");
      seq++;
    }
  } finally {
    await new Promise((r) => expServer.close(r));
  }

  // 4) NL compiler fixes
  assert.equal(compileNaturalLanguage("disable shield on http://localhost:3000").options.mode, "off");
  assert.equal(compileNaturalLanguage("protect http://localhost:3000 behind nginx on a vps").options.trustProxy, "127.0.0.1");
  assert.deepEqual(compileNaturalLanguage("protect entire site on http://localhost:3000").options.protectedPaths, ["/api"]);

  // 5) Python non-string client_pub_b64 guard, default-port Origin normalization, from_trusted_proxy, & multi-thread concurrency
  execFileSync(
    "python3",
    [
      "-c",
      `import sys, threading, time; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v = ProxySnareVerifier(mode="strict", protected_paths=["/api"])
# Non-string client_pub_b64 returns error cleanly (no AttributeError)
bad = v.issue_session(user_agent="Mozilla/5.0 Chrome/158.0", client_pub_b64=12345)
assert bad == {"error": "INVALID_CLIENT_ECDH_KEY"}, bad
# Default-port Origin normalization + strict scheme check on OPTIONS preflight + from_trusted_proxy Connection: close skip
s = v.issue_session(ip="203.0.113.5", user_agent="Mozilla/5.0 Chrome/158.0")
ts = str(int(time.time() * 1000))
nonce = "py-origin-nonce-1"
proof = v.sign_request(session_key_hex=s["sessionKeyHex"], method="GET", path_with_query="/api/ok", body=b"", seq="1", ts=ts, nonce=nonce, canary=s["canary"])
r_ok = v.inspect_request(method="GET", url="/api/ok", ip="203.0.113.5", from_trusted_proxy=True, headers={
    "Host": "app.example", "Origin": "https://app.example:443", "Connection": "close",
    "User-Agent": "Mozilla/5.0 Chrome/158.0", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "Accept-Language": "en-US",
    "X-PS-Session": s["sessionId"], "X-PS-Seq": "1", "X-PS-Ts": ts, "X-PS-Nonce": nonce, "X-PS-Canary": s["canary"], "X-PS-Proof": proof
})
assert not r_ok.blocked, f"unexpected block: {r_ok.reasons}"
# Default-port same-origin OPTIONS is NOT exempted as cross-origin preflight -> blocked
r_same_opt = v.inspect_request(method="OPTIONS", url="/api/ok", ip="203.0.113.5", headers={
    "Host": "app.example", "Origin": "https://app.example:443", "Access-Control-Request-Method": "POST",
    "User-Agent": "Mozilla/5.0 Chrome/158.0", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors",
})
assert r_same_opt.blocked and any(x["code"] == "REPEATER_PROOF_MISSING" for x in r_same_opt.reasons)
# Non-http/https scheme Origin (ftp://) is NOT exempted as cross-origin preflight -> blocked
r_ftp_opt = v.inspect_request(method="OPTIONS", url="/api/ok", ip="203.0.113.5", headers={
    "Host": "app.example", "Origin": "ftp://app.example", "Access-Control-Request-Method": "POST",
    "User-Agent": "Mozilla/5.0 Chrome/158.0", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors",
})
assert r_ftp_opt.blocked and any(x["code"] == "REPEATER_PROOF_MISSING" for x in r_ftp_opt.reasons)
# Genuine cross-origin https:// OPTIONS preflight IS exempted (even with Connection: close behind trusted proxy)
r_cors_opt = v.inspect_request(method="OPTIONS", url="/api/ok", ip="203.0.113.5", from_trusted_proxy=True, headers={
    "Host": "app.example", "Origin": "https://other.example", "Access-Control-Request-Method": "POST", "Connection": "close",
    "User-Agent": "Mozilla/5.0 Chrome/158.0", "Sec-Fetch-Site": "cross-site", "Sec-Fetch-Mode": "cors",
})
assert not r_cors_opt.blocked, f"cross-origin preflight blocked: {r_cors_opt.reasons}"
# Multi-thread stress test (zero RuntimeError from shared dicts)
errors = []
def worker(tid):
    try:
        for i in range(40):
            ip = f"198.51.100.{(tid * 40 + i) % 250 + 1}"
            b = v.issue_boot_challenge(ip=ip, user_agent="Mozilla/5.0 Chrome/158.0")
            assert b and "bootToken" in b
            sess = v.issue_session(ip=ip, user_agent="Mozilla/5.0 Chrome/158.0")
            assert sess and "sessionId" in sess
    except Exception as e:
        errors.append(repr(e))
threads = [threading.Thread(target=worker, args=(t,)) for t in range(8)]
for t in threads: t.start()
for t in threads: t.join()
assert not errors, f"thread errors: {errors}"`,
    ],
    { encoding: "utf8" }
  );
});

test("10. Loop C hardening: dual path-override headers, URLSearchParams & Express 4 req.body={}, wildcard 304/302, nl negatedProxy, Python init validation", async () => {
  // 1) Dual path-override headers + stripping on upstream forward + wildcard 304/302
  let seenHeaders = null;
  const backend = http.createServer((req, res) => {
    seenHeaders = req.headers;
    if (req.url === "/cached") {
      if (req.headers["if-modified-since"]) {
        res.writeHead(304);
        res.end();
        return;
      }
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Last-Modified": "Wed, 21 Oct 2025 07:28:00 GMT",
        ETag: '"v1"',
      });
      res.end("<html><head></head><body>cached</body></html>");
      return;
    }
    if (req.url === "/redirect") {
      res.writeHead(302, { Location: "/login" });
      res.end();
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, url: req.url }));
  });
  await new Promise((r) => backend.listen(0, "127.0.0.1", r));

  try {
    // Server A: protectedPaths: ["/api"] — dual override headers blocked & stripped
    const apiShield = createProxySnareServer({
      target: `http://127.0.0.1:${backend.address().port}`,
      mode: "strict",
      protectedPaths: ["/api"],
    });
    const apiUrl = await apiShield.listen(0, "127.0.0.1");
    try {
      const dualBypass = await fetch(`${apiUrl}/public`, {
        headers: makeBrowserHeaders({
          "x-original-url": "/public",
          "x-rewrite-url": "/api/secret",
        }),
      });
      assert.equal(dualBypass.status, 403, "X-Original-URL=/public must NOT mask X-Rewrite-URL=/api/secret");

      const okPub = await fetch(`${apiUrl}/public`, {
        headers: makeBrowserHeaders({
          "x-original-url": "/public",
          "x-rewrite-url": "/public2",
        }),
      });
      assert.equal(okPub.status, 200);
      assert.equal(seenHeaders["x-original-url"], undefined, "X-Original-URL must be stripped before upstream");
      assert.equal(seenHeaders["x-rewrite-url"], undefined, "X-Rewrite-URL must be stripped before upstream");
    } finally {
      await apiShield.close();
    }

    // Server B: protectedPaths: ["*"] — 304 reload & bodyless 302 redirect work cleanly
    const starShield = createProxySnareServer({
      target: `http://127.0.0.1:${backend.address().port}`,
      mode: "strict",
      protectedPaths: ["*"],
    });
    await starShield.listen(0, "127.0.0.1");
    try {
      const rawGet = (reqPath, headers) =>
        new Promise((resolve, reject) => {
          const req = http.request(
            { host: "127.0.0.1", port: starShield.server.address().port, method: "GET", path: reqPath, headers },
            (r) => {
              let data = "";
              r.on("data", (c) => (data += c));
              r.on("end", () => resolve({ status: r.statusCode, body: data, headers: r.headers }));
            }
          );
          req.on("error", reject);
          req.end();
        });
      const navHdrs = makeBrowserHeaders({
        accept: "text/html",
        "sec-fetch-mode": "navigate",
        "sec-fetch-dest": "document",
        "sec-fetch-site": "none",
      });
      const r1 = await rawGet("/cached", navHdrs);
      assert.equal(r1.status, 200);
      assert.equal(r1.headers["last-modified"], undefined, "last-modified stripped on rewritten HTML");
      assert.equal(r1.headers["etag"], undefined, "etag stripped on rewritten HTML");

      const rReload = await rawGet("/cached", { ...navHdrs, "if-modified-since": "Wed, 21 Oct 2025 07:28:00 GMT" });
      assert.equal(rReload.status, 200, "conditional HTML reload under ['*'] must return 200 with injected guard");
      assert.ok(rReload.body.includes("/__proxysnare/guard.js"));

      const rRedir = await rawGet("/redirect", navHdrs);
      assert.equal(rRedir.status, 302, "bodyless 302 redirect under ['*'] must pass");
      assert.equal(rRedir.headers.location, "/login");
    } finally {
      await starShield.close();
    }
  } finally {
    backend.closeAllConnections?.();
    await new Promise((r) => backend.close(r));
  }

  // 2) Express URLSearchParams (+ encoding) AND Express 4 empty req.body={} placeholder handling
  let sawDownstreamBody = null;
  const expMw = createProxySnareMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  const expSrv = http.createServer((req, res) => {
    if (req.url === "/api/pre-parsed") {
      // Simulate express.urlencoded() having already parsed req.body without rawBody
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", async () => {
        req._body = true;
        req.body = Object.fromEntries(new URLSearchParams(Buffer.concat(chunks).toString("utf8")));
        await expMw(req, res, () => {
          res.writeHead(200, { "Content-Type": "application/json" });
          res.end(JSON.stringify({ ok: true }));
        });
      });
      return;
    }
    // Simulate Express 4 express.json() initializing req.body = {} on a non-JSON request without setting req._body
    req.body = {};
    expMw(req, res, () => {
      sawDownstreamBody = req.body;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
  });
  await new Promise((r) => expSrv.listen(0, "127.0.0.1", r));
  try {
    const base = `http://127.0.0.1:${expSrv.address().port}`;
    const { hs, sessionKeyHex } = await performBrowserEcdhHandshake(base);
    const formBody = new URLSearchParams({ name: "Jane Doe", note: "hello world!" }).toString();
    const ts1 = String(Date.now());
    const proof1 = expMw.engine.signRequest({
      sessionKeyHex,
      method: "POST",
      pathWithQuery: "/api/pre-parsed",
      body: formBody,
      seq: "1",
      ts: ts1,
      nonce: "nonce-usp-12345",
      canary: hs.canary,
    });
    const rUsp = await fetch(`${base}/api/pre-parsed`, {
      method: "POST",
      headers: makeBrowserHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        "X-PS-Session": hs.sessionId,
        "X-PS-Seq": "1",
        "X-PS-Ts": ts1,
        "X-PS-Nonce": "nonce-usp-12345",
        "X-PS-Canary": hs.canary,
        "X-PS-Proof": proof1,
      }),
      body: formBody,
    });
    assert.equal(rUsp.status, 200, "URLSearchParams body with spaces and '!' must verify after express.urlencoded()");

    const c2 = rUsp.headers.get("x-ps-next-canary");
    const ts2 = String(Date.now());
    const proof2 = expMw.engine.signRequest({
      sessionKeyHex,
      method: "POST",
      pathWithQuery: "/api/express4-placeholder",
      body: formBody,
      seq: "2",
      ts: ts2,
      nonce: "nonce-exp4-12345",
      canary: c2,
    });
    const rExp4 = await fetch(`${base}/api/express4-placeholder`, {
      method: "POST",
      headers: makeBrowserHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        "X-PS-Session": hs.sessionId,
        "X-PS-Seq": "2",
        "X-PS-Ts": ts2,
        "X-PS-Nonce": "nonce-exp4-12345",
        "X-PS-Canary": c2,
        "X-PS-Proof": proof2,
      }),
      body: formBody,
    });
    assert.equal(rExp4.status, 200);
    assert.equal(sawDownstreamBody.name, "Jane Doe", "Express 4 empty req.body={} placeholder must be populated");
  } finally {
    expSrv.closeAllConnections?.();
    await new Promise((r) => expSrv.close(r));
  }

  // 3) NL negatedProxy word-order fixes
  assert.equal(compileNaturalLanguage("protect http://localhost:3000 not behind a reverse proxy").options.trustProxy, "");
  assert.equal(compileNaturalLanguage("protect http://localhost:3000 not behind proxy").options.trustProxy, "");
  assert.equal(compileNaturalLanguage("block proxy behind nginx on http://localhost:3000").options.trustProxy, "127.0.0.1");

  // 4) Python init validation & dual override headers
  execFileSync(
    "python3",
    [
      "-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier, normalize_pathname
assert normalize_pathname(normalize_pathname("/api/items/what%3Fnow")) == "/api/items/what%3Fnow"
for kw, exc in [
    ({"secret": 16}, TypeError),
    ({"threshold": float("nan")}, ValueError),
    ({"freshness_ms": float("inf")}, ValueError),
    ({"nonce_ttl_ms": True}, ValueError),
    ({"max_sessions": False}, ValueError),
]:
    try:
        ProxySnareVerifier(**kw)
        raise AssertionError(f"expected {exc} for {kw}")
    except exc:
        pass
v = ProxySnareVerifier(mode="strict", protected_paths=["/api"])
r = v.inspect_request(method="GET", url="/public", headers={"User-Agent": "curl/8.5.0", "X-Original-URL": "/public", "X-Rewrite-URL": "/api/secret"})
assert r.blocked and any(x["code"] == "PROXY_PATH_OVERRIDE_HEADER" for x in r.reasons)
import types
r_map = v.inspect_request(method="GET", url="/public", headers=types.MappingProxyType({"User-Agent": "Mozilla/5.0 Chrome/158.0", "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-Original-URL": "/public", "X-Rewrite-URL": "/api/secret"}))
assert r_map.blocked and any(x["code"] == "PROXY_PATH_OVERRIDE_HEADER" for x in r_map.reasons)`,
    ],
    { encoding: "utf8" }
  );
});

test("11. Bypasses 1–4 mitigations, active CDP, Firecrawl/AI crawlers, zero-FP presets, multi-worker ECDSA parity & Unified ProxySnare+VeilBreak shield", async () => {
  const veilbreak = require("../../veilbreak/src/index.js");

  // 1) Adjustable presets: zero false positives in balanced vs maximum hardening in paranoid
  const balPreset = resolvePreset("balanced");
  assert.equal(balPreset.bindIp, false, "balanced mode must keep bindIp=false for mobile Wi-Fi<->5G roaming");
  assert.equal(balPreset.blockConsoleEval, false);
  assert.equal(balPreset.blockCdpActive, false);
  assert.equal(balPreset.blockAiCrawlers, true);
  assert.equal(SECURITY_PRESETS.paranoid.requireUserGestureOnMutate, true);
  assert.equal(SECURITY_PRESETS.paranoid.blockCdpActive, true);

  // Mobile roaming IP change & human dev with DevTools open -> ZERO false positives in balanced mode!
  const balEng = createProxySnareEngine({ mode: "balanced", protectedPaths: ["/api"] });
  const balSess = balEng.issueSession({ ip: "198.51.100.1", userAgent: CHROME_UA });
  const ts0 = String(Date.now());
  const ctxDev = "ce=0;cdp=1;ug=0;ga=999999";
  const proofBal = balEng.signRequest({
    sessionKeyHex: balSess.sessionKeyHex,
    method: "GET",
    pathWithQuery: "/api/poll",
    body: "",
    seq: "1",
    ts: ts0,
    nonce: "nonce-bal-mobile-1",
    canary: balSess.canary,
    ctx: ctxDev,
  });
  const rBalOk = balEng.inspectRequest({
    method: "GET",
    url: "/api/poll",
    ip: "203.0.113.99", // switched cell tower / Wi-Fi!
    headers: makeBrowserHeaders({
      "x-ps-session": balSess.sessionId,
      "x-ps-seq": "1",
      "x-ps-ts": ts0,
      "x-ps-nonce": "nonce-bal-mobile-1",
      "x-ps-canary": balSess.canary,
      "x-ps-ctx": ctxDev,
      "x-ps-proof": proofBal,
    }),
  });
  assert.equal(rBalOk.blocked, false, `balanced mode must NOT false-positive on mobile IP switch + open DevTools: ${JSON.stringify(rBalOk.reasons)}`);

  // 2) Bypass 1 — DevTools Console fetch() (ce=1) blocked in strict/paranoid; tampering X-PS-Ctx breaks PS2 HMAC!
  const strictEng = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api"] });
  const sSess = strictEng.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const ts1 = String(Date.now());
  const ceCtx = "ce=1;cdp=1;ug=0;ga=999999";
  const ceProof = strictEng.signRequest({
    sessionKeyHex: sSess.sessionKeyHex,
    method: "POST",
    pathWithQuery: "/api/checkout",
    body: '{"price":1}',
    seq: "1",
    ts: ts1,
    nonce: "nonce-console-eval-1",
    canary: sSess.canary,
    ctx: ceCtx,
  });
  const rBypass1 = strictEng.inspectRequest({
    method: "POST",
    url: "/api/checkout",
    body: '{"price":1}',
    headers: makeBrowserHeaders({
      "x-ps-session": sSess.sessionId,
      "x-ps-seq": "1",
      "x-ps-ts": ts1,
      "x-ps-nonce": "nonce-console-eval-1",
      "x-ps-canary": sSess.canary,
      "x-ps-ctx": ceCtx,
      "x-ps-proof": ceProof,
    }),
  });
  assert.equal(rBypass1.blocked, true, "Bypass 1 (DevTools Console fetch ce=1) MUST be blocked in strict mode");
  assert.ok(rBypass1.reasons.some((x) => x.code === "CONSOLE_EVAL_DETECTED"));

  // Tampering ce=1 -> ce=0 in transit breaks PS2 HMAC immediately!
  const rCtxTamper = strictEng.inspectRequest({
    method: "POST",
    url: "/api/checkout",
    body: '{"price":1}',
    headers: makeBrowserHeaders({
      "x-ps-session": sSess.sessionId,
      "x-ps-seq": "1",
      "x-ps-ts": ts1,
      "x-ps-nonce": "nonce-console-eval-2",
      "x-ps-canary": sSess.canary,
      "x-ps-ctx": "ce=0;cdp=0;ug=1;ga=10",
      "x-ps-proof": ceProof,
    }),
  });
  assert.equal(rCtxTamper.blocked, true);
  assert.ok(rCtxTamper.reasons.some((x) => x.code === "REPEATER_BODY_OR_PATH_TAMPERED"));

  // Paranoid mode enforces active CDP, signed context, and user gesture on POST (while allowing background GET!)
  const paraEng = createProxySnareEngine({ mode: "paranoid", protectedPaths: ["/api"] });
  const pSess = paraEng.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const tsP1 = String(Date.now());
  const bgGetCtx = "ce=0;cdp=0;ug=0;ga=999999";
  const bgGetProof = paraEng.signRequest({
    sessionKeyHex: pSess.sessionKeyHex,
    method: "GET",
    pathWithQuery: "/api/status",
    body: "",
    seq: "1",
    ts: tsP1,
    nonce: "nonce-para-get-1",
    canary: pSess.canary,
    ctx: bgGetCtx,
  });
  const rParaGet = paraEng.inspectRequest({
    method: "GET",
    url: "/api/status",
    headers: makeBrowserHeaders({
      "x-ps-session": pSess.sessionId,
      "x-ps-seq": "1",
      "x-ps-ts": tsP1,
      "x-ps-nonce": "nonce-para-get-1",
      "x-ps-canary": pSess.canary,
      "x-ps-ctx": bgGetCtx,
      "x-ps-proof": bgGetProof,
    }),
  });
  assert.equal(rParaGet.blocked, false, "paranoid mode MUST NOT break background GET polling without user gesture");

  const noUgPostProof = paraEng.signRequest({
    sessionKeyHex: pSess.sessionKeyHex,
    method: "POST",
    pathWithQuery: "/api/transfer",
    body: '{"amt":50}',
    seq: "2",
    ts: tsP1,
    nonce: "nonce-para-post-2",
    canary: rParaGet.nextCanary,
    ctx: bgGetCtx,
  });
  const rParaPost = paraEng.inspectRequest({
    method: "POST",
    url: "/api/transfer",
    body: '{"amt":50}',
    headers: makeBrowserHeaders({
      "x-ps-session": pSess.sessionId,
      "x-ps-seq": "2",
      "x-ps-ts": tsP1,
      "x-ps-nonce": "nonce-para-post-2",
      "x-ps-canary": rParaGet.nextCanary,
      "x-ps-ctx": bgGetCtx,
      "x-ps-proof": noUgPostProof,
    }),
  });
  assert.equal(rParaPost.blocked, true, "paranoid mode MUST block non-gesture POST mutations");
  assert.ok(rParaPost.reasons.some((x) => x.code === "MUTATION_WITHOUT_USER_GESTURE"));

  // 3) Bypass 2 — Verify server computeGuardIntegrity().guardHash matches browser runtime window.ProxySnare.guardHash() EXACTLY!
  const testGuardSrc = buildBrowserGuardScript({
    basePath: "/__proxysnare",
    protectedPaths: ["/api"],
    serverVerifyPubB64: strictEng.serverVerifyPubB64,
  });
  const { sri: expectedSri, guardHash: expectedHash } = computeGuardIntegrity(testGuardSrc);
  assert.ok(expectedSri.startsWith("sha384-"));

  // Run guard.js inside an isolated browser-like VM realm with native WebIDL-formatted SubtleCrypto.prototype + clean iframe realm
  const runGuardInBrowserVm = (src, { tamperSubtle = false, spoofNodeProcess = false, omitSubtleCtor = false } = {}) => {
    const subtleProto = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const SubtleCryptoCtor = subtleProto.constructor;
    const subtleMethods = new Set(["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "sign", "verify", "digest"]);
    const iframeRealm = vm.createContext({ console: { debug: console.debug } });
    const iframeWin = vm.runInContext(
      `(() => {
        const origToStr = Function.prototype.toString;
        const names = new Set(${JSON.stringify([...subtleMethods, "URL", "get origin", "get pathname", "toString", "call", "apply", "bind", "test", "defineProperty", "createElement", "appendChild", "get documentElement", "get contentWindow", "contentWindow", "getAttribute", "debug", "encode", "set", "get", "has", "json", "clone", "arrayBuffer", "get status", "get headers", "get redirected", "get url", "get type", "fetch", "getRandomValues", "getEntriesByType", "now"])});
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && names.has(this.name)) {
            return "function " + this.name + "() { [native code] }";
          }
          return origToStr.call(this);
        };
        return globalThis;
      })();`,
      iframeRealm
    );
    class HTMLIFrameElement {
      constructor() { this.style = { cssText: "" }; }
      get contentWindow() { return iframeWin; }
      remove() {}
    }
    class Node { appendChild(c) { return c; } }
    class Element extends Node { getAttribute() { return null; } }
    class Document extends Node {
      constructor() {
        super();
        this.currentScript = null;
        this.baseURI = "https://app.example/";
        this._docEl = new Element();
      }
      get documentElement() { return this._docEl; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : {}; }
    }
    const ctx = vm.createContext({
      crypto: tamperSubtle
        ? {
            subtle: Object.create(subtleProto, {
              deriveKey: { value: function deriveKey() {}, configurable: true },
            }),
            getRandomValues: crypto.webcrypto.getRandomValues,
          }
        : crypto.webcrypto,
      TextEncoder,
      URL,
      Headers,
      Response,
      Request,
      console,
      setTimeout,
      clearTimeout,
      performance,
      navigator: { webdriver: false },
      document: new Document(),
      Document,
      Node,
      Element,
      HTMLIFrameElement,
      location: { origin: "https://app.example", href: "https://app.example/" },
      fetch: async function fetch() { return new Response("{}"); },
      addEventListener() {},
      ...(omitSubtleCtor ? {} : { SubtleCrypto: SubtleCryptoCtor }),
      ...(spoofNodeProcess ? { process: { versions: { node: "20.0.0" } } } : {}),
    });
    ctx.window = ctx;
    // Simulate real browser WebIDL Function.prototype.toString for Node's JS-implemented SubtleCrypto + mock DOM methods
    vm.runInContext(
      `(() => {
        const origToStr = Function.prototype.toString;
        const proto = Object.getPrototypeOf(crypto.subtle);
        const subtleNames = new Set(${JSON.stringify([...subtleMethods])});
        const domNames = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "get documentElement", "get contentWindow", "getAttribute", "encode", "set", "get", "has", "json", "clone", "arrayBuffer", "get status", "get headers", "get redirected", "get url", "get type", "fetch", "getRandomValues", "getEntriesByType", "now"]);
        const wrapped = function toString() {
          if (typeof this === "function" && ((subtleNames.has(this.name) && proto[this.name] === this) || domNames.has(this.name))) {
            return "function " + this.name + "() { [native code] }";
          }
          return origToStr.call(this);
        };
        Function.prototype.toString = wrapped;
      })();`,
      ctx
    );
    vm.runInContext(src, ctx);
    return ctx;
  };

  const vmWin = runGuardInBrowserVm(testGuardSrc);
  assert.equal(
    vmWin.ProxySnare.guardHash(),
    expectedHash,
    "Browser runtime guardHash() MUST match server computeGuardIntegrity().guardHash byte-for-byte!"
  );

  // Spoofing window.process = { versions: { node } } MUST NOT bypass SubtleCrypto tampering checks!
  const vmSpoofedNodeTamper = runGuardInBrowserVm(testGuardSrc, { tamperSubtle: true, spoofNodeProcess: true });
  assert.equal(
    vmSpoofedNodeTamper.ProxySnare.guardHash(),
    "TAMPERED_SUBTLE",
    "window.process.versions.node spoofing MUST NOT bypass SubtleCrypto integrity check!"
  );
  const vmOmitSubtle = runGuardInBrowserVm(testGuardSrc, { omitSubtleCtor: true, spoofNodeProcess: true });
  assert.equal(
    vmOmitSubtle.ProxySnare.guardHash(),
    "TAMPERED_SUBTLE",
    "Deleting window.SubtleCrypto MUST fail closed as TAMPERED_SUBTLE!"
  );

  // Simulating Caido Match & Replace editing false, ["sign"] -> true, ["sign"] OR ALLOW_DEVTOOLS=false -> true invalidates BOTH SRI and guardHash!
  const tamperedGuardSrc = testGuardSrc.replace(/false,(\s*\["sign"\])/, "true,$1");
  assert.notEqual(tamperedGuardSrc, testGuardSrc);
  const tamperedDigests = computeGuardIntegrity(tamperedGuardSrc);
  assert.notEqual(tamperedDigests.sri, expectedSri, "1-byte Match & Replace edit MUST invalidate sha384 SRI");
  assert.notEqual(tamperedDigests.guardHash, expectedHash, "1-byte Match & Replace edit MUST invalidate runtime guardHash");
  const tamperedDevToolsSrc = testGuardSrc.replace("const ALLOW_DEVTOOLS = false;", "const ALLOW_DEVTOOLS = true;");
  assert.notEqual(tamperedDevToolsSrc, testGuardSrc);
  assert.notEqual(
    computeGuardIntegrity(tamperedDevToolsSrc).guardHash,
    expectedHash,
    "Whole-closure guardHash MUST invalidate on top-level ALLOW_DEVTOOLS edit!"
  );

  // 4) Bypass 3 — Multi-worker deterministic ECDSA P-256 signing + MITM key-substitution rejection + Node <-> Python ECDSA parity!
  const sharedSecret = "super-secret-cluster-key-32bytes!";
  const worker1 = createProxySnareEngine({ mode: "strict", secret: sharedSecret });
  const worker2 = createProxySnareEngine({ mode: "strict", secret: sharedSecret });
  assert.equal(worker1.serverVerifyPubB64, worker2.serverVerifyPubB64, "Cluster workers sharing secret MUST derive identical ECDSA verify pubkey");
  const kpMitm = await crypto.webcrypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const clientPubB64 = Buffer.from(await crypto.webcrypto.subtle.exportKey("raw", kpMitm.publicKey)).toString("base64");
  const s1 = worker1.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64, bootToken: "bt-123" });
  assert.ok(s1.serverSigB64);
  assert.equal(
    worker2.verifyHandshakeSignature({
      sessionId: s1.sessionId,
      clientPubB64,
      serverPubB64: s1.serverPubB64,
      saltB64: s1.saltB64,
      bootToken: "bt-123",
      serverNowMs: s1.serverNowMs,
      canary: s1.canary,
      serverSigB64: s1.serverSigB64,
    }),
    true,
    "Worker 2 MUST verify Worker 1's ECDSA handshake signature"
  );
  // Active MITM substituting serverPubB64 or shifting serverNowMs MUST fail verification!
  assert.equal(
    worker2.verifyHandshakeSignature({
      sessionId: s1.sessionId,
      clientPubB64,
      serverPubB64: clientPubB64, // MITM substituted pubkey!
      saltB64: s1.saltB64,
      bootToken: "bt-123",
      serverNowMs: s1.serverNowMs,
      canary: s1.canary,
      serverSigB64: s1.serverSigB64,
    }),
    false,
    "MITM ECDH public key substitution MUST fail ECDSA signature verification"
  );
  assert.equal(
    worker2.verifyHandshakeSignature({
      sessionId: s1.sessionId,
      clientPubB64,
      serverPubB64: s1.serverPubB64,
      saltB64: s1.saltB64,
      bootToken: "bt-123",
      serverNowMs: s1.serverNowMs + 300_000, // MITM shifted clock forward!
      canary: s1.canary,
      serverSigB64: s1.serverSigB64,
    }),
    false,
    "MITM serverNowMs shift MUST fail ECDSA signature verification"
  );

  // Node <-> Python pure-stdlib deterministic ECDSA P-256 + PS2 X-PS-Ctx + Firecrawl parity!
  const pyEcdsaJson = execFileSync(
    "python3",
    [
      "-c",
      `import sys, json, time; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v = ProxySnareVerifier(mode="strict", secret=${JSON.stringify(sharedSecret)}, protected_paths=["/api"])
assert v.server_verify_pub_b64 == ${JSON.stringify(worker1.serverVerifyPubB64)}, "Python ECDSA pubkey MUST match Node bit-for-bit!"
s = v.issue_session(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)}, client_pub_b64=${JSON.stringify(clientPubB64)}, boot_token="bt-py-1")
assert v.verify_handshake_signature(session_id=s["sessionId"], client_pub_b64=${JSON.stringify(clientPubB64)}, server_pub_b64=s["serverPubB64"], salt_b64=s["saltB64"], boot_token="bt-py-1", server_now_ms=s["serverNowMs"], canary=s["canary"], server_sig_b64=s["serverSigB64"])
assert not v.verify_handshake_signature(session_id=s["sessionId"], client_pub_b64=${JSON.stringify(clientPubB64)}, server_pub_b64=s["serverPubB64"], salt_b64=s["saltB64"], boot_token="bt-py-1", server_now_ms=s["serverNowMs"] + 60000, canary=s["canary"], server_sig_b64=s["serverSigB64"])
# Verify Firecrawl & Console Eval PS2 blocking in Python
r_fc = v.inspect_request(method="GET", url="/public", headers={"User-Agent": "FirecrawlAgent/1.0"})
assert r_fc.blocked and any(x["code"] == "AI_CRAWLER_OR_SCRAPER_DENIED" for x in r_fc.reasons)
s_loc = v.issue_session(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
ts = str(int(time.time()*1000))
ctx = "ce=1;cdp=1;ug=0;ga=999999"
pr = v.sign_request(session_key_hex=s_loc["sessionKeyHex"], method="POST", path_with_query="/api/x", body=b"{}", seq="1", ts=ts, nonce="py-ce-nonce-1", canary=s_loc["canary"], ctx=ctx)
r_ce = v.inspect_request(method="POST", url="/api/x", body=b"{}", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-PS-Session": s_loc["sessionId"], "X-PS-Seq": "1", "X-PS-Ts": ts, "X-PS-Nonce": "py-ce-nonce-1", "X-PS-Canary": s_loc["canary"], "X-PS-Ctx": ctx, "X-PS-Proof": pr})
assert r_ce.blocked and any(x["code"] == "CONSOLE_EVAL_DETECTED" for x in r_ce.reasons)
print(json.dumps(s))`,
    ],
    { encoding: "utf8" }
  ).trim();
  const pySess = JSON.parse(pyEcdsaJson);
  assert.equal(
    worker1.verifyHandshakeSignature({
      sessionId: pySess.sessionId,
      clientPubB64,
      serverPubB64: pySess.serverPubB64,
      saltB64: pySess.saltB64,
      bootToken: "bt-py-1",
      serverNowMs: pySess.serverNowMs,
      canary: pySess.canary,
      serverSigB64: pySess.serverSigB64,
    }),
    true,
    "Node.js MUST verify Python pure-stdlib P-256 ECDSA IEEE-P1363 handshake signature!"
  );

  // 5) Bypass 4 + Firecrawl + Unified ProxySnare + VeilBreak Shield (Single Server, Single HTML Pass, Zero Extra Ticket Round-Trips!)
  const backend = http.createServer((req, res) => {
    if (req.url === "/api/checkout" && req.method === "POST") {
      let body = "";
      req.on("data", (c) => (body += c));
      req.on("end", () => {
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true, order: body }));
      });
      return;
    }
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end("<!doctype html><html><head><title>Unified</title></head><body><h1>Shop</h1></body></html>");
  });
  await new Promise((r) => backend.listen(0, "127.0.0.1", r));

  const unified = createUnifiedShield({
    target: `http://127.0.0.1:${backend.address().port}`,
    mode: "strict",
    protectedPaths: ["/api"],
    veilbreak,
  });
  const uUrl = await unified.listen(0, "127.0.0.1");
  try {
    // HTML response injects ONE combined SRI-pinned unified bundle (embedding VeilBreak inside ProxySnare's private lexical closure — zero MutationObserver/Symbol.for bridge hijack!)
    const pageResp = await fetch(`${uUrl}/`, { headers: makeBrowserHeaders() });
    assert.equal(pageResp.status, 200);
    const pageHtml = await pageResp.text();
    assert.ok(pageHtml.includes(`src="/__proxysnare/guard.js?v=${unified.guardVersion}" integrity="${unified.guardSri}"`), "must inject SRI-pinned versioned unified guard.js bundle");
    assert.ok(pageHtml.includes('data-require-vb="true"'), "must mark ProxySnare guard.js to require VeilBreak proof");
    assert.ok(pageHtml.includes('data-unified-bundle="true"'), "must mark single-bundle lexical-closure unified script");
    assert.ok(!pageHtml.includes("data-vb-bridge"), "single-bundle unified script MUST NOT expose hijackable data-vb-bridge");

    // Static /__veilbreak/gate.js is still served cleanly for standalone/playground use with exact SRI hash!
    const gateResp = await fetch(`${uUrl}/__veilbreak/gate.js`, { headers: makeBrowserHeaders() });
    assert.equal(gateResp.status, 200);
    const gateText = await gateResp.text();
    const actualGateSri = `sha384-${crypto.createHash("sha384").update(gateText, "utf8").digest("base64")}`;
    assert.equal(actualGateSri, unified.gateSri);

    // Firecrawl, Apify, Browserless, GPTBot & x-firecrawl-* header BLOCKED on HTML, /boot, and /api!
    for (const badHeaders of [
      { "user-agent": "FirecrawlAgent/1.0" },
      { "user-agent": "Mozilla/5.0 Chrome/130.0.0.0", "x-firecrawl-request-id": "fc-999" },
      { "user-agent": "ApifyBot/2.0" },
      { "user-agent": "Mozilla/5.0 Chrome/130.0.0.0", "x-browserless-token": "tok" },
      { "user-agent": "GPTBot/1.0" },
    ]) {
      const rPage = await fetch(`${uUrl}/`, { headers: badHeaders });
      assert.equal(rPage.status, 403, `Crawler must be blocked on /: ${JSON.stringify(badHeaders)}`);
      const rBoot = await fetch(`${uUrl}/__proxysnare/boot`, { headers: badHeaders });
      assert.equal(rBoot.status, 403, `Crawler must be blocked on /boot: ${JSON.stringify(badHeaders)}`);
    }

    // Bypass 4 — Standalone 40-line PS_ECDH_V2 script WITHOUT VeilBreak browserProof -> BLOCKED 403 at /handshake!
    const bootNoVb = await (await fetch(`${uUrl}/__proxysnare/boot`, { headers: makeBrowserHeaders() })).json();
    const kpScript = await crypto.webcrypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const pubScript = Buffer.from(await crypto.webcrypto.subtle.exportKey("raw", kpScript.publicKey)).toString("base64");
    const rScriptHs = await fetch(`${uUrl}/__proxysnare/handshake`, {
      method: "POST",
      headers: makeBrowserHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        protocol: "PS_ECDH_V2",
        clientPubB64: pubScript,
        bootToken: bootNoVb.bootToken,
        powNonce: solvePowChallenge("PS_POW_V2", bootNoVb.challenge, bootNoVb.difficulty),
        guardHash: unified.guardHash,
      }),
    });
    assert.equal(rScriptHs.status, 403, "Bypass 4 standalone script lacking VeilBreak proof MUST fail /handshake");
    assert.equal((await rScriptHs.json()).error, "BROWSER_INTEGRITY_FAILED");

    // Bypass 2 — Tampered guardHash at /handshake -> BLOCKED 403 GUARD_INTEGRITY_MISMATCH!
    const bootBadGuard = await (await fetch(`${uUrl}/__proxysnare/boot`, { headers: makeBrowserHeaders() })).json();
    const rTamperedGuard = await fetch(`${uUrl}/__proxysnare/handshake`, {
      method: "POST",
      headers: makeBrowserHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        protocol: "PS_ECDH_V2",
        clientPubB64: pubScript,
        bootToken: bootBadGuard.bootToken,
        powNonce: solvePowChallenge("PS_POW_V2", bootBadGuard.challenge, bootBadGuard.difficulty),
        guardHash: "f".repeat(64),
        browserProof: veilbreak.buildHandshakeProof({
          mode: "strict",
          challenge: bootBadGuard.challenge,
          telemetry: { platform: "Linux x86_64", webglRenderer: "ANGLE (Intel Mesa)" },
        }),
      }),
    });
    assert.equal(rTamperedGuard.status, 403);
    assert.equal((await rTamperedGuard.json()).error, "GUARD_INTEGRITY_MISMATCH");

    // Stealth browser (Playwright / CloakBrowser noise) -> BLOCKED 403 at /handshake!
    const bootStealth = await (await fetch(`${uUrl}/__proxysnare/boot`, { headers: makeBrowserHeaders() })).json();
    const stealthProof = veilbreak.buildHandshakeProof({
      mode: "strict",
      challenge: bootStealth.challenge,
      telemetry: { platform: "Linux x86_64", canvas2dUniqueColors: 6, cdpRuntimeEnable: true },
    });
    const rStealth = await fetch(`${uUrl}/__proxysnare/handshake`, {
      method: "POST",
      headers: makeBrowserHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        protocol: "PS_ECDH_V2",
        clientPubB64: pubScript,
        bootToken: bootStealth.bootToken,
        powNonce: solvePowChallenge("PS_POW_V2", bootStealth.challenge, bootStealth.difficulty),
        guardHash: unified.guardHash,
        browserProof: stealthProof,
      }),
    });
    assert.equal(rStealth.status, 403);
    assert.equal((await rStealth.json()).error, "BROWSER_INTEGRITY_FAILED");

    // Genuine clean browser with valid challenge-bound VeilBreak proof -> PASSES handshake + API POST with score=0!
    const { hs, sessionKeyHex } = await performBrowserEcdhHandshake(uUrl, {}, {
      browserProof: (challenge) =>
        veilbreak.buildHandshakeProof({
          mode: "strict",
          challenge,
          telemetry: { platform: "Linux x86_64", webglRenderer: "ANGLE (Intel Mesa)" },
        }),
    });
    const body = '{"item":"pro-plan","price":49}';
    const tsOk = String(Date.now());
    const ctxOk = "ce=0;cdp=0;ug=1;ga=120;ik=0";
    const proofOk = unified.engine.signRequest({
      sessionKeyHex,
      method: "POST",
      pathWithQuery: "/api/checkout",
      body,
      seq: "1",
      ts: tsOk,
      nonce: "nonce-unified-ok-1",
      canary: hs.canary,
      ctx: ctxOk,
    });
    const rOk = await fetch(`${uUrl}/api/checkout`, {
      method: "POST",
      headers: makeBrowserHeaders({
        "Content-Type": "application/json",
        "X-PS-Session": hs.sessionId,
        "X-PS-Seq": "1",
        "X-PS-Ts": tsOk,
        "X-PS-Nonce": "nonce-unified-ok-1",
        "X-PS-Canary": hs.canary,
        "X-PS-Ctx": ctxOk,
        "X-PS-Proof": proofOk,
      }),
      body,
    });
    assert.equal(rOk.status, 200);
    assert.equal(rOk.headers.get("x-proxysnare-score"), "0");
    assert.equal((await rOk.json()).order, body);

    // Unified middleware helper headTags() emits the single SRI-pinned combined bundle tag (zero hijackable data-vb-bridge!)
    const uMw = createUnifiedMiddleware({ mode: "balanced", veilbreak });
    const tags = uMw.headTags();
    assert.ok(tags.includes("/__proxysnare/guard.js") && tags.includes('data-require-vb="true"') && tags.includes('data-unified-bundle="true"'));
    assert.ok(!tags.includes("data-vb-bridge"));
  } finally {
    await unified.close();
    await new Promise((r) => backend.close(r));
  }
});

test("12. Pass-1 Audit Regressions: ReDoS immunity, allowDevTools/gestureExemptPaths, mobile rehandshake, unified automation blocking, replayable streams & Python consume_boot_challenge_detail", async () => {
  const veilbreak = require("../../veilbreak/src/index.js");

  // 1) ReDoS immunity on 14KB dot-filled URL & 200KB malformed HTML <head
  const eng = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api"] });
  const t0 = Date.now();
  assert.equal(eng.isPathProtected("/" + ".".repeat(14000) + "a"), false);
  assert.ok(Date.now() - t0 < 50, "14KB dot-filled path MUST complete in < 50ms without ReDoS");

  // 2) allowDevTools: true in paranoid mode + gestureExemptPaths for background heartbeats
  const paraDev = createProxySnareEngine({
    mode: "paranoid",
    protectedPaths: ["/api"],
    allowDevTools: true,
    gestureExemptPaths: ["/api/heartbeat"],
  });
  const sDev = paraDev.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const tsDev = String(Date.now());
  const ctxDev = "ce=0;cdp=1;ug=0;ga=999999";
  const prDev = paraDev.signRequest({
    sessionKeyHex: sDev.sessionKeyHex,
    method: "POST",
    pathWithQuery: "/api/heartbeat",
    body: '{"ping":1}',
    seq: "1",
    ts: tsDev,
    nonce: "nonce-para-dev-1",
    canary: sDev.canary,
    ctx: ctxDev,
  });
  const rDev = paraDev.inspectRequest({
    method: "POST",
    url: "/api/heartbeat",
    body: '{"ping":1}',
    headers: makeBrowserHeaders({
      "x-ps-session": sDev.sessionId,
      "x-ps-seq": "1",
      "x-ps-ts": tsDev,
      "x-ps-nonce": "nonce-para-dev-1",
      "x-ps-canary": sDev.canary,
      "x-ps-ctx": ctxDev,
      "x-ps-proof": prDev,
    }),
  });
  assert.equal(rDev.blocked, false, `allowDevTools + gestureExemptPaths must allow heartbeat: ${JSON.stringify(rDev.reasons)}`);

  // 3) Mobile Wi-Fi<->5G IP change on valid HMAC recommends clean auto-rehandshake (X-PS-Rehandshake: 1)
  const sRoam = eng.issueSession({ ip: "198.51.100.1", userAgent: CHROME_UA });
  const tsRoam = String(Date.now());
  const prRoam = eng.signRequest({
    sessionKeyHex: sRoam.sessionKeyHex,
    method: "POST",
    pathWithQuery: "/api/sync",
    body: "{}",
    seq: "1",
    ts: tsRoam,
    nonce: "nonce-roam-1234",
    canary: sRoam.canary,
  });
  const rRoam = eng.inspectRequest({
    method: "POST",
    url: "/api/sync",
    body: "{}",
    ip: "203.0.113.55",
    headers: makeBrowserHeaders({
      "x-ps-session": sRoam.sessionId,
      "x-ps-seq": "1",
      "x-ps-ts": tsRoam,
      "x-ps-nonce": "nonce-roam-1234",
      "x-ps-canary": sRoam.canary,
      "x-ps-proof": prRoam,
    }),
  });
  assert.equal(rRoam.blocked, true);
  assert.equal(rRoam.rehandshakeRecommended, true, "Valid HMAC on changed IP MUST recommend transparent rehandshake");

  // 4) Express/Connect replayable stream + captureRawBody + versioned immutable vs unversioned ETag/304 guard.js
  const mw = createProxySnareMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  let streamBodySeen = "";
  const srv = http.createServer((req, res) => {
    mw(req, res, () => {
      const chunks = [];
      req.on("data", (c) => chunks.push(c));
      req.on("end", () => {
        streamBodySeen = Buffer.concat(chunks).toString("utf8");
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ ok: true, streamLen: streamBodySeen.length }));
      });
    });
  });
  await new Promise((r) => srv.listen(0, "127.0.0.1", r));
  const mUrl = `http://127.0.0.1:${srv.address().port}`;
  try {
    // Versioned guard.js is immutable; unversioned guard.js is no-cache + ETag -> 304
    const gVer = await fetch(`${mUrl}/__proxysnare/guard.js?v=${mw.guardVersion}`, { headers: makeBrowserHeaders() });
    assert.equal(gVer.status, 200);
    assert.ok(gVer.headers.get("cache-control").includes("immutable"));
    const gUnver = await fetch(`${mUrl}/__proxysnare/guard.js`, { headers: makeBrowserHeaders() });
    assert.equal(gUnver.status, 200);
    assert.equal(gUnver.headers.get("cache-control"), "public, no-cache, no-transform");
    const etag = gUnver.headers.get("etag");
    assert.ok(etag);
    const g304 = await fetch(`${mUrl}/__proxysnare/guard.js`, { headers: makeBrowserHeaders({ "if-none-match": etag }) });
    assert.equal(g304.status, 304);

    // Downstream req.on('data') receives replayed raw multipart/octet-stream payload!
    const { hs, sessionKeyHex } = await performBrowserEcdhHandshake(mUrl);
    const payload = "--boundary\r\nhello-stream\r\n--boundary--";
    const tsS = String(Date.now());
    const prS = mw.engine.signRequest({
      sessionKeyHex,
      method: "POST",
      pathWithQuery: "/api/upload",
      body: payload,
      seq: "1",
      ts: tsS,
      nonce: "nonce-stream-1234",
      canary: hs.canary,
    });
    const upRes = await fetch(`${mUrl}/api/upload`, {
      method: "POST",
      headers: makeBrowserHeaders({
        "Content-Type": "multipart/form-data; boundary=boundary",
        "X-PS-Session": hs.sessionId,
        "X-PS-Seq": "1",
        "X-PS-Ts": tsS,
        "X-PS-Nonce": "nonce-stream-1234",
        "X-PS-Canary": hs.canary,
        "X-PS-Proof": prS,
      }),
      body: payload,
    });
    assert.equal(upRes.status, 200);
    assert.equal(streamBodySeen, payload, "Downstream stream handler MUST receive exact replayed raw body");
  } finally {
    await new Promise((r) => srv.close(r));
  }

  // 5) Unified shield blocks HeadlessChrome/curl on unprotected / AND fires onVeilBreakDetect + serves /ticket when playground enabled
  const vbEvents = [];
  const upHtml = http.createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<!doctype html><html><head><meta charset='utf-8'><title>X</title></head><body>OK</body></html>");
  });
  await new Promise((r) => upHtml.listen(0, "127.0.0.1", r));
  const uShield = createUnifiedShield({
    target: `http://127.0.0.1:${upHtml.address().port}`,
    mode: "strict",
    protectedPaths: ["/api"],
    enablePlayground: true,
    onVeilBreakDetect: (ev) => vbEvents.push(ev),
    veilbreak,
  });
  const uUrl2 = await uShield.listen(0, "127.0.0.1");
  try {
    const rHeadless = await fetch(`${uUrl2}/`, { headers: { "User-Agent": "Mozilla/5.0 HeadlessChrome/130.0.0.0" } });
    assert.equal(rHeadless.status, 403, "Unified shield MUST block HeadlessChrome even on unprotected HTML routes");
    const rTicket = await fetch(`${uUrl2}/__veilbreak/ticket`, { headers: makeBrowserHeaders() });
    assert.equal(rTicket.status, 200, "Unified shield with enablePlayground MUST serve /__veilbreak/ticket");
    const rBoot = await (await fetch(`${uUrl2}/__proxysnare/boot`, { headers: makeBrowserHeaders() })).json();
    const kp = await crypto.webcrypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const pub = Buffer.from(await crypto.webcrypto.subtle.exportKey("raw", kp.publicKey)).toString("base64");
    const rFailVb = await fetch(`${uUrl2}/__proxysnare/handshake`, {
      method: "POST",
      headers: makeBrowserHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        protocol: "PS_ECDH_V2",
        clientPubB64: pub,
        bootToken: rBoot.bootToken,
        powNonce: solvePowChallenge("PS_POW_V2", rBoot.challenge, rBoot.difficulty),
        guardHash: uShield.guardHash,
      }),
    });
    assert.equal(rFailVb.status, 403);
    assert.ok(vbEvents.length >= 1, "onVeilBreakDetect callback MUST fire on handshake VeilBreak rejection");
  } finally {
    await uShield.close();
    await new Promise((r) => upHtml.close(r));
  }

  // 6) Python consume_boot_challenge_detail atomic challenge retrieval + allow_devtools + ReDoS immunity
  execFileSync(
    "python3",
    [
      "-c",
      `import sys, time; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v = ProxySnareVerifier(mode="paranoid", allow_devtools=True, protected_paths=["/api"])
t0 = time.monotonic()
assert not v.is_path_protected("/" + "." * 14000 + "a")
assert time.monotonic() - t0 < 0.05
boot = v.issue_boot_challenge(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
import hashlib
def solve(ch, diff):
    for i in range(5000000):
        n = str(i)
        d = hashlib.sha256(f"PS_POW_V2|{ch}|{n}".encode()).digest()
        bits = 0
        for b in d:
            if b == 0: bits += 8
            else: bits += 8 - b.bit_length(); break
        if bits >= diff: return n
pn = solve(boot["challenge"], boot["difficulty"])
res = v.consume_boot_challenge_detail(boot_token=boot["bootToken"], pow_nonce=pn, ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
assert res["ok"] and res["challenge"] == boot["challenge"]
res2 = v.consume_boot_challenge_detail(boot_token=boot["bootToken"], pow_nonce=pn, ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
assert not res2["ok"] and res2["error"] == "BOOT_TOKEN_REPLAYED_OR_INVALID"`,
    ],
    { encoding: "utf8" }
  );
});

test("13. Pass-2 Audit Regressions: SubtleCrypto/hsBind/ReDoS/1k-header/off-shortcircuit/Express-stream/RFC3986-proxy/cross-worker-boot/Python parity", async () => {
  const veilbreak = require("../../veilbreak/src/index.js");

  // 1) Quadratic ReDoS immunity on %00*4900 + %0a AND 1,000 headers O(H) single-pass speed
  const eng = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api"] });
  const tNul = Date.now();
  assert.equal(eng.isPathProtected("/" + "%00".repeat(4900) + "%0a%3f%23"), false);
  assert.ok(Date.now() - tNul < 30, "%00*4900+%0a MUST complete in < 30ms without quadratic ReDoS");

  const manyHdrs = { "user-agent": CHROME_UA, "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors" };
  for (let i = 0; i < 1000; i++) manyHdrs[`x-custom-hdr-${i}`] = "v";
  const tHdr = Date.now();
  for (let i = 0; i < 20; i++) eng.inspectRequest({ method: "GET", url: "/public", headers: manyHdrs });
  assert.ok(Date.now() - tHdr < 100, "20x 1,000-header requests MUST stay fast with single-pass scan");

  // 2) hsBind transcript binding defeats in-flight MITM scrubbing of cdpActive / browserProof!
  const shared = "shared-cluster-secret-32-bytes!!";
  const wA = createProxySnareEngine({ mode: "strict", secret: shared, protectedPaths: ["/api"] });
  const wB = createProxySnareEngine({ mode: "strict", secret: shared, protectedPaths: ["/api"] });
  const kp = await crypto.webcrypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
  const clientPubB64 = Buffer.from(await crypto.webcrypto.subtle.exportKey("raw", kp.publicKey)).toString("base64");
  const bindReal = crypto.createHash("sha256").update("gh1|1|proofBad").digest("hex");
  const bindScrubbed = crypto.createHash("sha256").update("gh1|0|proofClean").digest("hex");
  const sBind = wA.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64, bootToken: "bt-1", hsBind: bindScrubbed });
  assert.equal(
    wB.verifyHandshakeSignature({
      sessionId: sBind.sessionId,
      clientPubB64,
      serverPubB64: sBind.serverPubB64,
      saltB64: sBind.saltB64,
      bootToken: "bt-1",
      serverNowMs: sBind.serverNowMs,
      canary: sBind.canary,
      hsBind: bindReal, // browser expected its original cdpActive=1/proofBad!
      serverSigB64: sBind.serverSigB64,
    }),
    false,
    "In-flight MITM scrubbing cdpActive/browserProof MUST fail ECDSA verification via hsBind!"
  );

  // 3) Cross-worker stateless bootToken works across Worker A -> Worker B sharing secret, and blocks replay!
  const bootA = wA.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const powA = solvePowChallenge("PS_POW_V2", bootA.challenge, bootA.difficulty);
  const cB1 = wB.consumeBootChallenge({ bootToken: bootA.bootToken, powNonce: powA, ip: "127.0.0.1", userAgent: CHROME_UA });
  assert.equal(cB1.ok, true, "Worker B sharing secret MUST accept Worker A's stateless bootToken");
  const cB2 = wB.consumeBootChallenge({ bootToken: bootA.bootToken, powNonce: powA, ip: "127.0.0.1", userAgent: CHROME_UA });
  assert.equal(cB2.ok, false, "Replaying stateless bootToken on Worker B MUST be rejected");

  // 4) Explicit blockCdpActive: true on balanced mode is NOT neutralized by default allowDevTools!
  const balCdp = createProxySnareEngine({ mode: "balanced", blockCdpActive: true, protectedPaths: ["/api"] });
  assert.equal(balCdp.allowDevTools, false);
  const sCdp = balCdp.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const tsC = String(Date.now());
  const ctxC = "ce=0;cdp=1;ug=1;ga=10";
  const prC = balCdp.signRequest({
    sessionKeyHex: sCdp.sessionKeyHex,
    method: "GET",
    pathWithQuery: "/api/x",
    body: "",
    seq: "1",
    ts: tsC,
    nonce: "nonce-bal-cdp-1",
    canary: sCdp.canary,
    ctx: ctxC,
  });
  const rBalCdp = balCdp.inspectRequest({
    method: "GET",
    url: "/api/x",
    headers: makeBrowserHeaders({
      "x-ps-session": sCdp.sessionId,
      "x-ps-seq": "1",
      "x-ps-ts": tsC,
      "x-ps-nonce": "nonce-bal-cdp-1",
      "x-ps-canary": sCdp.canary,
      "x-ps-ctx": ctxC,
      "x-ps-proof": prC,
    }),
  });
  assert.equal(rBalCdp.blocked, true, "balanced + explicit blockCdpActive:true MUST block cdp=1");

  // 5) Unified balanced mode SYNTHETIC_INTERACTION (ik=1) weight=6 blocks at threshold=6!
  const balIk = createProxySnareEngine({ mode: "balanced", protectedPaths: ["/api"] });
  const sIk = balIk.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const ctxIk = "ce=0;cdp=0;ug=1;ga=10;ik=1";
  const prIk = balIk.signRequest({
    sessionKeyHex: sIk.sessionKeyHex,
    method: "POST",
    pathWithQuery: "/api/buy",
    body: "{}",
    seq: "1",
    ts: tsC,
    nonce: "nonce-bal-ik-1",
    canary: sIk.canary,
    ctx: ctxIk,
  });
  const rIk = balIk.inspectRequest({
    method: "POST",
    url: "/api/buy",
    body: "{}",
    headers: makeBrowserHeaders({
      "x-ps-session": sIk.sessionId,
      "x-ps-seq": "1",
      "x-ps-ts": tsC,
      "x-ps-nonce": "nonce-bal-ik-1",
      "x-ps-canary": sIk.canary,
      "x-ps-ctx": ctxIk,
      "x-ps-proof": prIk,
    }),
  });
  assert.equal(rIk.blocked, true, "SYNTHETIC_INTERACTION (ik=1) MUST block in balanced mode (weight=6 >= threshold=6)");

  // 6) mode="off" short-circuits without 413 body buffering, AND raw-Node + express.raw (req.readable===true, !req._body) work cleanly!
  const offMw = createProxySnareMiddleware({ mode: "off", maxBodyBytes: 16, protectedPaths: ["/api"] });
  const offSrv = http.createServer(async (req, res) => {
    if (await offMw(req, res)) return;
    const chunks = [];
    for await (const c of req) chunks.push(c);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ len: Buffer.concat(chunks).length }));
  });
  await new Promise((r) => offSrv.listen(0, "127.0.0.1", r));
  try {
    const big = "x".repeat(256);
    const rOff = await fetch(`http://127.0.0.1:${offSrv.address().port}/api/big`, { method: "POST", body: big });
    assert.equal(rOff.status, 200, "mode='off' MUST NOT return 413 on bodies exceeding maxBodyBytes");
    assert.equal((await rOff.json()).len, 256);
  } finally {
    await new Promise((r) => offSrv.close(r));
  }

  // Raw-Node usage (no next callback) restores req.readable === true & !req._body so downstream for-await / express.raw works!
  const rawMw = createProxySnareMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  let sawReadable = false;
  let sawExpressBodyFlag = null;
  const rawSrv = http.createServer(async (req, res) => {
    if (await rawMw(req, res)) return;
    sawReadable = req.readable;
    sawExpressBodyFlag = Boolean(req._body);
    const chunks = [];
    for await (const c of req) chunks.push(c);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ raw: Buffer.concat(chunks).toString("utf8") }));
  });
  await new Promise((r) => rawSrv.listen(0, "127.0.0.1", r));
  try {
    const rUrl = `http://127.0.0.1:${rawSrv.address().port}`;
    const { hs, sessionKeyHex } = await performBrowserEcdhHandshake(rUrl);
    const body = "user[name]=alice";
    const tsR = String(Date.now());
    const prR = rawMw.engine.signRequest({
      sessionKeyHex,
      method: "POST",
      pathWithQuery: "/api/raw-node",
      body,
      seq: "1",
      ts: tsR,
      nonce: "nonce-rawnode-1",
      canary: hs.canary,
    });
    const rRaw = await fetch(`${rUrl}/api/raw-node`, {
      method: "POST",
      headers: makeBrowserHeaders({
        "Content-Type": "application/x-www-form-urlencoded",
        "X-PS-Session": hs.sessionId,
        "X-PS-Seq": "1",
        "X-PS-Ts": tsR,
        "X-PS-Nonce": "nonce-rawnode-1",
        "X-PS-Canary": hs.canary,
        "X-PS-Proof": prR,
      }),
      body,
    });
    assert.equal(rRaw.status, 200);
    assert.equal(sawReadable, true, "restoreRequestStream MUST restore req.readable=true for raw-Node/express.raw");
    assert.equal(sawExpressBodyFlag, false, "MUST NOT set req._body=true so downstream express.urlencoded({extended:true}) still parses");
    assert.equal((await rRaw.json()).raw, body);
  } finally {
    await new Promise((r) => rawSrv.close(r));
  }

  // 7) Reverse proxy preserves RFC 3986 path chars (@, :, +, ,) and %2F!
  const seenPaths = [];
  const upRfc = http.createServer((req, res) => {
    seenPaths.push(req.url);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end('{"ok":true}');
  });
  await new Promise((r) => upRfc.listen(0, "127.0.0.1", r));
  const rfcShield = createProxySnareServer({
    target: `http://127.0.0.1:${upRfc.address().port}`,
    mode: "strict",
    protectedPaths: ["/api"],
  });
  const rfcUrl = await rfcShield.listen(0, "127.0.0.1");
  try {
    for (const p of ["/@vite/client", "/public/users/@alice", "/public/v1/users:export", "/public/items/1,2,3", "/public/tags/c++", "/public/files/a%2Fb"]) {
      const r = await fetch(`${rfcUrl}${p}`, { headers: makeBrowserHeaders() });
      assert.equal(r.status, 200);
    }
    assert.deepEqual(seenPaths, ["/@vite/client", "/public/users/@alice", "/public/v1/users:export", "/public/items/1,2,3", "/public/tags/c++", "/public/files/a%2Fb"]);
  } finally {
    await rfcShield.close();
    await new Promise((r) => upRfc.close(r));
  }

  // 8) Unified veilbreakOptions.allowDevTools sync + Python parity (hs_bind, gesture_exempt_paths, block_cdp_active, .strip())
  const uSync = createUnifiedMiddleware({ mode: "paranoid", veilbreakOptions: { allowDevTools: true }, veilbreak });
  assert.equal(uSync.engine.allowDevTools, true, "veilbreakOptions.allowDevTools MUST propagate to ProxySnare engine");
  assert.equal(uSync.engine.blockCdpActive, false);

  execFileSync(
    "python3",
    [
      "-c",
      `import sys, time; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v = ProxySnareVerifier(mode="balanced", block_cdp_active=True, protected_paths=["  /api  "])
assert v.is_path_protected("/api/test") and not v.allow_devtools
v_para = ProxySnareVerifier(mode="paranoid", protected_paths=["/api"], gesture_exempt_paths=["/api/ping"])
s = v_para.issue_session(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
ts = str(int(time.time() * 1000))
ctx = "ce=0;cdp=0;ug=0;ga=999999"
pr = v_para.sign_request(session_key_hex=s["sessionKeyHex"], method="POST", path_with_query="/api/ping", body=b"{}", seq="1", ts=ts, nonce="py-exempt-1", canary=s["canary"], ctx=ctx)
r = v_para.inspect_request(method="POST", url="/api/ping", body=b"{}", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-PS-Session": s["sessionId"], "X-PS-Seq": "1", "X-PS-Ts": ts, "X-PS-Nonce": "py-exempt-1", "X-PS-Canary": s["canary"], "X-PS-Ctx": ctx, "X-PS-Proof": pr})
assert not r.blocked, f"Python gesture_exempt_paths failed: {r.reasons}"`,
    ],
    { encoding: "utf8" }
  );
});

test("14. Pass-3 Audit Regressions: X-PS-Canary-Ack, GET body rejection, orphaned data-vb-bridge, restoreRequestStream on('end'), multi-worker store, requireGuardIntegrity:false, PS_BOOT_V2S Python<->Node interop & IPv6 CORS", async () => {
  const { injectGuardIntoHtml } = require("../src/middleware.js");
  const veilbreak = require("../../veilbreak/src/index.js");

  // 1) Decoupled preset overrides: balanced + blockConsoleEval:true keeps allowDevTools:true (no false CDP lock), while blockCdpActive:true disables allowDevTools & propagates through unified!
  const balCe = resolvePreset("balanced", { blockConsoleEval: true });
  assert.equal(balCe.allowDevTools, true, "balanced + blockConsoleEval:true MUST keep allowDevTools:true so DevTools stays open while Console eval is blocked");
  assert.equal(balCe.blockConsoleEval, true);
  assert.equal(balCe.blockCdpActive, false);
  const balCdpPreset = resolvePreset("balanced", { blockCdpActive: true });
  assert.equal(balCdpPreset.allowDevTools, false, "explicit blockCdpActive:true MUST disable allowDevTools");
  const uBalCdp = createUnifiedMiddleware({ mode: "balanced", blockCdpActive: true, veilbreak });
  assert.equal(uBalCdp.veilbreak.preset.allowDevTools, false, "unified balanced + blockCdpActive:true MUST propagate allowDevTools:false to VeilBreak");

  // 2) Orphaned data-vb-bridge MUST NOT be stamped on guard.js when gate.js already exists in HTML!
  const preExistingGateHtml = '<!doctype html><html><head><script src="/__veilbreak/gate.js"></script></head><body>ok</body></html>';
  const injectedHtml = injectGuardIntoHtml(preExistingGateHtml, "/__proxysnare", {
    requireVeilBreak: true,
    prependTags: '<script src="/__veilbreak/gate.js" data-vb-bridge="tok123"></script>',
    prependSrc: "/__veilbreak/gate.js",
    bridgeToken: "tok123",
  });
  assert.ok(injectedHtml.includes("/__proxysnare/guard.js"), "guard.js should still be injected");
  assert.ok(!injectedHtml.includes('data-vb-bridge="tok123"'), "guard.js MUST NOT receive an orphaned data-vb-bridge token when gate.js already exists!");

  // 3) METHOD_OVERRIDE_DENIED on protected routes & X-PS-Canary-Ack emitted on valid signed advance
  const eng = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api"] });
  const s = eng.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const ts = String(Date.now());
  const pr = eng.signRequest({
    sessionKeyHex: s.sessionKeyHex,
    method: "GET",
    pathWithQuery: "/api/items",
    body: "",
    seq: "1",
    ts,
    nonce: "nonce-ack-1",
    canary: s.canary,
  });
  const okRes = eng.inspectRequest({
    method: "GET",
    url: "/api/items",
    headers: makeBrowserHeaders({
      "x-ps-session": s.sessionId,
      "x-ps-seq": "1",
      "x-ps-ts": ts,
      "x-ps-nonce": "nonce-ack-1",
      "x-ps-canary": s.canary,
      "x-ps-proof": pr,
    }),
  });
  assert.equal(okRes.blocked, false);
  assert.equal(okRes.canaryAck, `${s.sessionId.slice(0, 8)}:1`, "inspectRequest MUST return session-and-seq bound canaryAck");

  const ovRes = eng.inspectRequest({
    method: "GET",
    url: "/api/items",
    headers: makeBrowserHeaders({
      "x-http-method-override": "DELETE",
      "x-ps-session": s.sessionId,
      "x-ps-seq": "2",
      "x-ps-ts": ts,
      "x-ps-nonce": "nonce-ov-2",
      "x-ps-canary": okRes.nextCanary,
      "x-ps-proof": eng.signRequest({
        sessionKeyHex: s.sessionKeyHex,
        method: "GET",
        pathWithQuery: "/api/items",
        body: "",
        seq: "2",
        ts,
        nonce: "nonce-ov-2",
        canary: okRes.nextCanary,
      }),
    }),
  });
  assert.equal(ovRes.blocked, true, "Mismatched X-HTTP-Method-Override on protected route MUST be blocked");
  assert.ok(ovRes.reasons.some((r) => r.code === "METHOD_OVERRIDE_DENIED"));

  // 4) restoreRequestStream MUST NOT prematurely drain req when on-finished registers req.on("end", ...) before async body consumer!
  const mw = createProxySnareMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  const endSrv = http.createServer(async (req, res) => {
    if (await mw(req, res)) return;
    let endCount = 0;
    req.on("end", () => { endCount++; });
    // Simulate async middleware delay (like session lookup) BEFORE reading body stream
    await new Promise((r) => setTimeout(r, 20));
    assert.equal(endCount, 0, "req.on('end') MUST NOT trigger premature body replay/drain!");
    const chunks = [];
    for await (const c of req) chunks.push(c);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ body: Buffer.concat(chunks).toString("utf8"), endCount }));
  });
  await new Promise((r) => endSrv.listen(0, "127.0.0.1", r));
  try {
    const eUrl = `http://127.0.0.1:${endSrv.address().port}`;
    const { hs, sessionKeyHex } = await performBrowserEcdhHandshake(eUrl);
    const body = '{"msg":"async-safe"}';
    const tsE = String(Date.now());
    const prE = mw.engine.signRequest({
      sessionKeyHex,
      method: "POST",
      pathWithQuery: "/api/async",
      body,
      seq: "1",
      ts: tsE,
      nonce: "nonce-async-1",
      canary: hs.canary,
    });
    const rE = await fetch(`${eUrl}/api/async`, {
      method: "POST",
      headers: makeBrowserHeaders({
        "Content-Type": "application/json",
        "X-PS-Session": hs.sessionId,
        "X-PS-Seq": "1",
        "X-PS-Ts": tsE,
        "X-PS-Nonce": "nonce-async-1",
        "X-PS-Canary": hs.canary,
        "X-PS-Proof": prE,
      }),
      body,
    });
    assert.equal(rE.status, 200);
    assert.equal(rE.headers.get("x-ps-canary-ack"), `${hs.sessionId.slice(0, 8)}:1`);
    assert.ok(String(rE.headers.get("vary") || "").toLowerCase().includes("x-ps-session"));
    assert.equal((await rE.json()).body, body);

    // Protected GET with Content-Length > 0 body injection MUST be rejected 400!
    const badGetStatus = await new Promise((resolve, reject) => {
      const req = http.request(
        {
          host: "127.0.0.1",
          port: endSrv.address().port,
          method: "GET",
          path: "/api/items",
          headers: makeBrowserHeaders({ "Content-Length": "11" }),
        },
        (r) => {
          r.resume();
          r.on("end", () => resolve(r.statusCode));
        }
      );
      req.on("error", reject);
      req.end("smuggled=11");
    });
    assert.equal(badGetStatus, 400, "Unsigned body on protected GET MUST be rejected with 400");
  } finally {
    await new Promise((r) => endSrv.close(r));
  }

  // 5) requireGuardIntegrity: false (balanced) tolerates rolling-deploy hash skew while still rejecting tampered_subtle!
  const balMw = createProxySnareMiddleware({ mode: "balanced", protectedPaths: ["/api"] });
  const balSrv = http.createServer(async (req, res) => {
    if (await balMw(req, res)) return;
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end('{"ok":true}');
  });
  await new Promise((r) => balSrv.listen(0, "127.0.0.1", r));
  try {
    const bUrl = `http://127.0.0.1:${balSrv.address().port}`;
    const kp = await crypto.webcrypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const pubB64 = Buffer.from(await crypto.webcrypto.subtle.exportKey("raw", kp.publicKey)).toString("base64");
    const bt1 = await (await fetch(`${bUrl}/__proxysnare/boot`, { headers: makeBrowserHeaders() })).json();
    const rSkew = await fetch(`${bUrl}/__proxysnare/handshake`, {
      method: "POST",
      headers: makeBrowserHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        protocol: "PS_ECDH_V2",
        clientPubB64: pubB64,
        bootToken: bt1.bootToken,
        powNonce: solvePowChallenge("PS_POW_V2", bt1.challenge, bt1.difficulty),
        guardHash: "b".repeat(64), // rolling deploy hash skew
      }),
    });
    assert.equal(rSkew.status, 200, "balanced (requireGuardIntegrity:false) MUST tolerate rolling-deploy guardHash skew");

    const bt2 = await (await fetch(`${bUrl}/__proxysnare/boot`, { headers: makeBrowserHeaders() })).json();
    const rTamp = await fetch(`${bUrl}/__proxysnare/handshake`, {
      method: "POST",
      headers: makeBrowserHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        protocol: "PS_ECDH_V2",
        clientPubB64: pubB64,
        bootToken: bt2.bootToken,
        powNonce: solvePowChallenge("PS_POW_V2", bt2.challenge, bt2.difficulty),
        guardHash: "TAMPERED_SUBTLE",
      }),
    });
    assert.equal(rTamp.status, 403, "balanced MUST still reject explicit TAMPERED_SUBTLE sentinel");
  } finally {
    await new Promise((r) => balSrv.close(r));
  }

  // 6) Multi-worker shared async store adapter allows Worker 1 handshake -> Worker 2 signed request!
  const sharedMap = new Map();
  const sharedStore = {
    async get(k) { return sharedMap.get(k); },
    async set(k, v) { sharedMap.set(k, v); },
    async delete(k) { sharedMap.delete(k); },
  };
  const sharedSec = "cluster-shared-secret-32-bytes!!";
  const mwW1 = createProxySnareMiddleware({ mode: "strict", secret: sharedSec, store: sharedStore, protectedPaths: ["/api"] });
  const mwW2 = createProxySnareMiddleware({ mode: "strict", secret: sharedSec, store: sharedStore, protectedPaths: ["/api"] });
  const srvW1 = http.createServer(async (req, res) => { if (!(await mwW1(req, res))) { res.writeHead(200); res.end("w1"); } });
  const srvW2 = http.createServer(async (req, res) => { if (!(await mwW2(req, res))) { res.writeHead(200); res.end("w2"); } });
  await Promise.all([
    new Promise((r) => srvW1.listen(0, "127.0.0.1", r)),
    new Promise((r) => srvW2.listen(0, "127.0.0.1", r)),
  ]);
  try {
    const u1 = `http://127.0.0.1:${srvW1.address().port}`;
    const u2 = `http://127.0.0.1:${srvW2.address().port}`;
    const { hs, sessionKeyHex } = await performBrowserEcdhHandshake(u1);
    const tsW = String(Date.now());
    const prW = mwW1.engine.signRequest({
      sessionKeyHex,
      method: "GET",
      pathWithQuery: "/api/cluster",
      body: "",
      seq: "1",
      ts: tsW,
      nonce: "nonce-cluster-1",
      canary: hs.canary,
    });
    const rW2 = await fetch(`${u2}/api/cluster`, {
      headers: makeBrowserHeaders({
        "X-PS-Session": hs.sessionId,
        "X-PS-Seq": "1",
        "X-PS-Ts": tsW,
        "X-PS-Nonce": "nonce-cluster-1",
        "X-PS-Canary": hs.canary,
        "X-PS-Proof": prW,
      }),
    });
    assert.equal(rW2.status, 200, "Worker 2 sharing options.store MUST accept Worker 1's session seamlessly!");
    assert.equal(await rW2.text(), "w2");
  } finally {
    await Promise.all([
      new Promise((r) => srvW1.close(r)),
      new Promise((r) => srvW2.close(r)),
    ]);
  }

  // 7) Reverse proxy: private, max-age=3600 HTML rewritten to private, no-cache when SRI injected; wildcard 304 static asset reload succeeds; public CDN HTML with persistent secret retains SRI!
  const upStatic = http.createServer((req, res) => {
    if (req.url === "/priv") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "private, max-age=3600" });
      res.end("<!doctype html><html><head></head><body>priv</body></html>");
      return;
    }
    if (req.url === "/pub") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "public, max-age=60" });
      res.end("<!doctype html><html><head></head><body>pub</body></html>");
      return;
    }
    if (req.url === "/app.css") {
      if (req.headers["if-none-match"]) {
        res.writeHead(304);
        res.end();
        return;
      }
      res.writeHead(200, { "Content-Type": "text/css", ETag: '"css1"' });
      res.end("body{color:red}");
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end('{"secret":true}');
  });
  await new Promise((r) => upStatic.listen(0, "127.0.0.1", r));
  const starSrv = createProxySnareServer({
    target: `http://127.0.0.1:${upStatic.address().port}`,
    mode: "strict",
    secret: sharedSec,
    protectedPaths: ["*"],
  });
  const starUrl = await starSrv.listen(0, "127.0.0.1");
  const starPort = starSrv.server.address().port;
  const rawGetStar = (reqPath, headers) =>
    new Promise((resolve, reject) => {
      const req = http.request({ host: "127.0.0.1", port: starPort, method: "GET", path: reqPath, headers }, (r) => {
        let data = "";
        r.on("data", (c) => (data += c));
        r.on("end", () => resolve({ status: r.statusCode, headers: r.headers, body: data }));
      });
      req.on("error", reject);
      req.end();
    });
  try {
    const navHdrs = makeBrowserHeaders({ accept: "text/html", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", "sec-fetch-site": "none" });
    const rPriv = await rawGetStar("/priv", navHdrs);
    assert.equal(rPriv.status, 200);
    assert.ok(rPriv.headers["cache-control"].includes("no-store") || rPriv.headers["cache-control"] === "private, no-cache");

    const rPub = await rawGetStar("/pub", navHdrs);
    assert.equal(rPub.status, 200);
    assert.ok(!rPub.body.includes(`integrity="${starSrv.guardSri}"`), "Public CDN-cacheable HTML MUST omit SRI by default to prevent rolling-deploy outages!");
    assert.ok(rPub.body.includes("/__proxysnare/guard.js"), "Public HTML still injects guard.js");

    // Cached static CSS reload with If-None-Match in wildcard ['*'] mode MUST succeed (200, not 403!)
    const rCss = await rawGetStar("/app.css", makeBrowserHeaders({ "sec-fetch-dest": "style", "sec-fetch-site": "same-origin", "if-none-match": '"css1"' }));
    assert.equal(rCss.status, 200, "Cached static asset reload in wildcard ['*'] mode MUST NOT 403 on 304");

    // Non-static API path claiming Sec-Fetch-Dest: image MUST be blocked 403!
    const rApiSpoof = await rawGetStar("/api/secret", makeBrowserHeaders({ "sec-fetch-dest": "image", "sec-fetch-site": "same-origin" }));
    assert.equal(rApiSpoof.status, 403, "API path without static asset extension MUST NOT bypass wildcard via Sec-Fetch-Dest: image");
  } finally {
    await starSrv.close();
    await new Promise((r) => upStatic.close(r));
  }

  // 8) Node <-> Python 3-part PS_BOOT_V2S interop, duplicate-header Firecrawl detection, and IPv6 CORS preflight canonicalization!
  const nodeBoot = createProxySnareEngine({ mode: "strict", secret: sharedSec }).issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const nodePow = solvePowChallenge("PS_POW_V2", nodeBoot.challenge, nodeBoot.difficulty);
  const pyBootOut = execFileSync(
    "python3",
    [
      "-c",
      `import sys, json; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier, is_ai_crawler_request
v = ProxySnareVerifier(mode="strict", secret=${JSON.stringify(sharedSec)}, protected_paths=["/api"])
# Node-issued 3-part PS_BOOT_V2S token consumed by Python + replay blocked!
res1 = v.consume_boot_challenge_detail(boot_token=${JSON.stringify(nodeBoot.bootToken)}, pow_nonce=${JSON.stringify(nodePow)}, ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
assert res1["ok"], f"Python failed to consume Node PS_BOOT_V2S: {res1}"
res2 = v.consume_boot_challenge_detail(boot_token=${JSON.stringify(nodeBoot.bootToken)}, pow_nonce=${JSON.stringify(nodePow)}, ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
assert not res2["ok"], "Python MUST block replay of Node PS_BOOT_V2S token"
# Duplicate/mixed-case header Firecrawl bypass blocked!
assert is_ai_crawler_request({"User-Agent": "FirecrawlAgent/1.0", "user-agent": "Mozilla/5.0 Chrome/130.0.0.0"})
r_dup = v.inspect_request(method="GET", url="/public", headers={"User-Agent": "FirecrawlAgent/1.0", "user-agent": "Mozilla/5.0 Chrome/130.0.0.0"})
assert r_dup.blocked and any(x["code"] == "AI_CRAWLER_OR_SCRAPER_DENIED" for x in r_dup.reasons)
# IPv6 canonicalization in CORS preflight: Origin [0:0:0:0:0:0:0:1]:8080 == Host [::1]:8080 is SAME-ORIGIN (NOT exempt!)
r_v6 = v.inspect_request(method="OPTIONS", url="/api/x", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Host": "[::1]:8080", "Origin": "http://[0:0:0:0:0:0:0:1]:8080", "Access-Control-Request-Method": "POST", "Sec-Fetch-Mode": "cors"})
assert r_v6.blocked, "Same-origin IPv6 alias MUST NOT be exempted as cross-origin CORS preflight"
# Issue Python PS_BOOT_V2S token for Node consumption!
py_boot = v.issue_boot_challenge(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
print(json.dumps(py_boot))`,
    ],
    { encoding: "utf8" }
  ).trim();
  const pyBoot = JSON.parse(pyBootOut);
  assert.equal(pyBoot.bootToken.split(".").length, 3, "Python must emit 3-part PS_BOOT_V2S bootToken");
  const nodeConsumePy = createProxySnareEngine({ mode: "strict", secret: sharedSec }).consumeBootChallenge({
    bootToken: pyBoot.bootToken,
    powNonce: solvePowChallenge("PS_POW_V2", pyBoot.challenge, pyBoot.difficulty),
    ip: "127.0.0.1",
    userAgent: CHROME_UA,
  });
  assert.equal(nodeConsumePy.ok, true, `Node MUST consume Python 3-part PS_BOOT_V2S token: ${nodeConsumePy.error}`);
});

test("15. Pass-4 Audit Regressions: ready() state leak fix, .bind(null) & RegExp tamper defense, PS1 gesture bypass fix, Readable.toWeb stream, IPv6 Node/Python parity, Python trailing-\\n fast-path & distributed nonce claim", async () => {
  const { Readable } = require("node:stream");

  // 1) ProxySnare.ready() MUST NOT leak internal state/cryptoKey/canary AND .bind(null) + window.RegExp hooks MUST fail closed!
  const engStrict = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api"] });
  const guardSrc = buildBrowserGuardScript({
    basePath: "/__proxysnare",
    protectedPaths: ["/api"],
    serverVerifyPubB64: engStrict.serverVerifyPubB64,
  });
  assert.ok(guardSrc.includes("_reflectApply(_nativePromiseThen, ensureSession(false), [() => true])"), "ready() MUST only resolve boolean true via native Promise.then, NEVER live state/cryptoKey!");
  assert.ok(guardSrc.includes("_NATIVE_FN_RE") && guardSrc.includes("isNativeNamed"), "SubtleCrypto & console.debug checks MUST use pre-compiled anchored static regex literals (immune to window.RegExp hook & .bind(null))");

  // Verify window.RegExp AND RegExp.prototype.test hijack cannot fool computeRuntimeGuardHash() in a browser-like VM!
  const subtleProto = Object.getPrototypeOf(crypto.webcrypto.subtle);
  const iframeVm4 = vm.createContext({ console: { debug: console.debug } });
  const iframeWin4 = vm.runInContext(
    `(() => {
      const orig = Function.prototype.toString;
      const nativeNames = new Set(["URL", "get origin", "get pathname", "toString", "call", "apply", "bind", "test", "defineProperty", "createElement", "appendChild", "get documentElement", "get contentWindow", "contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "encode", "set", "get", "has", "json", "clone", "arrayBuffer", "get status", "get headers", "get redirected", "get url", "get type", "fetch", "getRandomValues", "getEntriesByType", "now"]);
      Function.prototype.toString = function toString() {
        if (typeof this === "function" && nativeNames.has(this.name)) return "function " + this.name + "() { [native code] }";
        return orig.call(this);
      };
      return globalThis;
    })();`,
    iframeVm4
  );
  class HTMLIFrameElement4 { constructor() { this.style = { cssText: "" }; } get contentWindow() { return iframeWin4; } remove() {} }
  class Node4 { appendChild(c) { return c; } }
  class Element4 extends Node4 { getAttribute() { return null; } }
  class Document4 extends Node4 { constructor() { super(); this.currentScript = null; this.baseURI = "https://app.example/"; this._docEl = new Element4(); } get documentElement() { return this._docEl; } createElement(t) { return t === "iframe" ? new HTMLIFrameElement4() : {}; } }
  const vmBadRegex = vm.createContext({
    crypto: {
      subtle: Object.create(subtleProto, { deriveKey: { value: function deriveKey() {}, configurable: true } }),
      getRandomValues: crypto.webcrypto.getRandomValues,
    },
    SubtleCrypto: subtleProto.constructor,
    TextEncoder, URL, Headers, Response, Request, console, setTimeout, clearTimeout, performance,
    navigator: { webdriver: false },
    document: new Document4(),
    Document: Document4,
    Node: Node4,
    Element: Element4,
    HTMLIFrameElement: HTMLIFrameElement4,
    location: { origin: "https://app.example", href: "https://app.example/" },
    fetch: async function fetch() { return new Response("{}"); },
    addEventListener() {},
  });
  vmBadRegex.window = vmBadRegex;
  vm.runInContext(
    `(() => {
      const orig = Function.prototype.toString;
      const domNames = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "get documentElement", "get contentWindow", "getAttribute", "encode", "set", "get", "has", "json", "clone", "arrayBuffer", "get status", "get headers", "get redirected", "get url", "get type", "fetch", "getRandomValues", "getEntriesByType", "now"]);
      Function.prototype.toString = function toString() {
        if (typeof this === "function" && domNames.has(this.name)) return "function " + this.name + "() { [native code] }";
        return orig.call(this);
      };
    })();`,
    vmBadRegex
  );
  vm.runInContext(`console.debug = (() => {}).bind(null);`, vmBadRegex);
  vm.runInContext(guardSrc, vmBadRegex);
  // Before window.RegExp hijack, tampered SubtleCrypto fails as TAMPERED_SUBTLE; after window.RegExp hijack, cross-realm check immediately fails closed as TAMPERED_GUARD!
  assert.equal(vmBadRegex.ProxySnare.guardHash(), "TAMPERED_SUBTLE", "Tampered SubtleCrypto MUST return TAMPERED_SUBTLE!");
  vm.runInContext(`window.RegExp = function FakeRegExp() { return { test: () => true }; };`, vmBadRegex);
  assert.equal(vmBadRegex.ProxySnare.guardHash(), "TAMPERED_GUARD", "window.RegExp hook MUST fail closed as TAMPERED_GUARD!");
  assert.equal(vmBadRegex.ProxySnare.detectCdpActive(), true, "console.debug = (() => {}).bind(null) MUST fail closed as CDP active!");

  // 2) requireUserGestureOnMutate: true CANNOT be bypassed by omitting X-PS-Ctx (PS1| signing) even when requireSignedContext: false!
  const gestEng = createProxySnareEngine({
    mode: "strict",
    requireUserGestureOnMutate: true,
    requireSignedContext: false,
    protectedPaths: ["/api"],
  });
  const gs = gestEng.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const tsG = String(Date.now());
  const ps1Proof = gestEng.signRequest({
    sessionKeyHex: gs.sessionKeyHex,
    method: "POST",
    pathWithQuery: "/api/transfer",
    body: '{"amt":100}',
    seq: "1",
    ts: tsG,
    nonce: "nonce-ps1-gest-1",
    canary: gs.canary,
    ctx: "", // omitted X-PS-Ctx!
  });
  const rPs1Gest = gestEng.inspectRequest({
    method: "POST",
    url: "/api/transfer",
    body: '{"amt":100}',
    headers: makeBrowserHeaders({
      "x-ps-session": gs.sessionId,
      "x-ps-seq": "1",
      "x-ps-ts": tsG,
      "x-ps-nonce": "nonce-ps1-gest-1",
      "x-ps-canary": gs.canary,
      "x-ps-proof": ps1Proof,
    }),
  });
  assert.equal(rPs1Gest.blocked, true, "Omitting X-PS-Ctx (PS1) MUST NOT bypass requireUserGestureOnMutate:true!");
  assert.ok(rPs1Gest.reasons.some((r) => r.code === "MUTATION_WITHOUT_USER_GESTURE"));

  // 3) Strict mode blocks active CDP even when ce=0 (defeats //# sourceURL=<location.href> bypass!), while strict+allowDevTools allows it!
  const ss = engStrict.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const cdpOnlyCtx = "ce=0;cdp=1;ug=1;ga=10";
  const rStrictCdp = engStrict.inspectRequest({
    method: "POST",
    url: "/api/checkout",
    body: "{}",
    headers: makeBrowserHeaders({
      "x-ps-session": ss.sessionId,
      "x-ps-seq": "1",
      "x-ps-ts": tsG,
      "x-ps-nonce": "nonce-strict-cdp-1",
      "x-ps-canary": ss.canary,
      "x-ps-ctx": cdpOnlyCtx,
      "x-ps-proof": engStrict.signRequest({
        sessionKeyHex: ss.sessionKeyHex,
        method: "POST",
        pathWithQuery: "/api/checkout",
        body: "{}",
        seq: "1",
        ts: tsG,
        nonce: "nonce-strict-cdp-1",
        canary: ss.canary,
        ctx: cdpOnlyCtx,
      }),
    }),
  });
  assert.equal(rStrictCdp.blocked, true, "strict mode MUST block cdp=1 even when ce=0 (closes //# sourceURL=<location.href> bypass)");

  // 4) Node CORS preflight: empty Access-Control-Request-Method NOT exempted, same-origin IPv6 Host alias NOT exempted, canaryAck === null!
  const rEmptyAcrm = engStrict.inspectRequest({
    method: "OPTIONS",
    url: "/api/secret",
    headers: makeBrowserHeaders({
      host: "app.example",
      origin: "https://other.example",
      "access-control-request-method": "   ",
      "sec-fetch-mode": "cors",
    }),
  });
  assert.equal(rEmptyAcrm.blocked, true, "Blank Access-Control-Request-Method MUST NOT exempt OPTIONS from auth");

  const rIpv6Same = engStrict.inspectRequest({
    method: "OPTIONS",
    url: "/api/secret",
    headers: makeBrowserHeaders({
      host: "[0:0:0:0:0:0:0:1]:8080",
      origin: "http://[::1]:8080",
      "access-control-request-method": "POST",
      "sec-fetch-mode": "cors",
    }),
  });
  assert.equal(rIpv6Same.blocked, true, "Node MUST canonicalize IPv6 Host alias and reject same-origin OPTIONS preflight!");

  const rCorsOk = engStrict.inspectRequest({
    method: "OPTIONS",
    url: "/api/secret",
    headers: makeBrowserHeaders({
      host: "app.example",
      origin: "https://other.example",
      "access-control-request-method": "POST",
      "sec-fetch-mode": "cors",
    }),
  });
  assert.equal(rCorsOk.blocked, false);
  assert.equal(rCorsOk.canaryAck, null, "CORS preflight verdict MUST include canaryAck: null");

  // 5) importSessionRecord enforces maxSessions cap (no unbounded memory leak!)
  const capEng = createProxySnareEngine({ mode: "strict", maxSessions: 4, secret: "cap-test-shared-secret-32-bytes!!" });
  const nowExp = Date.now() + 60_000;
  for (let i = 0; i < 12; i++) {
    capEng.importSessionRecord({
      sessionId: String(i).padStart(32, "a"),
      keyB64: Buffer.alloc(32, i).toString("base64"),
      lastSeq: 0,
      canary: "c".repeat(24),
      uaHash: "0".repeat(64),
      ip: "127.0.0.1",
      origin: "",
      exp: nowExp,
    });
  }
  assert.equal(capEng.exportSessionRecord("0".padStart(32, "a")), null, "Oldest imported sessions MUST be evicted when exceeding maxSessions");
  assert.ok(capEng.exportSessionRecord("11".padStart(32, "a")), "Most recent imported session MUST remain cached");

  // 6) options.store without persistent secret throws clear error, and distributed setIfNotExists prevents multi-worker nonce replay!
  assert.throws(
    () => createProxySnareMiddleware({ mode: "strict", store: { get() {}, set() {} } }),
    /persistent 'secret'/i,
    "options.store without persistent secret MUST throw configuration error"
  );

  const distMap = new Map();
  const atomicStore = {
    async get(k) { return distMap.get(k); },
    async set(k, v) { distMap.set(k, v); },
    async setIfNotExists(k, v) {
      if (distMap.has(k)) return false;
      distMap.set(k, v);
      return true;
    },
  };
  const sharedSec = "pass4-cluster-secret-32-bytes-ok!";
  const mwA = createProxySnareMiddleware({ mode: "strict", secret: sharedSec, store: atomicStore, protectedPaths: ["/api"] });
  const mwB = createProxySnareMiddleware({ mode: "strict", secret: sharedSec, store: atomicStore, protectedPaths: ["/api"] });
  const srvA = http.createServer(async (req, res) => { if (!(await mwA(req, res))) { res.writeHead(200); res.end("A"); } });
  const srvB = http.createServer(async (req, res) => { if (!(await mwB(req, res))) { res.writeHead(200); res.end("B"); } });
  await Promise.all([new Promise((r) => srvA.listen(0, "127.0.0.1", r)), new Promise((r) => srvB.listen(0, "127.0.0.1", r))]);
  try {
    const uA = `http://127.0.0.1:${srvA.address().port}`;
    const uB = `http://127.0.0.1:${srvB.address().port}`;
    const { hs, sessionKeyHex } = await performBrowserEcdhHandshake(uA);
    const tsD = String(Date.now());
    const prD = mwA.engine.signRequest({
      sessionKeyHex,
      method: "POST",
      pathWithQuery: "/api/pay",
      body: '{"v":1}',
      seq: "1",
      ts: tsD,
      nonce: "nonce-dist-race-1",
      canary: hs.canary,
    });
    const reqHdrs = makeBrowserHeaders({
      "Content-Type": "application/json",
      "X-PS-Session": hs.sessionId,
      "X-PS-Seq": "1",
      "X-PS-Ts": tsD,
      "X-PS-Nonce": "nonce-dist-race-1",
      "X-PS-Canary": hs.canary,
      "X-PS-Proof": prD,
    });
    const [ra, rb] = await Promise.all([
      fetch(`${uA}/api/pay`, { method: "POST", headers: reqHdrs, body: '{"v":1}' }),
      fetch(`${uB}/api/pay`, { method: "POST", headers: reqHdrs, body: '{"v":1}' }),
    ]);
    const statuses = [ra.status, rb.status].sort();
    assert.deepEqual(statuses, [200, 403], "Concurrent multi-worker replay of identical signed request MUST allow exactly ONE worker (200) and block the other (403)!");

    // Redirected GET carrying immediately prior POST's consumed X-PS-* headers emits X-PS-Redirect-Get: 1
    const rPrg = await fetch(`${uA}/api/done`, { method: "GET", headers: reqHdrs });
    assert.equal(rPrg.status, 403);
    assert.equal(rPrg.headers.get("x-ps-redirect-get"), "1", "Redirected GET after POST MUST emit X-PS-Redirect-Get: 1 recovery hint");
  } finally {
    await Promise.all([new Promise((r) => srvA.close(r)), new Promise((r) => srvB.close(r))]);
  }

  // 7) restoreRequestStream works cleanly with Readable.toWeb(req) AND paused-mode req.on("readable")/req.read()!
  const webMw = createProxySnareMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  const webSrv = http.createServer(async (req, res) => {
    if (await webMw(req, res)) return;
    if (req.url === "/api/toweb") {
      const webStream = Readable.toWeb(req);
      const reader = webStream.getReader();
      const parts = [];
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        parts.push(Buffer.from(value));
      }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ got: Buffer.concat(parts).toString("utf8") }));
      return;
    }
    const chunks = [];
    req.on("readable", () => {
      let c;
      while ((c = req.read()) !== null) chunks.push(Buffer.from(c));
    });
    req.on("end", () => {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ got: Buffer.concat(chunks).toString("utf8") }));
    });
  });
  await new Promise((r) => webSrv.listen(0, "127.0.0.1", r));
  try {
    const wUrl = `http://127.0.0.1:${webSrv.address().port}`;
    const { hs, sessionKeyHex } = await performBrowserEcdhHandshake(wUrl);
    const sendSigned = async (p, seqN, can, nonce) => {
      const tsW = String(Date.now());
      const body = `payload-${seqN}`;
      const pr = webMw.engine.signRequest({ sessionKeyHex, method: "POST", pathWithQuery: p, body, seq: String(seqN), ts: tsW, nonce, canary: can });
      return fetch(`${wUrl}${p}`, {
        method: "POST",
        headers: makeBrowserHeaders({ "Content-Type": "text/plain", "X-PS-Session": hs.sessionId, "X-PS-Seq": String(seqN), "X-PS-Ts": tsW, "X-PS-Nonce": nonce, "X-PS-Canary": can, "X-PS-Proof": pr }),
        body,
      });
    };
    const rWeb = await sendSigned("/api/toweb", 1, hs.canary, "nonce-toweb-1");
    assert.equal(rWeb.status, 200);
    assert.equal((await rWeb.json()).got, "payload-1", "Readable.toWeb(req) MUST read full restored body!");
    const rRead = await sendSigned("/api/readable", 2, rWeb.headers.get("x-ps-next-canary"), "nonce-read-2");
    assert.equal(rRead.status, 200);
    assert.equal((await rRead.json()).got, "payload-2", "Paused-mode req.on('readable')+req.read() MUST read full restored body!");
  } finally {
    await new Promise((r) => webSrv.close(r));
  }

  // 8) Python parity: trailing-newline fast-path immunity, PS1 gesture bypass fix, blank ACRM rejection!
  execFileSync(
    "python3",
    [
      "-c",
      `import sys, time; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier, normalize_pathname
v = ProxySnareVerifier(mode="strict", protected_paths=["/api"], require_user_gesture_on_mutate=True, require_signed_context=False)
assert v.is_path_protected("/api/secret\\n"), "Trailing \\n MUST NOT bypass Python _CLEAN_ASCII_PATH_RE!"
assert v.is_path_protected("/api\\n"), "Trailing \\n on /api MUST remain protected!"
# Blank Access-Control-Request-Method MUST NOT be exempted
r_acrm = v.inspect_request(method="OPTIONS", url="/api/x", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Host": "app.example", "Origin": "https://other.example", "Access-Control-Request-Method": "  ", "Sec-Fetch-Mode": "cors"})
assert r_acrm.blocked, "Blank Access-Control-Request-Method MUST be blocked"
# PS1 (omitted X-PS-Ctx) MUST NOT bypass require_user_gesture_on_mutate=True
s = v.issue_session(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
ts = str(int(time.time() * 1000))
pr = v.sign_request(session_key_hex=s["sessionKeyHex"], method="POST", path_with_query="/api/transfer", body=b"{}", seq="1", ts=ts, nonce="py-ps1-gest-1", canary=s["canary"], ctx="")
r_ps1 = v.inspect_request(method="POST", url="/api/transfer", body=b"{}", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-PS-Session": s["sessionId"], "X-PS-Seq": "1", "X-PS-Ts": ts, "X-PS-Nonce": "py-ps1-gest-1", "X-PS-Canary": s["canary"], "X-PS-Proof": pr})
assert r_ps1.blocked and any(x["code"] == "MUTATION_WITHOUT_USER_GESTURE" for x in r_ps1.reasons), f"Python PS1 gesture bypass: {r_ps1.reasons}"`,
    ],
    { encoding: "utf8" }
  );
});

test("16. Pass-5 Audit Regressions: unified sri:false & store & playground, method-override shadowing, custom-threshold body smuggling, Express+trustProxy XFF, signingKeyPair cluster boot, CDN headers, manifest.json, 304 ETag, RegExp.prototype.test defense & Python parity", async () => {
  // 1) Unified mode with sri:false MUST serve embedded VeilBreak SDK + matching guardHash AND start cleanly with ProxySnareStore (no delete/take)!
  const psOnlyStoreMap = new Map();
  const psOnlyStore = {
    async get(k) { return psOnlyStoreMap.get(k); },
    async set(k, v) { psOnlyStoreMap.set(k, v); },
    async setIfNotExists(k, v) {
      if (psOnlyStoreMap.has(k)) return false;
      psOnlyStoreMap.set(k, v);
      return true;
    },
  };
  const uNoSri = createUnifiedMiddleware({
    mode: "strict",
    sri: false,
    secret: "pass5-unified-no-sri-secret-32b!",
    store: psOnlyStore,
    protectedPaths: ["/api"],
  });
  let dynGuardBody = "";
  await uNoSri(
    {
      method: "GET",
      url: "/__proxysnare/guard.js",
      socket: { remoteAddress: "127.0.0.1" },
      headers: makeBrowserHeaders({ "sec-fetch-site": "same-origin", "sec-fetch-mode": "no-cors", "sec-fetch-dest": "script" }),
    },
    {
      headersSent: false,
      writableEnded: false,
      setHeader() {},
      writeHead() { this.headersSent = true; },
      end(b) { dynGuardBody = String(b || ""); this.writableEnded = true; },
    }
  );
  assert.ok(dynGuardBody.includes("const EMBEDDED_VB = true;"), "Unified sri:false dynamic /guard.js MUST include embedded VeilBreak SDK!");
  assert.ok(dynGuardBody.includes("__VB_PRIVATE_REGISTER__"), "Unified sri:false dynamic /guard.js MUST wire private closure!");
  assert.equal(computeGuardIntegrity(dynGuardBody).guardHash, uNoSri.guardHash, "Unified sri:false dynamic /guard.js MUST preserve exact guardHash!");

  // 2) Unified /__veilbreak/playground serves ONE unified guard.js tag with data-block-page="false" and NO duplicate gate.js!
  const uPg = createUnifiedMiddleware({ mode: "strict", enablePlayground: true, protectedPaths: ["/api"] });
  let pgHtml = "";
  await uPg(
    {
      method: "GET",
      url: "/__veilbreak/playground",
      socket: { remoteAddress: "127.0.0.1" },
      headers: makeBrowserHeaders({ accept: "text/html" }),
    },
    {
      headersSent: false,
      writableEnded: false,
      setHeader() {},
      writeHead() { this.headersSent = true; },
      end(b) { pgHtml = Buffer.isBuffer(b) ? b.toString("utf8") : String(b || ""); this.writableEnded = true; },
    }
  );
  assert.ok(pgHtml.includes('data-block-page="false"'), "Unified playground MUST stamp data-block-page='false' on guard.js tag");
  assert.ok(pgHtml.includes('data-unified-bundle="true"'), "Unified playground MUST serve unified guard.js");
  assert.ok(!pgHtml.includes("/__veilbreak/gate.js"), "Unified playground MUST NOT double-load standalone /__veilbreak/gate.js");

  // 3) Dual HTTP method-override shadowing blocked with METHOD_OVERRIDE_DENIED AND triggers MUTATION_WITHOUT_USER_GESTURE!
  const engPar = createProxySnareEngine({ mode: "paranoid", protectedPaths: ["/api"] });
  const psS = engPar.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const ts5 = String(Date.now());
  const ctx5 = "ce=0;cdp=0;ug=0;ga=999999";
  const pr5 = engPar.signRequest({
    sessionKeyHex: psS.sessionKeyHex,
    method: "GET",
    pathWithQuery: "/api/users/42",
    body: "",
    seq: "1",
    ts: ts5,
    nonce: "nonce-ov-shadow-1",
    canary: psS.canary,
    ctx: ctx5,
  });
  const rShadow = engPar.inspectRequest({
    method: "GET",
    url: "/api/users/42",
    headers: makeBrowserHeaders({
      "x-http-method-override": "GET",
      "x-method-override": "DELETE",
      "x-ps-session": psS.sessionId,
      "x-ps-seq": "1",
      "x-ps-ts": ts5,
      "x-ps-nonce": "nonce-ov-shadow-1",
      "x-ps-canary": psS.canary,
      "x-ps-ctx": ctx5,
      "x-ps-proof": pr5,
    }),
  });
  assert.equal(rShadow.blocked, true, "Dual override shadowing (GET + DELETE) MUST be blocked!");
  assert.ok(rShadow.reasons.some((r) => r.code === "METHOD_OVERRIDE_DENIED"));
  assert.ok(rShadow.reasons.some((r) => r.code === "MUTATION_WITHOUT_USER_GESTURE"));

  // 4) Custom threshold > 6: skipPreAuthBodyRead MUST NOT allow signed empty-body smuggling when X-Firecrawl-Job adds only +6 < threshold 8!
  const customMw = createProxySnareMiddleware({ mode: "balanced", threshold: 8, protectedPaths: ["/api"] });
  const customSrv = http.createServer(async (req, res) => {
    if (await customMw(req, res)) return;
    res.writeHead(200);
    res.end("ALLOWED");
  });
  await new Promise((r) => customSrv.listen(0, "127.0.0.1", r));
  try {
    const cUrl = `http://127.0.0.1:${customSrv.address().port}`;
    const { hs, sessionKeyHex } = await performBrowserEcdhHandshake(cUrl);
    const tsC = String(Date.now());
    // Sign over EMPTY body "" while sending an actual JSON body + X-Firecrawl-Job header!
    const emptySig = customMw.engine.signRequest({
      sessionKeyHex,
      method: "POST",
      pathWithQuery: "/api/transfer",
      body: "",
      seq: "1",
      ts: tsC,
      nonce: "nonce-smug-1234",
      canary: hs.canary,
    });
    const rSmug = await fetch(`${cUrl}/api/transfer`, {
      method: "POST",
      headers: makeBrowserHeaders({
        "Content-Type": "application/json",
        "X-Firecrawl-Job": "1",
        "X-PS-Session": hs.sessionId,
        "X-PS-Seq": "1",
        "X-PS-Ts": tsC,
        "X-PS-Nonce": "nonce-smug-1234",
        "X-PS-Canary": hs.canary,
        "X-PS-Proof": emptySig,
      }),
      body: '{"to":"attacker","amount":999999}',
    });
    assert.equal(rSmug.status, 403, "Custom threshold > 6 MUST NOT skip body buffering & allow empty-body HMAC smuggling!");
  } finally {
    await new Promise((r) => customSrv.close(r));
  }

  // 5) Multi-worker { store, signingKeyPair } WITHOUT secret derives shared boot secret so Worker 2 consumes Worker 1's boot token!
  const kpShared = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const wKp1 = createProxySnareEngine({ mode: "strict", signingKeyPair: kpShared });
  const wKp2 = createProxySnareEngine({ mode: "strict", signingKeyPair: kpShared });
  const bKp1 = wKp1.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const cKp2 = wKp2.consumeBootChallenge({
    bootToken: bKp1.bootToken,
    powNonce: solvePowChallenge("PS_POW_V2", bKp1.challenge, bKp1.difficulty),
    ip: "127.0.0.1",
    userAgent: CHROME_UA,
  });
  assert.equal(cKp2.ok, true, `Worker 2 sharing signingKeyPair MUST consume Worker 1 boot token: ${cKp2.error}`);

  // 6) Express trust proxy ('loopback') + options.trustProxy ('10.0.0.1'): direct untrusted IP CANNOT spoof X-Forwarded-For!
  const tpPsMw = createProxySnareMiddleware({ mode: "strict", trustProxy: ["10.0.0.1"], maxHandshakesPerMin: 1, protectedPaths: ["/api"] });
  const callBoot = async (remoteAddress, xff) => {
    let status = 0;
    await tpPsMw(
      {
        method: "GET",
        url: "/__proxysnare/boot",
        socket: { remoteAddress },
        ip: xff,
        app: { get: (k) => (k === "trust proxy" ? "loopback" : undefined) },
        headers: makeBrowserHeaders({ "x-forwarded-for": xff, "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors" }),
      },
      {
        headersSent: false,
        writableEnded: false,
        setHeader() {},
        writeHead(c) { status = c; this.headersSent = true; },
        end() { this.writableEnded = true; },
      }
    );
    return status;
  };
  assert.equal(await callBoot("203.0.113.99", "8.8.8.1"), 200);
  assert.equal(await callBoot("203.0.113.99", "8.8.8.2"), 429, "Untrusted direct IP MUST NOT spoof XFF when Express trust proxy + options.trustProxy are both configured");

  // 7) Versioned /guard.js?v=... returns 304 on matching If-None-Match + balanced allowDevTools:false blocks CDP!
  let g304 = 0;
  await tpPsMw(
    {
      method: "GET",
      url: `/__proxysnare/guard.js?v=${tpPsMw.guardVersion}`,
      socket: { remoteAddress: "127.0.0.1" },
      headers: { "if-none-match": `"${tpPsMw.guardVersion}"` },
    },
    {
      headersSent: false,
      writableEnded: false,
      setHeader() {},
      writeHead(c) { g304 = c; this.headersSent = true; },
      end() { this.writableEnded = true; },
    }
  );
  assert.equal(g304, 304, "Versioned /guard.js?v=... with matching ETag MUST return 304");

  const balNoDtEng = createProxySnareEngine({ mode: "balanced", allowDevTools: false, protectedPaths: ["/api"] });
  const bs5 = balNoDtEng.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const cdpCtx5 = "ce=0;cdp=1;ug=1;ga=10";
  const rBalCdp = balNoDtEng.inspectRequest({
    method: "POST",
    url: "/api/x",
    body: "{}",
    headers: makeBrowserHeaders({
      "x-ps-session": bs5.sessionId,
      "x-ps-seq": "1",
      "x-ps-ts": ts5,
      "x-ps-nonce": "nonce-bal-cdp-1",
      "x-ps-canary": bs5.canary,
      "x-ps-ctx": cdpCtx5,
      "x-ps-proof": balNoDtEng.signRequest({ sessionKeyHex: bs5.sessionKeyHex, method: "POST", pathWithQuery: "/api/x", body: "{}", seq: "1", ts: ts5, nonce: "nonce-bal-cdp-1", canary: bs5.canary, ctx: cdpCtx5 }),
    }),
  });
  assert.equal(rBalCdp.blocked, true, "balanced + allowDevTools:false MUST block cdp=1!");

  // 8) Reverse proxy: CDN-Cache-Control prevents data-ps-boot + SRI leakage, and wildcard /manifest.json served as application/json allowed!
  const upPs5 = http.createServer((req, res) => {
    if (req.url === "/cdn") {
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "max-age=0, must-revalidate",
        "CDN-Cache-Control": "public, max-age=3600",
        "Surrogate-Control": "max-age=3600",
      });
      res.end("<!doctype html><html><head></head><body>cdn</body></html>");
      return;
    }
    if (req.url === "/manifest.json") {
      res.writeHead(200, { "Content-Type": "application/json; charset=utf-8" });
      res.end('{"name":"PWA"}');
      return;
    }
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end('{"ok":true}');
  });
  await new Promise((r) => upPs5.listen(0, "127.0.0.1", r));
  const psSrv5 = createProxySnareServer({ target: `http://127.0.0.1:${upPs5.address().port}`, mode: "strict", protectedPaths: ["*"] });
  await psSrv5.listen(0, "127.0.0.1");
  const portPs5 = psSrv5.server.address().port;
  const reqPs5 = (p, headers) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port: portPs5, method: "GET", path: p, headers }, (resp) => {
        let d = "";
        resp.on("data", (c) => (d += c));
        resp.on("end", () => resolve({ status: resp.statusCode, headers: resp.headers, body: d }));
      });
      r.on("error", reject);
      r.end();
    });
  try {
    const rCdn = await reqPs5("/cdn", makeBrowserHeaders({ accept: "text/html", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", "sec-fetch-site": "none" }));
    assert.equal(rCdn.status, 200);
    assert.ok(!rCdn.body.includes("data-ps-boot"), "CDN-Cache-Control public HTML MUST NOT stamp per-user data-ps-boot");
    assert.ok(!rCdn.body.includes("integrity="), "CDN-Cache-Control public HTML MUST NOT pin ephemeral SRI");

    const rMan = await reqPs5("/manifest.json", makeBrowserHeaders({ "sec-fetch-dest": "manifest", "sec-fetch-site": "same-origin" }));
    assert.equal(rMan.status, 200, "Wildcard /manifest.json served as application/json with Sec-Fetch-Dest: manifest MUST succeed");
  } finally {
    await psSrv5.close();
    await new Promise((r) => upPs5.close(r));
  }

  // 9) Browser guard Pass-5 checks: RegExp.prototype.test pre-load hook fails closed, Safari global code@https://..., canonical trailing-?, 307/308, F12 exclusion, sticky cdpEverDetected
  const g5Src = buildBrowserGuardScript({ basePath: "/__proxysnare", protectedPaths: ["/api"] });
  new Function(g5Src);
  assert.ok(g5Src.includes("extractFrameLocation") && g5Src.includes("_LOC_PREFIX_RE"), "Structural frame location parser MUST safely separate Safari/Gecko @ locations (including global code@https://...)");
  assert.ok(g5Src.includes("canonicalTargetUrl") && g5Src.includes("canonicalXhrUrl"), "Fetch & XHR MUST dispatch canonical pathname+search URLs (fixing trailing '?')");
  assert.ok(g5Src.includes("missingCanaryDesync"), "Missing X-PS-Next-Canary on 5xx MUST reset session instead of bricking tab");
  assert.ok(g5Src.includes("preserveMutate"), "307/308 redirects MUST preserve method + body");
  assert.ok(g5Src.includes("cdpEverDetected") && g5Src.includes('"F12"'), "Guard MUST maintain sticky cdpEverDetected and exclude F12 from user gestures");

  // Pre-load RegExp.prototype.test hook MUST fail closed as TAMPERED_GUARD!
  const subtleP5 = Object.getPrototypeOf(crypto.webcrypto.subtle);
  const iframeVm5 = vm.createContext({ console: { debug: console.debug } });
  const iframeWin5 = vm.runInContext(
    `(() => {
      const orig = Function.prototype.toString;
      const nativeNames = new Set(["toString", "defineProperty", "createElement", "appendChild", "get contentWindow", "contentWindow", "debug"]);
      Function.prototype.toString = function toString() {
        if (typeof this === "function" && nativeNames.has(this.name)) return "function " + this.name + "() { [native code] }";
        return orig.call(this);
      };
      return globalThis;
    })();`,
    iframeVm5
  );
  class HTMLIFrameElement5 { constructor() { this.style = { cssText: "" }; } get contentWindow() { return iframeWin5; } remove() {} }
  class Node5 { appendChild(c) { return c; } }
  class Document5 extends Node5 { constructor() { super(); this.currentScript = null; this.baseURI = "https://app.example/"; this.documentElement = new Node5(); } createElement(t) { return t === "iframe" ? new HTMLIFrameElement5() : {}; } }
  const vmReHook = vm.createContext({
    crypto: { subtle: Object.create(subtleP5, { deriveBits: { value: function deriveBits() {}, configurable: true } }), getRandomValues: crypto.webcrypto.getRandomValues.bind(crypto.webcrypto) },
    SubtleCrypto: subtleP5.constructor,
    TextEncoder, URL, Headers, Response, Request, console, setTimeout, clearTimeout, performance,
    navigator: { webdriver: false },
    document: new Document5(),
    Document: Document5,
    Node: Node5,
    HTMLIFrameElement: HTMLIFrameElement5,
    location: { origin: "https://app.example", href: "https://app.example/" },
    fetch: async () => new Response("{}"),
    addEventListener() {},
  });
  vmReHook.window = vmReHook;
  vm.runInContext(`RegExp.prototype.test = function test() { return true; };`, vmReHook);
  vm.runInContext(g5Src, vmReHook);
  assert.equal(vmReHook.ProxySnare.guardHash(), "TAMPERED_GUARD", "Hooking RegExp.prototype.test before guard.js loads MUST fail closed as TAMPERED_GUARD!");

  // 10) Python parity: dual override shadowing, pre-crypto capacity check, None transcript coercion, CORS underscore + octal/int IPv4, balanced allow_devtools=False!
  execFileSync(
    "python3",
    [
      "-c",
      `import sys, time; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v = ProxySnareVerifier(mode="paranoid", protected_paths=["/api"], max_sessions=1)
s1 = v.issue_session(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
assert s1 is not None
t0 = time.perf_counter()
s2 = v.issue_session(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)}, client_pub_b64="A" * 88)
dt_ms = (time.perf_counter() - t0) * 1000
assert s2 is None and dt_ms < 2.0, f"Full capacity issue_session must reject before P-256 crypto (took {dt_ms:.2f}ms)"
# verify_handshake_signature None coercion
assert v.verify_handshake_signature(session_id="s", client_pub_b64="bad", server_pub_b64="bad", salt_b64="bad", boot_token=None, server_now_ms=None, canary=None, server_sig_b64="A" * 86) is False
# CORS underscore subdomain allowed, octal/int IPv4 canonicalized to same-origin (blocked)
r_sub = v.inspect_request(method="OPTIONS", url="/api/x", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Host": "app.test", "Origin": "https://sub_domain.other.test", "Access-Control-Request-Method": "POST", "Sec-Fetch-Mode": "cors"})
assert not r_sub.blocked, f"Underscore CORS subdomain should be allowed: {r_sub.reasons}"
r_oct = v.inspect_request(method="OPTIONS", url="/api/x", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Host": "127.0.0.1", "Origin": "http://0177.0.0.1", "Access-Control-Request-Method": "POST", "Sec-Fetch-Mode": "cors"})
assert r_oct.blocked, "Octal IPv4 0177.0.0.1 MUST canonicalize to same-origin 127.0.0.1 and be blocked!"
r_int = v.inspect_request(method="OPTIONS", url="/api/x", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Host": "127.0.0.1", "Origin": "http://2130706433", "Access-Control-Request-Method": "POST", "Sec-Fetch-Mode": "cors"})
assert r_int.blocked, "Integer IPv4 2130706433 MUST canonicalize to same-origin 127.0.0.1 and be blocked!"
# Dual method-override shadowing
ts = str(int(time.time() * 1000))
ctx = "ce=0;cdp=0;ug=0;ga=999999"
pr = v.sign_request(session_key_hex=s1["sessionKeyHex"], method="GET", path_with_query="/api/u", body=b"", seq="1", ts=ts, nonce="py-ov-shadow-1", canary=s1["canary"], ctx=ctx)
r_ov = v.inspect_request(method="GET", url="/api/u", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-HTTP-Method-Override": "GET", "X-Method-Override": "DELETE", "X-PS-Session": s1["sessionId"], "X-PS-Seq": "1", "X-PS-Ts": ts, "X-PS-Nonce": "py-ov-shadow-1", "X-PS-Canary": s1["canary"], "X-PS-Ctx": ctx, "X-PS-Proof": pr})
assert r_ov.blocked and any(x["code"] == "METHOD_OVERRIDE_DENIED" for x in r_ov.reasons) and any(x["code"] == "MUTATION_WITHOUT_USER_GESTURE" for x in r_ov.reasons)
# Balanced allow_devtools=False blocks cdp=1
vb = ProxySnareVerifier(mode="balanced", allow_devtools=False, protected_paths=["/api"])
sb = vb.issue_session(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
ctx_cdp = "ce=0;cdp=1;ug=1;ga=10"
prb = vb.sign_request(session_key_hex=sb["sessionKeyHex"], method="POST", path_with_query="/api/x", body=b"{}", seq="1", ts=ts, nonce="py-bal-cdp-1", canary=sb["canary"], ctx=ctx_cdp)
rb = vb.inspect_request(method="POST", url="/api/x", body=b"{}", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-PS-Session": sb["sessionId"], "X-PS-Seq": "1", "X-PS-Ts": ts, "X-PS-Nonce": "py-bal-cdp-1", "X-PS-Canary": sb["canary"], "X-PS-Ctx": ctx_cdp, "X-PS-Proof": prb})
assert rb.blocked and any(x["code"] == "CDP_ACTIVE_DETECTED" for x in rb.reasons)`,
    ],
    { encoding: "utf8" }
  );
});

test("17. Pass-6 Audit Regressions: Function.prototype.call & Element.prototype.appendChild tamper defenses, body-bearing OPTIONS bypass fix, Firefox 140 ESR stackTraceLimit, handshake trustProxy allowlist, unified multi-segment basePath & playground store, NL ReDoS, Python 5000-digit UA DoS", async () => {
  // 1) Body-bearing OPTIONS request with Access-Control-Request-Method MUST be blocked (NO score=0 CORS preflight bypass!)
  const parMw = createProxySnareMiddleware({ mode: "paranoid", protectedPaths: ["/api"] });
  const optSrv = http.createServer(async (req, res) => {
    if (await parMw(req, res)) return;
    res.writeHead(200);
    res.end("BYPASSED");
  });
  await new Promise((r) => optSrv.listen(0, "127.0.0.1", r));
  try {
    const oUrl = `http://127.0.0.1:${optSrv.address().port}`;
    const rOptBody = await fetch(`${oUrl}/api/transfer`, {
      method: "OPTIONS",
      headers: makeBrowserHeaders({
        origin: "https://evil.example",
        "access-control-request-method": "POST",
        "sec-fetch-mode": "cors",
        "content-type": "application/json",
      }),
      body: JSON.stringify({ to: "attacker", amount: 9999 }),
    });
    assert.equal(rOptBody.status, 403, "Body-bearing OPTIONS request with ACRM MUST NOT bypass ProxySnare via CORS preflight exemption!");
  } finally {
    await new Promise((r) => optSrv.close(r));
  }

  // 2) validateHandshakeClientHeaders honors explicit trustProxy allowlist even when Express 'trust proxy' is true!
  const tpAllowMw = createProxySnareMiddleware({ mode: "strict", trustProxy: ["10.0.0.1"], protectedPaths: ["/api"] });
  let xfhStatus = 0;
  await tpAllowMw(
    {
      method: "GET",
      url: "/__proxysnare/boot",
      socket: { remoteAddress: "203.0.113.99" },
      app: { get: (k) => (k === "trust proxy" ? true : undefined) },
      headers: makeBrowserHeaders({
        host: "app.example",
        origin: "https://evil.example",
        "x-forwarded-host": "evil.example",
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
      }),
    },
    {
      headersSent: false,
      writableEnded: false,
      setHeader() {},
      writeHead(c) { xfhStatus = c; this.headersSent = true; },
      end() { this.writableEnded = true; },
    }
  );
  assert.equal(xfhStatus, 403, "Untrusted direct client spoofing X-Forwarded-Host MUST be blocked at /boot even when Express trust proxy is true!");

  // 3) Unified middleware: enablePlayground:true + ProxySnareStore (no delete/take) starts cleanly & multi-segment veilbreakBasePath matches '//' and '/.'!
  const psStoreOnly = { async get() { return null; }, async set() {}, async setIfNotExists() { return true; } };
  const uMulti = createUnifiedMiddleware({
    mode: "strict",
    secret: "pass6-unified-multi-seg-secret-32b!",
    store: psStoreOnly,
    enablePlayground: true,
    veilbreakBasePath: "/sec/vb",
    protectedPaths: ["/api"],
  });
  let multiStatus = 0;
  await uMulti(
    { method: "GET", url: "/sec//vb/health", socket: { remoteAddress: "127.0.0.1" }, headers: makeBrowserHeaders() },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead(c) { multiStatus = c; this.headersSent = true; }, end() { this.writableEnded = true; } }
  );
  assert.equal(multiStatus, 200, "Multi-segment veilbreakBasePath MUST match normalized '/sec//vb/health'");

  // 4) captureRawBody preserves 0-byte Buffer (empty chunked JSON after express.json())
  const mockReq0 = {};
  tpAllowMw.captureRawBody(mockReq0, null, Buffer.alloc(0));
  assert.ok(Buffer.isBuffer(mockReq0.rawBody) && mockReq0.rawBody.length === 0, "captureRawBody MUST store 0-byte buffers");

  // 5) Browser guard Pass-6 defenses: post-load Function.prototype.call hijack AND Element.prototype.appendChild shadowing BOTH fail closed as TAMPERED_GUARD!
  const g6Src = buildBrowserGuardScript({ basePath: "/__proxysnare", protectedPaths: ["/api"] });
  new Function(g6Src);
  assert.ok(g6Src.includes("_hasInitialStackTraceLimit") && !g6Src.includes('"captureStackTrace" in _Error'), "Guard MUST use _hasInitialStackTraceLimit (0-FP on Firefox 138-152 / 140 ESR)");
  assert.ok(g6Src.includes("BOOT_TOKEN_IP_MISMATCH"), "Guard MUST retry once on BOOT_TOKEN_IP_MISMATCH even when !fromStamped");

  const makeCleanBrowserVm = ({ preLoadHook = null } = {}) => {
    const sp = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const sMethods = ["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "sign", "verify", "digest"];
    // Isolated per-VM wrappers so prototype-hook tests NEVER mutate host Node globals (TextEncoder/Headers)!
    const origEncode = TextEncoder.prototype.encode;
    const origHdrSet = Headers.prototype.set;
    const origHdrGet = Headers.prototype.get;
    const origHdrHas = Headers.prototype.has;
    const origRespJson = Response.prototype.json;
    class VmTextEncoder { encode(s) { return origEncode.call(new TextEncoder(), s); } }
    class VmHeaders {
      constructor(init) { this._h = new Headers(init); }
      set(k, v) { return origHdrSet.call(this._h, k, v); }
      get(k) { return origHdrGet.call(this._h, k); }
      has(k) { return origHdrHas.call(this._h, k); }
    }
    class VmResponse {
      constructor(b, init) { this._r = new Response(b, init); }
      json() { return origRespJson.call(this._r); }
      get ok() { return this._r.ok; }
      get status() { return this._r.status; }
      get headers() { return new VmHeaders(this._r.headers); }
      clone() { return new VmResponse(this._r.clone()); }
    }
    const vmFetch = async function fetch() { return new VmResponse("{}"); };
    const vmDbg9 = function debug() {};
    const nativeRefs = new Set([
      ...sMethods.map((m) => sp[m]),
      VmTextEncoder.prototype.encode,
      VmHeaders.prototype.set,
      VmHeaders.prototype.get,
      VmHeaders.prototype.has,
      VmResponse.prototype.json,
      vmFetch,
      crypto.webcrypto.getRandomValues,
      performance.getEntriesByType,
      vmDbg9,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmDbg9 }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        return globalThis;
      })();`,
      ifrCtx
    );
    class HTMLIFrameElement { constructor() { this.style = {}; } get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node { getAttribute() { return null; } }
    class Document extends Node { constructor() { super(); this.currentScript = null; this.baseURI = "https://app.example/"; this._el = new Element(); } get documentElement() { return this._el; } createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : {}; } }
    const ctx = vm.createContext({
      crypto: crypto.webcrypto,
      SubtleCrypto: sp.constructor,
      TextEncoder: VmTextEncoder,
      Headers: VmHeaders,
      Response: VmResponse,
      URL, URLSearchParams, Request, console: { ...console, debug: vmDbg9 }, setTimeout, clearTimeout, performance,
      navigator: { webdriver: false },
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement,
      location: { origin: "https://app.example", href: "https://app.example/" },
      fetch: vmFetch,
      addEventListener() {},
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(g6Src, ctx);
    return ctx;
  };
  const expectedG6Hash = computeGuardIntegrity(g6Src).guardHash;
  const vmCallHook = makeCleanBrowserVm();
  assert.equal(vmCallHook.ProxySnare.guardHash(), expectedG6Hash, "Clean VM MUST produce exact server guardHash before tampering");
  vm.runInContext(`const _c = Function.prototype.call; Function.prototype.call = function call(t, ...a) { return _c.apply(this, [t, ...a]); };`, vmCallHook);
  assert.equal(vmCallHook.ProxySnare.guardHash(), "TAMPERED_GUARD", "Post-load Function.prototype.call hook MUST fail closed as TAMPERED_GUARD!");

  // Post-load CMP/APM DOM wrapper (OneTrust/Cookiebot/New Relic) MUST NOT cause false-positive TAMPERED_GUARD!
  const vmCmp = makeCleanBrowserVm();
  vm.runInContext(`Element.prototype.appendChild = function appendChild(n) { return n; }; document.createElement = function createElement(t) { return {}; };`, vmCmp);
  assert.equal(vmCmp.ProxySnare.guardHash(), expectedG6Hash, "Post-load CMP/APM DOM wrappers MUST remain 0-FP (captured intrinsics invoked directly!)");

  // Pre-load TextEncoder.prototype.encode / Headers.prototype.set / JSON.stringify / Object.getOwnPropertyDescriptor hooks MUST fail closed as TAMPERED_GUARD!
  for (const [label, hook] of [
    ["TextEncoder.prototype.encode", `TextEncoder.prototype.encode = function encode(s) { return new Uint8Array(0); };`],
    ["Headers.prototype.set", `Headers.prototype.set = function set(k, v) {};`],
    ["JSON.stringify", `JSON.stringify = function stringify() { return "{}"; };`],
    ["Object.getOwnPropertyDescriptor", `const _d = Object.getOwnPropertyDescriptor; Object.getOwnPropertyDescriptor = function getOwnPropertyDescriptor(o, k) { return _d(o, k); };`],
  ]) {
    const vmHooked = makeCleanBrowserVm({ preLoadHook: hook });
    assert.equal(vmHooked.ProxySnare.guardHash(), "TAMPERED_GUARD", `Pre-load ${label} hook MUST fail closed as TAMPERED_GUARD!`);
  }

  // 6) compileNaturalLanguage O(N) ReDoS immunity on 50KB adversarial inputs
  const tNl0 = performance.now();
  try { compileNaturalLanguage("a".repeat(50_000) + "!"); } catch {}
  try { compileNaturalLanguage("protect http://localhost:3000" + ".".repeat(50_000) + "x"); } catch {}
  assert.ok(performance.now() - tNl0 < 200, "compileNaturalLanguage MUST remain linear on 50KB adversarial input");

  // 7) Python parity: 5000-digit Chrome/Firefox UA DoS immunity + body-bearing OPTIONS blocked!
  execFileSync(
    "python3",
    [
      "-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v = ProxySnareVerifier(mode="paranoid", protected_paths=["/api"])
big_ua = "Mozilla/5.0 Chrome/" + ("9" * 5000) + " Firefox/" + ("8" * 5000)
r_big = v.inspect_request(method="GET", url="/api/x", headers={"User-Agent": big_ua})
assert r_big.blocked
r_opt = v.inspect_request(method="OPTIONS", url="/api/x", body=b"", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Host": "app.example", "Origin": "https://evil.example", "Access-Control-Request-Method": "POST", "Sec-Fetch-Mode": "cors", "Content-Length": "48"})
assert r_opt.blocked, "Python MUST NOT exempt OPTIONS with Content-Length > 0 as CORS preflight!"`,
    ],
    { encoding: "utf8" }
  );
});

test("18. Pass-7 Audit Regressions: zero-exception UTF-8 path DoS fix, pre-auth 6-dummy-header & unprotected 413 fix, lazy req.body & req.complete/close fix, /handshake strict CDP reject, short PROXYSNARE_SECRET throw, Safari<16.4 & injectGuard:false wildcards, unified allowDevTools:false sync, browser guard Pass-7 & Python parity", async () => {
  const { evaluatePreBodyMinScore, normalizePathname } = require("../src/detector.js");
  const veilbreak = require("../../veilbreak/src/index.js");

  // 1) Perf #1: 13.5KB invalid %FF URL completes in < 30ms (down from 265ms!) + exact UTF-8 parity
  const eng7 = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api"] });
  const evilPath = "/x/" + "%FF".repeat(4400) + "%00%3F%23#a";
  const t0 = performance.now();
  assert.equal(eng7.isPathProtected(evilPath), false);
  const dt = performance.now() - t0;
  assert.ok(dt < 30, `13.5KB %FF path normalization MUST stay < 30ms (took ${dt.toFixed(1)}ms)`);
  assert.equal(normalizePathname("/api/%E6%97%A5%E6%9C%AC%E8%AA%9E/%F0%9F%9A%80"), "/api/日本語/🚀");
  assert.equal(normalizePathname("/api/%C0%AF/%ED%A0%80/%F4%90%80%80"), "/api/%C0%AF/%ED%A0%80/%F4%90%80%80");

  // 2) Perf #2: 6x 1-byte dummy X-PS-* headers immediately score guaranteed >= 10 (skips 1MB body buffering!),
  // AND single dummy X-PS-Session on unprotected route does NOT buffer body or return 413!
  const dummyEval = evaluatePreBodyMinScore(
    makeBrowserHeaders({ "x-ps-session": "x", "x-ps-seq": "1", "x-ps-ts": "1", "x-ps-nonce": "x", "x-ps-canary": "x", "x-ps-proof": "x" }),
    { mode: "strict", blockAiCrawlers: true, hasSession: eng7.hasActiveSession }
  );
  assert.ok(dummyEval.guaranteed >= 10, "6 dummy 1-byte X-PS-* headers MUST return guaranteed >= 10 to skip pre-auth body buffering");

  const unprotMw = createProxySnareMiddleware({ mode: "strict", protectedPaths: ["/api"], maxBodyBytes: 32 });
  const unprotSrv = http.createServer(async (req, res) => {
    if (await unprotMw(req, res)) return;
    const chunks = [];
    for await (const c of req) chunks.push(c);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ len: Buffer.concat(chunks).length }));
  });
  await new Promise((r) => unprotSrv.listen(0, "127.0.0.1", r));
  try {
    const rUpload = await fetch(`http://127.0.0.1:${unprotSrv.address().port}/upload`, {
      method: "POST",
      headers: makeBrowserHeaders({ "x-ps-session": "dummy" }),
      body: "a".repeat(256),
    });
    assert.equal(rUpload.status, 200, "Single dummy X-PS-* header on unprotected route MUST NOT trigger 413 BODY_TOO_LARGE");
    assert.equal((await rUpload.json()).len, 256);
  } finally {
    await new Promise((r) => unprotSrv.close(r));
  }

  // 3) Avail #5 & Perf #3: req.complete stays true when req.body is used directly, zero duplicate 'close' events on stream replay, AND lazy req.body avoids double JSON.parse!
  const streamMw = createProxySnareMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  let directComplete = null;
  let closeCount = 0;
  let directParsed = null;
  const streamSrv = http.createServer(async (req, res) => {
    if (req.url && req.url.startsWith("/api/")) req.on("close", () => { closeCount += 1; });
    if (await streamMw(req, res)) return;
    if (req.url === "/api/direct") {
      directComplete = req.complete;
      directParsed = req.body;
      res.writeHead(200);
      res.end("ok");
      return;
    }
    // Simulate express.json() overwriting req.body after consuming replayed stream
    const chunks = [];
    for await (const c of req) chunks.push(c);
    req.body = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify(req.body));
  });
  await new Promise((r) => streamSrv.listen(0, "127.0.0.1", r));
  try {
    const sUrl = `http://127.0.0.1:${streamSrv.address().port}`;
    const { hs, sessionKeyHex } = await performBrowserEcdhHandshake(sUrl);
    const sendSigned = async (p, seq, canary, nonce) => {
      const body = '{"hello":"world"}';
      const ts = String(Date.now());
      const proof = streamMw.engine.signRequest({ sessionKeyHex, method: "POST", pathWithQuery: p, body, seq: String(seq), ts, nonce, canary });
      const r = await fetch(`${sUrl}${p}`, {
        method: "POST",
        headers: makeBrowserHeaders({ "Content-Type": "application/json", "X-PS-Session": hs.sessionId, "X-PS-Seq": String(seq), "X-PS-Ts": ts, "X-PS-Nonce": nonce, "X-PS-Canary": canary, "X-PS-Proof": proof }),
        body,
      });
      return { status: r.status, nextCanary: r.headers.get("x-ps-next-canary"), text: await r.text() };
    };
    const r1 = await sendSigned("/api/direct", 1, hs.canary, "nonce-str-1");
    assert.equal(r1.status, 200);
    assert.equal(directComplete, true, "req.complete MUST stay true when handler reads req.body directly!");
    assert.deepEqual(directParsed, { hello: "world" }, "Lazy req.body getter MUST parse JSON on first access");
    const r2 = await sendSigned("/api/express", 2, r1.nextCanary, "nonce-str-2");
    assert.equal(r2.status, 200);
    assert.deepEqual(JSON.parse(r2.text), { hello: "world" });
    await new Promise((r) => setTimeout(r, 20));
    assert.ok(closeCount <= 2, `2 requests MUST NOT emit duplicate 'close' events (got ${closeCount})`);
  } finally {
    await new Promise((r) => streamSrv.close(r));
  }

  // 4) RedTeam #2 & #4: /handshake rejects cdpActive:true in strict mode (!allowDevTools), AND unified veilbreakOptions.allowDevTools:false syncs to ProxySnare!
  const strictHsSrv = http.createServer(async (req, res) => {
    if (await streamMw(req, res)) return;
    res.writeHead(200); res.end("ok");
  });
  await new Promise((r) => strictHsSrv.listen(0, "127.0.0.1", r));
  try {
    const hUrl = `http://127.0.0.1:${strictHsSrv.address().port}`;
    const bt = await (await fetch(`${hUrl}/__proxysnare/boot`, { headers: makeBrowserHeaders() })).json();
    const kp = await crypto.webcrypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, false, ["deriveBits"]);
    const pubB64 = Buffer.from(await crypto.webcrypto.subtle.exportKey("raw", kp.publicKey)).toString("base64");
    const rCdpHs = await fetch(`${hUrl}/__proxysnare/handshake`, {
      method: "POST",
      headers: makeBrowserHeaders({ "Content-Type": "application/json" }),
      body: JSON.stringify({
        protocol: "PS_ECDH_V2",
        clientPubB64: pubB64,
        bootToken: bt.bootToken,
        powNonce: solvePowChallenge("PS_POW_V2", bt.challenge, bt.difficulty),
        guardHash: streamMw.guardHash,
        cdpActive: true,
      }),
    });
    assert.equal(rCdpHs.status, 403, "strict mode (!allowDevTools) MUST reject cdpActive:true at /handshake!");
    assert.equal((await rCdpHs.json()).error, "CDP_ACTIVE_DENIED");
  } finally {
    await new Promise((r) => strictHsSrv.close(r));
  }

  const uBalNoDt = createUnifiedMiddleware({ mode: "balanced", veilbreakOptions: { allowDevTools: false }, veilbreak });
  assert.equal(uBalNoDt.engine.allowDevTools, false, "unified veilbreakOptions.allowDevTools:false MUST propagate to ProxySnare engine!");
  assert.ok(!uBalNoDt.proxysnare.guardHash || uBalNoDt.proxysnare.guardHash.length === 64);

  // 5) Avail #7: Short (< 16-byte) PROXYSNARE_SECRET env var throws explicitly!
  const prevSecret = process.env.PROXYSNARE_SECRET;
  process.env.PROXYSNARE_SECRET = "too-short";
  try {
    assert.throws(() => createProxySnareEngine({ mode: "strict" }), /Invalid PROXYSNARE_SECRET/);
  } finally {
    if (prevSecret === undefined) delete process.env.PROXYSNARE_SECRET;
    else process.env.PROXYSNARE_SECRET = prevSecret;
  }

  // 6) Avail #4, #6, #8: Safari < 16.4 static CSS + injectGuard:false HTML under ['*'] + balanced nginx Connection:close /boot!
  const upPs7 = http.createServer((req, res) => {
    if (req.url === "/") { res.writeHead(200, { "Content-Type": "text/html" }); res.end("<!doctype html><html><head><script src='/__proxysnare/guard.js'></script></head><body>ok</body></html>"); return; }
    if (req.url === "/app.css") { res.writeHead(200, { "Content-Type": "text/css" }); res.end("body{}"); return; }
    res.writeHead(200, { "Content-Type": "application/json" }); res.end('{"ok":true}');
  });
  await new Promise((r) => upPs7.listen(0, "127.0.0.1", r));
  const srvPs7 = createProxySnareServer({ target: `http://127.0.0.1:${upPs7.address().port}`, mode: "strict", protectedPaths: ["*"], injectGuard: false });
  await srvPs7.listen(0, "127.0.0.1");
  const balPs7 = createProxySnareServer({ target: `http://127.0.0.1:${upPs7.address().port}`, mode: "balanced", protectedPaths: ["*"] });
  await balPs7.listen(0, "127.0.0.1");
  const reqPs7 = (port, p, headers) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port, method: "GET", path: p, headers }, (resp) => {
        let d = "";
        resp.on("data", (c) => (d += c));
        resp.on("end", () => resolve({ status: resp.statusCode, body: d }));
      });
      r.on("error", reject);
      r.end();
    });
  try {
    const safari16Ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15";
    assert.equal((await reqPs7(srvPs7.server.address().port, "/app.css", { "user-agent": safari16Ua, accept: "text/css" })).status, 200, "Safari < 16.4 static CSS MUST succeed under protectedPaths:['*']");
    assert.equal((await reqPs7(srvPs7.server.address().port, "/", makeBrowserHeaders({ accept: "text/html", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", "sec-fetch-site": "none" }))).status, 200, "injectGuard:false under ['*'] MUST allow browser HTML navigation");
    assert.equal((await reqPs7(balPs7.server.address().port, "/__proxysnare/boot", makeBrowserHeaders({ connection: "close" }))).status, 200, "balanced mode behind default nginx (Connection: close) MUST allow /boot");
  } finally {
    await srvPs7.close();
    await balPs7.close();
    await new Promise((r) => upPs7.close(r));
  }

  // 7) Browser guard Pass-7 structural checks: non-forgeable init guard, Next.js (auth) extractFrameUrls, PerformanceObserver, sticky cdpEverDetected, balanced collectCe=false!
  const balGuard = buildBrowserGuardScript({ basePath: "/__proxysnare", protectedPaths: ["/api"], allowDevTools: true, blockConsoleEval: false, collectConsoleEvalTelemetry: false, requireVeilBreak: true });
  new Function(balGuard);
  assert.ok(!balGuard.includes('Symbol.for("__PS_GUARD_INIT__")'), "Guard MUST NOT use forgeable Symbol.for init kill switch");
  assert.ok(balGuard.includes("extractFrameUrls") && balGuard.includes("PerformanceObserver"), "Guard MUST use paren-balanced extractFrameUrls and buffered PerformanceObserver");
  assert.ok(balGuard.includes("_BARE_TOP_FRAME_RE") && balGuard.includes("(!ALLOW_DEVTOOLS && cdpEverDetected)"), "Guard MUST enforce sticky cdpEverDetected and catch bare top-level sourceURL spoofing");
  assert.ok(balGuard.includes("const REQUIRE_VB = true ||"), "data-require-vb='false' MUST NOT downgrade server-compiled requireVeilBreak:true");
  assert.ok(!balGuard.includes("last.dwellMs >= 0"), "Guard kinematics MUST skip dwellMs === 0 assistive clicks");

  // 8) Python parity: 13.5KB %FF DoS (< 50ms) + malformed IPv4 CORS Origin matches Node parseHttpOriginHost!
  execFileSync(
    "python3",
    [
      "-c",
      `import sys, time; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier, normalize_pathname
v = ProxySnareVerifier(mode="strict", protected_paths=["/api"])
evil = "/x/" + ("%FF" * 4400) + "%00%3F%23#a"
t0 = time.perf_counter()
assert not v.is_path_protected(evil)
dt_ms = (time.perf_counter() - t0) * 1000
assert dt_ms < 50.0, f"Python 13.5KB %FF too slow: {dt_ms:.1f}ms"
assert normalize_pathname("/api/%E6%97%A5%E6%9C%AC%E8%AA%9E/%F0%9F%9A%80") == "/api/日本語/🚀"
assert normalize_pathname("/api/%C0%AF/%ED%A0%80/%F4%90%80%80") == "/api/%C0%AF/%ED%A0%80/%F4%90%80%80"
for bad_orig in ("http://999.999.999.999", "http://0x100000000", "http://08.0.0.1"):
    r = v.inspect_request(method="OPTIONS", url="/api/x", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Host": "app.test", "Origin": bad_orig, "Access-Control-Request-Method": "POST", "Sec-Fetch-Mode": "cors"})
    assert r.blocked, f"Invalid IPv4-shaped Origin {bad_orig} MUST NOT be exempted as CORS preflight!"`,
    ],
    { encoding: "utf8" }
  );
});

test("19. Pass-8 Audit Regressions: Promise.prototype/Object.prototype.then ECDH exfil defense + Angular Zone.js 0-FP, pure-JS Base64 & RegExp[Symbol.replace] defense, Error.prepareStackTrace & finalizeBody numeric fix, non-forgeable init & VB_TAMPER_SYM, paranoid+blockCdpActive:false, IPv6 https://[...]:80 & ?/#/@ Origin, unprotected 6-header body DoS skip, unified enableVeilBreakTickets & x-font/manifest", async () => {
  const { parseHttpOriginHost, evaluatePreBodyMinScore } = require("../src/detector.js");
  const veilbreak = require("../../veilbreak/src/index.js");

  // Helper to build a clean isolated browser VM realm (zero host-global mutation!)
  const eng8 = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api"] });
  const guard8Src = buildBrowserGuardScript({
    basePath: "/__proxysnare",
    protectedPaths: ["/api"],
    serverVerifyPubB64: eng8.serverVerifyPubB64,
  });
  const expectedG8Hash = computeGuardIntegrity(guard8Src).guardHash;

  const makeVm8 = ({ preLoadHook = null, fetchImpl = null, src = guard8Src } = {}) => {
    const sp = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const sMethods = ["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "sign", "verify", "digest"];
    const origEncode = TextEncoder.prototype.encode;
    const origHdrSet = Headers.prototype.set;
    const origHdrGet = Headers.prototype.get;
    const origHdrHas = Headers.prototype.has;
    const origRespJson = Response.prototype.json;
    class VmTextEncoder { encode(s) { return origEncode.call(new TextEncoder(), s); } }
    class VmHeaders {
      constructor(init) { this._h = new Headers(init); }
      set(k, v) { return origHdrSet.call(this._h, k, v); }
      get(k) { return origHdrGet.call(this._h, k); }
      has(k) { return origHdrHas.call(this._h, k); }
    }
    class VmResponse {
      constructor(b, init) { this._r = new Response(b, init); }
      json() { return origRespJson.call(this._r); }
      text() { return this._r.text(); }
      get ok() { return this._r.ok; }
      get status() { return this._r.status; }
      get headers() { return new VmHeaders(this._r.headers); }
      clone() { return new VmResponse(this._r.clone()); }
    }
    const vmFetch = fetchImpl
      ? function fetch(u, init) { return fetchImpl(u, init, VmResponse); }
      : async function fetch() { return new VmResponse("{}"); };
    const vmDbg9 = function debug() {};
    const nativeRefs = new Set([
      ...sMethods.map((m) => sp[m]),
      VmTextEncoder.prototype.encode,
      VmHeaders.prototype.set,
      VmHeaders.prototype.get,
      VmHeaders.prototype.has,
      VmResponse.prototype.json,
      vmFetch,
      crypto.webcrypto.getRandomValues,
      performance.getEntriesByType,
      vmDbg9,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmDbg9 }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        return globalThis;
      })();`,
      ifrCtx
    );
    class HTMLIFrameElement { constructor() { this.style = {}; } get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node { getAttribute() { return null; } }
    class Document extends Node {
      constructor() { super(); this.currentScript = null; this.baseURI = "https://app.example/"; this.readyState = "complete"; this._el = new Element(); }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : {}; }
      querySelectorAll() { return []; }
    }
    const ctx = vm.createContext({
      crypto: crypto.webcrypto,
      SubtleCrypto: sp.constructor,
      TextEncoder: VmTextEncoder,
      TextDecoder,
      Headers: VmHeaders,
      Response: VmResponse,
      URL, URLSearchParams, Request, console: { ...console, debug: vmDbg9 }, setTimeout, clearTimeout, performance,
      navigator: { webdriver: false },
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement,
      location: { origin: "https://app.example", href: "https://app.example/" },
      fetch: vmFetch,
      addEventListener() {},
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return ctx;
  };

  // 1) CRITICAL #1: Promise.prototype.constructor/then & Object.prototype.then/ArrayBuffer.prototype.then fail closed as TAMPERED_GUARD & reject ensureSession(),
  // while Angular Zone.js (`window.Promise = class ZoneAwarePromise {}` leaving native Promise.prototype intact) stays 0-FP!
  const vmZone = makeVm8();
  vm.runInContext(`window.Zone = { current: { name: "<root>" } }; window.__zone_symbol__Promise = window.Promise; window.Promise = function ZoneAwarePromise(fn) { return new Object(); };`, vmZone);
  assert.equal(vmZone.ProxySnare.guardHash(), expectedG8Hash, "Angular Zone.js replacing window.Promise (without mutating native Promise.prototype) MUST remain 0-FP!");

  for (const [label, hook] of [
    ["Promise.prototype.then", `const _t = Promise.prototype.then; Promise.prototype.then = function then(a, b) { return _t.call(this, a, b); };`],
    ["Promise.prototype.constructor", `Promise.prototype.constructor = function FakeP(fn) { return new Promise(fn); };`],
    ["Object.prototype.then", `Object.prototype.then = function(r) { r(this); };`],
    ["ArrayBuffer.prototype.then", `ArrayBuffer.prototype.then = function(r) { r(this); };`],
    ["RegExp.prototype[Symbol.replace]", `RegExp.prototype[Symbol.replace] = function() { return "spoofed"; };`],
  ]) {
    const vmBad = makeVm8();
    vm.runInContext(hook, vmBad);
    assert.equal(vmBad.ProxySnare.guardHash(), "TAMPERED_GUARD", `Post-load ${label} hook MUST fail closed as TAMPERED_GUARD!`);
  }

  // Live ensureSession() with Promise.prototype.then hijacked MUST reject with PROXYSNARE_PROMISE_TAMPERED and NEVER leak sharedBits/CryptoKey!
  let leakedValues = [];
  const vmExfil = makeVm8({
    fetchImpl: async (url, init, VmResponse) => {
      if (String(url).includes("/boot")) {
        const b = eng8.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA });
        return new VmResponse(JSON.stringify(b), { status: 200, headers: { "content-type": "application/json" } });
      }
      return new VmResponse("{}", { status: 200, headers: { "content-type": "application/json" } });
    },
  });
  vm.runInContext(
    `const _origThen = Promise.prototype.then;
     Promise.prototype.then = function then(onFul, onRej) {
       return _origThen.call(this, (v) => { __leaked(v); return onFul ? onFul(v) : v; }, onRej);
     };`,
    Object.assign(vmExfil, { __leaked: (v) => { if (v instanceof ArrayBuffer || (v && v.type === "secret")) leakedValues.push(v); } })
  );
  await assert.rejects(() => vmExfil.ProxySnare.ready(), /PROXYSNARE_PROMISE_TAMPERED/, "Promise.prototype.then exfil attempt MUST reject ensureSession()");
  assert.equal(leakedValues.length, 0, "Zero ECDH sharedBits/CryptoKey MUST leak to Promise.prototype.then");

  // 2) HIGH #2: window.atob override CANNOT tamper with ECDSA pubkey verification (pure-JS Base64) AND finalizeBody handles numeric body `123` (no ReferenceError: encoder is not defined!)
  let sentBody = null;
  let sentHeaders = null;
  const vmRealHs = makeVm8({
    preLoadHook: `window.atob = () => { throw new Error("ATOB_MUST_NOT_BE_CALLED"); }; window.btoa = () => { throw new Error("BTOA_MUST_NOT_BE_CALLED"); };`,
    fetchImpl: async (url, init, VmResponse) => {
      const sUrl = String(url);
      if (sUrl.endsWith("/boot")) {
        const b = eng8.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA });
        return new VmResponse(JSON.stringify(b), { status: 200, headers: { "content-type": "application/json" } });
      }
      if (sUrl.endsWith("/handshake")) {
        const body = JSON.parse(init.body);
        const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|`).digest("hex");
        const s = eng8.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
        return new VmResponse(JSON.stringify({
          protocol: "PS_ECDH_V2",
          sessionId: s.sessionId,
          serverPubB64: s.serverPubB64,
          saltB64: s.saltB64,
          canary: s.canary,
          serverNowMs: s.serverNowMs,
          serverSigB64: s.serverSigB64,
        }), { status: 200, headers: { "content-type": "application/json" } });
      }
      sentBody = init.body;
      sentHeaders = init.headers;
      return new VmResponse('{"ok":true}', { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "a".repeat(32) } });
    },
  });
  const numRes = await vmRealHs.fetch("/api/num", { method: "POST", body: 12345 });
  assert.equal(numRes.status, 200, "Pure-JS Base64 ECDSA handshake + numeric body `12345` MUST succeed cleanly without calling window.atob or throwing ReferenceError!");
  assert.equal(Buffer.from(sentBody).toString("utf8"), "12345");
  assert.ok(sentHeaders.get("X-PS-Proof").length === 64);

  // 3) HIGH #3: V8 Error.prepareStackTrace forgery is neutralized during captureConsoleEvalFlag (ce=1 still caught when called from anonymous eval!)
  let seenCeCtx = "";
  const vmPst = makeVm8({
    fetchImpl: async (url, init, VmResponse) => {
      const sUrl = String(url);
      if (sUrl.endsWith("/boot")) {
        return new VmResponse(JSON.stringify(eng8.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
      }
      if (sUrl.endsWith("/handshake")) {
        const body = JSON.parse(init.body);
        const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|`).digest("hex");
        const s = eng8.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
        return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
      }
      seenCeCtx = init.headers.get("X-PS-Ctx") || "";
      return new VmResponse("{}", { status: 200, headers: { "content-type": "application/json" } });
    },
  });
  // Attacker sets Error.prepareStackTrace to spoof a fake app stack AND calls fetch via DevTools-like eval!
  await vm.runInContext(
    `Error.prepareStackTrace = () => "Error\\n    at fn (https://app.example/app.js:1:1)";
     eval("window.fetch('/api/buy', { method: 'POST', body: '{}' })");`,
    vmPst
  );
  assert.ok(seenCeCtx.includes("ce=1"), `Error.prepareStackTrace forgery MUST be neutralized and flag ce=1 (got ${seenCeCtx})`);

  // 4) HIGH #6 & MEDIUM #7: 4-line forged frozen window.ProxySnare preload does NOT abort init, AND VB_TAMPER_SYM=false fails closed!
  const vmFakeInit = makeVm8({
    preLoadHook: `Object.defineProperty(window, "ProxySnare", {
      value: Object.freeze({ version: ${JSON.stringify(require("../package.json").version)}, ready: async () => true, guardHash: () => "fake" }),
      writable: false, configurable: false,
    });`,
  });
  // Because our init ran despite the forged non-configurable ProxySnare, window.fetch was still wrapped!
  assert.notEqual(vmFakeInit.fetch.name, "fetch", "4-line forged frozen window.ProxySnare MUST NOT abort guard.js fetch wrapping!");
  assert.ok(!guard8Src.includes("frame.style.cssText"), "guard.js MUST use CSP-safe individual frame.style.* assignments (no cssText)");
  assert.ok(guard8Src.includes('if (hk.toLowerCase().startsWith("x-ps-")) continue;'), "guard.js XHR MUST unconditionally strip caller-supplied x-ps-* headers");

  // Pre-defined Symbol.for("__VB_BRIDGE_TAMPERED__") = false MUST fail closed when requireVeilBreak:true (no spoofed browserProof sent!)
  const vbReqSrc = buildBrowserGuardScript({ basePath: "/__proxysnare", protectedPaths: ["/api"], requireVeilBreak: true });
  let hsPayloadWithVbTamper = null;
  const vmVbTamper = makeVm8({
    src: vbReqSrc,
    preLoadHook: `window[Symbol.for("__VB_BRIDGE_TAMPERED__")] = false; window[Symbol.for("__VEILBREAK_INTERNAL__")] = { collectHandshakeProof: () => ({ v: 3, spoof: true }) };`,
    fetchImpl: async (url, init, VmResponse) => {
      if (String(url).endsWith("/boot")) {
        return new VmResponse(JSON.stringify(eng8.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
      }
      hsPayloadWithVbTamper = JSON.parse(init.body);
      return new VmResponse('{"error":"BROWSER_INTEGRITY_FAILED"}', { status: 403, headers: { "content-type": "application/json" } });
    },
  });
  await assert.rejects(() => vmVbTamper.ProxySnare.ready(), /PROXYSNARE_HANDSHAKE_FAILED_403/, "VB_TAMPER_SYM set to ANY value (even false) MUST refuse spoofed VeilBreak bridge!");
  assert.equal(hsPayloadWithVbTamper.browserProof, undefined, "Spoofed VeilBreak bridge MUST NOT be trusted when VB_TAMPER_SYM is present (even false)");

  // 5) Server fixes: explicit paranoid + blockCdpActive:false honors blockCdpActive:false (telemetry weight 1, NOT blocked), while strict default (blockCdpActive:true) blocks cdp=1; IPv6 https://[2001:db8::1]:80 port preserved, ?/#/@ Origin rejected!
  const parNoCdp = createProxySnareEngine({ mode: "paranoid", blockCdpActive: false, protectedPaths: ["/api"] });
  const sPnc = parNoCdp.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const tsPnc = String(Date.now());
  const ctxPnc = "ce=0;cdp=1;ug=1;ga=10";
  const rPnc = parNoCdp.inspectRequest({
    method: "POST",
    url: "/api/x",
    body: "{}",
    headers: makeBrowserHeaders({
      "x-ps-session": sPnc.sessionId,
      "x-ps-seq": "1",
      "x-ps-ts": tsPnc,
      "x-ps-nonce": "nonce-pnc-1",
      "x-ps-canary": sPnc.canary,
      "x-ps-ctx": ctxPnc,
      "x-ps-proof": parNoCdp.signRequest({ sessionKeyHex: sPnc.sessionKeyHex, method: "POST", pathWithQuery: "/api/x", body: "{}", seq: "1", ts: tsPnc, nonce: "nonce-pnc-1", canary: sPnc.canary, ctx: ctxPnc }),
    }),
  });
  assert.equal(rPnc.blocked, false, "Explicit paranoid + blockCdpActive:false MUST honor blockCdpActive:false (non-blocking telemetry weight 1)!");
  assert.ok(rPnc.reasons.some((x) => x.code === "CDP_ACTIVE_DETECTED" && x.weight === 1));
  assert.equal(parseHttpOriginHost("https://[2001:db8::1]:80"), "[2001:db8::1]:80", "https://[IPv6]:80 MUST preserve non-default port 80!");
  assert.equal(parseHttpOriginHost("https://[2001:db8::1]:443"), "[2001:db8::1]", "https://[IPv6]:443 MUST strip default port 443!");
  assert.equal(parseHttpOriginHost("http://app.example?q=1"), "", "Origin with ? MUST be rejected");
  assert.equal(parseHttpOriginHost("http://app.example#f"), "", "Origin with # MUST be rejected");
  assert.equal(parseHttpOriginHost("http://user@app.example"), "", "Origin with @ MUST be rejected");

  // 6) Unprotected POST route with 6 syntactically valid X-PS-* headers for an UNKNOWN session skips 1MB body buffering (no RAM DoS / 413!)
  const fakeValidHdrs = makeBrowserHeaders({
    "x-ps-session": "a".repeat(32),
    "x-ps-seq": "1",
    "x-ps-ts": String(Date.now()),
    "x-ps-nonce": "valid-nonce-1234",
    "x-ps-canary": "b".repeat(32),
    "x-ps-proof": "c".repeat(64),
  });
  const unprotPre = evaluatePreBodyMinScore(fakeValidHdrs, { mode: "strict", isProtected: false, hasSession: () => false });
  assert.ok(unprotPre.guaranteed >= 8, "Unknown session on unprotected route with 6 X-PS-* headers MUST return guaranteed >= 8 to skip body buffering");

  let unprotBodyRead = false;
  const unprotDoSMw = createProxySnareMiddleware({ mode: "strict", protectedPaths: ["/api"], maxBodyBytes: 32 });
  const unprotDoSSrv = http.createServer(async (req, res) => {
    if (await unprotDoSMw(req, res)) return;
    unprotBodyRead = true;
    res.writeHead(200);
    res.end("OK");
  });
  await new Promise((r) => unprotDoSSrv.listen(0, "127.0.0.1", r));
  try {
    const rFakeUnprot = await fetch(`http://127.0.0.1:${unprotDoSSrv.address().port}/public/upload`, {
      method: "POST",
      headers: fakeValidHdrs,
      body: "z".repeat(256),
    });
    assert.equal(rFakeUnprot.status, 403, "Unprotected route with 6 unknown-session X-PS-* headers MUST reject 403 BEFORE 413 body buffering!");
    assert.equal(unprotBodyRead, false);
  } finally {
    await new Promise((r) => unprotDoSSrv.close(r));
  }

  // 7) Unified enableVeilBreakTickets: true compiles real solveTicketPow, and reverse proxy allows x-font-* & Safari < 16.4 /manifest.json!
  const uTick = createUnifiedMiddleware({ mode: "strict", enableVeilBreakTickets: true, veilbreak });
  let uGateBody = "";
  await uTick(
    { method: "GET", url: "/__veilbreak/gate.js", socket: { remoteAddress: "127.0.0.1" }, headers: makeBrowserHeaders() },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead() { this.headersSent = true; }, end(b) { uGateBody = String(b || ""); this.writableEnded = true; } }
  );
  assert.ok(uGateBody.includes("_POW_SCRATCH") && uGateBody.includes("VB_POW_V2|"), "Unified enableVeilBreakTickets:true MUST compile real solveTicketPow in /__veilbreak/gate.js");

  const upMime8 = http.createServer((req, res) => {
    if (req.url === "/f.woff") { res.writeHead(200, { "Content-Type": "application/x-font-woff" }); res.end("wOFF"); return; }
    if (req.url === "/manifest.json") { res.writeHead(200, { "Content-Type": "application/json" }); res.end('{"name":"App"}'); return; }
    res.writeHead(200, { "Content-Type": "application/json" }); res.end('{"secret":1}');
  });
  await new Promise((r) => upMime8.listen(0, "127.0.0.1", r));
  const srvMime8 = createProxySnareServer({ target: `http://127.0.0.1:${upMime8.address().port}`, mode: "strict", protectedPaths: ["*"] });
  await srvMime8.listen(0, "127.0.0.1");
  const reqMime8 = (p, headers) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port: srvMime8.server.address().port, method: "GET", path: p, headers }, (resp) => {
        resp.resume();
        resp.on("end", () => resolve(resp.statusCode));
      });
      r.on("error", reject);
      r.end();
    });
  try {
    const safari16Ua = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.1 Safari/605.1.15";
    assert.equal(await reqMime8("/f.woff", { "user-agent": CHROME_UA, "sec-fetch-dest": "font", "sec-fetch-site": "same-origin" }), 200);
    assert.equal(await reqMime8("/manifest.json", { "user-agent": safari16Ua }), 200);
  } finally {
    await srvMime8.close();
    await new Promise((r) => upMime8.close(r));
  }

  // 8) Python parity: paranoid + block_cdp_active=False honors block_cdp_active=False (telemetry weight 1, not blocked), strict default blocks cdp=1 (+4), AND ?/#/@ Origin rejected!
  execFileSync(
    "python3",
    [
      "-c",
      `import sys, time; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
vp = ProxySnareVerifier(mode="paranoid", block_cdp_active=False, protected_paths=["/api"])
sp = vp.issue_session(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
ts = str(int(time.time() * 1000))
ctx = "ce=0;cdp=1;ug=1;ga=10"
pr = vp.sign_request(session_key_hex=sp["sessionKeyHex"], method="POST", path_with_query="/api/x", body=b"{}", seq="1", ts=ts, nonce="py-pnc-1", canary=sp["canary"], ctx=ctx)
rp = vp.inspect_request(method="POST", url="/api/x", body=b"{}", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-PS-Session": sp["sessionId"], "X-PS-Seq": "1", "X-PS-Ts": ts, "X-PS-Nonce": "py-pnc-1", "X-PS-Canary": sp["canary"], "X-PS-Ctx": ctx, "X-PS-Proof": pr})
assert (not rp.blocked) and any(x["code"] == "CDP_ACTIVE_DETECTED" and x["weight"] == 1 for x in rp.reasons), f"Python paranoid+block_cdp_active=False mismatch: {rp.reasons}"
vs = ProxySnareVerifier(mode="strict", protected_paths=["/api"])
ss = vs.issue_session(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
prs = vs.sign_request(session_key_hex=ss["sessionKeyHex"], method="POST", path_with_query="/api/x", body=b"{}", seq="1", ts=ts, nonce="py-sc-01", canary=ss["canary"], ctx=ctx)
rs = vs.inspect_request(method="POST", url="/api/x", body=b"{}", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-PS-Session": ss["sessionId"], "X-PS-Seq": "1", "X-PS-Ts": ts, "X-PS-Nonce": "py-sc-01", "X-PS-Canary": ss["canary"], "X-PS-Ctx": ctx, "X-PS-Proof": prs})
assert rs.blocked and any(x["code"] == "CDP_ACTIVE_DETECTED" and x["weight"] == 4 for x in rs.reasons), f"Python strict default CDP block mismatch: {rs.reasons}"
for bad_orig in ("https://other.example?a=1", "https://other.example#frag", "https://user@other.example"):
    r_o = vp.inspect_request(method="OPTIONS", url="/api/x", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Host": "app.test", "Origin": bad_orig, "Access-Control-Request-Method": "POST", "Sec-Fetch-Mode": "cors"})
    assert r_o.blocked, f"Python MUST reject Origin with ?/#/@: {bad_orig}"`,
    ],
    { encoding: "utf8" }
  );
});

test("20. Pass-9 Audit Regressions: ready() state/CryptoKey leak fix, fromBase64 Array.push/charCodeAt fix, Error.prepareStackTrace accessor/proto & DOM modulepreload fix, Error/getOwnPropertyNames & fail-closed CDP, init kill-switch defense, RUM post-load 0-FP, OPTIONS+body DoS, unprotected chunked req.body, verifyBrowserIntegrity default, Vite/Next wildcard, s-maxage=0 & Python parity", async () => {
  const { evaluatePreBodyMinScore } = require("../src/detector.js");
  const veilbreak = require("../../veilbreak/src/index.js");

  const eng9 = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api"] });
  const guard9Src = buildBrowserGuardScript({
    basePath: "/__proxysnare",
    protectedPaths: ["/api"],
    serverVerifyPubB64: eng9.serverVerifyPubB64,
  });
  const expectedG9Hash = computeGuardIntegrity(guard9Src).guardHash;

  const makeVm9 = ({ preLoadHook = null, fetchImpl = null, src = guard9Src, extraDoc = {} } = {}) => {
    const sp = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const sMethods = ["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "sign", "verify", "digest"];
    const origEncode = TextEncoder.prototype.encode;
    const origHdrSet = Headers.prototype.set;
    const origHdrGet = Headers.prototype.get;
    const origHdrHas = Headers.prototype.has;
    const origRespJson = Response.prototype.json;
    class VmTextEncoder { encode(s) { return origEncode.call(new TextEncoder(), s); } }
    class VmHeaders {
      constructor(init) { this._h = new Headers(init); }
      set(k, v) { return origHdrSet.call(this._h, k, v); }
      get(k) { return origHdrGet.call(this._h, k); }
      has(k) { return origHdrHas.call(this._h, k); }
    }
    class VmResponse {
      constructor(b, init) { this._r = new Response(b, init); }
      json() { return origRespJson.call(this._r); }
      text() { return this._r.text(); }
      get ok() { return this._r.ok; }
      get status() { return this._r.status; }
      get headers() { return new VmHeaders(this._r.headers); }
      clone() { return new VmResponse(this._r.clone()); }
    }
    const vmFetch = fetchImpl
      ? function fetch(u, init) { return fetchImpl(u, init, VmResponse); }
      : async function fetch() { return new VmResponse("{}"); };
    const vmDbg9 = function debug() {};
    const nativeRefs = new Set([
      ...sMethods.map((m) => sp[m]),
      VmTextEncoder.prototype.encode,
      VmHeaders.prototype.set,
      VmHeaders.prototype.get,
      VmHeaders.prototype.has,
      VmResponse.prototype.json,
      vmFetch,
      crypto.webcrypto.getRandomValues,
      performance.getEntriesByType,
      vmDbg9,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmDbg9 }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        return globalThis;
      })();`,
      ifrCtx
    );
    class HTMLIFrameElement { constructor() { this.style = {}; } get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node { getAttribute() { return null; } }
    class Document extends Node {
      constructor() {
        super();
        this.currentScript = null;
        this.baseURI = "https://app.example/";
        this.readyState = "complete";
        this._el = new Element();
        Object.assign(this, extraDoc);
      }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : {}; }
      querySelectorAll() { return []; }
      querySelector() { return null; }
    }
    const ctx = vm.createContext({
      crypto: crypto.webcrypto,
      SubtleCrypto: sp.constructor,
      TextEncoder: VmTextEncoder,
      TextDecoder,
      Headers: VmHeaders,
      Response: VmResponse,
      URL, URLSearchParams, Request, console: { ...console, debug: vmDbg9 }, setTimeout, clearTimeout, performance,
      navigator: { webdriver: false },
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement,
      location: { origin: "https://app.example", href: "https://app.example/" },
      fetch: vmFetch,
      addEventListener() {},
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return ctx;
  };

  const makeHsFetch = (onApi) => async (url, init, VmResponse) => {
    const sUrl = String(url);
    if (sUrl.endsWith("/boot")) {
      return new VmResponse(JSON.stringify(eng9.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (sUrl.endsWith("/handshake")) {
      const body = JSON.parse(init.body);
      const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|${body.browserProof?.d || ""}`).digest("hex");
      const s = eng9.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
      return new VmResponse(JSON.stringify({
        protocol: "PS_ECDH_V2",
        sessionId: s.sessionId,
        serverPubB64: s.serverPubB64,
        saltB64: s.saltB64,
        canary: s.canary,
        serverNowMs: s.serverNowMs,
        serverSigB64: s.serverSigB64,
      }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (onApi) onApi(sUrl, init);
    return new VmResponse('{"ok":true}', { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "a".repeat(32) } });
  };

  // 1) CRITICAL #1: Post-load Promise.prototype.then hook + ProxySnare.ready() MUST NEVER leak state/cryptoKey/canary AND rejects PROXYSNARE_PROMISE_TAMPERED!
  const vmLeak = makeVm9({ fetchImpl: makeHsFetch() });
  assert.equal(await vmLeak.ProxySnare.ready(), true, "Initial clean handshake succeeds");
  let capturedState = null;
  vmLeak.__capture = (v) => { if (v && typeof v === "object" && ("cryptoKey" in v || "canary" in v)) capturedState = v; };
  vm.runInContext(`
    const _t = Promise.prototype.then;
    Promise.prototype.then = function then(f, r) {
      return _t.call(this, (v) => { __capture(v); return f ? f(v) : v; }, r);
    };
  `, vmLeak);
  await assert.rejects(() => vmLeak.ProxySnare.ready(), /PROXYSNARE_PROMISE_TAMPERED/, "Second ready() under Promise.prototype.then hook MUST reject!");
  assert.equal(capturedState, null, "Zero session state/cryptoKey/canary may EVER leak through ready()!");

  // 2) CRITICAL #2 & HIGH #4 & LOW #9: Array.prototype.push hook cannot corrupt fromBase64; String.prototype.charCodeAt/charAt/slice, Error, Object.getOwnPropertyNames fail closed as TAMPERED_GUARD; post-load RUM Response.prototype.json & Headers.prototype.set stay 0-FP!
  const vmPush = makeVm9({ fetchImpl: makeHsFetch() });
  vm.runInContext(`Array.prototype.push = function() { throw new Error("PUSH_MUST_NOT_BE_CALLED_IN_FROMBASE64"); };`, vmPush);
  assert.equal(await vmPush.ProxySnare.ready(), true, "fromBase64() MUST NOT touch Array.prototype.push!");

  for (const [label, hook] of [
    ["String.prototype.charCodeAt", `String.prototype.charCodeAt = function charCodeAt() { return 65; };`],
    ["String.prototype.charAt", `String.prototype.charAt = function charAt() { return "A"; };`],
    ["String.prototype.slice", `String.prototype.slice = function slice() { return ""; };`],
    ["Object.getOwnPropertyNames", `Object.getOwnPropertyNames = function getOwnPropertyNames() { return []; };`],
  ]) {
    const vmT = makeVm9();
    vm.runInContext(hook, vmT);
    assert.equal(vmT.ProxySnare.guardHash(), "TAMPERED_GUARD", `${label} hook MUST fail closed as TAMPERED_GUARD!`);
  }
  // Pre-load window.Error tamper fails closed, while post-load Angular ZoneAwareError stays 0-FP!
  const vmPreErr = makeVm9({ preLoadHook: `const _OE = Error; window.Error = function Error(m) { return new _OE(m); };` });
  assert.equal(vmPreErr.ProxySnare.guardHash(), "TAMPERED_GUARD", "Pre-load window.Error tamper MUST fail closed as TAMPERED_GUARD!");
  const vmZoneErr = makeVm9();
  vm.runInContext(`const _OE = Error; window.Error = function ZoneAwareError(m) { return new _OE(m); };`, vmZoneErr);
  assert.equal(vmZoneErr.ProxySnare.guardHash(), expectedG9Hash, "Post-load Angular ZoneAwareError MUST stay 0-FP!");

  // Post-load RUM/APM wrappers on Response.prototype.json and Headers.prototype.set stay 0-FP!
  const vmRum = makeVm9();
  vm.runInContext(`Response.prototype.json = function json() { return Promise.resolve({}); }; Headers.prototype.set = function set() {};`, vmRum);
  assert.equal(vmRum.ProxySnare.guardHash(), expectedG9Hash, "Post-load RUM wrappers on Response.prototype.json & Headers.prototype.set MUST stay 0-FP!");

  // 3) HIGH #3 & MEDIUM #4: Error.prepareStackTrace non-configurable accessor & Function.prototype.prepareStackTrace -> ce=1,
  // while configurable getter-only Error.prepareStackTrace stays 0-FP (no strict-mode TypeError)!
  let seenCtx = "";
  const vmPstAcc = makeVm9({ fetchImpl: makeHsFetch((u, init) => { seenCtx = init.headers.get("X-PS-Ctx") || ""; }) });
  await vm.runInContext(`
    Object.defineProperty(Error, "prepareStackTrace", { get() { return () => "Error\\n  at f (https://app.example/app.js:1:1)"; }, set() {}, configurable: false });
    window.fetch("/api/a", { method: "POST", body: "{}" });
  `, vmPstAcc);
  assert.ok(seenCtx.includes("ce=1"), `Non-configurable Error.prepareStackTrace accessor MUST flag ce=1 (got ${seenCtx})`);

  seenCtx = "";
  const vmPstProto = makeVm9({ fetchImpl: makeHsFetch((u, init) => { seenCtx = init.headers.get("X-PS-Ctx") || ""; }) });
  await vm.runInContext(`
    delete Error.prepareStackTrace;
    Function.prototype.prepareStackTrace = () => "Error\\n  at f (https://app.example/app.js:1:1)";
    window.fetch("/api/b", { method: "POST", body: "{}" });
  `, vmPstProto);
  assert.ok(seenCtx.includes("ce=1"), `Inherited Function.prototype.prepareStackTrace MUST flag ce=1 (got ${seenCtx})`);

  seenCtx = "";
  const vmPstGetter = makeVm9({
    src: buildBrowserGuardScript({ basePath: "/__proxysnare", protectedPaths: ["/api"], serverVerifyPubB64: eng9.serverVerifyPubB64, allowDevTools: true, blockConsoleEval: false, collectConsoleEvalTelemetry: true }),
    fetchImpl: makeHsFetch((u, init) => { seenCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`
    let getterCalled = 0;
    Object.defineProperty(Error, "prepareStackTrace", { get() { getterCalled++; return undefined; }, configurable: true });
    window.fetch("/api/c", { method: "GET" });
  `, vmPstGetter);
  assert.ok(seenCtx.includes("ce=0"), `Configurable getter-only Error.prepareStackTrace MUST NOT throw strict-mode TypeError (got ${seenCtx})`);
  assert.equal(
    vm.runInContext(`typeof Object.getOwnPropertyDescriptor(Error, "prepareStackTrace")?.get`, vmPstGetter),
    "function",
    "Original getter descriptor MUST be restored in finally"
  );

  // 4) HIGH #5: Pre-existing window.ProxySnare (even with exact copied guardHash source!) MUST fail closed as TAMPERED_GUARD!
  const vmPrePs = makeVm9({
    preLoadHook: `Object.defineProperty(window, "ProxySnare", {
      value: Object.freeze({ version: ${JSON.stringify(require("../package.json").version)}, ready: async () => true, guardHash: () => "fake" }),
      writable: false, configurable: false,
    });`,
  });
  assert.equal(vmPrePs.ProxySnare.guardHash(), "fake");
  // Check that real guard.js wrapped fetch AND sent TAMPERED_GUARD on handshake!
  let hsGuardHashSeen = "";
  const vmPrePsHs = makeVm9({
    preLoadHook: `Object.defineProperty(window, "ProxySnare", {
      value: Object.freeze({ version: ${JSON.stringify(require("../package.json").version)}, ready: async () => true, guardHash: () => "fake" }),
      writable: false, configurable: false,
    });`,
    fetchImpl: async (url, init, VmResponse) => {
      if (String(url).endsWith("/boot")) return new VmResponse(JSON.stringify(eng9.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
      if (String(url).endsWith("/handshake")) { hsGuardHashSeen = JSON.parse(init.body).guardHash; return new VmResponse('{"error":"GUARD_INTEGRITY_MISMATCH"}', { status: 403, headers: { "content-type": "application/json" } }); }
      return new VmResponse("{}", { status: 403 });
    },
  });
  await assert.rejects(() => vmPrePsHs.fetch("/api/x"), /PROXYSNARE_HANDSHAKE_FAILED_403/);
  assert.equal(hsGuardHashSeen, "TAMPERED_GUARD", "Pre-existing window.ProxySnare MUST force guardHash='TAMPERED_GUARD' on handshake!");

  // 5) MEDIUM #6 / Perf #1 & #2 & #3: OPTIONS+ACRM+body skips 1MB buffering; unprotected chunked circular req.body skips JSON.stringify; evaluatePreBodyMinScore cliUa parity!
  const optDosMw = createProxySnareMiddleware({ mode: "strict", protectedPaths: ["/api"], maxBodyBytes: 32 });
  const optDosSrv = http.createServer(async (req, res) => {
    if (req.url === "/public-chunked") {
      // Simulate Express pre-parsed circular req.body on an unprotected chunked route!
      const circ = { a: 1 };
      circ.self = circ;
      req._body = true;
      req.body = circ;
    }
    if (await optDosMw(req, res)) return;
    res.writeHead(200);
    res.end("OK");
  });
  await new Promise((r) => optDosSrv.listen(0, "127.0.0.1", r));
  try {
    const port = optDosSrv.address().port;
    const optBodyRes = await new Promise((resolve, reject) => {
      const r = http.request({
        host: "127.0.0.1", port, method: "OPTIONS", path: "/api/secret",
        headers: makeBrowserHeaders({ "access-control-request-method": "POST", "content-length": "256" }),
      }, (resp) => { resp.resume(); resp.on("end", () => resolve(resp.statusCode)); });
      r.on("error", reject);
      r.end("x".repeat(256));
    });
    assert.equal(optBodyRes, 403, "Body-bearing OPTIONS+ACRM MUST reject 403 BEFORE 413 body buffering!");

    const chunkedPubRes = await new Promise((resolve, reject) => {
      const r = http.request({
        host: "127.0.0.1", port, method: "POST", path: "/public-chunked",
        headers: { ...makeBrowserHeaders(), "transfer-encoding": "chunked" },
      }, (resp) => { resp.resume(); resp.on("end", () => resolve(resp.statusCode)); });
      r.on("error", reject);
      r.end('{"a":1}');
    });
    assert.equal(chunkedPubRes, 200, "Unprotected chunked route with pre-parsed req.body MUST NOT JSON.stringify or throw!");
  } finally {
    await new Promise((r) => optDosSrv.close(r));
  }

  const cliUnprotPre = evaluatePreBodyMinScore(
    { "user-agent": "curl/8.5.0" },
    { mode: "balanced", blockAiCrawlers: true, blockAutomationOnAllRoutes: false, isProtected: false }
  );
  assert.equal(cliUnprotPre.guaranteed, 0, "evaluatePreBodyMinScore MUST NOT score cliUa on unprotected route when blockAutomationOnAllRoutes=false!");

  // 6) Avail #6: createProxySnareMiddleware({ verifyBrowserIntegrity }) defaults requireVeilBreak to true!
  const vbiMw = createProxySnareMiddleware({ mode: "strict", verifyBrowserIntegrity: () => ({ ok: true }) });
  let vbiGuardText = "";
  await vbiMw(
    { method: "GET", url: "/__proxysnare/guard.js", socket: { remoteAddress: "127.0.0.1" }, headers: makeBrowserHeaders({ "sec-fetch-dest": "script" }) },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead() { this.headersSent = true; }, end(b) { vbiGuardText = String(b || ""); this.writableEnded = true; } }
  );
  assert.ok(vbiGuardText.includes("const REQUIRE_VB = true ||"), "verifyBrowserIntegrity MUST default requireVeilBreak to true!");

  // 7) Perf #6 + Avail #2/#5/#8: Unified bundle omits duplicate SHA256_K inside embedded VeilBreak, XHR same-URL PRG & !canaryHandled present, Vite/Next wildcard & s-maxage=0 work!
  const uEmb = createUnifiedMiddleware({ mode: "strict", veilbreak });
  let uGuardStr = "";
  await uEmb(
    { method: "GET", url: "/__proxysnare/guard.js", socket: { remoteAddress: "127.0.0.1" }, headers: makeBrowserHeaders({ "sec-fetch-dest": "script" }) },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead() { this.headersSent = true; }, end(b) { uGuardStr = String(b || ""); this.writableEnded = true; } }
  );
  assert.equal((uGuardStr.match(/const SHA256_K = \[/g) || []).length, 1, "Unified guard.js MUST contain exactly ONE SHA256_K (zero duplicate VeilBreak fallback!)");
  assert.ok(guard9Src.includes("(redirGet || (respUrl && respUrl !== expectedUrl))"), "XHR MUST recover on same-URL PRG via X-PS-Redirect-Get: 1");
  assert.ok(guard9Src.includes("if (!canaryHandled && signed && state"), "XHR onerror/ontimeout MUST NOT wipe shared state after canaryHandled!");

  const up9 = http.createServer((req, res) => {
    if (req.url === "/page") { res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "max-age=0, s-maxage=0" }); res.end("<!doctype html><html><head></head><body>ok</body></html>"); return; }
    if (req.url === "/@vite/client" || req.url === "/src/App.tsx") { res.writeHead(200, { "Content-Type": "text/javascript" }); res.end("export default 1;"); return; }
    if (req.url.startsWith("/_next/image")) { res.writeHead(200, { "Content-Type": "image/webp" }); res.end("RIFF"); return; }
    res.writeHead(200, { "Content-Type": "application/json" }); res.end('{"secret":1}');
  });
  await new Promise((r) => up9.listen(0, "127.0.0.1", r));
  const srv9 = createProxySnareServer({ target: `http://127.0.0.1:${up9.address().port}`, mode: "strict", protectedPaths: ["*"] });
  await srv9.listen(0, "127.0.0.1");
  const p9 = srv9.server.address().port;
  const req9 = (p, headers) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port: p9, method: "GET", path: p, headers }, (resp) => {
        let d = "";
        resp.on("data", (c) => (d += c));
        resp.on("end", () => resolve({ status: resp.statusCode, body: d }));
      });
      r.on("error", reject);
      r.end();
    });
  try {
    const rPage = await req9("/page", makeBrowserHeaders({ accept: "text/html", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", "sec-fetch-site": "none" }));
    assert.equal(rPage.status, 200);
    assert.ok(rPage.body.includes("integrity="), "Cache-Control: max-age=0, s-maxage=0 MUST keep SRI pinning!");
    assert.equal((await req9("/@vite/client", makeBrowserHeaders({ "sec-fetch-dest": "script", "sec-fetch-site": "same-origin" }))).status, 200);
    assert.equal((await req9("/src/App.tsx", makeBrowserHeaders({ "sec-fetch-dest": "script", "sec-fetch-site": "same-origin" }))).status, 200);
    assert.equal((await req9("/_next/image?url=%2Fa.png&w=640", makeBrowserHeaders({ "sec-fetch-dest": "image", "sec-fetch-site": "same-origin" }))).status, 200);
    assert.equal((await req9("/api/secret", makeBrowserHeaders({ "sec-fetch-dest": "image", "sec-fetch-site": "same-origin" }))).status, 403);
  } finally {
    await srv9.close();
    await new Promise((r) => up9.close(r));
  }

  // 8) Node + Python parity: WSGI comma-coalesced X-Original-URL, bare 0x IPv4 Origin, PROXYSNARE_SECRET env fallback & truthy block_cdp_active=1!
  const rComma = eng9.inspectRequest({
    method: "GET",
    url: "/public",
    headers: makeBrowserHeaders({ "x-original-url": "/public, /api/admin" }),
  });
  assert.equal(rComma.blocked, true);
  assert.ok(rComma.reasons.some((r) => r.code === "PROXY_PATH_OVERRIDE_HEADER"));

  execFileSync(
    "python3",
    [
      "-c",
      `import os, sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
os.environ["PROXYSNARE_SECRET"] = "env-cluster-secret-32-bytes-ok!!"
v1 = ProxySnareVerifier(mode="strict", protected_paths=["/api"])
v2 = ProxySnareVerifier(mode="strict", secret="env-cluster-secret-32-bytes-ok!!", protected_paths=["/api"])
assert v1.server_verify_pub_b64 == v2.server_verify_pub_b64, "Python MUST honor PROXYSNARE_SECRET env fallback!"
del os.environ["PROXYSNARE_SECRET"]
# WSGI comma-coalesced X-Original-URL & raw_header_lines duplicate X-Original-URL
r_wsgi = v1.inspect_request(method="GET", url="/public", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-Original-URL": "/public, /api/admin"})
assert r_wsgi.blocked and any(x["code"] == "PROXY_PATH_OVERRIDE_HEADER" for x in r_wsgi.reasons)
r_raw = v1.inspect_request(method="GET", url="/public", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-Original-URL": "/public"}, raw_header_lines=["X-Original-URL: /public", "X-Original-URL: /api/admin"])
assert r_raw.blocked and any(x["code"] == "PROXY_PATH_OVERRIDE_HEADER" for x in r_raw.reasons)
# Bare '0x' IPv4 Origin canonicalizes to 0.0.0.0 -> same-origin OPTIONS preflight blocked!
r_0x = v1.inspect_request(method="OPTIONS", url="/api/secret", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Host": "0.0.0.0", "Origin": "http://0x", "Access-Control-Request-Method": "POST", "Sec-Fetch-Mode": "cors"})
assert r_0x.blocked, "Python Origin: http://0x with Host: 0.0.0.0 MUST canonicalize to same-origin and block!"
# Truthy non-bool block_cdp_active=1 disables allow_devtools!
vt = ProxySnareVerifier(mode="balanced", block_cdp_active=1)
assert vt.allow_devtools is False and vt.block_cdp_active is True`,
    ],
    { encoding: "utf8" }
  );
});

test("21. Pass-10 Audit Regressions: Promise[Symbol.species] & Array[Symbol.iterator] TOCTOU defense, webpack-internal:/// & Error.stackTraceLimit=4 & deferred setTimeout Console bypass fixes, aborted gate.js Resource Timing check, unified veilbreakOptions/antiCdp/mode:off & gate.js stripping, readRequestBody pre-aborted reject, SWR & no-transform, Python lock-free SHA-256 & tokenId/flags parity", async () => {
  const veilbreak = require("../../veilbreak/src/index.js");

  const eng10 = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api"] });
  const guard10Src = buildBrowserGuardScript({
    basePath: "/__proxysnare",
    protectedPaths: ["/api"],
    serverVerifyPubB64: eng10.serverVerifyPubB64,
  });

  const makeVm10 = ({ preLoadHook = null, fetchImpl = null, src = guard10Src, perfEntries = [] } = {}) => {
    const sp = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const sMethods = ["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "sign", "verify", "digest"];
    const origEncode = TextEncoder.prototype.encode;
    const origHdrSet = Headers.prototype.set;
    const origHdrGet = Headers.prototype.get;
    const origHdrHas = Headers.prototype.has;
    const origRespJson = Response.prototype.json;
    class VmTextEncoder { encode(s) { return origEncode.call(new TextEncoder(), s); } }
    class VmHeaders {
      constructor(init) { this._h = new Headers(init); }
      set(k, v) { return origHdrSet.call(this._h, k, v); }
      get(k) { return origHdrGet.call(this._h, k); }
      has(k) { return origHdrHas.call(this._h, k); }
    }
    class VmResponse {
      constructor(b, init) { this._r = new Response(b, init); }
      json() { return origRespJson.call(this._r); }
      text() { return this._r.text(); }
      get ok() { return this._r.ok; }
      get status() { return this._r.status; }
      get headers() { return new VmHeaders(this._r.headers); }
      clone() { return new VmResponse(this._r.clone()); }
    }
    class VmPerformance {
      now() { return performance.now(); }
      getEntriesByType(t) { return t === "resource" ? perfEntries : []; }
    }
    const vmFetch = fetchImpl
      ? function fetch(u, init) { return fetchImpl(u, init, VmResponse); }
      : async function fetch() { return new VmResponse("{}"); };
    const vmConsole = {
      debug: function debug() {},
      table: function table() {},
      clear: function clear() {},
      log: function log() {},
    };
    const nativeRefs = new Set([
      ...sMethods.map((m) => sp[m]),
      VmTextEncoder.prototype.encode,
      VmHeaders.prototype.set,
      VmHeaders.prototype.get,
      VmHeaders.prototype.has,
      VmResponse.prototype.json,
      VmPerformance.prototype.getEntriesByType,
      vmFetch,
      crypto.webcrypto.getRandomValues,
      vmConsole.debug,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        return globalThis;
      })();`,
      ifrCtx
    );
    class HTMLIFrameElement { constructor() { this.style = {}; } get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node { getAttribute() { return null; } }
    class Document extends Node {
      constructor() { super(); this.currentScript = null; this.baseURI = "https://app.example/"; this.readyState = "complete"; this._el = new Element(); }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : {}; }
      querySelectorAll() { return []; }
      querySelector() { return null; }
      addEventListener() {}
    }
    const ctx = vm.createContext({
      crypto: crypto.webcrypto,
      SubtleCrypto: sp.constructor,
      TextEncoder: VmTextEncoder,
      TextDecoder,
      Headers: VmHeaders,
      Response: VmResponse,
      Performance: VmPerformance,
      URL, URLSearchParams, Request, console: vmConsole, setTimeout, clearTimeout,
      performance: new VmPerformance(),
      navigator: { webdriver: false },
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement,
      location: { origin: "https://app.example", href: "https://app.example/" },
      fetch: vmFetch,
      addEventListener() {},
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return ctx;
  };

  const makeHsFetch10 = (onApi) => async (url, init, VmResponse) => {
    const sUrl = String(url);
    if (sUrl.endsWith("/boot")) {
      return new VmResponse(JSON.stringify(eng10.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (sUrl.endsWith("/handshake")) {
      const body = JSON.parse(init.body);
      const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|${body.browserProof?.d || ""}`).digest("hex");
      const s = eng10.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
      return new VmResponse(JSON.stringify({
        protocol: "PS_ECDH_V2",
        sessionId: s.sessionId,
        serverPubB64: s.serverPubB64,
        saltB64: s.saltB64,
        canary: s.canary,
        serverNowMs: s.serverNowMs,
        serverSigB64: s.serverSigB64,
      }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (onApi) onApi(sUrl, init);
    return new VmResponse('{"ok":true}', { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "a".repeat(32) } });
  };

  // 1) CRITICAL #1: Promise[Symbol.species] & Array.prototype[Symbol.iterator] TOCTOU gadgets fail closed as TAMPERED_GUARD & reject ensureSession()!
  for (const [label, hook] of [
    ["Promise[Symbol.species]", `Object.defineProperty(Promise, Symbol.species, { get() { return Promise; }, configurable: true });`],
    ["Array.prototype[Symbol.iterator]", `const _it = Array.prototype[Symbol.iterator]; Array.prototype[Symbol.iterator] = function() { return _it.call(this); };`],
    ["Object.create", `const _oc = Object.create; Object.create = function create(p) { return _oc(p); };`],
  ]) {
    const vmSp = makeVm10({ fetchImpl: makeHsFetch10() });
    vm.runInContext(hook, vmSp);
    assert.equal(vmSp.ProxySnare.guardHash(), "TAMPERED_GUARD", `${label} tamper MUST return TAMPERED_GUARD!`);
    await assert.rejects(() => vmSp.ProxySnare.ready(), /PROXYSNARE_PROMISE_TAMPERED/, `${label} tamper MUST reject ensureSession()!`);
  }

  // 2) HIGH #2 & #3 & MEDIUM #5: //# sourceURL=webpack-internal:///x.js in strict mode, Error.stackTraceLimit=4 deep call, AND deferred anonymous eval with closed DevTools ALL flag ce=1!
  let ctxSeen = "";
  const vmCe10 = makeVm10({ fetchImpl: makeHsFetch10((u, init) => { ctxSeen = init.headers.get("X-PS-Ctx") || ""; }) });
  // (a) //# sourceURL=webpack-internal:///x.js in strict mode (!ALLOW_DEVTOOLS) -> ce=1!
  await vm.runInContext(`eval('window.fetch("/api/w", { method: "POST", body: "{}" })\\n//# sourceURL=webpack-internal:///x.js');`, vmCe10);
  assert.ok(ctxSeen.includes("ce=1"), `//# sourceURL=webpack-internal:///x.js MUST flag ce=1 in strict mode (got ${ctxSeen})`);

  // (b) Error.stackTraceLimit = 4 with nested helper call from anonymous eval -> temporarily raised to 64 -> catches ce=1!
  ctxSeen = "";
  await vm.runInContext(`
    Error.stackTraceLimit = 4;
    function helper1() { return helper2(); }
    function helper2() { return helper3(); }
    function helper3() { return window.fetch("/api/stl", { method: "POST", body: "{}" }); }
    eval("helper1()");
  `, vmCe10);
  assert.ok(ctxSeen.includes("ce=1"), `Error.stackTraceLimit = 4 MUST NOT truncate Console eval frame (got ${ctxSeen})`);
  assert.equal(vm.runInContext("Error.stackTraceLimit", vmCe10), 4, "Original Error.stackTraceLimit MUST be restored after capture");

  // 3) HIGH #4: Aborted gate.js (no /gate.js Resource Timing entry) + pre-defined Symbol.for("__VEILBREAK_INTERNAL__") is REJECTED by guard.js!
  const vbReq10 = buildBrowserGuardScript({ basePath: "/__proxysnare", protectedPaths: ["/api"], requireVeilBreak: true });
  let abortedGateHsBody = null;
  const vmAbortedGate = makeVm10({
    src: vbReq10,
    perfEntries: [], // gate.js was aborted via page.route!
    preLoadHook: `
      const fakeVb = Object.freeze({ collectHandshakeProof: () => ({ v: 3, s: 0, f: 0, cdp: 0, spoof: true }) });
      Object.defineProperty(window, Symbol.for("__VEILBREAK_INTERNAL__"), { value: fakeVb, writable: false, configurable: false });
      Object.defineProperty(window, "VeilBreak", { value: fakeVb, writable: false, configurable: false });
    `,
    fetchImpl: async (url, init, VmResponse) => {
      if (String(url).endsWith("/boot")) return new VmResponse(JSON.stringify(eng10.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
      abortedGateHsBody = JSON.parse(init.body);
      return new VmResponse('{"error":"BROWSER_INTEGRITY_FAILED"}', { status: 403, headers: { "content-type": "application/json" } });
    },
  });
  await assert.rejects(() => vmAbortedGate.ProxySnare.ready(), /PROXYSNARE_HANDSHAKE_FAILED_403/);
  assert.equal(abortedGateHsBody.browserProof, undefined, "Aborted gate.js (absent from Resource Timing) MUST NOT trust pre-defined __VEILBREAK_INTERNAL__!");

  // 4) MEDIUM #6 (unified.js): veilbreakOptions cannot clobber embedded:true/unified:true; antiCdp:false keeps blockConsoleEval:true; mode:'off' playground keeps gate.js; createUnifiedShield strips pre-existing gate.js!
  const uNoCdp = createUnifiedMiddleware({
    mode: "strict",
    antiCdp: false,
    veilbreakOptions: { unified: false, embedded: false, includeTicketPow: true },
    veilbreak,
  });
  assert.equal(uNoCdp.engine.blockConsoleEval, true, "antiCdp:false MUST NOT silently disable blockConsoleEval!");
  assert.equal(uNoCdp.engine.blockCdpActive, false);
  let uGuardC = "";
  await uNoCdp(
    { method: "GET", url: "/__proxysnare/guard.js", socket: { remoteAddress: "127.0.0.1" }, headers: makeBrowserHeaders({ "sec-fetch-dest": "script" }) },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead() { this.headersSent = true; }, end(b) { uGuardC = String(b || ""); this.writableEnded = true; } }
  );
  assert.ok(!uGuardC.includes("veilBreakFetch"), "veilbreakOptions:{unified:false} MUST NOT clobber embedded unified invariants!");

  const uOffPg = createUnifiedMiddleware({ mode: "off", enablePlayground: true, veilbreak });
  let offPgHtml = "";
  await uOffPg(
    { method: "GET", url: "/__veilbreak/playground", socket: { remoteAddress: "127.0.0.1" }, headers: makeBrowserHeaders({ accept: "text/html" }) },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead() { this.headersSent = true; }, end(b) { offPgHtml = Buffer.isBuffer(b) ? b.toString("utf8") : String(b || ""); this.writableEnded = true; } }
  );
  assert.ok(offPgHtml.includes("/__veilbreak/gate.js"), "Unified playground in mode:'off' MUST retain standalone gate.js so window.VeilBreak loads!");

  // createUnifiedShield strips pre-existing <script src="/__veilbreak/gate.js"> tag from upstream HTML AND SWR HTML omits SRI & guard.js sends no-transform!
  const upU10 = http.createServer((req, res) => {
    if (req.url === "/swr") {
      res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "max-age=0, stale-while-revalidate=3600" });
      res.end('<!doctype html><html><head><script src="/__veilbreak/gate.js"></script></head><body>swr</body></html>');
      return;
    }
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end('<!doctype html><html><head><script src="/__veilbreak/gate.js" data-unified="true"></script></head><body>ok</body></html>');
  });
  await new Promise((r) => upU10.listen(0, "127.0.0.1", r));
  const uSh10 = createUnifiedShield({ target: `http://127.0.0.1:${upU10.address().port}`, mode: "strict", veilbreak });
  const uUrl10 = await uSh10.listen(0, "127.0.0.1");
  try {
    const rG = await fetch(`${uUrl10}/__proxysnare/guard.js`, { headers: makeBrowserHeaders() });
    assert.ok(rG.headers.get("cache-control").includes("no-transform"), "/__proxysnare/guard.js MUST include Cache-Control: no-transform!");
    const rHtml = await (await fetch(`${uUrl10}/`, { headers: makeBrowserHeaders({ accept: "text/html" }) })).text();
    assert.ok(!rHtml.includes("/__veilbreak/gate.js"), "createUnifiedShield MUST strip pre-existing standalone gate.js tag when injecting unified guard.js!");
    assert.ok(rHtml.includes('data-unified-bundle="true"'));
    const rSwr = await (await fetch(`${uUrl10}/swr`, { headers: makeBrowserHeaders({ accept: "text/html" }) })).text();
    assert.ok(!rSwr.includes("integrity="), "stale-while-revalidate HTML MUST omit ephemeral SRI pinning!");
    assert.ok(!rSwr.includes("data-ps-boot"), "stale-while-revalidate HTML MUST NOT stamp per-user data-ps-boot!");
  } finally {
    await uSh10.close();
    await new Promise((r) => upU10.close(r));
  }

  // 5) Perf MEDIUM #1: readRequestBody immediately rejects pre-aborted/destroyed req (NEVER hangs!)
  const { EventEmitter } = require("node:events");
  const deadReq = Object.assign(new EventEmitter(), {
    method: "POST",
    url: "/__proxysnare/handshake",
    socket: { remoteAddress: "127.0.0.1" },
    headers: makeBrowserHeaders({ "content-type": "application/json" }),
    readableEnded: false,
    aborted: true,
    destroyed: true,
  });
  let deadStatus = 0;
  const hsMw = createProxySnareMiddleware({ mode: "strict" });
  await hsMw(deadReq, {
    headersSent: false, writableEnded: false, setHeader() {},
    writeHead(c) { deadStatus = c; this.headersSent = true; },
    end() { this.writableEnded = true; },
  });
  assert.equal(deadStatus, 400, "Pre-aborted req MUST immediately settle with 400 REQUEST_ABORTED (never hang!)");

  // 6) Low #4 (_ERR_STACK_GET_RE linear time) + Python parity (consume_boot_challenge_detail tokenId + serialize_protected_rules m/s flags + lock-free body SHA-256!)
  const errStackRe = /^function(?:\s+(?:get\s+)?stack)?\s*\(\s*\)\s*\{\s*\[native code\]\s*\}$/;
  const tRe0 = performance.now();
  assert.equal(errStackRe.test("function" + " ".repeat(40_000) + "x"), false);
  assert.ok(performance.now() - tRe0 < 20, "_ERR_STACK_GET_RE MUST stay strictly linear O(N)!");

  execFileSync(
    "python3",
    [
      "-c",
      `import re, sys, time; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v = ProxySnareVerifier(mode="strict", handshake_pow_bits=0, protected_paths=[re.compile(r"^/api/v[0-9]+", re.I | re.M | re.S)])
rules = v.serialize_protected_rules()
assert rules == [{"regex": "^/api/v[0-9]+", "flags": "ims"}], f"Expected ims flags, got {rules}"
b = v.issue_boot_challenge(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
det = v.consume_boot_challenge_detail(boot_token=b["bootToken"], pow_nonce="0", ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
assert det["ok"] and isinstance(det.get("tokenId"), str) and len(det["tokenId"]) == 32, f"Missing tokenId: {det}"`,
    ],
    { encoding: "utf8" }
  );
});

test("22. Pass-11 Audit Regressions: decoupled blockCdpActive:false / antiCdp:false, structural stack-frame parser (fn-name spoof / nested eval / fake sourceURL / live DOM mutation / Webpack5 / stackTraceLimit=Infinity), gate.js Resource Timing hardening & preload/Safari<16.4/RUM latch, %ArrayIteratorPrototype%.next & load-time I/O integrity, Vercel/Netlify CDN headers, O(N) stripScriptBySrc, 250ms CDP coalesce, extStore local-reject skip, express.raw/text handshake & Python parity", async () => {
  const { stripScriptBySrc } = require("../src/middleware.js");
  const veilbreak = require("../../veilbreak/src/index.js");

  // 1) Security HIGH #1: blockCdpActive:false & unified antiCdp:false honored on /handshake AND requests (strict default blocks CDP!)
  const engStrictDef = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api"] });
  assert.equal(engStrictDef.blockCdpActive, true, "strict preset MUST default to blockCdpActive:true");

  const mwNoCdp = createProxySnareMiddleware({ mode: "strict", blockCdpActive: false, handshakePowBits: 0, protectedPaths: ["/api"] });
  const bootNc = mwNoCdp.engine.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const ecdhClient = crypto.createECDH("prime256v1");
  ecdhClient.generateKeys();
  const hsNcBody = JSON.stringify({
    clientPubB64: ecdhClient.getPublicKey().toString("base64"),
    bootToken: bootNc.bootToken,
    powNonce: "0",
    guardHash: mwNoCdp.guardHash,
    cdpActive: true,
  });
  let hsNcStatus = 0;
  await mwNoCdp(
    { method: "POST", url: "/__proxysnare/handshake", socket: { remoteAddress: "127.0.0.1" }, headers: makeBrowserHeaders({ "content-type": "application/json" }), readableEnded: true, body: Buffer.from(hsNcBody) },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead(c) { hsNcStatus = c; this.headersSent = true; }, end() { this.writableEnded = true; } }
  );
  assert.equal(hsNcStatus, 200, "Explicit blockCdpActive:false MUST allow handshake with cdpActive:true (and Avail LOW #7 express.raw Buffer req.body works!)");

  // Avail LOW #7: express.text() string req.body on /handshake also works!
  const bootTxt = mwNoCdp.engine.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA });
  let hsTxtStatus = 0;
  await mwNoCdp(
    {
      method: "POST",
      url: "/__proxysnare/handshake",
      socket: { remoteAddress: "127.0.0.1" },
      headers: makeBrowserHeaders({ "content-type": "text/plain" }),
      readableEnded: true,
      body: JSON.stringify({
        clientPubB64: ecdhClient.getPublicKey().toString("base64"),
        bootToken: bootTxt.bootToken,
        powNonce: "0",
        guardHash: mwNoCdp.guardHash,
        cdpActive: false,
      }),
    },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead(c) { hsTxtStatus = c; this.headersSent = true; }, end() { this.writableEnded = true; } }
  );
  assert.equal(hsTxtStatus, 200, "POST /__proxysnare/handshake MUST accept express.text() string req.body!");

  // Unified strict + antiCdp:false does NOT block CDP at handshake, AND unified monitor mode reports AI crawler headers to onVeilBreakDetect!
  const uStrictNoCdp = createUnifiedMiddleware({ mode: "strict", antiCdp: false, handshakePowBits: 0, veilbreak });
  assert.equal(uStrictNoCdp.engine.blockCdpActive, false);
  assert.equal(uStrictNoCdp.engine.blockConsoleEval, true);
  let monVbCalled = false;
  const uMon = createUnifiedMiddleware({ mode: "monitor", veilbreak, onVeilBreakDetect: () => { monVbCalled = true; } });
  const bootMon = uMon.engine.issueBootChallenge({ ip: "127.0.0.1", userAgent: "FirecrawlAgent/1.0" });
  await uMon(
    {
      method: "POST",
      url: "/__proxysnare/handshake",
      socket: { remoteAddress: "127.0.0.1" },
      headers: { "user-agent": "FirecrawlAgent/1.0", "x-firecrawl-api": "1", "content-type": "application/json" },
      readableEnded: true,
      body: JSON.stringify({ clientPubB64: ecdhClient.getPublicKey().toString("base64"), bootToken: bootMon.bootToken, powNonce: "0" }),
    },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead() { this.headersSent = true; }, end() { this.writableEnded = true; } }
  );
  assert.equal(monVbCalled, true, "Unified monitor mode MUST pass skipHeaderChecks:false so onVeilBreakDetect observes AI-crawler handshake headers!");

  // 2) Security HIGH #2 + #3 + MEDIUM #6 + Avail HIGH #2 + MEDIUM #4/#6 + Perf MEDIUM #2 VM tests!
  const eng11 = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api"] });
  const guard11Src = buildBrowserGuardScript({
    basePath: "/__proxysnare",
    protectedPaths: ["/api"],
    serverVerifyPubB64: eng11.serverVerifyPubB64,
  });
  const expectedG11Hash = computeGuardIntegrity(guard11Src).guardHash;

  const makeVm11 = ({ preLoadHook = null, fetchImpl = null, src = guard11Src, perfEntries = [], onConsoleDebug = null, initialHasInline = false, scriptSrcs = [] } = {}) => {
    const sp = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const sMethods = ["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "sign", "verify", "digest"];
    const origEncode = TextEncoder.prototype.encode;
    const origHdrSet = Headers.prototype.set;
    const origHdrGet = Headers.prototype.get;
    const origHdrHas = Headers.prototype.has;
    const origRespJson = Response.prototype.json;
    class VmTextEncoder { encode(s) { return origEncode.call(new TextEncoder(), s); } }
    class VmHeaders {
      constructor(i) { this._h = new Headers(i); }
      set(k, v) { return origHdrSet.call(this._h, k, v); }
      get(k) { return origHdrGet.call(this._h, k); }
      has(k) { return origHdrHas.call(this._h, k); }
    }
    class VmResponse {
      constructor(b, i) { this._r = new Response(b, i); }
      json() { return origRespJson.call(this._r); }
      text() { return this._r.text(); }
      get ok() { return this._r.ok; }
      get status() { return this._r.status; }
      get headers() { return new VmHeaders(this._r.headers); }
      clone() { return new VmResponse(this._r.clone()); }
    }
    let livePerfEntries = perfEntries;
    class VmPerformance {
      now() { return performance.now(); }
      getEntriesByType(t) { return t === "resource" ? livePerfEntries : []; }
      clearResourceTimings() { livePerfEntries = []; }
    }
    const vmFetch = fetchImpl
      ? function fetch(u, init) { return fetchImpl(u, init, VmResponse); }
      : async function fetch() { return new VmResponse("{}"); };
    const dbgFn = onConsoleDebug
      ? function debug(arg) { return onConsoleDebug(arg); }
      : console.debug;
    const nativeRefs = new Set([
      ...sMethods.map((m) => sp[m]),
      VmTextEncoder.prototype.encode,
      VmHeaders.prototype.set,
      VmHeaders.prototype.get,
      VmHeaders.prototype.has,
      VmResponse.prototype.json,
      VmPerformance.prototype.getEntriesByType,
      vmFetch,
      crypto.webcrypto.getRandomValues,
      dbgFn,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: dbgFn }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        return globalThis;
      })();`,
      ifrCtx
    );
    let inlineNow = initialHasInline;
    class HTMLIFrameElement { constructor() { this.style = {}; } get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node {
      constructor(attrs = null) { super(); this._attrs = attrs; }
      getAttribute(n) { return this._attrs && Object.prototype.hasOwnProperty.call(this._attrs, n) ? this._attrs[n] : null; }
    }
    class Document extends Node {
      constructor() { super(); this.currentScript = null; this.baseURI = "https://app.example/"; this.readyState = "complete"; this._el = new Element(); this.location = { href: "https://app.example/" }; }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : {}; }
      querySelectorAll(sel) {
        if (sel === "script[src]" && scriptSrcs.length) {
          return scriptSrcs.map((s) => new Element({ src: s }));
        }
        return [];
      }
      querySelector() { return inlineNow ? {} : null; }
      addEventListener() {}
    }
    const ctx = vm.createContext({
      crypto: crypto.webcrypto,
      SubtleCrypto: sp.constructor,
      TextEncoder: VmTextEncoder,
      TextDecoder,
      Headers: VmHeaders,
      Response: VmResponse,
      Performance: VmPerformance,
      URL, URLSearchParams, Request,
      console: { ...console, debug: dbgFn },
      setTimeout, clearTimeout,
      performance: new VmPerformance(),
      navigator: { webdriver: false },
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement,
      location: { origin: "https://app.example", href: "https://app.example/" },
      fetch: vmFetch,
      addEventListener() {},
      _setInlineDom: (v) => { inlineNow = v; },
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return ctx;
  };

  const makeHs11 = (onApi) => async (url, init, VmResponse) => {
    const sUrl = String(url);
    if (sUrl.endsWith("/boot")) return new VmResponse(JSON.stringify(eng11.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
    if (sUrl.endsWith("/handshake")) {
      const body = JSON.parse(init.body);
      const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|${body.browserProof?.d || ""}`).digest("hex");
      const s = eng11.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
      return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (onApi) onApi(sUrl, init);
    return new VmResponse('{"ok":true}', { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "a".repeat(32) } });
  };

  // 2a) Security HIGH #2: Function-name `(eval at x (https://app.example/app.js:1:1))` spoof & nested eval spoof & fake sourceURL & live DOM mutation ALL flag ce=1!
  let seenCtx11 = "";
  const vmSpoofFn = makeVm11({
    perfEntries: [{ name: "https://app.example/app.js", initiatorType: "script", decodedBodySize: 1000 }],
    fetchImpl: makeHs11((u, init) => { seenCtx11 = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`
    const k = "(eval at x (https://app.example/app.js:1:1))";
    eval('Promise.resolve().then(({ [k]() { return window.fetch("/api/spoof1", { method: "POST", body: "{}" }); } })[k])');
  `, vmSpoofFn);
  assert.ok(seenCtx11.includes("ce=1"), `Function-name (eval at x (https://...)) spoof MUST flag ce=1 (got ${seenCtx11})`);

  seenCtx11 = "";
  await vm.runInContext(`
    const k2 = "x (https://app.example/app.js:1:1)";
    eval('({ [k2]() { return eval("window.fetch(\\'/api/spoof2\\', { method: \\'POST\\', body: \\'{}\\' })"); } })[k2]()');
  `, vmSpoofFn);
  assert.ok(seenCtx11.includes("ce=1"), `Nested eval inside spoofed function name MUST flag ce=1 (got ${seenCtx11})`);

  seenCtx11 = "";
  await vm.runInContext(`
    eval('function go() { return window.fetch("/api/spoof3", { method: "POST", body: "{}" }); } go()\\n//# sourceURL=https://bogus.invalid/x.js');
  `, vmSpoofFn);
  assert.ok(seenCtx11.includes("ce=1"), `Fake //# sourceURL=https://bogus.invalid/x.js MUST flag ce=1 even when DevTools closed (got ${seenCtx11})`);

  // Live DOM mutation after load cannot defeat initial inline-script snapshot!
  seenCtx11 = "";
  const vmDomMut = makeVm11({
    initialHasInline: false,
    onConsoleDebug: (e) => { void e.stack; }, // simulate DevTools open
    fetchImpl: makeHs11((u, init) => { seenCtx11 = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`
    _setInlineDom(true);
    eval('function go() { return window.fetch("/api/spoof4", { method: "POST", body: "{}" }); } go()\\n//# sourceURL=https://app.example/');
  `, vmDomMut);
  assert.ok(seenCtx11.includes("ce=1"), `Post-load DOM onclick mutation MUST NOT defeat load-time hasInitialInlineScripts snapshot (got ${seenCtx11})`);

  // 2b) Avail MEDIUM #4 & #6: Webpack 5 dev arrow callback (balanced allowDevTools:true, blockConsoleEval:false) & Error.stackTraceLimit = Infinity stay 0-FP (ce=0)!
  let wpCtx = "";
  const wpGuardSrc = buildBrowserGuardScript({
    basePath: "/__proxysnare",
    protectedPaths: ["/api"],
    serverVerifyPubB64: eng11.serverVerifyPubB64,
    allowDevTools: true,
    blockConsoleEval: false,
    collectConsoleEvalTelemetry: true,
  });
  const vmWp = makeVm11({
    src: wpGuardSrc,
    onConsoleDebug: (e) => { void e.stack; }, // DevTools open
    fetchImpl: makeHs11((u, init) => { wpCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`
    Error.stackTraceLimit = Infinity;
    Promise.resolve().then(() => eval('(() => window.fetch("/api/wp", { method: "POST", body: "{}" }))()\\n//# sourceURL=webpack-internal:///./src/App.tsx'));
  `, vmWp, { filename: "webpack-internal:///./src/entry.js" });
  assert.ok(wpCtx.includes("ce=0"), `Webpack 5 dev arrow callback + Error.stackTraceLimit=Infinity with allowDevTools:true MUST stay 0-FP ce=0 (got ${wpCtx})`);

  // 2c) Perf MEDIUM #2: Burst of 5 concurrent protected fetch() calls invokes console.debug at most ONCE (250ms coalesce)!
  let dbgCount = 0;
  const vmBurst = makeVm11({
    onConsoleDebug: () => { dbgCount++; },
    fetchImpl: makeHs11(),
  });
  await vmBurst.ProxySnare.ready();
  dbgCount = 0;
  await vm.runInContext(`
    Promise.all([
      window.fetch("/api/b1"),
      window.fetch("/api/b2"),
      window.fetch("/api/b3"),
      window.fetch("/api/b4"),
      window.fetch("/api/b5"),
    ]);
  `, vmBurst);
  assert.ok(dbgCount <= 1, `250ms coalesce window MUST run console.debug <= 1 time across 5 concurrent calls (got ${dbgCount})`);

  // 2d) Security HIGH #3 + Avail HIGH #2: gate.js Resource Timing hardening & preload/Safari<16.4/RUM clearResourceTimings 0-FP!
  const vbReq11 = buildBrowserGuardScript({ basePath: "/__proxysnare", protectedPaths: ["/api"], requireVeilBreak: true });
  const fakeVbPreload = `
    const fakeVb = Object.freeze({ collectHandshakeProof: () => ({ v: 3, s: 0, f: 0, cdp: 0, ok: true }) });
    Object.defineProperty(window, Symbol.for("__VEILBREAK_INTERNAL__"), { value: fakeVb, writable: false, configurable: false });
    Object.defineProperty(window, "VeilBreak", { value: fakeVb, writable: false, configurable: false });
  `;
  for (const [label, perfEntries, extraPre] of [
    ["cross-origin 0-byte /gate.js", [{ name: "https://evil.invalid/gate.js", initiatorType: "script", decodedBodySize: 0 }], ""],
    ["Chromium aborted responseStatus:0", [{ name: "https://app.example/__veilbreak/gate.js", initiatorType: "script", decodedBodySize: 0, responseStatus: 0, responseEnd: 100, duration: 5 }], ""],
    ["deleted Performance.prototype.getEntriesByType", [{ name: "https://app.example/__veilbreak/gate.js", initiatorType: "script", decodedBodySize: 500 }], "delete Performance.prototype.getEntriesByType; delete performance.getEntriesByType;"],
  ]) {
    let hsSeen = null;
    const vmBadGate = makeVm11({
      src: vbReq11,
      perfEntries,
      preLoadHook: fakeVbPreload + extraPre,
      fetchImpl: async (url, init, VmResponse) => {
        if (String(url).endsWith("/boot")) return new VmResponse(JSON.stringify(eng11.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
        hsSeen = JSON.parse(init.body);
        return new VmResponse('{"error":"BROWSER_INTEGRITY_FAILED"}', { status: 403, headers: { "content-type": "application/json" } });
      },
    });
    await assert.rejects(() => vmBadGate.ProxySnare.ready(), /PROXYSNARE_HANDSHAKE_FAILED_403/);
    assert.equal(hsSeen.browserProof, undefined, `${label} MUST reject unverified VeilBreak bridge!`);
  }
  // Legitimate <link rel="preload"> paired with <script src="/__veilbreak/gate.js"> + Safari < 16.4 (undefined decodedBodySize) + post-load RUM clearResourceTimings() ALL stay 0-FP!
  for (const [label, entry, sSrcs] of [
    ["<link rel=preload>", { name: "https://app.example/__veilbreak/gate.js", initiatorType: "link", decodedBodySize: 4096 }, ["/__veilbreak/gate.js"]],
    ["Safari < 16.4 (undefined sizes)", { name: "https://app.example/__veilbreak/gate.js", initiatorType: "script" }, []],
  ]) {
    let hsOk = null;
    const vmOkGate = makeVm11({
      src: vbReq11,
      perfEntries: [entry],
      scriptSrcs: sSrcs,
      preLoadHook: fakeVbPreload,
      fetchImpl: async (url, init, VmResponse) => {
        if (String(url).endsWith("/boot")) return new VmResponse(JSON.stringify(eng11.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
        hsOk = JSON.parse(init.body);
        return new VmResponse('{"error":"DONE"}', { status: 403, headers: { "content-type": "application/json" } });
      },
    });
    // Simulate Datadog/New Relic RUM calling performance.clearResourceTimings() BEFORE handshake!
    vm.runInContext("performance.clearResourceTimings();", vmOkGate);
    await assert.rejects(() => vmOkGate.ProxySnare.ready(), /PROXYSNARE_HANDSHAKE_FAILED_403/);
    assert.ok(hsOk && hsOk.browserProof && hsOk.browserProof.v === 3, `${label} + RUM clearResourceTimings() MUST remain 0-FP via _gateScriptVerified latch!`);
  }

  // 2e) Security MEDIUM #6: %ArrayIteratorPrototype%.next & pre-load fetch/JSON.parse/getRandomValues tamper fail closed, while post-load RUM fetch wrapper stays 0-FP!
  const vmArrNext = makeVm11({ fetchImpl: makeHs11() });
  vm.runInContext(`const ip = Object.getPrototypeOf([].values()); const _n = ip.next; ip.next = function next() { return _n.call(this); };`, vmArrNext);
  assert.equal(vmArrNext.ProxySnare.guardHash(), "TAMPERED_GUARD", "%ArrayIteratorPrototype%.next tamper MUST return TAMPERED_GUARD!");
  await assert.rejects(() => vmArrNext.ProxySnare.ready(), /PROXYSNARE_PROMISE_TAMPERED/, "%ArrayIteratorPrototype%.next tamper MUST reject ensureSession()!");

  for (const [label, preHook] of [
    ["pre-load window.fetch", `const _f = window.fetch; window.fetch = function fetch(u, i) { return _f(u, i); };`],
    ["pre-load JSON.parse", `const _p = JSON.parse; JSON.parse = function parse(s) { return _p(s); };`],
    ["pre-load Performance.prototype.getEntriesByType", `Performance.prototype.getEntriesByType = function getEntriesByType() { return []; };`],
  ]) {
    const vmPre = makeVm11({ preLoadHook: preHook });
    assert.equal(vmPre.ProxySnare.guardHash(), "TAMPERED_GUARD", `${label} MUST return TAMPERED_GUARD!`);
  }
  const vmPostFetch = makeVm11();
  vm.runInContext(`const _f = window.fetch; window.fetch = function rumFetch(u, i) { return _f(u, i); };`, vmPostFetch);
  assert.equal(vmPostFetch.ProxySnare.guardHash(), expectedG11Hash, "Post-load RUM window.fetch wrapper MUST stay 0-FP!");

  // 3) Perf HIGH #1: stripScriptBySrc strictly O(N) on 316KB adversarial HTML (< 30ms vs 2,781ms ReDoS!)
  const evilHtml = "<script " + 'src="/__veilbreak/gate.js" '.repeat(12_000) + ">x</script>";
  const tStrip0 = performance.now();
  const strippedRes = stripScriptBySrc(evilHtml, "/__veilbreak/gate.js");
  const dtStrip = performance.now() - tStrip0;
  assert.equal(strippedRes, evilHtml, "Non-empty script body must remain untouched");
  assert.ok(dtStrip < 50, `stripScriptBySrc MUST be strictly linear O(N) on 316KB input (took ${dtStrip.toFixed(1)}ms)`);

  // 4) Avail HIGH #3: Vercel-CDN-Cache-Control & Netlify-CDN-Cache-Control omit ephemeral SRI + data-ps-boot!
  const upCdn11 = http.createServer((req, res) => {
    if (req.url === "/vercel") {
      res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-cache", "Vercel-CDN-Cache-Control": "public, s-maxage=3600" });
      res.end("<!doctype html><html><head></head><body>vercel</body></html>");
      return;
    }
    res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "private, no-store", "Netlify-CDN-Cache-Control": "public, max-age=600" });
    res.end("<!doctype html><html><head></head><body>netlify</body></html>");
  });
  await new Promise((r) => upCdn11.listen(0, "127.0.0.1", r));
  const srvCdn11 = createProxySnareServer({ target: `http://127.0.0.1:${upCdn11.address().port}`, mode: "strict", protectedPaths: ["/api"] });
  const cdnUrl11 = await srvCdn11.listen(0, "127.0.0.1");
  try {
    for (const p of ["/vercel", "/netlify"]) {
      const html = await (await fetch(`${cdnUrl11}${p}`, { headers: makeBrowserHeaders({ accept: "text/html" }) })).text();
      assert.ok(!html.includes("integrity="), `${p} CDN header MUST omit ephemeral SRI!`);
      assert.ok(!html.includes("data-ps-boot"), `${p} CDN header MUST NOT stamp per-user data-ps-boot!`);
    }
  } finally {
    await srvCdn11.close();
    await new Promise((r) => upCdn11.close(r));
  }

  // 5) Perf MEDIUM #3: extStore.get() SKIPPED on crawler flood with 6 syntactically valid fake X-PS-* headers & CORS preflights!
  let storeGets = 0;
  const fakeStore = {
    async get() { storeGets++; return null; },
    async set() {},
    async setIfNotExists() { return true; },
  };
  const mwStore11 = createProxySnareMiddleware({
    mode: "strict",
    secret: "pass11-cluster-secret-32-bytes!!",
    protectedPaths: ["/api"],
    store: fakeStore,
  });
  const fakeCrawlerHdrs = {
    "user-agent": "FirecrawlAgent/1.0",
    "x-firecrawl-id": "fc-1",
    "x-ps-session": "a".repeat(32),
    "x-ps-seq": "1",
    "x-ps-ts": String(Date.now()),
    "x-ps-nonce": "nonce12345678",
    "x-ps-canary": "b".repeat(24),
    "x-ps-proof": "c".repeat(64),
  };
  let crawlerStatus = 0;
  await mwStore11(
    { method: "GET", url: "/api/secret", socket: { remoteAddress: "127.0.0.1" }, headers: fakeCrawlerHdrs },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead(c) { crawlerStatus = c; this.headersSent = true; }, end() { this.writableEnded = true; } }
  );
  assert.equal(crawlerStatus, 403);
  assert.equal(storeGets, 0, "extStore.get() MUST be skipped when cheap local crawler/CLI/CL+TE rejection already meets threshold!");

  await mwStore11(
    {
      method: "OPTIONS",
      url: "/api/secret",
      socket: { remoteAddress: "127.0.0.1" },
      headers: { ...fakeCrawlerHdrs, "user-agent": CHROME_UA, "host": "app.test", "origin": "https://other.test", "access-control-request-method": "POST", "sec-fetch-mode": "cors" },
    },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead() { this.headersSent = true; }, end() { this.writableEnded = true; } }
  );
  assert.equal(storeGets, 0, "extStore.get() MUST be skipped on CORS OPTIONS preflight!");

  // 6) Python parity: 162-combo preset matrix matches Node resolvePreset bit-for-bit AND unprotected requests skip lock!
  execFileSync(
    "python3",
    [
      "-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v_bal_ce = ProxySnareVerifier(mode="balanced", block_console_eval=True)
assert v_bal_ce.allow_devtools is True and v_bal_ce.block_cdp_active is False and v_bal_ce.block_console_eval is True
v_strict = ProxySnareVerifier(mode="strict")
assert v_strict.allow_devtools is False and v_strict.block_cdp_active is True and v_strict.block_console_eval is True
v_strict_nocdp = ProxySnareVerifier(mode="strict", block_cdp_active=False)
assert v_strict_nocdp.allow_devtools is False and v_strict_nocdp.block_cdp_active is False and v_strict_nocdp.block_console_eval is True
# Unprotected clean route runs without acquiring _lock (verify counter unchanged)
c0 = v_strict._inspect_counter
r_pub = v_strict.inspect_request(method="GET", url="/public/logo.png", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}})
assert not r_pub.blocked and v_strict._inspect_counter == c0, "Unprotected clean route MUST skip lock acquisition!"`,
    ],
    { encoding: "utf8" }
  );
});

test("23. Pass-12 Audit Regressions: parseBootAttr TDZ fix (zero /boot round-trip), Response.prototype.then & Object.prototype.signal defense, redirected script 0-FP, bounded X-Original-URL DoS cap (JS+Python), linear _EVAL_TAIL_ANON_RE, unified blockCdpActive:false VeilBreak sync, precomputed br/gzip guard.js & legacy Expires shared-cache check", async () => {
  const zlib = require("node:zlib");
  const veilbreak = require("../../veilbreak/src/index.js");

  // 1) Security TDZ fix + Response.prototype.then & Object.prototype.signal defense!
  const eng12 = createProxySnareEngine({ mode: "strict", handshakePowBits: 0, protectedPaths: ["/api"] });
  const guard12Src = buildBrowserGuardScript({
    basePath: "/__proxysnare",
    protectedPaths: ["/api"],
    serverVerifyPubB64: eng12.serverVerifyPubB64,
  });
  const stampedBoot = eng12.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const stampedB64 = Buffer.from(JSON.stringify(stampedBoot), "utf8").toString("base64url");

  const makeVm12 = ({ fetchImpl = null, scriptAttrs = null, preLoadHook = null, src = guard12Src, rtEntries = [] } = {}) => {
    const sp = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const sMethods = ["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "sign", "verify", "digest"];
    const origEncode = TextEncoder.prototype.encode;
    const origHdrSet = Headers.prototype.set;
    const origHdrGet = Headers.prototype.get;
    const origHdrHas = Headers.prototype.has;
    const origRespJson = Response.prototype.json;
    class VmTextEncoder { encode(s) { return origEncode.call(new TextEncoder(), s); } }
    class VmHeaders {
      constructor(i) { this._h = new Headers(i); }
      set(k, v) { return origHdrSet.call(this._h, k, v); }
      get(k) { return origHdrGet.call(this._h, k); }
      has(k) { return origHdrHas.call(this._h, k); }
    }
    class VmResponse {
      constructor(b, i) { this._r = new Response(b, i); }
      json() { return origRespJson.call(this._r); }
      text() { return this._r.text(); }
      get ok() { return this._r.ok; }
      get status() { return this._r.status; }
      get headers() { return new VmHeaders(this._r.headers); }
      clone() { return new VmResponse(this._r.clone()); }
    }
    class VmPerformance {
      now() { return performance.now(); }
      getEntriesByType(t) { return t === "resource" ? rtEntries : []; }
    }
    const vmFetch = fetchImpl
      ? function fetch(u, init) { return fetchImpl(u, init, VmResponse); }
      : async function fetch() { return new VmResponse("{}"); };
    const vmConsole = {
      debug: function debug() {},
      table: function table() {},
      clear: function clear() {},
      log: function log() {},
    };
    const nativeRefs = new Set([
      ...sMethods.map((m) => sp[m]),
      VmTextEncoder.prototype.encode,
      VmHeaders.prototype.set,
      VmHeaders.prototype.get,
      VmHeaders.prototype.has,
      VmResponse.prototype.json,
      VmPerformance.prototype.getEntriesByType,
      vmFetch,
      crypto.webcrypto.getRandomValues,
      vmConsole.debug,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        return globalThis;
      })();`,
      ifrCtx
    );
    class HTMLIFrameElement { constructor() { this.style = {}; } get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node {
      constructor(attrs = null) { super(); this._attrs = attrs; }
      getAttribute(k) { return this._attrs && k in this._attrs ? this._attrs[k] : null; }
    }
    class Document extends Node {
      constructor() {
        super();
        this.currentScript = scriptAttrs ? new Element(scriptAttrs) : null;
        this.baseURI = "https://app.example/";
        this.readyState = "complete";
        this._el = new Element();
        this.location = { href: "https://app.example/" };
      }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : {}; }
      querySelectorAll() { return []; }
      querySelector() { return null; }
      addEventListener() {}
    }
    const ctx = vm.createContext({
      crypto: crypto.webcrypto,
      SubtleCrypto: sp.constructor,
      TextEncoder: VmTextEncoder,
      TextDecoder,
      Headers: VmHeaders,
      Response: VmResponse,
      Performance: VmPerformance,
      URL, URLSearchParams, Request, console: vmConsole, setTimeout, clearTimeout,
      performance: new VmPerformance(),
      navigator: { webdriver: false },
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement,
      location: { origin: "https://app.example", href: "https://app.example/" },
      fetch: vmFetch,
      addEventListener() {},
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return ctx;
  };

  let bootFetchCount = 0;
  let signalGetterTrips = 0;
  const vmBoot = makeVm12({
    scriptAttrs: { "data-ps-boot": stampedB64 },
    fetchImpl: async (url, init, VmResponse) => {
      if (init && "signal" in init) { void init.signal; } // verify null-proto init does NOT inherit Object.prototype.signal!
      if (String(url).endsWith("/boot")) {
        bootFetchCount++;
        return new VmResponse(JSON.stringify(eng12.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
      }
      if (String(url).endsWith("/handshake")) {
        const body = JSON.parse(init.body);
        const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|`).digest("hex");
        const s = eng12.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
        return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
      }
      return new VmResponse("{}", { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "a".repeat(32) } });
    },
  });
  vmBoot.__tripSignal = () => { signalGetterTrips++; };
  vm.runInContext(`Object.defineProperty(Object.prototype, "signal", { get() { __tripSignal(); return undefined; }, configurable: true });`, vmBoot);
  assert.equal(await vmBoot.ProxySnare.ready(), true, "Stamped data-ps-boot MUST parse cleanly (zero TDZ ReferenceError!)");
  assert.equal(bootFetchCount, 0, "Stamped data-ps-boot MUST avoid redundant GET /__proxysnare/boot round trip!");
  assert.equal(signalGetterTrips, 0, "Null-prototype handshake fetch init MUST NOT trigger Object.prototype.signal getter!");

  // Response.prototype.then fails closed!
  const vmRespThen = makeVm12();
  vm.runInContext(`Response.prototype.then = function(r) { r(this); };`, vmRespThen);
  assert.equal(vmRespThen.ProxySnare.guardHash(), "TAMPERED_GUARD", "Response.prototype.then MUST fail closed as TAMPERED_GUARD!");
  await assert.rejects(() => vmRespThen.ProxySnare.ready(), /PROXYSNARE_PROMISE_TAMPERED/, "Response.prototype.then MUST reject ensureSession()!");

  // 2) Availability: 302-redirected trusted-origin script stays 0-FP (ce=0) when DevTools closed!
  let redirCtx = "";
  const vmRedirScript = makeVm12({
    rtEntries: [{ name: "https://app.example/cdn/latest.js", initiatorType: "script", redirectStart: 1, redirectEnd: 5, responseStatus: 200, decodedBodySize: 500 }],
    fetchImpl: async (url, init, VmResponse) => {
      if (String(url).endsWith("/boot")) return new VmResponse(JSON.stringify(eng12.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
      if (String(url).endsWith("/handshake")) {
        const body = JSON.parse(init.body);
        const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|`).digest("hex");
        const s = eng12.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
        return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
      }
      redirCtx = init.headers.get("X-PS-Ctx") || "";
      return new VmResponse("{}", { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "a".repeat(32) } });
    },
  });
  await new Promise((r) => setTimeout(r, 0));
  await vm.runInContext(
    `Promise.resolve().then(() => { function appInit() { return window.fetch("/api/r", { method: "POST", body: "{}" }); } return appInit(); });`,
    vmRedirScript,
    { filename: "https://app.example/cdn/v2/bundle.js" }
  );
  assert.ok(redirCtx.includes("ce=0"), `302-redirected same-origin .js script with DevTools closed MUST stay 0-FP ce=0 (got ${redirCtx})`);
  assert.ok(redirCtx.includes("cdp=0"), `Closed DevTools mock MUST report cdp=0 (got ${redirCtx})`);

  // 3) Perf HIGH #1: Unbounded X-Original-URL comma-split DoS (1,500 tokens) fails closed in < 15ms (JS + Python)!
  const evilOv = Array.from({ length: 1500 }, () => "%2e#?%00").join(",");
  const tOv0 = performance.now();
  const rOv = eng12.inspectRequest({ method: "GET", url: "/public", headers: makeBrowserHeaders({ "x-original-url": evilOv }) });
  const dtOv = performance.now() - tOv0;
  assert.equal(rOv.blocked, true);
  assert.ok(rOv.reasons.some((r) => r.code === "PROXY_PATH_OVERRIDE_HEADER"));
  assert.ok(dtOv < 15, `1,500-part X-Original-URL MUST fail closed in < 15ms (took ${dtOv.toFixed(2)}ms)`);

  // 4) Perf MEDIUM #2: _EVAL_TAIL_ANON_RE linear time on 50KB whitespace!
  const linearEvalRe = /(?:<anonymous>(?::\d+(?::\d+)?)?|VM\d+:\d+(?::\d+)?)$/i;
  const tEv0 = performance.now();
  assert.equal(linearEvalRe.test("eval at " + " ".repeat(50_000) + "(http://x)"), false);
  assert.ok(performance.now() - tEv0 < 15, "_EVAL_TAIL_ANON_RE MUST stay strictly linear O(N) on 50KB whitespace!");

  // 5) Perf MEDIUM #3: createUnifiedMiddleware({ mode: "strict", blockCdpActive: false }) syncs VeilBreak allowDevTools:true while keeping blockConsoleEval:true!
  const uNoCdp12 = createUnifiedMiddleware({ mode: "strict", blockCdpActive: false, handshakePowBits: 0, veilbreak });
  assert.equal(uNoCdp12.engine.blockCdpActive, false);
  assert.equal(uNoCdp12.engine.blockConsoleEval, true, "ProxySnare MUST retain blockConsoleEval:true when only blockCdpActive:false is set!");
  assert.equal(uNoCdp12.veilbreak.preset.allowDevTools, true, "VeilBreak MUST lower cdpRuntimeWeight via allowDevTools:true when unified blockCdpActive:false!");
  const ch12 = "ch-unified-nocdp";
  const d12 = crypto.createHash("sha256").update(`VB_HS_V3|${ch12}|1|128|Linux x86_64|1||1|5`).digest("hex");
  const vbVerdict12 = uNoCdp12.veilbreak.verifyHandshakeProof({
    headers: makeBrowserHeaders(),
    proof: { v: 3, ch: ch12, s: 1, f: 128, p: "Linux x86_64", cdp: 1, wr: "", wk: 1, ms: 5, d: d12 },
    expectedChallenge: ch12,
    skipHeaderChecks: true,
  });
  assert.equal(vbVerdict12.blocked, false, `Unified strict+blockCdpActive:false MUST allow open DevTools handshake proof (got ${JSON.stringify(vbVerdict12)})`);

  // 6) Perf MEDIUM #4 + Availability Expires: precomputed br/gzip guard.js (4-5x smaller) + 304 ETag + legacy future Expires shared-cache omission!
  const up12 = http.createServer((req, res) => {
    if (req.url === "/future-exp") {
      res.writeHead(200, { "Content-Type": "text/html", Expires: "Wed, 21 Oct 2035 07:28:00 GMT" });
      res.end("<!doctype html><html><head></head><body>exp</body></html>");
      return;
    }
    res.writeHead(200, { "Content-Type": "text/html", Expires: "Thu, 01 Jan 1970 00:00:00 GMT" });
    res.end("<!doctype html><html><head></head><body>noexp</body></html>");
  });
  await new Promise((r) => up12.listen(0, "127.0.0.1", r));
  const uSh12 = createUnifiedShield({ target: `http://127.0.0.1:${up12.address().port}`, mode: "strict", veilbreak });
  await uSh12.listen(0, "127.0.0.1");
  const p12 = uSh12.server.address().port;
  const rawReq12 = (pathStr, headers) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port: p12, method: "GET", path: pathStr, headers }, (resp) => {
        const chunks = [];
        resp.on("data", (c) => chunks.push(c));
        resp.on("end", () => resolve({ status: resp.statusCode, headers: resp.headers, buf: Buffer.concat(chunks) }));
      });
      r.on("error", reject);
      r.end();
    });
  try {
    const rRaw = await rawReq12("/__proxysnare/guard.js", makeBrowserHeaders());
    const rBr = await rawReq12("/__proxysnare/guard.js", makeBrowserHeaders({ "accept-encoding": "gzip, deflate, br" }));
    assert.equal(rBr.status, 200);
    assert.equal(rBr.headers["content-encoding"], "br");
    assert.equal(rBr.headers["vary"], "Accept-Encoding");
    assert.ok(rBr.buf.length * 3 < rRaw.buf.length, `Brotli guard.js (${rBr.buf.length}B) MUST be >3x smaller than raw (${rRaw.buf.length}B)!`);
    assert.equal(zlib.brotliDecompressSync(rBr.buf).equals(rRaw.buf), true, "Decompressed Brotli guard.js MUST match raw bytes bit-for-bit (W3C SRI intact)!");
    const r304 = await rawReq12("/__proxysnare/guard.js", makeBrowserHeaders({ "accept-encoding": "br", "if-none-match": rBr.headers["etag"] }));
    assert.equal(r304.status, 304, "Encoding-specific ETag MUST return 304 Not Modified!");

    const rFut = await rawReq12("/future-exp", makeBrowserHeaders({ accept: "text/html" }));
    assert.ok(!rFut.buf.toString("utf8").includes("integrity="), "Future Expires without private/no-store MUST omit ephemeral SRI!");
    assert.ok(!rFut.buf.toString("utf8").includes("data-ps-boot"), "Future Expires without private/no-store MUST NOT stamp data-ps-boot!");
    const rPast = await rawReq12("/past-exp", makeBrowserHeaders({ accept: "text/html" }));
    assert.ok(rPast.buf.toString("utf8").includes("integrity="), "Past Expires (1970) MUST keep SRI pinning!");
  } finally {
    await uSh12.close();
    await new Promise((r) => up12.close(r));
  }

  // 7) Python parity: 1,500-part X-Original-URL DoS capped in < 15ms + empty-body signed GET single-lock parity!
  execFileSync(
    "python3",
    [
      "-c",
      `import sys, time; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v = ProxySnareVerifier(mode="strict", protected_paths=["/api"])
evil = ",".join(["%2e#?%00"] * 1500)
t0 = time.perf_counter()
r = v.inspect_request(method="GET", url="/public", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "X-Original-URL": evil})
dt = (time.perf_counter() - t0) * 1000
assert r.blocked and any(x["code"] == "PROXY_PATH_OVERRIDE_HEADER" for x in r.reasons), f"Expected bounded fail-closed: {r.reasons}"
assert dt < 15.0, f"Python 1,500-part X-Original-URL DoS took {dt:.2f}ms!"
s = v.issue_session(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
ts = str(int(time.time() * 1000))
pr = v.sign_request(session_key_hex=s["sessionKeyHex"], method="GET", path_with_query="/api/empty", body=b"", seq="1", ts=ts, nonce="py-empty-01", canary=s["canary"])
r2 = v.inspect_request(method="GET", url="/api/empty", body=b"", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-PS-Session": s["sessionId"], "X-PS-Seq": "1", "X-PS-Ts": ts, "X-PS-Nonce": "py-empty-01", "X-PS-Canary": s["canary"], "X-PS-Proof": pr})
assert not r2.blocked, f"Empty-body signed GET failed: {r2.reasons}"`,
    ],
    { encoding: "utf8" }
  );
});

test("24. Pass-13 Audit Regressions: RegExp.prototype.exec & Array.push/Set.has defenses, gestureExemptPaths traversal (JS+Python), Error.stackTraceLimit getter, Angular Zone.js NativePromise.then 0-FP, strict+blockCdpActive:false SPA callback 0-FP, Safari cached gate.js duration===0, pre-DOMContentLoaded & cross-origin 302 script 0-FP, O(1) RT cache, Accept-Encoding q=0.5/0.8, '|' delimiter & extensionless image->JS MIME block", async () => {
  const vm = require("node:vm");
  const { computeGuardIntegrity } = require("../src/browser-guard.js");
  const eng13 = createProxySnareEngine({
    mode: "paranoid",
    protectedPaths: ["/api"],
    gestureExemptPaths: ["/api/telemetry"],
    handshakePowBits: 0,
    requireGuardIntegrity: true,
    secret: "pass13-regression-secret-32bytes!",
  });

  // 1) Security HIGH #3: gestureExemptPaths path traversal (/api/telemetry/../transfer) MUST NOT be exempted!
  const s13 = eng13.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const ts13 = String(Date.now());
  const ctxNoUg = "ce=0;cdp=0;ug=0;ga=999999";
  const sign13 = (urlPath, seq, nonce, canary) =>
    eng13.signRequest({
      sessionKeyHex: s13.sessionKeyHex,
      method: "POST",
      pathWithQuery: urlPath,
      body: "{}",
      seq,
      ts: ts13,
      nonce,
      canary,
      ctx: ctxNoUg,
    });
  const pEx = sign13("/api/telemetry", "1", "p13-n0001", s13.canary);
  const rEx = eng13.inspectRequest({
    method: "POST",
    url: "/api/telemetry",
    body: "{}",
    ip: "127.0.0.1",
    headers: makeBrowserHeaders({
      "x-ps-session": s13.sessionId,
      "x-ps-seq": "1",
      "x-ps-ts": ts13,
      "x-ps-nonce": "p13-n0001",
      "x-ps-canary": s13.canary,
      "x-ps-ctx": ctxNoUg,
      "x-ps-proof": pEx,
    }),
  });
  assert.equal(rEx.blocked, false, "Genuine /api/telemetry MUST remain gesture-exempt");
  const pTrav = sign13("/api/telemetry/../transfer", "2", "p13-n0002", rEx.nextCanary);
  const rTrav = eng13.inspectRequest({
    method: "POST",
    url: "/api/telemetry/../transfer",
    body: "{}",
    ip: "127.0.0.1",
    headers: makeBrowserHeaders({
      "x-ps-session": s13.sessionId,
      "x-ps-seq": "2",
      "x-ps-ts": ts13,
      "x-ps-nonce": "p13-n0002",
      "x-ps-canary": rEx.nextCanary,
      "x-ps-ctx": ctxNoUg,
      "x-ps-proof": pTrav,
    }),
  });
  assert.equal(rTrav.blocked, true, "Traversal /api/telemetry/../transfer MUST NOT bypass requireUserGestureOnMutate!");
  assert.ok(rTrav.reasons.some((r) => r.code === "MUTATION_WITHOUT_USER_GESTURE"));

  // 2) Security LOW: '|' delimiter rejected in bootToken / hsBind in issueSession & verifyHandshakeSignature!
  const badHs = eng13.issueSession({
    ip: "127.0.0.1",
    userAgent: CHROME_UA,
    clientPubB64: crypto.createECDH("prime256v1").generateKeys().toString("base64"),
    bootToken: "tok|9999999999999",
  });
  assert.equal(badHs.error, "INVALID_HANDSHAKE_PARAMETERS", "'|' in bootToken MUST fail closed in issueSession()");

  // Helper VM factory for Pass-13 browser-guard regressions
  const makeVm13 = ({
    guardOpts = {},
    readyState = "complete",
    rtEntries = [],
    scriptEls = [],
    inlineEl = false,
    cdpOpen = false,
    fetchImpl = null,
    preLoadHook = null,
  } = {}) => {
    const src = buildBrowserGuardScript({
      basePath: "/__proxysnare",
      protectedRules: ["/api"],
      serverVerifyPubB64: eng13.serverVerifyPubB64,
      allowDevTools: false,
      blockCdpActive: true,
      blockConsoleEval: true,
      ...guardOpts,
    });
    const { guardHash: expHash } = computeGuardIntegrity(src);
    const sp = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const sMethods = ["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "verify", "sign", "digest"];
    const origEncode = TextEncoder.prototype.encode;
    const origHdrSet = Headers.prototype.set;
    const origHdrGet = Headers.prototype.get;
    const origHdrHas = Headers.prototype.has;
    const origRespJson = Response.prototype.json;
    class VmTextEncoder extends TextEncoder {}
    VmTextEncoder.prototype.encode = origEncode;
    class VmHeaders extends Headers {}
    VmHeaders.prototype.set = origHdrSet;
    VmHeaders.prototype.get = origHdrGet;
    VmHeaders.prototype.has = origHdrHas;
    class VmResponse extends Response {}
    VmResponse.prototype.json = origRespJson;
    let rtCalls = 0;
    class VmPerformance {
      now() { return performance.now(); }
      getEntriesByType(t) {
        if (t === "resource") { rtCalls++; return rtEntries; }
        return [];
      }
    }
    const vmFetch = fetchImpl
      ? function fetch(u, init) { return fetchImpl(u, init, VmResponse); }
      : async function fetch() { return new VmResponse("{}"); };
    const vmConsole = {
      debug: function debug(x) { if (cdpOpen && x && typeof x === "object") void x.stack; },
      table: function table() {},
      clear: function clear() {},
      log: function log() {},
    };
    const nativeRefs = new Set([
      ...sMethods.map((m) => sp[m]),
      VmTextEncoder.prototype.encode,
      VmHeaders.prototype.set,
      VmHeaders.prototype.get,
      VmHeaders.prototype.has,
      VmResponse.prototype.json,
      VmPerformance.prototype.getEntriesByType,
      vmFetch,
      crypto.webcrypto.getRandomValues,
      vmConsole.debug,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        return globalThis;
      })();`,
      ifrCtx
    );
    class HTMLIFrameElement { constructor() { this.style = {}; } get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node {
      constructor(attrs = null) { super(); this._attrs = attrs; }
      getAttribute(k) { return this._attrs && k in this._attrs ? this._attrs[k] : null; }
    }
    class Document extends Node {
      constructor() {
        super();
        this.currentScript = null;
        this.baseURI = "https://app.example/";
        this.readyState = readyState;
        this._el = new Element();
        this.location = { href: "https://app.example/" };
      }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : {}; }
      querySelectorAll() { return scriptEls.map((a) => new Element(a)); }
      querySelector() { return inlineEl ? new Element({}) : null; }
      addEventListener() {}
    }
    const ctx = vm.createContext({
      crypto: crypto.webcrypto,
      SubtleCrypto: sp.constructor,
      TextEncoder: VmTextEncoder,
      TextDecoder,
      Headers: VmHeaders,
      Response: VmResponse,
      Performance: VmPerformance,
      URL, URLSearchParams, Request, console: vmConsole, setTimeout, clearTimeout,
      performance: new VmPerformance(),
      navigator: { webdriver: false },
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement,
      location: { origin: "https://app.example", href: "https://app.example/" },
      fetch: vmFetch,
      addEventListener() {},
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, expHash, getRtCalls: () => rtCalls };
  };

  // 3) CRITICAL #1: Hooking RegExp.prototype.exec (leaving RegExp.prototype.test native) MUST fail closed (both pre-load AND post-load)!
  const vmReExecPre = makeVm13({
    preLoadHook: `const _origExec = RegExp.prototype.exec; RegExp.prototype.exec = function(s) { return this.global ? _origExec.call(this, s) : ["ok"]; };`,
  });
  assert.equal(vmReExecPre.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", "Pre-load RegExp.prototype.exec hook MUST fail closed as TAMPERED_GUARD!");
  const vmReExecPost = makeVm13();
  vm.runInContext(`const _origExec = RegExp.prototype.exec; RegExp.prototype.exec = function(s) { return this.global ? _origExec.call(this, s) : ["ok"]; };`, vmReExecPost.ctx);
  assert.equal(vmReExecPost.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", "Post-load RegExp.prototype.exec hook MUST fail closed as TAMPERED_GUARD!");
  await assert.rejects(() => vmReExecPost.ctx.ProxySnare.ready(), /PROXYSNARE_PROMISE_TAMPERED/, "Post-load RegExp.prototype.exec hook MUST reject ready()!");

  // 4) HIGH #2: Post-load Array.prototype.push & Set.prototype.has hooks CANNOT bypass captureConsoleEvalFlag!
  let pushHookCtx = "";
  const makeHsFetch = (onApi) => async (url, init, VmResponse) => {
    if (String(url).endsWith("/__proxysnare/boot")) return new VmResponse(JSON.stringify(eng13.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
    if (String(url).endsWith("/__proxysnare/handshake")) {
      const body = JSON.parse(init.body);
      const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|${body.browserProof?.d || ""}`).digest("hex");
      const s = eng13.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
      return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (onApi) onApi(init);
    return new VmResponse("{}", { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "b".repeat(32) } });
  };
  const vmPush = makeVm13({
    cdpOpen: true,
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 100 }],
    fetchImpl: makeHsFetch((init) => { pushHookCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`
    const _op = Array.prototype.push;
    Array.prototype.push = function(...a) { return _op.apply(this, a.map((x) => typeof x === "string" && x.includes("anonymous") ? "at app (https://app.example/app.js:1:1)" : x)); };
    Set.prototype.has = () => true;
    window.fetch("/api/p", { method: "POST", body: "{}" });
  `, vmPush.ctx);
  assert.ok(pushHookCtx.includes("ce=1"), `Array.prototype.push + Set.prototype.has hooks MUST NOT bypass Console eval detection (got ${pushHookCtx})`);

  // 5) MEDIUM #4: Configurable Error.stackTraceLimit getter suppressing V8 stack MUST fail closed (ce=1)!
  let stlGetterCtx = "";
  const vmStlGet = makeVm13({
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    fetchImpl: makeHsFetch((init) => { stlGetterCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`
    Object.defineProperty(Error, "stackTraceLimit", { configurable: true, get() { return 64; } });
    window.fetch("/api/stl", { method: "POST", body: "{}" });
  `, vmStlGet.ctx, { filename: "https://app.example/app.js" });
  assert.ok(stlGetterCtx.includes("ce=1"), `Error.stackTraceLimit configurable getter MUST fail closed ce=1 (got ${stlGetterCtx})`);

  // 6) Availability HIGH #1: Angular Zone.js patching NativePromise.prototype.then stays 0-FP & leaks ZERO CryptoKeys!
  let zoneSawCryptoKey = false;
  const vmAngular = makeVm13({ fetchImpl: makeHsFetch() });
  vmAngular.ctx.__markLeak = () => { zoneSawCryptoKey = true; };
  vm.runInContext(`
    window.Zone = { current: { name: "<root>" } };
    const origThen = Promise.prototype.then;
    Promise.prototype.__zone_symbol__then = origThen;
    Promise.prototype.then = function zonePatchedThen(onF, onR) {
      const wrap = typeof onF === "function" ? function(v) {
        if (v && (v.constructor?.name === "CryptoKey" || v instanceof ArrayBuffer || (v.privateKey && v.publicKey))) __markLeak();
        return onF(v);
      } : onF;
      return origThen.call(this, wrap, onR);
    };
  `, vmAngular.ctx);
  assert.equal(vmAngular.ctx.ProxySnare.guardHash(), vmAngular.expHash, "Angular Zone.js __zone_symbol__then patch MUST stay 0-FP on guardHash!");
  assert.equal(await vmAngular.ctx.ProxySnare.ready(), true, "Angular Zone.js MUST complete ECDH+ECDSA handshake cleanly!");
  assert.equal(zoneSawCryptoKey, false, "Patched Promise.prototype.then MUST NEVER observe CryptoKey or ArrayBuffer!");

  // 7) Availability HIGH #2: strict+blockCdpActive:false allows SPA bare callback (Promise.then/setTimeout arrow) while still blocking Console eval!
  let spaCbCtx = "";
  const vmSpaCb = makeVm13({
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    cdpOpen: true,
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 200 }],
    fetchImpl: makeHsFetch((init) => { spaCbCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`Promise.resolve().then(() => window.fetch("/api/cb", { method: "POST", body: "{}" }));`, vmSpaCb.ctx, { filename: "https://app.example/app.js" });
  assert.ok(spaCbCtx.includes("ce=0"), `strict+blockCdpActive:false with DevTools open MUST allow verified app bare callback (got ${spaCbCtx})`);
  await vm.runInContext(`eval('window.fetch("/api/evil", { method: "POST", body: "{}" })');`, vmSpaCb.ctx);
  assert.ok(spaCbCtx.includes("ce=1"), `strict+blockCdpActive:false MUST STILL block Console eval (got ${spaCbCtx})`);

  // 8) Availability HIGH #3: Safari/RFP cached gate.js (responseStatus:undefined, sizes:0, duration:0, responseEnd:12) passes Resource Timing verification!
  const vmSafGate = makeVm13({
    guardOpts: { requireVeilBreak: true },
    rtEntries: [{ name: "https://app.example/__veilbreak/gate.js?v=123", initiatorType: "script", transferSize: 0, encodedBodySize: 0, decodedBodySize: 0, responseEnd: 12, duration: 0 }],
    fetchImpl: makeHsFetch(),
  });
  let proofCalled = false;
  const fakeVb = Object.freeze({
    collectHandshakeProof: async (ch) => { proofCalled = true; return { v: 3, ch, s: 0, f: 0, p: "MacIntel", cdp: 0, wr: "", wk: 1, ms: 2, d: "0".repeat(64) }; },
    getLastInteraction: () => null,
    mode: "strict",
  });
  Object.defineProperty(vmSafGate.ctx, "VeilBreak", { value: fakeVb, writable: false, configurable: false });
  Object.defineProperty(vmSafGate.ctx, Symbol.for("__VEILBREAK_INTERNAL__"), { value: fakeVb, writable: false, configurable: false });
  await vmSafGate.ctx.ProxySnare.ready();
  assert.equal(proofCalled, true, "Safari cached gate.js with duration===0 & responseEnd>0 MUST pass Resource Timing check!");

  // 9) Availability HIGH #4 + Security MEDIUM #6 + Perf HIGH #1: Pre-DOMContentLoaded inline <script> 0-FP + cross-origin 302 script 0-FP + O(1) RT cache!
  let preDclCtx = "";
  const vmPreDcl = makeVm13({
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    readyState: "loading",
    inlineEl: true,
    cdpOpen: true,
    fetchImpl: makeHsFetch((init) => { preDclCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`Promise.resolve().then(() => { function bootApp() { return window.fetch("/api/boot", { method: "POST", body: "{}" }); } return bootApp(); });`, vmPreDcl.ctx, { filename: "https://app.example/" });
  assert.ok(preDclCtx.includes("ce=0"), `Pre-DOMContentLoaded inline <script> with DevTools open MUST stay 0-FP ce=0 (got ${preDclCtx})`);

  let xorigCtx = "";
  const vmXorig = makeVm13({
    rtEntries: [{ name: "https://app.example/latest/sdk.js", initiatorType: "script", transferSize: 0, encodedBodySize: 0, decodedBodySize: 0, responseEnd: 18, duration: 10 }],
    fetchImpl: makeHsFetch((init) => { xorigCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  for (let i = 0; i < 4; i++) {
    await new Promise((r) => setTimeout(r, 0));
    await vm.runInContext(`Promise.resolve().then(() => { function runSdk() { return window.fetch("/api/sdk", { method: "POST", body: "{}" }); } return runSdk(); });`, vmXorig.ctx, { filename: "https://cdn.other.example/sdk@2.0.js" });
    assert.ok(xorigCtx.includes("ce=0"), `Cross-origin 302-redirected script with DevTools closed MUST stay 0-FP ce=0 (got ${xorigCtx})`);
  }
  assert.equal(vmXorig.getRtCalls(), 1, `Closed-DevTools redirected fetches MUST hit O(1) cache (expected 1 RT scan, got ${vmXorig.getRtCalls()})`);

  // 10) Perf MEDIUM #3 + Security LOW: Accept-Encoding fractional q=0.5/0.8 & extensionless Sec-Fetch-Dest: image MUST block application/javascript!
  const up13 = http.createServer((req, res) => {
    if (req.url === "/jsonp-endpoint") {
      res.writeHead(200, { "Content-Type": "application/javascript" });
      res.end("callback({secret:true});");
      return;
    }
    res.writeHead(200, { "Content-Type": "image/png" });
    res.end(Buffer.from([137, 80, 78, 71]));
  });
  await new Promise((r) => up13.listen(0, "127.0.0.1", r));
  const srv13 = createProxySnareServer({ target: `http://127.0.0.1:${up13.address().port}`, mode: "strict", protectedPaths: ["*"] });
  await srv13.listen(0, "127.0.0.1");
  const p13 = srv13.server.address().port;
  const req13 = (pathStr, headers) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port: p13, method: "GET", path: pathStr, headers }, (resp) => {
        const chunks = [];
        resp.on("data", (c) => chunks.push(c));
        resp.on("end", () => resolve({ status: resp.statusCode, headers: resp.headers, buf: Buffer.concat(chunks) }));
      });
      r.on("error", reject);
      r.end();
    });
  try {
    const rQ = await req13("/__proxysnare/guard.js", makeBrowserHeaders({ "accept-encoding": "gzip;q=0.8, br;q=0.5" }));
    assert.equal(rQ.headers["content-encoding"], "br", "Fractional Accept-Encoding br;q=0.5 MUST return br!");
    const rZero = await req13("/__proxysnare/guard.js", makeBrowserHeaders({ "accept-encoding": "br;q=0, gzip;q=0.5" }));
    assert.equal(rZero.headers["content-encoding"], "gzip", "br;q=0 with gzip;q=0.5 MUST fall back to gzip!");
    const rImgJs = await req13("/jsonp-endpoint", makeBrowserHeaders({ "sec-fetch-dest": "image", "sec-fetch-site": "same-origin" }));
    assert.equal(rImgJs.status, 403, "Extensionless Sec-Fetch-Dest: image MUST reject application/javascript response!");
    const rImgOk = await req13("/_next/image", makeBrowserHeaders({ "sec-fetch-dest": "image", "sec-fetch-site": "same-origin" }));
    assert.equal(rImgOk.status, 200, "Extensionless Sec-Fetch-Dest: image MUST allow image/png response!");
  } finally {
    await srv13.close();
    await new Promise((r) => up13.close(r));
  }

  // 11) Python parity: gestureExemptPaths traversal blocked, '|' in boot_token rejected, and 8-part raw_header_lines NOT double-counted!
  execFileSync(
    "python3",
    [
      "-c",
      `import sys, time; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v = ProxySnareVerifier(mode="paranoid", protected_paths=["/api"], gesture_exempt_paths=["/api/telemetry"])
s = v.issue_session(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
assert v.issue_session(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)}, boot_token="a|b").get("error") == "INVALID_HANDSHAKE_PARAMETERS"
ts = str(int(time.time() * 1000))
ctx = "ce=0;cdp=0;ug=0;ga=999999"
pr = v.sign_request(session_key_hex=s["sessionKeyHex"], method="POST", path_with_query="/api/telemetry/../transfer", body=b"{}", seq="1", ts=ts, nonce="py-trv-01", canary=s["canary"], ctx=ctx)
r = v.inspect_request(method="POST", url="/api/telemetry/../transfer", body=b"{}", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-PS-Session": s["sessionId"], "X-PS-Seq": "1", "X-PS-Ts": ts, "X-PS-Nonce": "py-trv-01", "X-PS-Canary": s["canary"], "X-PS-Ctx": ctx, "X-PS-Proof": pr})
assert r.blocked and any(x["code"] == "MUTATION_WITHOUT_USER_GESTURE" for x in r.reasons), f"Python traversal bypass: {r.reasons}"
ov8 = "/p1,/p2,/p3,/p4,/p5,/p6,/p7,/p8"
r8 = v.inspect_request(method="GET", url="/public", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "X-Original-URL": ov8}, raw_header_lines=["User-Agent: " + ${JSON.stringify(CHROME_UA)}, f"X-Original-URL: {ov8}"])
assert not r8.blocked, f"8-part X-Original-URL with raw_header_lines MUST NOT double-count over cap=16: {r8.reasons}"`,
    ],
    { encoding: "utf8" }
  );
});

test("25. Pass-14 Audit Regressions: Error.prototype.name & guardMarker fn-name stack spoofing blocked, String/Math/Uint8Array/Int32Array tamper defenses, multi-worker OPTIONS+X-PS-Session & onDetect on distributed nonce replay, synchronous passive-click TTL across handshake RTT, RFC 9111 no-store+Expires:0, TAO-masked CORS module redirect & pre-DevTools cache, single startup iframe & balanced guardHash skip, parseHttpOriginHost & expired nonce parity, Python 18-comma cap & lock-free gesture path", async () => {
  const { parseHttpOriginHost } = require("../src/detector.js");
  const { buildBrowserGateScript } = require("../../veilbreak/src/browser-sdk.js");

  const eng14 = createProxySnareEngine({
    mode: "strict",
    protectedPaths: ["/api"],
    handshakePowBits: 0,
    requireGuardIntegrity: true,
    secret: "pass14-regression-secret-32bytes!",
  });

  // Helper VM for Pass-14 browser-guard regressions
  const makeVm14 = ({
    guardOpts = {},
    rtEntries = [],
    initScripts = [],
    cdpOpenRef = { v: false },
    nowRef = { v: 1000 },
    fetchImpl = null,
    preLoadHook = null,
  } = {}) => {
    const src = buildBrowserGuardScript({
      basePath: "/__proxysnare",
      protectedRules: ["/api"],
      serverVerifyPubB64: eng14.serverVerifyPubB64,
      allowDevTools: false,
      blockCdpActive: true,
      blockConsoleEval: true,
      requireGuardIntegrity: true,
      ...guardOpts,
    });
    const { guardHash: expHash } = computeGuardIntegrity(src);
    const sp = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const sMethods = ["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "verify", "sign", "digest"];
    const origEncode = TextEncoder.prototype.encode;
    const origHdrSet = Headers.prototype.set;
    const origHdrGet = Headers.prototype.get;
    const origHdrHas = Headers.prototype.has;
    const origRespJson = Response.prototype.json;
    class VmTextEncoder extends TextEncoder {}
    VmTextEncoder.prototype.encode = origEncode;
    class VmHeaders extends Headers {}
    VmHeaders.prototype.set = origHdrSet;
    VmHeaders.prototype.get = origHdrGet;
    VmHeaders.prototype.has = origHdrHas;
    class VmResponse extends Response {}
    VmResponse.prototype.json = origRespJson;
    let iframeCount = 0;
    const listeners = {};
    class VmPerformance {
      now() { return nowRef.v; }
      getEntriesByType(t) { return t === "resource" ? rtEntries : []; }
    }
    const vmFetch = fetchImpl
      ? function fetch(u, init) { return fetchImpl(u, init, VmResponse); }
      : async function fetch() { return new VmResponse("{}"); };
    const vmConsole = {
      debug: function debug(x) { if (cdpOpenRef.v && x && typeof x === "object") void x.stack; },
      table: function table() {},
      clear: function clear() {},
      log: function log() {},
    };
    const nativeRefs = new Set([
      ...sMethods.map((m) => sp[m]),
      VmTextEncoder.prototype.encode,
      VmHeaders.prototype.set,
      VmHeaders.prototype.get,
      VmHeaders.prototype.has,
      VmResponse.prototype.json,
      VmPerformance.prototype.getEntriesByType,
      vmFetch,
      crypto.webcrypto.getRandomValues,
      vmConsole.debug,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "get isTrusted", "webdriver", "platform", "userAgent", "toDataURL", "getImageData", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        return globalThis;
      })();`,
      ifrCtx
    );
    class HTMLIFrameElement { constructor() { this.style = {}; } get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node {
      constructor() { super(); this.style = {}; }
      getAttribute() { return null; }
      remove() {}
      get offsetWidth() { return 100; }
      closest() { return this.tagName === "BUTTON" ? this : null; }
      getClientRects() { return [this.getBoundingClientRect()]; }
      getBoundingClientRect() { return { left: 10, top: 10, right: 90, bottom: 40, width: 80, height: 30 }; }
    }
    class Document extends Node {
      constructor() {
        super();
        this.currentScript = null;
        this.baseURI = "https://app.example/";
        this.readyState = "complete";
        this._el = new Element();
        this.body = new Element();
        this.location = { href: "https://app.example/" };
      }
      get documentElement() { return this._el; }
      createElement(t) {
        if (t === "iframe") { iframeCount++; return new HTMLIFrameElement(); }
        if (t === "canvas") return { width: 32, height: 32, getContext() { return null; } };
        return new Element();
      }
      querySelectorAll() { return []; }
      querySelector() { return null; }
      addEventListener() {}
    }
    const VmEvent = class Event { constructor(t, trusted) { this.type = t; this._tr = trusted; } get isTrusted() { return this._tr; } }
    class VmNavigator {}
    Object.defineProperty(VmNavigator.prototype, "webdriver", { get: function webdriver() { return false; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "platform", { get: function platform() { return "Linux x86_64"; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "userAgent", { get: function userAgent() { return CHROME_UA; }, configurable: true });
    const navInst = Object.create(VmNavigator.prototype);
    navInst.hardwareConcurrency = 8;
    navInst.maxTouchPoints = 0;
    const ctx = vm.createContext({
      crypto: crypto.webcrypto,
      SubtleCrypto: sp.constructor,
      TextEncoder: VmTextEncoder,
      TextDecoder,
      Headers: VmHeaders,
      Response: VmResponse,
      Performance: VmPerformance,
      Event: VmEvent,
      Navigator: VmNavigator,
      HTMLCanvasElement: { prototype: { toDataURL: function toDataURL() { return ""; } } },
      CanvasRenderingContext2D: { prototype: { getImageData: function getImageData() { return { data: [] }; } } },
      URL, URLSearchParams, Request, console: vmConsole, setTimeout, clearTimeout,
      performance: new VmPerformance(),
      screen: { width: 1440, height: 900, availWidth: 1440, availHeight: 860 },
      innerWidth: 1200, innerHeight: 800, outerWidth: 1200, outerHeight: 880, devicePixelRatio: 1, screenX: 10, screenY: 10,
      navigator: navInst,
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement,
      location: { origin: "https://app.example", href: "https://app.example/" },
      fetch: vmFetch,
      addEventListener(ev, fn) { (listeners[ev] ||= []).push(fn); },
      getComputedStyle: () => ({ display: "block", visibility: "visible", opacity: "1" }),
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "get isTrusted", "webdriver", "platform", "userAgent", "toDataURL", "getImageData", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, src, expHash, listeners, getIframeCount: () => iframeCount, VmEvent, Element };
  };

  const makeHsFetch14 = (onApi, { onHandshake = null, hsDelayHook = null } = {}) => async (url, init, VmResponse) => {
    if (String(url).endsWith("/__proxysnare/boot")) {
      return new VmResponse(JSON.stringify(eng14.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (String(url).endsWith("/__proxysnare/handshake")) {
      if (hsDelayHook) hsDelayHook();
      const body = JSON.parse(init.body);
      if (onHandshake) onHandshake(body);
      const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|${body.browserProof?.d || ""}`).digest("hex");
      const s = eng14.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
      return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (onApi) onApi(init);
    return new VmResponse("{}", { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "b".repeat(32) } });
  };

  // 1) HIGH #2: Error.prototype.name/message frame injection AND function named "/__proxysnare/guard.js" CANNOT bypass ce=1!
  let spoofCtx = "";
  const vmSpoof = makeVm14({
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 200 }],
    fetchImpl: makeHsFetch14((init) => { spoofCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`
    Error.prototype.name = "Error\\n    at legit (https://app.example/app.js:1:1)";
    Error.prototype.message = "\\n    at legit2 (https://app.example/app.js:1:1)";
    const evilObj = { ["/__proxysnare/guard.js"]() { return window.fetch("/api/spoof", { method: "POST", body: "{}" }); } };
    evilObj["/__proxysnare/guard.js"]();
  `, vmSpoof.ctx, { filename: "<anonymous>" });
  assert.ok(spoofCtx.includes("ce=1"), `Error.prototype.name + guardMarker fn-name spoofing MUST be caught as ce=1 (got ${spoofCtx})`);

  // 2) HIGH #3: Pre-load & post-load String, Math.round, Uint8Array, Int32Array hooks MUST fail closed; zero DataView/Int16Array usage!
  const cleanVm = makeVm14();
  assert.equal(cleanVm.ctx.ProxySnare.guardHash(), cleanVm.expHash, "In-place UTF-8 sha256WsHexSync MUST match computeGuardIntegrity byte-for-byte!");
  assert.ok(!/\bnew\s+(?:DataView|Int16Array)\b/.test(cleanVm.src), "browser-guard.js MUST NOT construct unverified DataView or Int16Array!");
  for (const [label, hook] of [
    ["String", `window.String = function String(x) { return ""; };`],
    ["Math.round", `Math.round = () => 0;`],
    ["Uint8Array", `window.Uint8Array = function Uint8Array() { return []; };`],
    ["Int32Array", `window.Int32Array = function Int32Array() { return []; };`],
  ]) {
    const vPre = makeVm14({ preLoadHook: hook });
    assert.equal(vPre.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", `Pre-load ${label} hook MUST return TAMPERED_GUARD!`);
    const vPost = makeVm14();
    vm.runInContext(hook, vPost.ctx);
    assert.equal(vPost.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", `Post-load ${label} hook MUST return TAMPERED_GUARD!`);
  }

  // 3) MEDIUM #12: Unified embedded bundle spawns ONLY 1 startup iframe total (shared with VeilBreak), and requireGuardIntegrity:false skips 212KB hash on handshake!
  const embVb = buildBrowserGateScript({ defaultMode: "strict", unified: true, embedded: true, includeTicketPow: false });
  let balHsBody = null;
  const vmUni14 = makeVm14({
    guardOpts: { requireVeilBreak: true, embeddedVeilBreakScript: embVb, requireGuardIntegrity: false },
    fetchImpl: makeHsFetch14(null, { onHandshake: (b) => { balHsBody = b; } }),
  });
  assert.equal(vmUni14.getIframeCount(), 0, `Unified embedded bundle MUST defer iframe off synchronous <head> parsing (got ${vmUni14.getIframeCount()})`);
  await vmUni14.ctx.ProxySnare.ready();
  assert.equal(vmUni14.getIframeCount(), 1, `Unified embedded bundle MUST spawn exactly 1 startup iframe total on cold boot (got ${vmUni14.getIframeCount()})`);
  assert.equal(balHsBody && balHsBody.guardHash, "UNPINNED_OK", "requireGuardIntegrity:false MUST skip 212KB startup source hash in handshake!");
  assert.equal(vmUni14.ctx.ProxySnare.guardHash(), vmUni14.expHash, "Explicit ProxySnare.guardHash() MUST still compute exact hash!");

  // 4) MEDIUM #6 (Security + Availability): Passive untrusted .click() TTL (250ms) frozen synchronously at fetch() invocation across >350ms handshake RTT!
  const nowClick = { v: 1000 };
  let clickCtx = "";
  const vmClickRtt = makeVm14({
    nowRef: nowClick,
    guardOpts: { requireVeilBreak: true, embeddedVeilBreakScript: embVb },
    fetchImpl: makeHsFetch14((init) => { clickCtx = init.headers.get("X-PS-Ctx") || ""; }, {
      hsDelayHook: () => { nowClick.v += 400; }, // 400ms handshake RTT exceeds 250ms click TTL!
    }),
  });
  const btn14 = new vmClickRtt.Element();
  btn14.tagName = "BUTTON";
  const evU = new vmClickRtt.VmEvent("click", false);
  evU.target = btn14;
  evU.clientX = 50;
  evU.clientY = 25;
  for (const fn of vmClickRtt.listeners.click || []) fn(evU);
  nowClick.v = 1100; // 100ms after untrusted click (< 250ms)
  await vm.runInContext(`function appPay() { return window.fetch("/api/pay", { method: "POST", body: "{}" }); } appPay();`, vmClickRtt.ctx, { filename: "https://app.example/app.js" });
  assert.ok(clickCtx.includes("ik=1"), `Passive untrusted click frozen at callMono MUST survive 400ms handshake RTT (got ${clickCtx})`);
  nowClick.v = 1600; // well past 250ms TTL -> unrelated fetch MUST stay ik=0
  await vm.runInContext(`function appPing() { return window.fetch("/api/ping", { method: "GET" }); } appPing();`, vmClickRtt.ctx, { filename: "https://app.example/app.js" });
  assert.ok(!clickCtx.includes("ik=1"), `Fetch initiated >250ms after passive untrusted click MUST stay 0-FP (got ${clickCtx})`);

  // 5) MEDIUM #8 (Availability): Cross-origin 302-redirected CORS <script type="module"> without TAO (transferSize:0, responseStart:0, decodedBodySize:500, responseEnd:15) stays 0-FP AND pre-DevTools redirect cache survives opening DevTools under strict+blockCdpActive:false!
  const cdpToggle = { v: false };
  let modCtx = "";
  const vmCorsMod = makeVm14({
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    cdpOpenRef: cdpToggle,
    rtEntries: [{ name: "https://app.example/mod/entry.mjs", initiatorType: "script", transferSize: 0, encodedBodySize: 0, decodedBodySize: 500, responseStart: 0, responseEnd: 15, duration: 12 }],
    fetchImpl: makeHsFetch14((init) => { modCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await new Promise((r) => setTimeout(r, 0));
  await vm.runInContext(`Promise.resolve().then(() => { function runMod() { return window.fetch("/api/m1", { method: "POST", body: "{}" }); } return runMod(); });`, vmCorsMod.ctx, { filename: "https://cdn.other.example/entry@3.mjs" });
  assert.ok(modCtx.includes("ce=0"), `TAO-masked CORS module 302 redirect MUST stay 0-FP ce=0 (got ${modCtx})`);
  cdpToggle.v = true; // User opens DevTools AFTER module already loaded!
  await new Promise((r) => setTimeout(r, 0));
  await vm.runInContext(`Promise.resolve().then(() => { function runMod2() { return window.fetch("/api/m2", { method: "POST", body: "{}" }); } return runMod2(); });`, vmCorsMod.ctx, { filename: "https://cdn.other.example/entry@3.mjs" });
  assert.ok(modCtx.includes("ce=0"), `Pre-DevTools verified redirect cache MUST remain valid when DevTools opens under strict+blockCdpActive:false (got ${modCtx})`);

  // 6) MEDIUM #5 (Security): Multi-worker extStore: cross-origin OPTIONS carrying X-PS-Session MUST NOT bypass extStore/nonce-claim, AND distributed nonce replay MUST fire onDetect!
  const dMap14 = new Map();
  let sessBarrierWaiter = null;
  let sessGets = 0;
  const dStore14 = {
    async get(k) {
      if (k.startsWith("ps:sess:")) {
        const snap = dMap14.get(k);
        sessGets++;
        if (sessGets === 1) {
          await new Promise((r) => { sessBarrierWaiter = r; });
        } else if (sessGets === 2 && sessBarrierWaiter) {
          const release = sessBarrierWaiter;
          sessBarrierWaiter = null;
          release();
        }
        return snap;
      }
      return dMap14.get(k);
    },
    async set(k, v) { dMap14.set(k, v); },
    async setIfNotExists(k, v) { if (dMap14.has(k)) return false; dMap14.set(k, v); return true; },
  };
  const sec14 = "pass14-cluster-shared-secret-32b!";
  const detectEvents = [];
  const mw14A = createProxySnareMiddleware({ mode: "strict", secret: sec14, store: dStore14, protectedPaths: ["/api"], onDetect: (ev) => detectEvents.push(ev) });
  const mw14B = createProxySnareMiddleware({ mode: "strict", secret: sec14, store: dStore14, protectedPaths: ["/api"], onDetect: (ev) => detectEvents.push(ev) });
  const s14A = http.createServer(async (req, res) => { if (!(await mw14A(req, res))) { res.writeHead(200); res.end("A"); } });
  const s14B = http.createServer(async (req, res) => { if (!(await mw14B(req, res))) { res.writeHead(200); res.end("B"); } });
  await Promise.all([new Promise((r) => s14A.listen(0, "127.0.0.1", r)), new Promise((r) => s14B.listen(0, "127.0.0.1", r))]);
  try {
    const uA = `http://127.0.0.1:${s14A.address().port}`;
    const uB = `http://127.0.0.1:${s14B.address().port}`;
    const { hs, sessionKeyHex } = await performBrowserEcdhHandshake(uA);
    const tsO = String(Date.now());
    const prO = mw14A.engine.signRequest({
      sessionKeyHex, method: "OPTIONS", pathWithQuery: "/api/opt", body: "", seq: "1", ts: tsO, nonce: "opt-dist-nonce-1", canary: hs.canary,
    });
    const optHdrs = makeBrowserHeaders({
      Origin: "https://other.example",
      "Access-Control-Request-Method": "POST",
      "Sec-Fetch-Mode": "cors",
      "X-PS-Session": hs.sessionId,
      "X-PS-Seq": "1",
      "X-PS-Ts": tsO,
      "X-PS-Nonce": "opt-dist-nonce-1",
      "X-PS-Canary": hs.canary,
      "X-PS-Proof": prO,
    });
    const [roA, roB] = await Promise.all([
      fetch(`${uA}/api/opt`, { method: "OPTIONS", headers: optHdrs }),
      fetch(`${uB}/api/opt`, { method: "OPTIONS", headers: optHdrs }),
    ]);
    assert.deepEqual([roA.status, roB.status].sort(), [200, 403], "Header-augmented OPTIONS across workers MUST enforce distributed nonce claim (one 200, one 403)!");
    assert.ok(
      detectEvents.some((e) => e.blocked && e.reasons.some((r) => r.code === "REPEATER_NONCE_REPLAYED")),
      "Distributed nonce replay MUST invoke options.onDetect with REPEATER_NONCE_REPLAYED!"
    );
  } finally {
    await Promise.all([new Promise((r) => s14A.close(r)), new Promise((r) => s14B.close(r))]);
  }

  // 7) MEDIUM #7 (Availability): createProxySnareServer preserves Cache-Control: no-store + Expires: 0 AND unmodified HTML ETag/Last-Modified!
  const up14 = http.createServer((req, res) => {
    if (req.url === "/nostore") {
      res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "no-store", Expires: "0" });
      res.end("<!doctype html><html><head></head><body>secret</body></html>");
      return;
    }
    if (req.url === "/already") {
      res.writeHead(200, { "Content-Type": "text/html", "Cache-Control": "private, max-age=300", ETag: '"ps-etag"', "Last-Modified": "Wed, 21 Oct 2015 07:28:00 GMT" });
      res.end('<!doctype html><html><head><script src="/__proxysnare/guard.js"></script></head><body>ok</body></html>');
      return;
    }
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ok");
  });
  await new Promise((r) => up14.listen(0, "127.0.0.1", r));
  const srv14 = createProxySnareServer({ target: `http://127.0.0.1:${up14.address().port}`, mode: "strict", protectedPaths: ["/api"] });
  await srv14.listen(0, "127.0.0.1");
  const p14 = srv14.server.address().port;
  const rawReq14 = (method, reqPath, headers) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port: p14, method, path: reqPath, headers }, (resp) => {
        let d = "";
        resp.on("data", (c) => (d += c));
        resp.on("end", () => resolve({ status: resp.statusCode, headers: resp.headers, body: d }));
      });
      r.on("error", reject);
      r.end();
    });
  try {
    // POST returning HTML (htmlBoot === null) with Cache-Control: no-store + Expires: 0 MUST preserve no-store (NOT downgrade to private, no-cache!)
    const rNs = await rawReq14("POST", "/nostore", makeBrowserHeaders({ accept: "text/html" }));
    assert.equal(rNs.status, 200);
    assert.equal(rNs.headers["cache-control"], "no-store", "Cache-Control: no-store + Expires: 0 MUST NOT be downgraded to private, no-cache!");
    const rAlr = await rawReq14("GET", "/already", makeBrowserHeaders({ accept: "text/html" }));
    assert.equal(rAlr.status, 200);
    assert.equal(rAlr.headers["etag"], '"ps-etag"', "Unmodified HTML already containing guard.js MUST preserve ETag!");
    assert.equal(rAlr.headers["last-modified"], "Wed, 21 Oct 2015 07:28:00 GMT", "Unmodified HTML MUST preserve Last-Modified!");
    assert.equal(rAlr.headers["cache-control"], "private, max-age=300", "Unmodified HTML MUST preserve Cache-Control!");
  } finally {
    await srv14.close();
    await new Promise((r) => up14.close(r));
  }

  // 8) LOW #15 + HIGH #4: parseHttpOriginHost strict scheme, expired-but-unpruned nonce rehandshakeRecommended parity, and Python 18-comma cap + OPTIONS+X-PS-Session + wildcard short-circuit!
  assert.equal(parseHttpOriginHost("http:example.com"), "", "parseHttpOriginHost MUST reject scheme-relative http:example.com");
  assert.equal(parseHttpOriginHost("http:///example.com"), "", "parseHttpOriginHost MUST reject triple-slash http:///example.com");
  assert.equal(parseHttpOriginHost("https://example.com:443"), "example.com");

  const engExp = createProxySnareEngine({ mode: "strict", nonceTtlMs: 1000, protectedPaths: ["/api"] });
  const sExp = engExp.issueSession({ ip: "1.1.1.1", userAgent: CHROME_UA });
  const t0 = 1_700_000_000_000;
  const p1 = engExp.signRequest({ sessionKeyHex: sExp.sessionKeyHex, method: "GET", pathWithQuery: "/api/a", body: "", seq: "1", ts: String(t0), nonce: "exp-nonce-01", canary: sExp.canary });
  const r1 = engExp.inspectRequest({
    method: "GET", url: "/api/a", ip: "1.1.1.1", now: t0,
    headers: makeBrowserHeaders({ "x-ps-session": sExp.sessionId, "x-ps-seq": "1", "x-ps-ts": String(t0), "x-ps-nonce": "exp-nonce-01", "x-ps-canary": sExp.canary, "x-ps-proof": p1 }),
  });
  assert.equal(r1.blocked, false);
  const t2 = t0 + 2000; // nonce expired (> 1000ms) but unpruned in Map; IP roamed to 2.2.2.2
  const p2 = engExp.signRequest({ sessionKeyHex: sExp.sessionKeyHex, method: "GET", pathWithQuery: "/api/a", body: "", seq: "2", ts: String(t2), nonce: "exp-nonce-01", canary: r1.nextCanary });
  const r2 = engExp.inspectRequest({
    method: "GET", url: "/api/a", ip: "2.2.2.2", now: t2,
    headers: makeBrowserHeaders({ "x-ps-session": sExp.sessionId, "x-ps-seq": "2", "x-ps-ts": String(t2), "x-ps-nonce": "exp-nonce-01", "x-ps-canary": r1.nextCanary, "x-ps-proof": p2 }),
  });
  assert.equal(r2.rehandshakeRecommended, true, "Expired-but-unpruned nonce on IP roam MUST still emit rehandshakeRecommended: true!");

  const padOv14 = "/public" + ",".repeat(18) + "/api/secret";
  const rNodePad = eng14.inspectRequest({ method: "GET", url: "/public", headers: makeBrowserHeaders({ "x-original-url": padOv14 }) });
  assert.equal(rNodePad.blocked, true, "Node 18-comma X-Original-URL padding bypass MUST be blocked!");
  assert.ok(rNodePad.reasons.some((r) => r.code === "PROXY_PATH_OVERRIDE_HEADER"));

  execFileSync(
    "python3",
    [
      "-c",
      `import sys, time; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v = ProxySnareVerifier(mode="strict", protected_paths=["/api"])
r_pad = v.inspect_request(method="GET", url="/public", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "X-Original-URL": ${JSON.stringify(padOv14)}})
assert r_pad.blocked and any(x["code"] == "PROXY_PATH_OVERRIDE_HEADER" for x in r_pad.reasons), f"Python 18-comma bypass failed: {r_pad.reasons}"
# OPTIONS carrying X-PS-Session MUST NOT be exempted as CORS preflight!
r_opt = v.inspect_request(method="OPTIONS", url="/api/x", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Host": "app.example", "Origin": "https://other.example", "Access-Control-Request-Method": "POST", "Sec-Fetch-Mode": "cors", "X-PS-Session": "a"*32})
assert r_opt.blocked, f"Python OPTIONS with X-PS-Session MUST NOT be exempted as CORS preflight: {r_opt}"
# Wildcard protected_paths=["*"] O(1) match_all!
vw = ProxySnareVerifier(mode="strict", protected_paths=["*"])
assert vw._protected_match_all is True and vw.is_path_protected("/anything/at/all")`,
    ],
    { encoding: "utf8" }
  );
});

test("26. Pass-15 Audit Regressions: Safari 17.2+/iOS 17.2+ JSC Error.stackTraceLimit 0-FP, performance.now/Date.now & String.prototype & RegExp[Symbol.replace] defenses, clearResourceTimings & history.replaceState bypass fixes, 302-redirect Alpine eval & strict+blockCdpActive:false 0-FP, unified strict 1-iframe TDZ fix, guard.js depth-2 cap, null interactionSnap no-FP, verifyHandshakeSignature '|' validation (JS+Python), balanced zero-CDP-poll, zero-gesture ug=0, strict HTML MIME essence & RFC 9111 field-qualified Cache-Control", async () => {
  const { buildBrowserGateScript } = require("../../veilbreak/src/browser-sdk.js");

  const eng15 = createProxySnareEngine({
    mode: "strict",
    protectedPaths: ["/api"],
    handshakePowBits: 0,
    requireGuardIntegrity: true,
    secret: "pass15-regression-secret-32bytes!",
  });

  const makeVm15 = ({
    guardOpts = {},
    rtEntries = [],
    initScripts = [],
    cdpOpenRef = { v: false },
    nowRef = { v: 1000 },
    fetchImpl = null,
    preLoadHook = null,
    safari172Jsc = false,
    onConsoleDebug = null,
  } = {}) => {
    const src = buildBrowserGuardScript({
      basePath: "/__proxysnare",
      protectedRules: ["/api"],
      serverVerifyPubB64: eng15.serverVerifyPubB64,
      allowDevTools: false,
      blockCdpActive: true,
      blockConsoleEval: true,
      requireGuardIntegrity: true,
      ...guardOpts,
    });
    const { guardHash: expHash } = computeGuardIntegrity(src);
    const sp = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const sMethods = ["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "verify", "sign", "digest"];
    const origEncode = TextEncoder.prototype.encode;
    const origHdrSet = Headers.prototype.set;
    const origHdrGet = Headers.prototype.get;
    const origHdrHas = Headers.prototype.has;
    const origRespJson = Response.prototype.json;
    class VmTextEncoder extends TextEncoder {}
    VmTextEncoder.prototype.encode = origEncode;
    class VmHeaders extends Headers {}
    VmHeaders.prototype.set = origHdrSet;
    VmHeaders.prototype.get = origHdrGet;
    VmHeaders.prototype.has = origHdrHas;
    class VmResponse extends Response {}
    VmResponse.prototype.json = origRespJson;
    let iframeCount = 0;
    const listeners = {};
    let currentRt = rtEntries;
    class VmPerformance {
      now() { return nowRef.v; }
      getEntriesByType(t) { return t === "resource" ? currentRt : []; }
      clearResourceTimings() { currentRt = []; }
    }
    const vmFetch = fetchImpl
      ? function fetch(u, init) { return fetchImpl(u, init, VmResponse); }
      : async function fetch() { return new VmResponse("{}"); };
    const vmConsole = {
      debug: function debug(x) {
        if (onConsoleDebug) onConsoleDebug();
        if (cdpOpenRef.v && x && typeof x === "object") void x.stack;
      },
      table: function table() {},
      clear: function clear() {},
      log: function log() {},
    };
    const nativeRefs = new Set([
      ...sMethods.map((m) => sp[m]),
      VmTextEncoder.prototype.encode,
      VmHeaders.prototype.set,
      VmHeaders.prototype.get,
      VmHeaders.prototype.has,
      VmResponse.prototype.json,
      VmPerformance.prototype.getEntriesByType,
      VmPerformance.prototype.now,
      vmFetch,
      crypto.webcrypto.getRandomValues,
      vmConsole.debug,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "get isTrusted", "webdriver", "platform", "userAgent", "toDataURL", "getImageData", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader", "stack", "get stack"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        ${safari172Jsc ? 'Object.defineProperty(Error.prototype, "stack", { configurable: true, get: function stack() { return ""; } });' : ""}
        return globalThis;
      })();`,
      ifrCtx
    );
    class HTMLIFrameElement { constructor() { this.style = {}; } get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node {
      constructor(attrs = null) { super(); this.style = {}; this._attrs = attrs; }
      getAttribute(k) { return this._attrs && k in this._attrs ? this._attrs[k] : null; }
      remove() {}
      get offsetWidth() { return 100; }
      closest() { return this.tagName === "BUTTON" ? this : null; }
      getClientRects() { return [this.getBoundingClientRect()]; }
      getBoundingClientRect() { return { left: 10, top: 10, right: 90, bottom: 40, width: 80, height: 30 }; }
    }
    const locObj = { origin: "https://app.example", href: "https://app.example/" };
    class Document extends Node {
      constructor() {
        super();
        this.currentScript = null;
        this.baseURI = "https://app.example/";
        this.readyState = "complete";
        this._el = new Element();
        this.body = new Element();
        this.location = locObj;
      }
      get documentElement() { return this._el; }
      createElement(t) {
        if (t === "iframe") { iframeCount++; return new HTMLIFrameElement(); }
        if (t === "canvas") return { width: 32, height: 32, getContext() { return null; } };
        return new Element();
      }
      querySelectorAll(sel) {
        if (sel.includes("script[src]") && initScripts.length) return initScripts.map((s) => new Element({ src: s }));
        return [];
      }
      querySelector() { return null; }
      addEventListener() {}
    }
    const VmEvent = class Event { constructor(t, tr) { this.type = t; this._tr = tr; } get isTrusted() { return this._tr; } }
    class VmNavigator {}
    Object.defineProperty(VmNavigator.prototype, "webdriver", { get: function webdriver() { return false; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "platform", { get: function platform() { return "Linux x86_64"; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "userAgent", { get: function userAgent() { return CHROME_UA; }, configurable: true });
    const navInst = Object.create(VmNavigator.prototype);
    navInst.hardwareConcurrency = 8;
    navInst.maxTouchPoints = 0;
    const ctx = vm.createContext({
      crypto: crypto.webcrypto,
      SubtleCrypto: sp.constructor,
      TextEncoder: VmTextEncoder,
      TextDecoder,
      Headers: VmHeaders,
      Response: VmResponse,
      Performance: VmPerformance,
      PerformanceObserver: class PerformanceObserver { observe() {} },
      Event: VmEvent,
      Navigator: VmNavigator,
      HTMLCanvasElement: { prototype: { toDataURL: function toDataURL() { return ""; } } },
      CanvasRenderingContext2D: { prototype: { getImageData: function getImageData() { return { data: [] }; } } },
      URL, URLSearchParams, Request, console: vmConsole, setTimeout, clearTimeout,
      performance: new VmPerformance(),
      screen: { width: 1440, height: 900, availWidth: 1440, availHeight: 860 },
      innerWidth: 1200, innerHeight: 800, outerWidth: 1200, outerHeight: 880, devicePixelRatio: 1, screenX: 10, screenY: 10,
      navigator: navInst,
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement,
      location: locObj,
      fetch: vmFetch,
      addEventListener(ev, fn) { (listeners[ev] ||= []).push(fn); },
      getComputedStyle: () => ({ display: "block", visibility: "visible", opacity: "1" }),
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "get isTrusted", "webdriver", "platform", "userAgent", "toDataURL", "getImageData", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader", "stack", "get stack"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (safari172Jsc) {
      // Simulate WebKit / JavaScriptCore 17.2+: numeric Error.stackTraceLimit === 100 AND Error.prototype.stack formats JSC frames WITHOUT leading "Error" line!
      vm.runInContext(`
        Error.stackTraceLimit = 100;
        const origErr = Error;
        Object.defineProperty(Error.prototype, "stack", {
          configurable: true,
          get: function stack() {
            return "captureConsoleEvalFlag@https://app.example/__proxysnare/guard.js:1:1\\nproxySnareFetch@https://app.example/__proxysnare/guard.js:2:1\\nappHandler@https://app.example/app.js:10:5";
          }
        });
      `, ctx);
    }
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, src, expHash, listeners, locObj, getIframeCount: () => iframeCount, VmEvent, Element };
  };

  const makeHsFetch15 = (onApi, { onHandshake = null, hsHook = null } = {}) => async (url, init, VmResponse) => {
    if (String(url).endsWith("/__proxysnare/boot")) {
      return new VmResponse(JSON.stringify(eng15.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (String(url).endsWith("/__proxysnare/handshake")) {
      if (hsHook) hsHook();
      const body = JSON.parse(init.body);
      if (onHandshake) onHandshake(body);
      const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|${body.browserProof?.d || ""}`).digest("hex");
      const s = eng15.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
      return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (onApi) onApi(init);
    return new VmResponse("{}", { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "b".repeat(32) } });
  };

  // 1) CRITICAL #1: Safari 17.2+ / iOS 17.2+ JSC (numeric Error.stackTraceLimit === 100 without leading "Error" header) MUST stay 0-FP ce=0!
  let safCtx = "";
  const vmSaf172 = makeVm15({
    safari172Jsc: true,
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 200 }],
    fetchImpl: makeHsFetch15((init) => { safCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`window.fetch("/api/saf172", { method: "POST", body: "{}" });`, vmSaf172.ctx);
  assert.ok(safCtx.includes("ce=0"), `Safari 17.2+/iOS 17.2+ JSC stack MUST stay 0-FP ce=0 (got ${safCtx})`);

  // 2) HIGH #1 & HIGH #4: Pre-load & post-load performance.now, Date.now, String.prototype.{toLowerCase,toUpperCase,endsWith}, and RegExp.prototype[Symbol.replace] hooks MUST fail closed!
  for (const [label, hook] of [
    ["performance.now", `performance.now = () => 1000;`],
    ["Date.now", `Date.now = () => 1000;`],
    ["String.prototype.toLowerCase", `String.prototype.toLowerCase = () => "touch";`],
    ["String.prototype.toUpperCase", `String.prototype.toUpperCase = () => "GET";`],
    ["String.prototype.endsWith", `String.prototype.endsWith = () => true;`],
    ["RegExp.prototype[Symbol.replace]", `RegExp.prototype[Symbol.replace] = () => "https://app.example/app.js";`],
  ]) {
    const vPre = makeVm15({ preLoadHook: hook });
    assert.equal(vPre.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", `Pre-load ${label} hook MUST return TAMPERED_GUARD!`);
    const vPost = makeVm15();
    vm.runInContext(hook, vPost.ctx);
    assert.equal(vPost.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", `Post-load ${label} hook MUST return TAMPERED_GUARD!`);
  }

  // 3) HIGH #2: performance.clearResourceTimings() AND >=150 non-script RT entries CANNOT bypass isKnownPageScriptUrl while CDP is active!
  let clearRtCtx = "";
  const vmClearRt = makeVm15({
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    cdpOpenRef: { v: true },
    rtEntries: [],
    fetchImpl: makeHsFetch15((init) => { clearRtCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`
    performance.clearResourceTimings();
    function spoof() { return window.fetch("/api/pwn", { method: "POST", body: "{}" }); }
    spoof();
  `, vmClearRt.ctx, { filename: "https://app.example/fake.js" });
  assert.ok(clearRtCtx.includes("ce=1"), `clearResourceTimings() MUST NOT allow fake //# sourceURL while CDP is active (got ${clearRtCtx})`);

  let floodRtCtx = "";
  const floodEntries = Array.from({ length: 160 }, (_, i) => ({ name: `https://app.example/img${i}.png`, initiatorType: "img", decodedBodySize: 100 }));
  const vmFloodRt = makeVm15({
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    cdpOpenRef: { v: true },
    rtEntries: floodEntries,
    fetchImpl: makeHsFetch15((init) => { floodRtCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`
    function spoof160() { return window.fetch("/api/pwn160", { method: "POST", body: "{}" }); }
    spoof160();
  `, vmFloodRt.ctx, { filename: "https://app.example/fake160.js" });
  assert.ok(floodRtCtx.includes("ce=1"), `>=150 non-script RT entries MUST NOT allow fake //# sourceURL while CDP is active (got ${floodRtCtx})`);

  // 4) HIGH #3: Mutating document.location.href (history.replaceState) CANNOT bypass !hasInitialInlineScripts!
  let pushCtx = "";
  const vmPushLoc = makeVm15({
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    cdpOpenRef: { v: true },
    fetchImpl: makeHsFetch15((init) => { pushCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  vmPushLoc.locObj.href = "https://app.example/pwn";
  await vm.runInContext(`function pwnLoc() { return window.fetch("/api/pwnloc", { method: "POST", body: "{}" }); } pwnLoc();`, vmPushLoc.ctx, { filename: "https://app.example/pwn" });
  assert.ok(pushCtx.includes("ce=1"), `Mutated document.location.href MUST NOT satisfy isKnownPageScriptUrl or set hasVerifiedNonDocScript (got ${pushCtx})`);

  // 5) MEDIUM #5: //# sourceURL=<origin>/__proxysnare/guard.js at depth >= 2 CANNOT strip caller frames and fail open!
  let guardSpoofCtx = "";
  const vmGuardSpoof = makeVm15({
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    cdpOpenRef: { v: false },
    fetchImpl: makeHsFetch15((init) => { guardSpoofCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`function fakeGuardCaller() { return window.fetch("/api/gspoof", { method: "POST", body: "{}" }); } fakeGuardCaller();`, vmGuardSpoof.ctx, { filename: "https://app.example/__proxysnare/guard.js" });
  assert.ok(guardSpoofCtx.includes("ce=1"), `Spoofed //# sourceURL=<origin>/__proxysnare/guard.js caller MUST NOT be stripped (got ${guardSpoofCtx})`);

  // 6) HIGH Avail #2: 302-redirected CDN script with app-parented eval (DevTools closed) AND strict+blockCdpActive:false (DevTools open across reload) stay 0-FP, while Console eval stays blocked!
  let alpineCtx = "";
  const vmAlpine = makeVm15({
    initScripts: ["https://unpkg.com/alpinejs"],
    rtEntries: [{ name: "https://unpkg.com/alpinejs", initiatorType: "script", transferSize: 0, encodedBodySize: 0, decodedBodySize: 0, responseEnd: 14, duration: 10 }],
    fetchImpl: makeHsFetch15((init) => { alpineCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await new Promise((r) => setTimeout(r, 0));
  await vm.runInContext(`Promise.resolve().then(() => { function safeAsyncFunction() { return eval('window.fetch("/api/alpine", { method: "POST", body: "{}" })'); } return safeAsyncFunction(); });`, vmAlpine.ctx, { filename: "https://unpkg.com/alpinejs@3.14.1/dist/cdn.min.js" });
  assert.ok(alpineCtx.includes("ce=0"), `302-redirected Alpine.js app-parented eval with DevTools closed MUST stay 0-FP ce=0 (got ${alpineCtx})`);

  let devRedirCtx = "";
  const vmDevRedir = makeVm15({
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    cdpOpenRef: { v: true },
    rtEntries: [{ name: "https://app.example/app-latest.js", initiatorType: "script", redirectStart: 1, redirectEnd: 5, responseStatus: 200, decodedBodySize: 500, responseEnd: 18, duration: 15 }],
    fetchImpl: makeHsFetch15((init) => { devRedirCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`Promise.resolve().then(() => { function clickHandler() { return window.fetch("/api/devredir", { method: "POST", body: "{}" }); } return clickHandler(); });`, vmDevRedir.ctx, { filename: "https://app.example/assets/app.abc123.js" });
  assert.ok(devRedirCtx.includes("ce=0"), `302-redirected bundle under strict+blockCdpActive:false with DevTools open MUST stay 0-FP ce=0 (got ${devRedirCtx})`);
  await vm.runInContext(`eval('window.fetch("/api/deveval", { method: "POST", body: "{}" })');`, vmDevRedir.ctx);
  assert.ok(devRedirCtx.includes("ce=1"), `Console eval under strict+blockCdpActive:false MUST STILL be blocked ce=1 (got ${devRedirCtx})`);

  // 7) HIGH Perf #1: Unified strict (requireGuardIntegrity:true, BOTH autoBlockPage:true AND autoBlockPage:false) runs ONLY 1 total startup iframe (zero TDZ ReferenceError!) and sends exact expHash!
  for (const abp of [true, false]) {
    const embVbStrict = buildBrowserGateScript({ defaultMode: "strict", unified: true, embedded: true, autoBlockPage: abp, includeTicketPow: false });
    let strictHsBody = null;
    const vmUniStrict = makeVm15({
      guardOpts: { requireVeilBreak: true, embeddedVeilBreakScript: embVbStrict, requireGuardIntegrity: true },
      fetchImpl: makeHsFetch15(null, { onHandshake: (b) => { strictHsBody = b; } }),
    });
    await vmUniStrict.ctx.ProxySnare.ready();
    assert.equal(vmUniStrict.getIframeCount(), 1, `Unified strict (autoBlockPage=${abp}) MUST spawn ONLY 1 iframe total on cold boot (got ${vmUniStrict.getIframeCount()})`);
    assert.equal(strictHsBody && strictHsBody.guardHash, vmUniStrict.expHash, `Unified strict (autoBlockPage=${abp}) MUST send exact expHash without TDZ!`);
  }

  // 8) MEDIUM #6: Queued/cold-handshake POST with interactionSnap===null at call time MUST NOT false-positive ;ik=1 if an untrusted .click() occurs DURING the async handshake wait!
  const embVbKin = buildBrowserGateScript({ defaultMode: "strict", unified: true, embedded: true, includeTicketPow: false });
  const nowQ = { v: 1000 };
  let queuedCtx = "";
  let vmQueuedRef = null;
  const vmQueued = makeVm15({
    nowRef: nowQ,
    guardOpts: { requireVeilBreak: true, embeddedVeilBreakScript: embVbKin },
    fetchImpl: makeHsFetch15(
      (init) => { queuedCtx = init.headers.get("X-PS-Ctx") || ""; },
      {
        hsHook: () => {
          // Simulate an unrelated programmatic .click() occurring DURING the cold handshake RTT!
          nowQ.v = 1150;
          const b = new vmQueuedRef.Element();
          b.tagName = "BUTTON";
          const ev = new vmQueuedRef.VmEvent("click", false);
          ev.target = b;
          ev.clientX = 50;
          ev.clientY = 25;
          for (const fn of vmQueuedRef.listeners.click || []) fn(ev);
        },
      }
    ),
  });
  vmQueuedRef = vmQueued;
  await vm.runInContext(`function earlyPost() { return window.fetch("/api/early", { method: "POST", body: "{}" }); } earlyPost();`, vmQueued.ctx, { filename: "https://app.example/app.js" });
  assert.ok(!queuedCtx.includes("ik=1"), `Early POST with interactionSnap===null at call time MUST NOT false-positive ik=1 from later click during handshake (got ${queuedCtx})`);

  // 9) MEDIUM Perf #2 + Security LOW #2: Balanced mode skips periodic detectCdpActive() polling in buildRuntimeContextHeader(), and userGestureWindowMs >= 999_999 still emits ug=0 with zero gestures!
  let dbgCalls = 0;
  let balZeroGestCtx = "";
  const nowBal = { v: 1000 };
  const vmBal15 = makeVm15({
    nowRef: nowBal,
    guardOpts: { allowDevTools: true, blockCdpActive: false, blockConsoleEval: false, userGestureWindowMs: 2_000_000 },
    onConsoleDebug: () => { dbgCalls++; },
    fetchImpl: makeHsFetch15((init) => { balZeroGestCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vmBal15.ctx.ProxySnare.ready();
  const dbgAfterHs = dbgCalls;
  nowBal.v = 60_000; // jump 60s past 15s/30s CDP TTL!
  await vm.runInContext(`window.fetch("/api/bal", { method: "POST", body: "{}" });`, vmBal15.ctx);
  assert.equal(dbgCalls, dbgAfterHs, "Balanced mode MUST NOT poll detectCdpActive() in buildRuntimeContextHeader()!");
  assert.ok(balZeroGestCtx.includes("ug=0;ga=999999"), `Zero gestures MUST emit ug=0 even when userGestureWindowMs >= 999_999 (got ${balZeroGestCtx})`);

  // 10) MEDIUM #7: Node & Python verifyHandshakeSignature() MUST reject '|' field-shifting / hsBind stripping!
  const kp15 = crypto.createECDH("prime256v1");
  const cPub15 = kp15.generateKeys().toString("base64");
  const realBind = "a".repeat(64);
  const hs15 = eng15.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: cPub15, bootToken: "bt15", hsBind: realBind });
  assert.equal(
    eng15.verifyHandshakeSignature({
      sessionId: hs15.sessionId, clientPubB64: cPub15, serverPubB64: hs15.serverPubB64, saltB64: hs15.saltB64,
      bootToken: "bt15", serverNowMs: hs15.serverNowMs, canary: hs15.canary, hsBind: realBind, serverSigB64: hs15.serverSigB64,
    }),
    true
  );
  assert.equal(
    eng15.verifyHandshakeSignature({
      sessionId: hs15.sessionId, clientPubB64: cPub15, serverPubB64: hs15.serverPubB64, saltB64: hs15.saltB64,
      bootToken: "bt15", serverNowMs: hs15.serverNowMs, canary: `${hs15.canary}|${realBind}`, hsBind: "", serverSigB64: hs15.serverSigB64,
    }),
    false,
    "Node verifyHandshakeSignature MUST reject '|' in canary stripping hsBind!"
  );
  assert.equal(
    eng15.verifyHandshakeSignature({
      sessionId: `${hs15.sessionId}|${cPub15}`, clientPubB64: hs15.serverPubB64, serverPubB64: hs15.saltB64, saltB64: "bt15",
      bootToken: String(hs15.serverNowMs), serverNowMs: hs15.canary, canary: realBind, hsBind: "", serverSigB64: hs15.serverSigB64,
    }),
    false,
    "Node verifyHandshakeSignature MUST reject field-shifted '|' transcript!"
  );

  execFileSync(
    "python3",
    [
      "-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v = ProxySnareVerifier(mode="strict", secret="pass15-regression-secret-32bytes!")
assert v.verify_handshake_signature(session_id=${JSON.stringify(hs15.sessionId)}, client_pub_b64=${JSON.stringify(cPub15)}, server_pub_b64=${JSON.stringify(hs15.serverPubB64)}, salt_b64=${JSON.stringify(hs15.saltB64)}, boot_token="bt15", server_now_ms=${JSON.stringify(hs15.serverNowMs)}, canary=${JSON.stringify(hs15.canary)}, hs_bind=${JSON.stringify(realBind)}, server_sig_b64=${JSON.stringify(hs15.serverSigB64)}) is True
assert v.verify_handshake_signature(session_id=${JSON.stringify(hs15.sessionId)}, client_pub_b64=${JSON.stringify(cPub15)}, server_pub_b64=${JSON.stringify(hs15.serverPubB64)}, salt_b64=${JSON.stringify(hs15.saltB64)}, boot_token="bt15", server_now_ms=${JSON.stringify(hs15.serverNowMs)}, canary=${JSON.stringify(`${hs15.canary}|${realBind}`)}, hs_bind="", server_sig_b64=${JSON.stringify(hs15.serverSigB64)}) is False, "Python MUST reject '|' in canary!"`,
    ],
    { encoding: "utf8" }
  );

  // 11) Security LOW #1 + Availability LOW #5 + MEDIUM Perf #3: Strict HTML MIME essence, RFC 9111 field-qualified Cache-Control, and dual-stack IPv4/IPv6 trustProxy!
  const up15 = http.createServer((req, res) => {
    if (req.url === "/fake-html") {
      res.writeHead(200, { "Content-Type": 'application/json; profile="https://x/text/html"' });
      res.end('{"secret":1}');
      return;
    }
    if (req.url === "/field-priv") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": 'public, max-age=600, private="Set-Cookie"' });
      res.end("<!doctype html><html><head></head><body>cdn-priv</body></html>");
      return;
    }
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ok");
  });
  await new Promise((r) => up15.listen(0, "127.0.0.1", r));
  const srv15 = createProxySnareServer({ target: `http://127.0.0.1:${up15.address().port}`, mode: "strict", protectedPaths: ["*"] });
  await srv15.listen(0, "127.0.0.1");
  const p15 = srv15.server.address().port;
  const rawGet15 = (reqPath, headers) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port: p15, method: "GET", path: reqPath, headers }, (resp) => {
        let d = "";
        resp.on("data", (c) => (d += c));
        resp.on("end", () => resolve({ status: resp.statusCode, headers: resp.headers, body: d }));
      });
      r.on("error", reject);
      r.end();
    });
  try {
    const navH = makeBrowserHeaders({ accept: "text/html", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", "sec-fetch-site": "none" });
    const rFake = await rawGet15("/fake-html", navH);
    assert.equal(rFake.status, 403, 'Non-HTML MIME with substring text/html parameter MUST be blocked 403!');
    const rFp = await rawGet15("/field-priv", navH);
    assert.equal(rFp.status, 200);
    assert.ok(!rFp.body.includes("integrity="), 'Field-qualified private="Set-Cookie" MUST stay shared-cacheable (omit SRI)!');
    assert.ok(!rFp.body.includes("data-ps-boot="), 'Field-qualified private="Set-Cookie" MUST NOT stamp per-user data-ps-boot!');
  } finally {
    await srv15.close();
    await new Promise((r) => up15.close(r));
  }

  // Dual-stack trustProxy accuracy (::ffff:-mapped IPv4 + IPv6 CIDRs)
  const tpEng15 = createProxySnareEngine({ mode: "strict", trustProxy: ["10.0.0.0/8", "2001:db8::/32", "::ffff:172.16.0.0/108"] });
  assert.equal(tpEng15.trustedProxies.has("::ffff:10.1.2.3"), true);
  assert.equal(tpEng15.trustedProxies.has("172.16.0.9"), true);
  assert.equal(tpEng15.trustedProxies.has("2001:db8::99"), true);
  assert.equal(tpEng15.trustedProxies.has("::ffff:192.168.1.1"), false);
  assert.equal(tpEng15.trustedProxies.has("2001:db9::1"), false);
});

test("27. Pass-16 Audit Regressions: window.Promise hijack & Angular ZoneAwarePromise 0-FP, captureConsoleEvalFlag deep-frame & hasUnverifiedHttpUrl, Response/XHR prototype getter capture, non-TAO cross-origin script origin lock, unified blockCdpActive precedence, Vite 700-module FIFO verifiedUrlCache, Safari empty initiatorType, frozen stackTraceLimit=20 & Array[Symbol.iterator] getter, private SWR SRI cache", async () => {
  const vm = require("node:vm");
  const { computeGuardIntegrity } = require("../src/browser-guard.js");
  const { createUnifiedMiddleware } = require("../src/unified.js");
  const eng16 = createProxySnareEngine({ mode: "strict", secret: "pass16-regression-secret-32bytes!" });

  const makeVm16 = ({ guardOpts = {}, rtEntries = [], initScripts = [], fetchImpl = null, cdpOpen = false, includeXhr = false, xhrRespond = null, poDeliver = null } = {}) => {
    const src = buildBrowserGuardScript({
      basePath: "/__proxysnare",
      protectedPaths: ["/api"],
      serverVerifyPubB64: eng16.serverVerifyPubB64,
      allowDevTools: false,
      blockCdpActive: false,
      blockConsoleEval: true,
      ...guardOpts,
    });
    const expHash = computeGuardIntegrity(src).guardHash;
    const sp = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const sMethods = ["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "verify", "sign", "digest"];
    const origTeEncode = TextEncoder.prototype.encode;
    const origHdrSet = Headers.prototype.set;
    const origHdrGet = Headers.prototype.get;
    const origHdrHas = Headers.prototype.has;
    const origRespJson = Response.prototype.json;
    class VmTextEncoder { constructor() { this._te = new TextEncoder(); } encode(s) { return origTeEncode.call(this._te, s); } }
    class VmHeaders {
      constructor(init) { this._h = new Headers(init instanceof VmHeaders ? init._h : init); }
      set(k, v) { return origHdrSet.call(this._h, k, v); }
      get(k) { return origHdrGet.call(this._h, k); }
      has(k) { return origHdrHas.call(this._h, k); }
      entries() { return this._h.entries(); }
      [Symbol.iterator]() { return this._h[Symbol.iterator](); }
    }
    class VmResponse {
      constructor(b, init = {}) {
        this._r = new Response(b, init);
        this._redir = Boolean(init.redirected);
        this._url = init.url || "";
        this._type = init.type || "basic";
      }
      json() { return origRespJson.call(this._r); }
      arrayBuffer() { return this._r.arrayBuffer(); }
      get ok() { return this._r.ok; }
      get status() { return this._r.status; }
      get headers() { return new VmHeaders(this._r.headers); }
      get redirected() { return this._redir; }
      get url() { return this._url; }
      get type() { return this._type; }
      clone() { return new VmResponse(this._r.clone(), { redirected: this._redir, url: this._url, type: this._type }); }
    }
    const VmEvent = class Event { constructor(type) { this.type = type; } }
    const VmXHR = class XMLHttpRequest {
      constructor() {
        this._rs = 0;
        this._st = 0;
        this._rUrl = "";
        this._rHdrs = {};
        this._reqHdrs = {};
        this.responseText = "";
        this.response = "";
        this.statusText = "";
      }
      get readyState() { return this._rs; }
      get status() { return this._st; }
      get responseURL() { return this._rUrl; }
      getResponseHeader(k) { return this._rHdrs[String(k || "").toLowerCase()] ?? null; }
      getAllResponseHeaders() { return ""; }
      open(m, u) { this._m = m; this._u = u; this._rs = 1; }
      setRequestHeader(k, v) { this._reqHdrs[String(k).toLowerCase()] = v; }
      overrideMimeType() {}
      abort() {}
      dispatchEvent() {}
      send(body) {
        if (xhrRespond) xhrRespond(this, body);
      }
    }
    const vmFetch = fetchImpl
      ? function fetch(u, init) { return fetchImpl(u, init, VmResponse); }
      : async function fetch() { return new VmResponse("{}"); };
    const vmConsole = {
      debug: function debug(arg) { if (cdpOpen && arg && typeof arg === "object") { try { void arg.stack; } catch (_) {} } },
      error: function error() {},
      warn: function warn() {},
    };
    const vmPerf = {
      now: function now() { return 1000; },
      getEntriesByType: function getEntriesByType(t) { return t === "resource" ? rtEntries : []; },
    };
    const nativeRefs = new Set([
      ...sMethods.map((m) => sp[m]),
      VmTextEncoder.prototype.encode,
      VmHeaders.prototype.set, VmHeaders.prototype.get, VmHeaders.prototype.has,
      VmResponse.prototype.json, VmResponse.prototype.clone, VmResponse.prototype.arrayBuffer,
      Object.getOwnPropertyDescriptor(VmResponse.prototype, "status").get,
      Object.getOwnPropertyDescriptor(VmResponse.prototype, "headers").get,
      Object.getOwnPropertyDescriptor(VmResponse.prototype, "redirected").get,
      Object.getOwnPropertyDescriptor(VmResponse.prototype, "url").get,
      Object.getOwnPropertyDescriptor(VmResponse.prototype, "type").get,
      VmXHR.prototype.open, VmXHR.prototype.send, VmXHR.prototype.setRequestHeader, VmXHR.prototype.getResponseHeader,
      Object.getOwnPropertyDescriptor(VmXHR.prototype, "readyState").get,
      Object.getOwnPropertyDescriptor(VmXHR.prototype, "status").get,
      Object.getOwnPropertyDescriptor(VmXHR.prototype, "responseURL").get,
      vmFetch, crypto.webcrypto.getRandomValues, vmPerf.getEntriesByType, vmPerf.now, vmConsole.debug,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString","createElement","appendChild","get documentElement","get contentWindow","getAttribute", "XMLHttpRequest", "Event","debug","now"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        return globalThis;
      })();`,
      ifrCtx
    );
    class HTMLIFrameElement { constructor() { this.style = {}; } get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node {
      constructor(attrs = {}) { super(); this._attrs = attrs; }
      getAttribute(k) { return this._attrs[k] ?? null; }
    }
    class Document extends Node {
      constructor() {
        super();
        this.currentScript = null;
        this.readyState = "complete";
        this.baseURI = "https://app.example/";
        this._el = new Element();
        this._scriptEls = initScripts.map((s) => new Element({ src: s }));
        this.scripts = this._scriptEls;
      }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : new Element(); }
      querySelectorAll(sel) { return String(sel).includes("script[src]") ? this._scriptEls : []; }
      querySelector() { return null; }
      addEventListener() {}
    }
    let poCb = null;
    class VmPerfObs {
      constructor(cb) { poCb = cb; }
      observe() { if (poDeliver && poCb) poDeliver(poCb); }
    }
    const ctx = vm.createContext({
      crypto: crypto.webcrypto, SubtleCrypto: sp.constructor,
      TextEncoder: VmTextEncoder, Headers: VmHeaders, Response: VmResponse,
      ...(includeXhr ? { XMLHttpRequest: VmXHR } : {}),
      Event: VmEvent, URL, URLSearchParams, Request,
      console: vmConsole, setTimeout, clearTimeout,
      performance: vmPerf, PerformanceObserver: VmPerfObs,
      navigator: { webdriver: false },
      document: new Document(), Document, Node, Element, HTMLIFrameElement,
      location: { origin: "https://app.example", href: "https://app.example/" },
      fetch: vmFetch,
      addEventListener() {},
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString","createElement","appendChild","get documentElement","get contentWindow","getAttribute", "XMLHttpRequest", "Event","now"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    vm.runInContext(src, ctx);
    return { ctx, expHash, deliverPo: (ents) => poCb && poCb({ getEntries: () => ents }) };
  };

  const makeHsFetch16 = (onApi) => async (url, init, VmResponse) => {
    if (String(url).endsWith("/__proxysnare/boot")) {
      return new VmResponse(JSON.stringify(eng16.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (String(url).endsWith("/__proxysnare/handshake")) {
      const body = JSON.parse(init.body);
      const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|${body.browserProof?.d || ""}`).digest("hex");
      const s = eng16.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
      return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (onApi) return onApi(url, init, VmResponse);
    return new VmResponse("{}", { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "a".repeat(32) } });
  };

  // 1) HIGH #1: Replacing window.Promise triggers TAMPERED_GUARD; Angular ZoneAwarePromise stays 0-FP; proxySnareXhrSend cannot be hijacked via window.Promise!
  const sentXhrs = [];
  const vmProm = makeVm16({
    includeXhr: true,
    fetchImpl: makeHsFetch16(),
    xhrRespond: (x) => {
      sentXhrs.push({ m: x._m, u: x._u });
      x._rs = 2;
      x._st = 200;
      x._rUrl = x._u;
      x._rHdrs = { "x-ps-next-canary": "b".repeat(32) };
      if (x.onreadystatechange) x.onreadystatechange();
      x._rs = 4;
      if (x.onload) x.onload();
    },
  });
  await vmProm.ctx.ProxySnare.ready();
  vm.runInContext(`
    const RealP = window.Promise;
    window.Promise = function HijackPromise(ex) {
      return new RealP((res) => res({ kind: "redirect", url: new URL("https://app.example/api/pwn"), method: "DELETE", bytes: new Uint8Array(0) }));
    };
  `, vmProm.ctx);
  assert.equal(vmProm.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", "Post-load window.Promise replacement MUST return TAMPERED_GUARD!");
  vm.runInContext(`
    const x = new XMLHttpRequest();
    x.open("GET", "/api/safe", true);
    x.send();
  `, vmProm.ctx, { filename: "https://app.example/app.js" });
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(sentXhrs.some((r) => r.u.includes("/api/pwn")), false, "Hijacked window.Promise MUST NEVER redirect proxySnareXhrSend to /api/pwn!");

  // Legitimate Angular ZoneAwarePromise stays 0-FP!
  const vmZone = makeVm16({ fetchImpl: makeHsFetch16() });
  vm.runInContext(`
    window.Zone = { current: { name: "<root>" } };
    window.__zone_symbol__Promise = window.Promise;
    window.Promise = function ZoneAwarePromise(ex) { return new window.__zone_symbol__Promise(ex); };
  `, vmZone.ctx);
  assert.equal(vmZone.ctx.ProxySnare.guardHash(), vmZone.expHash, "Angular ZoneAwarePromise MUST stay 0-FP on guardHash()!");
  assert.equal(await vmZone.ctx.ProxySnare.ready(), true, "Angular ZoneAwarePromise MUST complete handshake cleanly!");

  // 2) HIGH #2: captureConsoleEvalFlag inspects ALL frames & flags hasUnverifiedHttpUrl / disallowed webpack:// when CDP is active!
  let deepCtx = "";
  const vmDeep = makeVm16({
    cdpOpen: true,
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 200 }],
    fetchImpl: makeHsFetch16((u, init, VmResponse) => {
      deepCtx = init.headers.get("X-PS-Ctx") || "";
      return new VmResponse("{}", { status: 200, headers: { "x-ps-next-canary": "c".repeat(32) } });
    }),
  });
  vm.runInContext(`window.appHelper = function appHelper() { return window.fetch("/api/deep", { method: "POST", body: "{}" }); };`, vmDeep.ctx, { filename: "https://app.example/app.js" });
  await vm.runInContext(`function evilCaller() { return window.appHelper(); } evilCaller();`, vmDeep.ctx, { filename: "https://evil.invalid/pwn.js" });
  assert.ok(deepCtx.includes("ce=1"), `Console calling appHelper via unverified sourceURL MUST be flagged ce=1 (got ${deepCtx})`);
  let wpStrictCtx = "";
  const vmDeepWp = makeVm16({
    cdpOpen: true,
    guardOpts: { allowDevTools: false, blockCdpActive: true, blockConsoleEval: true },
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 200 }],
    fetchImpl: makeHsFetch16((u, init, VmResponse) => {
      wpStrictCtx = init.headers.get("X-PS-Ctx") || "";
      return new VmResponse("{}", { status: 200, headers: { "x-ps-next-canary": "c".repeat(32) } });
    }),
  });
  vm.runInContext(`window.appHelper = function appHelper() { return window.fetch("/api/deep", { method: "POST", body: "{}" }); };`, vmDeepWp.ctx, { filename: "https://app.example/app.js" });
  await vm.runInContext(`function evilWp() { return window.appHelper(); } evilWp();`, vmDeepWp.ctx, { filename: "webpack://evil/pwn.js" });
  assert.ok(wpStrictCtx.includes("ce=1"), `Console calling appHelper via disallowed webpack:// in strict mode MUST be flagged ce=1 (got ${wpStrictCtx})`);

  // 3) MEDIUM #3: Post-load overriding Response.prototype getters / Headers.prototype.get CANNOT hijack fetch 403-redirect retry!
  const fetchUrls = [];
  const vmRespTamper = makeVm16({
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 200 }],
    fetchImpl: makeHsFetch16((u, init, VmResponse) => {
      fetchUrls.push(String(u));
      return new VmResponse('{"ok":true}', { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "d".repeat(32) } });
    }),
  });
  await vmRespTamper.ctx.ProxySnare.ready();
  vm.runInContext(`
    Object.defineProperty(Response.prototype, "status", { get() { return 403; }, configurable: true });
    Object.defineProperty(Response.prototype, "redirected", { get() { return true; }, configurable: true });
    Object.defineProperty(Response.prototype, "url", { get() { return "https://app.example/api/pwn-target"; }, configurable: true });
    Headers.prototype.get = function(k) { return String(k).toLowerCase() === "x-ps-redirect-get" ? "1" : null; };
  `, vmRespTamper.ctx);
  await vm.runInContext(`function safeFetch() { return window.fetch("/api/safe", { method: "POST", body: "{}" }); } safeFetch();`, vmRespTamper.ctx, { filename: "https://app.example/app.js" });
  assert.equal(fetchUrls.some((u) => u.includes("/api/pwn-target")), false, "Tampered Response.prototype/Headers.prototype MUST NOT trigger 403 redirect signing to /api/pwn-target!");

  // 4) MEDIUM #4: Normal non-TAO cross-origin script MUST NOT latch hasRedirectedScriptResource, and trustedScriptOrigins MUST stay enforced when CDP is open!
  let nonTaoCtx = "";
  const vmNonTao = makeVm16({
    cdpOpen: true,
    rtEntries: [{ name: "https://analytics.thirdparty.example/tag.js", initiatorType: "script", transferSize: 0, responseStart: 0, encodedBodySize: 0, decodedBodySize: 0, responseEnd: 15, duration: 12 }],
    fetchImpl: makeHsFetch16((u, init, VmResponse) => {
      nonTaoCtx = init.headers.get("X-PS-Ctx") || "";
      return new VmResponse("{}", { status: 200, headers: { "x-ps-next-canary": "e".repeat(32) } });
    }),
  });
  await vm.runInContext(`function outer() { return (function inner() { return window.fetch("/api/x", { method: "POST", body: "{}" }); })(); } outer();`, vmNonTao.ctx, { filename: "https://evil.invalid/pwn.js" });
  assert.ok(nonTaoCtx.includes("ce=1"), `Non-TAO cross-origin analytics.js MUST NOT allow evil.invalid sourceURL (got ${nonTaoCtx})`);

  let redirOrigCtx = "";
  const vmRedirOrig = makeVm16({
    cdpOpen: true,
    rtEntries: [
      { name: "https://app.example/latest.js", initiatorType: "script", redirectStart: 1, redirectEnd: 5, responseStatus: 200, decodedBodySize: 500, responseEnd: 15, duration: 12 },
      { name: "https://evil.invalid/pwn.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 200, responseEnd: 20, duration: 5 },
    ],
    fetchImpl: makeHsFetch16((u, init, VmResponse) => {
      redirOrigCtx = init.headers.get("X-PS-Ctx") || "";
      return new VmResponse("{}", { status: 200, headers: { "x-ps-next-canary": "f".repeat(32) } });
    }),
  });
  await vm.runInContext(`Promise.resolve().then(() => { function outer() { return (function inner() { return window.fetch("/api/x2", { method: "POST", body: "{}" }); })(); } return outer(); });`, vmRedirOrig.ctx, { filename: "https://evil.invalid/pwn.js" });
  assert.ok(redirOrigCtx.includes("ce=1"), `Even with redirectEnd>0, post-load injected unknown origin evil.invalid MUST be rejected while CDP is open (got ${redirOrigCtx})`);
  await vm.runInContext(`eval('window.fetch("/api/x2b", { method: "POST", body: "{}" })\\n//# sourceURL=https://evil.invalid/pwn2.js');`, vmRedirOrig.ctx);
  assert.ok(redirOrigCtx.includes("ce=1"), `Even with redirectEnd>0, Console //# sourceURL=https://evil.invalid/pwn2.js MUST be rejected while CDP is open (got ${redirOrigCtx})`);
  await vm.runInContext(`Promise.resolve().then(() => { function outer() { return (function inner() { return window.fetch("/api/x3", { method: "POST", body: "{}" }); })(); } return outer(); });`, vmRedirOrig.ctx, { filename: "https://app.example/assets/app.hash.js" });
  assert.ok(redirOrigCtx.includes("ce=0"), `Same-origin confirmed redirect MUST remain 0-FP ce=0 (got ${redirOrigCtx})`);

  // 5) MEDIUM #5: Unified mode prioritizes explicit blockCdpActive over allowDevTools for VeilBreak!
  const uBothFalse = createUnifiedMiddleware({ mode: "strict", allowDevTools: false, blockCdpActive: false });
  assert.equal(uBothFalse.veilbreak.preset.allowDevTools, true, "unified { strict, allowDevTools:false, blockCdpActive:false } MUST set vb.allowDevTools=true!");
  assert.equal(uBothFalse.engine.blockCdpActive, false);
  assert.equal(uBothFalse.engine.blockConsoleEval, true);
  const vAllowCdp = uBothFalse.veilbreak.verifyHandshakeProof({
    headers: makeBrowserHeaders({ "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors" }),
    proof: { v: 3, ch: "ch16", s: 0, f: 0, p: "Linux x86_64", cdp: 1, wr: "", wk: 1, ms: 3, d: crypto.createHash("sha256").update("VB_HS_V3|ch16|0|0|Linux x86_64|1||1|3").digest("hex") },
    expectedChallenge: "ch16",
  });
  assert.equal(vAllowCdp.blocked, false, `unified blockCdpActive:false MUST NOT block CDP=1 handshakes in VeilBreak (reasons=${vAllowCdp.reasons})`);

  const uBalCdp = createUnifiedMiddleware({ mode: "balanced", allowDevTools: true, blockCdpActive: true });
  assert.equal(uBalCdp.veilbreak.preset.allowDevTools, false, "unified { balanced, allowDevTools:true, blockCdpActive:true } MUST set vb.allowDevTools=false!");
  const vBlockCdp = uBalCdp.veilbreak.verifyHandshakeProof({
    headers: makeBrowserHeaders({ "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors" }),
    proof: { v: 3, ch: "ch16b", s: 0, f: 0, p: "Linux x86_64", cdp: 1, wr: "", wk: 1, ms: 3, d: crypto.createHash("sha256").update("VB_HS_V3|ch16b|0|0|Linux x86_64|1||1|3").digest("hex") },
    expectedChallenge: "ch16b",
  });
  assert.equal(vBlockCdp.blocked, true, "unified balanced + blockCdpActive:true MUST block CDP=1 handshakes in VeilBreak!");

  // 6) Avail MEDIUM #2 + Perf MEDIUM #1 + Avail MEDIUM #3: Vite 700-module FIFO verifiedUrlCache (boot script pinned, non-script <link> excluded) & Safari empty initiatorType!
  let viteCtx = "";
  const vmVite = makeVm16({
    cdpOpen: true,
    initScripts: ["https://app.example/assets/boot.js"],
    rtEntries: [], // Simulates >250 RT buffer eviction!
    fetchImpl: makeHsFetch16((u, init, VmResponse) => {
      viteCtx = init.headers.get("X-PS-Ctx") || "";
      return new VmResponse("{}", { status: 200, headers: { "x-ps-next-canary": "a".repeat(32) } });
    }),
  });
  const poBatch = [];
  for (let i = 0; i < 600; i++) poBatch.push({ name: `https://app.example/style${i}.css`, initiatorType: "link", responseEnd: 5 });
  for (let i = 0; i < 600; i++) poBatch.push({ name: `https://app.example/src/mod${i}.ts`, initiatorType: "script", responseEnd: 5 });
  poBatch.push({ name: "https://app.example/chunk-safari.mjs", initiatorType: "", transferSize: 0, responseEnd: 8 });
  vmVite.deliverPo(poBatch);
  await vm.runInContext(`Promise.resolve().then(() => { function bootCall() { return window.fetch("/api/b", { method: "POST", body: "{}" }); } return bootCall(); });`, vmVite.ctx, { filename: "https://app.example/assets/boot.js" });
  assert.ok(viteCtx.includes("ce=0"), `Pinned boot.js MUST stay verified after 600 CSS + 600 TS modules (got ${viteCtx})`);
  await vm.runInContext(`Promise.resolve().then(() => { function modCall() { return window.fetch("/api/m", { method: "POST", body: "{}" }); } return modCall(); });`, vmVite.ctx, { filename: "https://app.example/src/mod10.ts" });
  assert.ok(viteCtx.includes("ce=0"), `Module #10 past old 512 wipe limit MUST stay verified in FIFO cache (got ${viteCtx})`);
  await vm.runInContext(`Promise.resolve().then(() => { function safCall() { return window.fetch("/api/s", { method: "POST", body: "{}" }); } return safCall(); });`, vmVite.ctx, { filename: "https://app.example/chunk-safari.mjs" });
  assert.ok(viteCtx.includes("ce=0"), `Safari empty initiatorType cached module MUST stay verified ce=0 (got ${viteCtx})`);

  // 7) Security LOW #6 & #7: Frozen Error.stackTraceLimit=20 caught as ce=1, AND prototype-sensitive Array.prototype[Symbol.iterator] getter caught as TAMPERED_GUARD!
  let stl20Ctx = "";
  const vmStl20 = makeVm16({
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 200 }],
    fetchImpl: makeHsFetch16((u, init, VmResponse) => {
      stl20Ctx = init.headers.get("X-PS-Ctx") || "";
      return new VmResponse("{}", { status: 200, headers: { "x-ps-next-canary": "b".repeat(32) } });
    }),
  });
  await vm.runInContext(`
    Object.defineProperty(Error, "stackTraceLimit", { value: 20, writable: false, configurable: false });
    function f20() { return window.fetch("/api/stl20", { method: "POST", body: "{}" }); }
    f20();
  `, vmStl20.ctx, { filename: "https://app.example/app.js" });
  assert.ok(stl20Ctx.includes("ce=1"), `Frozen Error.stackTraceLimit=20 (< 64) MUST be flagged ce=1 (got ${stl20Ctx})`);

  const vmArrGet = makeVm16({ fetchImpl: makeHsFetch16() });
  vm.runInContext(`
    const origIter = Array.prototype[Symbol.iterator];
    Object.defineProperty(Array.prototype, Symbol.iterator, {
      get() { return this === Array.prototype ? origIter : function* () { yield "sign"; }; },
      configurable: true,
    });
  `, vmArrGet.ctx);
  assert.equal(vmArrGet.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", "Prototype-sensitive Array.prototype[Symbol.iterator] getter MUST return TAMPERED_GUARD!");

  // 8) Availability LOW #4: Private stale-while-revalidate & s-maxage=0 + future Expires SRI HTML cache rewrite (when htmlBoot is not stamped, e.g. 201 HTML)
  const up16 = http.createServer((req, res) => {
    if (req.url === "/swr-priv") {
      res.writeHead(200, { "Content-Type": "text/html; charset=utf-8", "Cache-Control": "private, max-age=0, stale-while-revalidate=600" });
      res.end("<!doctype html><html><head></head><body>swr</body></html>");
      return;
    }
    if (req.url === "/smax0-exp") {
      res.writeHead(200, {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "private, s-maxage=0",
        Expires: new Date(Date.now() + 3600_000).toUTCString(),
      });
      res.end("<!doctype html><html><head></head><body>smax0</body></html>");
      return;
    }
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ok");
  });
  await new Promise((r) => up16.listen(0, "127.0.0.1", r));
  const srv16 = createProxySnareServer({ target: `http://127.0.0.1:${up16.address().port}`, mode: "strict", protectedPaths: ["/api"], sri: true, maxHtmlBootsPerMinPerIp: 0 });
  await srv16.listen(0, "127.0.0.1");
  const p16 = srv16.server.address().port;
  const rawPost16 = (reqPath) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port: p16, method: "POST", path: reqPath, headers: makeBrowserHeaders({ accept: "text/html" }) }, (resp) => {
        let d = "";
        resp.on("data", (c) => (d += c));
        resp.on("end", () => resolve({ status: resp.statusCode, headers: resp.headers, body: d }));
      });
      r.on("error", reject);
      r.end();
    });
  try {
    const rSwr = await rawPost16("/swr-priv");
    assert.equal(rSwr.status, 200);
    assert.ok(rSwr.body.includes("integrity="));
    assert.equal(rSwr.headers["cache-control"], "private, no-cache", "ProxySnare private stale-while-revalidate SRI HTML MUST rewrite to private, no-cache!");
    const rSmax = await rawPost16("/smax0-exp");
    assert.equal(rSmax.status, 200);
    assert.ok(rSmax.body.includes("integrity="));
    assert.equal(rSmax.headers["cache-control"], "private, no-cache", "ProxySnare private s-maxage=0 + future Expires SRI HTML MUST rewrite to private, no-cache!");
    assert.equal(rSmax.headers["expires"], undefined);
  } finally {
    await srv16.close();
    await new Promise((r) => up16.close(r));
  }
});

test("28. Pass-17 Audit Regressions: CRITICAL unified startRendering/String.replace/Object.prototype.then bypass sealed, non-HTTP sourceURL & strict+blockCdpActive:false webpack:// blocked, V8 Array.map/new Promise 0-FP, minified Angular ZoneAwarePromise 0-FP, cross-origin non-TAO CDN & strict+blockCdpActive:false 302 redirects 0-FP, lazy unified gateSri getters, and Python empty-url/OPTIONS parity", async () => {
  const vm = require("node:vm");
  const { computeGuardIntegrity } = require("../src/browser-guard.js");
  const { createUnifiedMiddleware, createUnifiedShield } = require("../src/unified.js");
  const { buildBrowserGateScript } = require("../../veilbreak/src/browser-sdk.js");
  const eng17 = createProxySnareEngine({ mode: "strict", secret: "pass17-regression-secret-32bytes!" });

  const makeVm17 = ({ guardOpts = {}, rtEntries = [], initScripts = [], fetchImpl = null, cdpOpen = false, webdriver = false, playwrightGlobal = false } = {}) => {
    const src = buildBrowserGuardScript({
      basePath: "/__proxysnare",
      protectedPaths: ["/api"],
      serverVerifyPubB64: eng17.serverVerifyPubB64,
      allowDevTools: false,
      blockCdpActive: false,
      blockConsoleEval: true,
      ...guardOpts,
    });
    const expHash = computeGuardIntegrity(src).guardHash;
    const sp = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const sMethods = ["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "verify", "sign", "digest"];
    const origTeEncode = TextEncoder.prototype.encode;
    const origHdrSet = Headers.prototype.set;
    const origHdrGet = Headers.prototype.get;
    const origHdrHas = Headers.prototype.has;
    const origRespJson = Response.prototype.json;
    class VmTextEncoder { constructor() { this._te = new TextEncoder(); } encode(s) { return origTeEncode.call(this._te, s); } }
    class VmHeaders {
      constructor(init) { this._h = new Headers(init instanceof VmHeaders ? init._h : init); }
      set(k, v) { return origHdrSet.call(this._h, k, v); }
      get(k) { return origHdrGet.call(this._h, k); }
      has(k) { return origHdrHas.call(this._h, k); }
      entries() { return this._h.entries(); }
      [Symbol.iterator]() { return this._h[Symbol.iterator](); }
    }
    class VmResponse {
      constructor(b, init = {}) {
        this._r = new Response(b, init);
        this._redir = Boolean(init.redirected);
        this._url = init.url || "";
        this._type = init.type || "basic";
      }
      json() { return origRespJson.call(this._r); }
      arrayBuffer() { return this._r.arrayBuffer(); }
      get ok() { return this._r.ok; }
      get status() { return this._r.status; }
      get headers() { return new VmHeaders(this._r.headers); }
      get redirected() { return this._redir; }
      get url() { return this._url; }
      get type() { return this._type; }
      clone() { return new VmResponse(this._r.clone(), { redirected: this._redir, url: this._url, type: this._type }); }
    }
    class VmOfflineAudioContext {
      constructor() { this.state = "running"; this.destination = {}; }
      createBuffer() { return { getChannelData: () => new Float32Array(512) }; }
      createBufferSource() { return { connect() {}, start() {} }; }
      startRendering() { return Promise.resolve({ getChannelData: () => new Float32Array(512) }); }
    }
    class VmNavigator {}
    Object.defineProperty(VmNavigator.prototype, "webdriver", { get: function webdriverGetter() { return webdriver; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "platform", { get: function platform() { return "Linux x86_64"; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "userAgent", { get: function userAgent() { return CHROME_UA; }, configurable: true });
    const navInst = Object.create(VmNavigator.prototype);
    navInst.hardwareConcurrency = 8;
    navInst.maxTouchPoints = 0;
    const vmFetch = fetchImpl
      ? function fetch(u, init) { return fetchImpl(u, init, VmResponse); }
      : async function fetch() { return new VmResponse("{}"); };
    const vmConsole = {
      debug: function debug(arg) { if (cdpOpen && arg && typeof arg === "object") { try { void arg.stack; } catch (_) {} } },
      error: function error() {},
      warn: function warn() {},
    };
    const vmPerf = {
      now: function now() { return 1000; },
      getEntriesByType: function getEntriesByType(t) { return t === "resource" ? rtEntries : []; },
    };
    const nativeRefs = new Set([
      ...sMethods.map((m) => sp[m]),
      VmTextEncoder.prototype.encode,
      VmHeaders.prototype.set, VmHeaders.prototype.get, VmHeaders.prototype.has,
      VmResponse.prototype.json, VmResponse.prototype.clone, VmResponse.prototype.arrayBuffer,
      Object.getOwnPropertyDescriptor(VmResponse.prototype, "status").get,
      Object.getOwnPropertyDescriptor(VmResponse.prototype, "headers").get,
      Object.getOwnPropertyDescriptor(VmResponse.prototype, "redirected").get,
      Object.getOwnPropertyDescriptor(VmResponse.prototype, "url").get,
      Object.getOwnPropertyDescriptor(VmResponse.prototype, "type").get,
      VmOfflineAudioContext.prototype.startRendering,
      Object.getOwnPropertyDescriptor(VmNavigator.prototype, "webdriver").get,
      Object.getOwnPropertyDescriptor(VmNavigator.prototype, "platform").get,
      Object.getOwnPropertyDescriptor(VmNavigator.prototype, "userAgent").get,
      vmFetch, crypto.webcrypto.getRandomValues, vmPerf.getEntriesByType, vmPerf.now, vmConsole.debug,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString","createElement","appendChild","get documentElement","get contentWindow","getAttribute", "XMLHttpRequest", "Event","get isTrusted","debug","now","toDataURL","getImageData"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) {
            const nm = this.name === "webdriverGetter" ? "get webdriver" : this.name;
            return "function " + nm + "() { [native code] }";
          }
          return orig.call(this);
        };
        return globalThis;
      })();`,
      ifrCtx
    );
    class HTMLIFrameElement { constructor() { this.style = {}; } get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node {
      constructor(attrs = {}) { super(); this._attrs = attrs; }
      getAttribute(k) { return this._attrs[k] ?? null; }
      remove() {}
    }
    class Document extends Node {
      constructor() {
        super();
        this.currentScript = null;
        this.readyState = "complete";
        this.baseURI = "https://app.example/";
        this._el = new Element();
        this.body = new Element();
        this._scriptEls = initScripts.map((s) => new Element({ src: s }));
        this.scripts = this._scriptEls;
      }
      get documentElement() { return this._el; }
      createElement(t) {
        if (t === "iframe") return new HTMLIFrameElement();
        if (t === "canvas") return { width: 32, height: 32, getContext() { return null; } };
        return new Element();
      }
      querySelectorAll(sel) { return String(sel).includes("script[src]") ? this._scriptEls : []; }
      querySelector() { return null; }
      addEventListener() {}
    }
    const VmEvent = class Event { constructor(type, tr) { this.type = type; this._tr = tr; } get isTrusted() { return this._tr; } }
    const ctx = vm.createContext({
      crypto: crypto.webcrypto, SubtleCrypto: sp.constructor,
      TextEncoder: VmTextEncoder, Headers: VmHeaders, Response: VmResponse,
      OfflineAudioContext: VmOfflineAudioContext,
      Event: VmEvent, Navigator: VmNavigator, navigator: navInst,
      HTMLCanvasElement: { prototype: { toDataURL: function toDataURL() { return ""; } } },
      CanvasRenderingContext2D: { prototype: { getImageData: function getImageData() { return { data: [] }; } } },
      URL, URLSearchParams, Request,
      console: vmConsole, setTimeout, clearTimeout,
      performance: vmPerf,
      screen: { width: 1440, height: 900, availWidth: 1440, availHeight: 860 },
      innerWidth: 1200, innerHeight: 800, outerWidth: 1200, outerHeight: 880, devicePixelRatio: 1, screenX: 10, screenY: 10,
      document: new Document(), Document, Node, Element, HTMLIFrameElement,
      location: { origin: "https://app.example", href: "https://app.example/" },
      fetch: vmFetch,
      addEventListener() {},
      getComputedStyle: () => ({ display: "block", visibility: "visible", opacity: "1" }),
      ...(playwrightGlobal ? { __playwright: true } : {}),
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString","createElement","appendChild","get documentElement","get contentWindow","getAttribute", "XMLHttpRequest", "Event","get isTrusted","debug","now","toDataURL","getImageData"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) {
            const nm = this.name === "webdriverGetter" ? "get webdriver" : this.name;
            return "function " + nm + "() { [native code] }";
          }
          return orig.call(this);
        };
      })();`,
      ctx
    );
    vm.runInContext(src, ctx);
    return { ctx, expHash };
  };

  const makeHsFetch17 = (onApi, { onHs = null } = {}) => async (url, init, VmResponse) => {
    if (String(url).endsWith("/__proxysnare/boot")) {
      return new VmResponse(JSON.stringify(eng17.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (String(url).endsWith("/__proxysnare/handshake")) {
      const body = JSON.parse(init.body);
      if (onHs) onHs(body);
      const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|${body.browserProof?.d || ""}`).digest("hex");
      const s = eng17.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
      return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (onApi) return onApi(url, init, VmResponse);
    return new VmResponse("{}", { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "a".repeat(32) } });
  };

  // 1) CRITICAL #1: Live replay of OfflineAudioContext.startRendering + String.prototype.replace + transient Object.prototype.then bypass against unified paranoid!
  const embVbPar = buildBrowserGateScript({ defaultMode: "paranoid", unified: true, embedded: true, includeTicketPow: false });
  let hsCritBody = null;
  const vmCrit = makeVm17({
    guardOpts: { requireVeilBreak: true, embeddedVeilBreakScript: embVbPar, allowDevTools: false, blockCdpActive: true, blockConsoleEval: true },
    cdpOpen: true,
    webdriver: true,
    playwrightGlobal: true,
    fetchImpl: makeHsFetch17(null, { onHs: (b) => { hsCritBody = b; } }),
  });
  vm.runInContext(`
    const origStart = OfflineAudioContext.prototype.startRendering;
    OfflineAudioContext.prototype.startRendering = function startRendering() {
      const origRep = String.prototype.replace;
      String.prototype.replace = function replace(a, b) {
        if (this.length === 32) {
          Object.defineProperty(Object.prototype, "then", {
            configurable: true,
            get() {
              delete Object.prototype.then;
              if (this && this.v === 3) { this.s = 0; this.f = 0; this.cdp = 0; }
              return undefined;
            },
          });
        }
        return origRep.call(this, a, b);
      };
      return origStart.call(this);
    };
  `, vmCrit.ctx);
  await vmCrit.ctx.ProxySnare.ready();
  assert.ok(hsCritBody, "Handshake payload should be captured");
  assert.equal(hsCritBody.cdpActive, true, "ProxySnare MUST independently report cdpActive=true on webdriver/playwright/CDP!");
  assert.ok(hsCritBody.browserProof && hsCritBody.browserProof.s >= 4 && hsCritBody.browserProof.cdp === 1, `Forged clean VB_HS_V3 MUST be impossible (got ${JSON.stringify(hsCritBody.browserProof)})`);

  // Also post-load String.prototype.replace tamper alone MUST fail guardHash!
  const vmStrRep = makeVm17({ fetchImpl: makeHsFetch17() });
  vm.runInContext(`const _r = String.prototype.replace; String.prototype.replace = function replace(a,b){ return _r.call(this,a,b); };`, vmStrRep.ctx);
  assert.equal(vmStrRep.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", "Post-load String.prototype.replace hook MUST fail guardHash as TAMPERED_GUARD!");

  // 2) HIGH #2 & HIGH #3: Non-HTTP //# sourceURL= (pwn.js, blob:, file:, data:, chrome-extension://) AND strict+blockCdpActive:false //# sourceURL=webpack:// MUST emit ce=1!
  let nonHttpCtx = "";
  const vmNonHttp = makeVm17({
    cdpOpen: true,
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 200 }],
    fetchImpl: makeHsFetch17((u, init, VmResponse) => {
      nonHttpCtx = init.headers.get("X-PS-Ctx") || "";
      return new VmResponse("{}", { status: 200, headers: { "x-ps-next-canary": "b".repeat(32) } });
    }),
  });
  vm.runInContext(`window.appHelper = function appHelper() { return window.fetch("/api/x", { method: "POST", body: "{}" }); };`, vmNonHttp.ctx, { filename: "https://app.example/app.js" });
  for (const fakeFile of ["pwn.js", "blob:https://app.example/1234", "file:///tmp/pwn.js", "data:text/javascript,evil", "chrome-extension://abcdef/pwn.js", "webpack://evil/pwn.js"]) {
    await vm.runInContext(`function evil() { return window.appHelper(); } evil();`, vmNonHttp.ctx, { filename: fakeFile });
    assert.ok(nonHttpCtx.includes("ce=1"), `Calling appHelper via fake sourceURL '${fakeFile}' under strict+blockCdpActive:false MUST emit ce=1 (got ${nonHttpCtx})`);
  }
  // Also deferred setTimeout with closed DevTools (!cdpFlagged) and bare non-HTTP sourceURL=pwn.js MUST emit ce=1!
  let defNonHttpCtx = "";
  const vmDefNonHttp = makeVm17({
    cdpOpen: false,
    guardOpts: { allowDevTools: false, blockCdpActive: true, blockConsoleEval: true },
    fetchImpl: makeHsFetch17((u, init, VmResponse) => {
      defNonHttpCtx = init.headers.get("X-PS-Ctx") || "";
      return new VmResponse("{}", { status: 200, headers: { "x-ps-next-canary": "c".repeat(32) } });
    }),
  });
  await vm.runInContext(`function deferred() { return window.fetch("/api/def", { method: "POST", body: "{}" }); } deferred();`, vmDefNonHttp.ctx, { filename: "pwn.js" });
  assert.ok(defNonHttpCtx.includes("ce=1"), `Deferred fetch via bare sourceURL=pwn.js with !cdpFlagged MUST emit ce=1 (got ${defNonHttpCtx})`);

  // 3) HIGH #4: Legitimate V8 Array.map/forEach/reduce and new Promise calls from verified app.js MUST stay 0-FP ce=0 when DevTools is open, while Console Array.map calling appHelper STILL emits ce=1!
  let hofCtx = "";
  const vmHof = makeVm17({
    cdpOpen: true,
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 200 }],
    fetchImpl: makeHsFetch17((u, init, VmResponse) => {
      hofCtx = init.headers.get("X-PS-Ctx") || "";
      return new VmResponse("{}", { status: 200, headers: { "x-ps-next-canary": "d".repeat(32) } });
    }),
  });
  await vm.runInContext(`
    Promise.resolve().then(() => {
      function loadAll() { return Promise.all([1].map(() => window.fetch("/api/ok1", { method: "POST", body: "{}" }))); }
      return loadAll();
    });
  `, vmHof.ctx, { filename: "https://app.example/app.js" });
  assert.ok(hofCtx.includes("ce=0"), `Legitimate Array.map(() => fetch()) from app.js with DevTools open MUST stay 0-FP ce=0 (got ${hofCtx})`);
  await vm.runInContext(`
    Promise.resolve().then(() => {
      function wrappedPromise() { return new Promise((res) => window.fetch("/api/ok2", { method: "POST", body: "{}" }).then(res)); }
      return wrappedPromise();
    });
  `, vmHof.ctx, { filename: "https://app.example/app.js" });
  assert.ok(hofCtx.includes("ce=0"), `Legitimate new Promise(() => fetch()) from app.js with DevTools open MUST stay 0-FP ce=0 (got ${hofCtx})`);
  vm.runInContext(`window.appHelper = () => window.fetch("/api/ok3", { method: "POST", body: "{}" });`, vmHof.ctx, { filename: "https://app.example/app.js" });
  await vm.runInContext(`Promise.resolve().then(() => Promise.all([1].map(() => window.appHelper())));`, vmHof.ctx, { filename: "<anonymous>" });
  assert.ok(hofCtx.includes("ce=1"), `Console [1].map(() => appHelper()) MUST STILL emit ce=1 (got ${hofCtx})`);

  // 4) Avail HIGH #1: Production-minified Angular ZoneAwarePromise (class r with static toString()) stays 0-FP!
  const vmMinZone = makeVm17({ fetchImpl: makeHsFetch17() });
  vm.runInContext(`
    window.Zone = { current: { name: "<root>" } };
    window.__zone_symbol__Promise = window.Promise;
    class r {
      constructor(ex) { return new window.__zone_symbol__Promise(ex); }
      static toString() { return "function ZoneAwarePromise() { [native code] }"; }
    }
    window.Promise = r;
  `, vmMinZone.ctx);
  assert.equal(vmMinZone.ctx.ProxySnare.guardHash(), vmMinZone.expHash, "Production-minified Angular ZoneAwarePromise MUST stay 0-FP on guardHash()!");
  assert.equal(await vmMinZone.ctx.ProxySnare.ready(), true, "Production-minified Angular ZoneAwarePromise MUST complete handshake cleanly!");

  // 5) Avail MEDIUM #2: Cross-origin non-TAO .js CDN 302 redirect (vue@3 -> vue@3.4.21) using new Function() with DevTools closed stays 0-FP!
  let vueCtx = "";
  const vmVue = makeVm17({
    cdpOpen: false,
    guardOpts: { allowDevTools: false, blockCdpActive: true, blockConsoleEval: true },
    initScripts: ["https://cdn.jsdelivr.net/npm/vue@3/dist/vue.global.js"],
    rtEntries: [{ name: "https://cdn.jsdelivr.net/npm/vue@3/dist/vue.global.js", initiatorType: "script", transferSize: 0, responseStart: 0, encodedBodySize: 0, decodedBodySize: 0, responseEnd: 12 }],
    fetchImpl: makeHsFetch17((u, init, VmResponse) => {
      vueCtx = init.headers.get("X-PS-Ctx") || "";
      return new VmResponse("{}", { status: 200, headers: { "x-ps-next-canary": "e".repeat(32) } });
    }),
  });
  await new Promise((r) => setTimeout(r, 0));
  await vm.runInContext(`
    Promise.resolve().then(() => {
      function compileTpl() { return new Function('return window.fetch("/api/vue", { method: "POST", body: "{}" })')(); }
      return compileTpl();
    });
  `, vmVue.ctx, { filename: "https://cdn.jsdelivr.net/npm/vue@3.4.21/dist/vue.global.js" });
  assert.ok(vueCtx.includes("ce=0"), `Cross-origin non-TAO .js CDN 302 Vue new Function() with DevTools closed MUST stay 0-FP ce=0 (got ${vueCtx})`);

  // 6) Avail MEDIUM #3: strict+blockCdpActive:false with DevTools OPEN stays 0-FP on single-frame redirected arrow callback, Alpine CDN new Function, proven TAO-masked cross-origin 302, and 2-level nested IIFE new Function!
  let r302Ctx = "";
  const vmR302 = makeVm17({
    cdpOpen: true,
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    initScripts: ["https://unpkg.com/alpinejs"],
    rtEntries: [
      { name: "https://app.example/js/latest.js", initiatorType: "script", redirectStart: 1, redirectEnd: 5, responseStatus: 200, decodedBodySize: 500, responseEnd: 15 },
      { name: "https://unpkg.com/alpinejs", initiatorType: "script", transferSize: 0, responseStart: 0, encodedBodySize: 0, decodedBodySize: 0, responseEnd: 14 },
    ],
    fetchImpl: makeHsFetch17((u, init, VmResponse) => {
      r302Ctx = init.headers.get("X-PS-Ctx") || "";
      return new VmResponse("{}", { status: 200, headers: { "x-ps-next-canary": "f".repeat(32) } });
    }),
  });
  await vm.runInContext(`Promise.resolve().then(() => window.fetch("/api/arrow", { method: "POST", body: "{}" }));`, vmR302.ctx, { filename: "https://app.example/js/app.v42.js" });
  assert.ok(r302Ctx.includes("ce=0"), `Single-frame arrow callback from confirmed same-origin 302 script MUST stay 0-FP ce=0 (got ${r302Ctx})`);
  await vm.runInContext(`Promise.resolve().then(() => { function runAlpine() { return new Function('return window.fetch("/api/alp2", { method: "POST", body: "{}" })')(); } return runAlpine(); });`, vmR302.ctx, { filename: "https://unpkg.com/alpinejs@3.14.0/dist/cdn.min.js" });
  assert.ok(r302Ctx.includes("ce=0"), `Alpine new Function() from confirmed CDN redirect under strict+blockCdpActive:false MUST stay 0-FP ce=0 (got ${r302Ctx})`);
  await vm.runInContext(`Promise.resolve().then(() => (() => { const f1 = new Function("return new Function('return window.fetch(\\"/api/nest\\", { method: \\"POST\\", body: \\"{}\\" })')()"); return f1(); })());`, vmR302.ctx, { filename: "https://app.example/js/app.v42.js" });
  assert.ok(r302Ctx.includes("ce=0"), `2-level nested IIFE new Function() MUST stay 0-FP ce=0 (got ${r302Ctx})`);
  await vm.runInContext(`Promise.resolve().then(() => eval('window.fetch("/api/console-eval", { method: "POST", body: "{}" })'));`, vmR302.ctx);
  assert.ok(r302Ctx.includes("ce=1"), `Direct Console eval MUST STILL emit ce=1 (got ${r302Ctx})`);

  let xoDevCtx = "";
  const vmXoDev = makeVm17({
    cdpOpen: true,
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    rtEntries: [{ name: "https://app.example/js/app.js", initiatorType: "script", transferSize: 0, responseStart: 0, encodedBodySize: 0, decodedBodySize: 0, responseEnd: 15 }],
    fetchImpl: makeHsFetch17((u, init, VmResponse) => {
      xoDevCtx = init.headers.get("X-PS-Ctx") || "";
      return new VmResponse("{}", { status: 200, headers: { "x-ps-next-canary": "a".repeat(32) } });
    }),
  });
  await vm.runInContext(`Promise.resolve().then(() => { function outer() { return (function inner() { return window.fetch("/api/xo", { method: "POST", body: "{}" }); })(); } return outer(); });`, vmXoDev.ctx, { filename: "https://cdn.example.net/app.v42.js" });
  assert.ok(xoDevCtx.includes("ce=0"), `Proven TAO-masked same-origin-to-cross-origin 302 named call under strict+blockCdpActive:false MUST stay 0-FP ce=0 (got ${xoDevCtx})`);

  // 7) Perf MEDIUM #1: createUnifiedMiddleware & createUnifiedShield keep gateSri / gateVersion as lazy enumerable getters!
  const uMwLazy = createUnifiedMiddleware({ mode: "strict", secret: "lazy-test-secret-32-bytes-long!!" });
  assert.equal(typeof Object.getOwnPropertyDescriptor(uMwLazy, "gateSri")?.get, "function", "createUnifiedMiddleware.gateSri MUST be a lazy getter!");
  assert.equal(typeof Object.getOwnPropertyDescriptor(uMwLazy, "gateVersion")?.get, "function", "createUnifiedMiddleware.gateVersion MUST be a lazy getter!");
  const uShLazy = createUnifiedShield({ target: "http://127.0.0.1:9", mode: "strict", secret: "lazy-test-secret-32-bytes-long!!" });
  assert.equal(typeof Object.getOwnPropertyDescriptor(uShLazy, "gateSri")?.get, "function", "createUnifiedShield.gateSri MUST be a lazy getter!");
  assert.equal(typeof Object.getOwnPropertyDescriptor(uShLazy, "gateVersion")?.get, "function", "createUnifiedShield.gateVersion MUST be a lazy getter!");

  // 8) Parity LOW #1/#2/#3 (Python): empty url="" defaults to "/" in HMAC/burst & whitespace-only X-PS-Session on OPTIONS preflight matches Node.js!
  const pyOut17 = execFileSync(
    "python3",
    [
      "-c",
      `import sys, hashlib, hmac; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v = ProxySnareVerifier(mode="strict", secret="pass17-py-secret-32-bytes-long!!", protected_paths=["*"])
# Whitespace-only X-PS-Session on valid cross-origin OPTIONS preflight must NOT fail closed
r_opt = v.inspect_request(method="OPTIONS", url="/api/x", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Host": "api.example.com", "Origin": "https://app.example.com", "Access-Control-Request-Method": "POST", "Sec-Fetch-Mode": "cors", "X-PS-Session": "   "}, ip="127.0.0.1")
assert not r_opt.blocked, f"Whitespace-only X-PS-Session on OPTIONS should pass: {r_opt}"
# Empty url="" signs identically to "/"
hs = v.issue_session(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)}, boot_token="bt17")
sess = v._sessions[hs["sessionId"]]
ts = str(hs["serverNowMs"])
nonce = "a" * 16
ctx = "ce=0;cdp=0;ug=1;ga=100"
empty_hash = hashlib.sha256(b"").hexdigest()
canon = f"PS2|GET|/|" + empty_hash + f"|1|{ts}|{nonce}|{hs['canary']}|{ctx}"
proof = hmac.new(sess["key"], canon.encode(), hashlib.sha256).hexdigest()
r_empty = v.inspect_request(method="GET", url="", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-PS-Session": hs["sessionId"], "X-PS-Seq": "1", "X-PS-Ts": ts, "X-PS-Nonce": nonce, "X-PS-Canary": hs["canary"], "X-PS-Ctx": ctx, "X-PS-Proof": proof}, ip="127.0.0.1", now_ms=hs["serverNowMs"])
assert not r_empty.blocked and r_empty.score == 0, f"Empty url='' should canonicalize to '/': {r_empty}"
print("PY17_OK")`,
    ],
    { encoding: "utf8" }
  );
  assert.ok(pyOut17.includes("PY17_OK"));
});

test("29. Pass-18 Audit Regressions: Closed ShadowRoot iframe isolation & no frame.style, Symbol.split stack-split defense, Error.prototype.stack .bind(null)/Gecko-delete defense, post-load untrusted/4xx script RT rejection, null toString/valueOf JSON 403 (no 500), non-embedded <link prefetch>/3xx gate.js rejection, V8 async Promise.all 0-FP, Safari/JSC anonymous@/eval code@ 0-FP, Safari <16.4 /_next/image 0-FP, PerformanceObserver.takeRecords() lazy chunk 0-FP, balanced pre-loaded Sentry RUM 0-FP, tighter data-ps-boot & mixed-case duplicate UA", async () => {
  const eng18 = createProxySnareEngine({
    mode: "strict",
    protectedPaths: ["/api"],
    handshakePowBits: 0,
    requireGuardIntegrity: true,
    secret: "pass18-regression-secret-32bytes!",
  });

  const makeVm18 = ({
    guardOpts = {},
    rtEntries = [],
    poPending = [],
    cdpOpen = false,
    fetchImpl = null,
    preLoadHook = null,
    useShadow = true,
    geckoStack = false,
    readyState = "complete",
    scriptSrcs = [],
    onFrameStyleTouch = null,
    onDocLoadEvent = null,
  } = {}) => {
    const src = buildBrowserGuardScript({
      basePath: "/__proxysnare",
      protectedRules: ["/api"],
      serverVerifyPubB64: eng18.serverVerifyPubB64,
      allowDevTools: false,
      blockCdpActive: true,
      blockConsoleEval: true,
      requireGuardIntegrity: true,
      ...guardOpts,
    });
    const { guardHash: expHash } = computeGuardIntegrity(src);
    const sp = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const sMethods = ["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "verify", "sign", "digest"];
    const origEncode = TextEncoder.prototype.encode;
    const origHdrSet = Headers.prototype.set;
    const origHdrGet = Headers.prototype.get;
    const origHdrHas = Headers.prototype.has;
    const origRespJson = Response.prototype.json;
    class VmTextEncoder extends TextEncoder {}
    VmTextEncoder.prototype.encode = origEncode;
    class VmHeaders extends Headers {}
    VmHeaders.prototype.set = origHdrSet;
    VmHeaders.prototype.get = origHdrGet;
    VmHeaders.prototype.has = origHdrHas;
    class VmResponse extends Response {}
    VmResponse.prototype.json = origRespJson;
    class VmPerformance {
      now() { return Date.now(); }
      getEntriesByType(t) { return t === "resource" ? rtEntries : []; }
    }
    class VmPerformanceObserver {
      constructor(cb) { this._cb = cb; }
      observe() {}
      disconnect() {}
      takeRecords() { const out = poPending.splice(0, poPending.length); return out; }
    }
    const VmXHR = class XMLHttpRequest {
      open() {}
      send() {}
      setRequestHeader() {}
      getResponseHeader() { return null; }
      get readyState() { return 4; }
      get status() { return 200; }
      get responseURL() { return ""; }
    }
    const vmFetch = fetchImpl
      ? function fetch(u, init) { return fetchImpl(u, init, VmResponse); }
      : async function fetch() { return new VmResponse("{}"); };
    const vmConsole = {
      debug: function debug(x) { if (cdpOpen && x && typeof x === "object") void x.stack; },
      log: function log() {},
      warn: function warn() {},
    };
    const nativeRefs = new Set([
      ...sMethods.map((m) => sp[m]),
      VmTextEncoder.prototype.encode,
      VmHeaders.prototype.set,
      VmHeaders.prototype.get,
      VmHeaders.prototype.has,
      VmResponse.prototype.json,
      VmPerformance.prototype.getEntriesByType,
      VmXHR.prototype.open,
      VmXHR.prototype.send,
      VmXHR.prototype.setRequestHeader,
      vmFetch,
      crypto.webcrypto.getRandomValues,
      vmConsole.debug,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader", "open", "send", "setRequestHeader", "get stack"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", { configurable: true, get: function stack() { return ""; } });' : ""}
        return globalThis;
      })();`,
      ifrCtx
    );
    let shadowUsed = false;
    let hostRemoved = false;
    class ShadowRoot {
      constructor(mode) { this._mode = mode; this._children = []; }
      appendChild(c) { this._children.push(c); return c; }
    }
    class HTMLIFrameElement {
      constructor() {
        this._shadowConnected = false;
      }
      get style() { if (onFrameStyleTouch) onFrameStyleTouch(); return {}; }
      get contentWindow() { return ifrWin; }
      remove() {}
    }
    class Node {
      appendChild(c) {
        // Simulate Chromium synchronous capture-phase document 'load' ONLY when iframe is appended directly to light DOM!
        if (c instanceof HTMLIFrameElement && !(this instanceof ShadowRoot) && onDocLoadEvent) {
          onDocLoadEvent(c);
        }
        return c;
      }
    }
    class Element extends Node {
      constructor(attrs = null) { super(); this._shadowRoot = null; this._attrs = attrs; }
      get shadowRoot() { return this._shadowRoot; }
      getAttribute(n) { return this._attrs && Object.prototype.hasOwnProperty.call(this._attrs, n) ? this._attrs[n] : null; }
      remove() { hostRemoved = true; }
    }
    if (useShadow) {
      Element.prototype.attachShadow = function attachShadow(init) {
        if (!init || (init.mode !== "closed" && init.mode !== "open")) throw new TypeError("bad mode");
        shadowUsed = true;
        const sr = new ShadowRoot(init.mode);
        if (init.mode === "open") this._shadowRoot = sr;
        return sr;
      };
    }
    class Document extends Node {
      constructor() {
        super();
        this.currentScript = null;
        this.baseURI = "https://app.example/";
        this.readyState = readyState;
        this._el = new Element();
        this.body = new Element();
        this.location = { href: "https://app.example/" };
      }
      get documentElement() { return this._el; }
      createElement(t) {
        if (t === "iframe") return new HTMLIFrameElement();
        return new Element();
      }
      querySelectorAll(sel) {
        if (sel === "script[src]" && scriptSrcs.length) {
          return scriptSrcs.map((s) => new Element({ src: s }));
        }
        return [];
      }
      querySelector() { return null; }
      addEventListener() {}
    }
    const ctx = vm.createContext({
      crypto: crypto.webcrypto,
      SubtleCrypto: sp.constructor,
      TextEncoder: VmTextEncoder,
      TextDecoder,
      Headers: VmHeaders,
      Response: VmResponse,
      Performance: VmPerformance,
      PerformanceObserver: VmPerformanceObserver,
      XMLHttpRequest: VmXHR,
      URL, URLSearchParams, Request, console: vmConsole, setTimeout, clearTimeout,
      performance: new VmPerformance(),
      navigator: { webdriver: false },
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement, ShadowRoot,
      location: { origin: "https://app.example", href: "https://app.example/" },
      fetch: vmFetch,
      addEventListener() {},
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader", "open", "send", "setRequestHeader", "get stack"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", { configurable: true, get: function stack() { return ""; } });' : ""}
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, expHash, wasShadowUsed: () => shadowUsed, wasHostRemoved: () => hostRemoved };
  };

  const makeHs18 = (onApi) => async (url, init, VmResponse) => {
    const sUrl = String(url);
    if (sUrl.endsWith("/__proxysnare/boot")) {
      return new VmResponse(JSON.stringify(eng18.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (sUrl.endsWith("/__proxysnare/handshake")) {
      const body = JSON.parse(init.body);
      const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|${body.browserProof?.d || ""}`).digest("hex");
      const s = eng18.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
      return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (onApi) onApi(sUrl, init);
    return new VmResponse("{}", { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "a".repeat(32) } });
  };

  // 1) CRITICAL #1: Closed ShadowRoot iframe isolation — zero frame.style access, zero light-DOM load event leak, host cleaned up, & attachShadow tamper caught!
  let styleTouched = false;
  let docLoadFired = false;
  const vmShadow = makeVm18({
    onFrameStyleTouch: () => { styleTouched = true; },
    onDocLoadEvent: () => { docLoadFired = true; },
    fetchImpl: makeHs18(),
  });
  assert.equal(vmShadow.ctx.ProxySnare.guardHash(), vmShadow.expHash, "Closed ShadowRoot fresh realm MUST produce valid guardHash!");
  assert.equal(vmShadow.wasShadowUsed(), true, "openBaseFreshRealm MUST isolate iframe inside a closed ShadowRoot!");
  assert.equal(vmShadow.wasHostRemoved(), true, "ShadowRoot host element MUST be synchronously removed in cleanup()!");
  assert.equal(styleTouched, false, "openBaseFreshRealm MUST NOT touch frame.style prior to appendChild!");
  assert.equal(docLoadFired, false, "Iframe inside closed ShadowRoot MUST NOT leak synchronous load event to light DOM!");

  const vmBadShadow = makeVm18({
    preLoadHook: `const _origAs = Element.prototype.attachShadow; Element.prototype.attachShadow = function attachShadow(o) { return _origAs.call(this, { mode: "open" }); };`,
    fetchImpl: makeHs18(),
  });
  assert.equal(vmBadShadow.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", "Hooked Element.prototype.attachShadow MUST fail closed as TAMPERED_GUARD!");

  // 2) HIGH #2: String.prototype[Symbol.split] & Object.prototype[Symbol.split] CANNOT hijack captureConsoleEvalFlag() or bypass guardHash()!
  for (const [label, targetObj] of [["String.prototype", "String.prototype"], ["Object.prototype", "Object.prototype"]]) {
    let splitCtx = "";
    const vmSplit = makeVm18({
      cdpOpen: true,
      guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
      rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 200 }],
      fetchImpl: makeHs18((u, init) => { splitCtx = init.headers.get("X-PS-Ctx") || ""; }),
    });
    await vmSplit.ctx.ProxySnare.ready();
    vm.runInContext(`
      Object.defineProperty(${targetObj}, Symbol.split, {
        configurable: true,
        value(s) {
          return ["Error", "    at captureConsoleEvalFlag (https://app.example/__proxysnare/guard.js:1:1)", "    at proxySnareFetch (https://app.example/__proxysnare/guard.js:1:1)", "    at app (https://app.example/app.js:1:1)"];
        },
      });
    `, vmSplit.ctx);
    assert.equal(vmSplit.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", `${label}[Symbol.split] tamper MUST fail guardHash()!`);
    await vm.runInContext(`Promise.resolve().then(() => window.fetch("/api/split", { method: "POST", body: "{}" }));`, vmSplit.ctx, { filename: "<anonymous>" }).catch(() => {});
    // Also verify directly when fetch proceeds before session invalidation: even without promise failure, splitByChar ignores Symbol.split!
    const vmSplit2 = makeVm18({
      cdpOpen: true,
      guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
      rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 200 }],
      fetchImpl: makeHs18((u, init) => { splitCtx = init.headers.get("X-PS-Ctx") || ""; }),
    });
    await vmSplit2.ctx.ProxySnare.ready();
    // Temporarily poison Symbol.split only around fetch() call via eval
    await vm.runInContext(`
      Promise.resolve().then(() => {
        Object.defineProperty(${targetObj}, Symbol.split, {
          configurable: true,
          value() { return ["Error", "    at captureConsoleEvalFlag (https://app.example/__proxysnare/guard.js:1:1)", "    at proxySnareFetch (https://app.example/__proxysnare/guard.js:1:1)", "    at app (https://app.example/app.js:1:1)"]; }
        });
        const p = window.fetch("/api/split2", { method: "POST", body: "{}" });
        delete ${targetObj}[Symbol.split];
        return p;
      });
    `, vmSplit2.ctx, { filename: "<anonymous>" });
    assert.ok(splitCtx.includes("ce=1"), `Transient ${label}[Symbol.split] hijack MUST STILL emit ce=1 (got ${splitCtx})`);
  }

  // 3) HIGH #3: .bind(null) on Error.prototype.stack on V8 AND Gecko/WebKit delete Error.prototype.stack / .bind(null) ALL fail closed!
  const vmV8BindStack = makeVm18({
    preLoadHook: `
      function fakeStack() { return "Error\\n    at captureConsoleEvalFlag (https://app.example/__proxysnare/guard.js:1:1)\\n    at proxySnareFetch (https://app.example/__proxysnare/guard.js:1:1)\\n    at app (https://app.example/app.js:1:1)"; }
      Object.defineProperty(Error.prototype, "stack", { get: fakeStack.bind(null), configurable: true });
    `,
    fetchImpl: makeHs18(),
  });
  assert.equal(vmV8BindStack.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", "Pre-load V8 Error.prototype.stack .bind(null) injection MUST fail guardHash() as TAMPERED_GUARD!");

  const vmGeckoDelStack = makeVm18({
    geckoStack: true,
    preLoadHook: `delete Error.prototype.stack;`,
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true, requireGuardIntegrity: false },
    fetchImpl: makeHs18((u, init) => { geckoDelCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  let geckoDelCtx = "";
  assert.equal(vmGeckoDelStack.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", "Pre-load Gecko delete Error.prototype.stack MUST fail guardHash() as TAMPERED_GUARD!");

  const vmGeckoBindStack = makeVm18({
    geckoStack: true,
    preLoadHook: `Object.defineProperty(Error.prototype, "stack", { get: (() => "").bind(null), configurable: true });`,
    fetchImpl: makeHs18(),
  });
  assert.equal(vmGeckoBindStack.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", "Pre-load Gecko Error.prototype.stack .bind(null) MUST fail guardHash() as TAMPERED_GUARD!");

  // Even when requireGuardIntegrity:false and rawStack is undefined on a non-V8 stack, captureConsoleEvalFlag MUST fail closed (ce=1)!
  let emptyStackCtx = "";
  const vmEmptyStack = makeVm18({
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true, requireGuardIntegrity: false },
    fetchImpl: makeHs18((u, init) => { emptyStackCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vmEmptyStack.ctx.ProxySnare.ready();
  await vm.runInContext(`
    Promise.resolve().then(() => {
      Object.defineProperty(Error.prototype, "stack", { value: undefined, configurable: true });
      return window.fetch("/api/emptystack", { method: "POST", body: "{}" });
    });
  `, vmEmptyStack.ctx, { filename: "https://app.example/app.js" });
  assert.ok(emptyStackCtx.includes("ce=1"), `Injecting Error.prototype.stack post-load MUST trigger errStackTampered -> ce=1 (got ${emptyStackCtx})`);

  // 4) MEDIUM #4: Post-load untrusted-origin & 404 <script> entries MUST NOT enter verifiedUrlCache!
  let badRtCtx = "";
  const vmBadRt = makeVm18({
    cdpOpen: true,
    readyState: "complete",
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    rtEntries: [
      { name: "https://attacker.invalid/pwn.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 200 },
      { name: "https://app.example/nonexistent-404.js", initiatorType: "script", responseStatus: 404, decodedBodySize: 0 },
    ],
    fetchImpl: makeHs18((u, init) => { badRtCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`Promise.resolve().then(() => { function pwn() { return window.fetch("/api/pwn1", { method: "POST", body: "{}" }); } return pwn(); });`, vmBadRt.ctx, { filename: "https://attacker.invalid/pwn.js" });
  assert.ok(badRtCtx.includes("ce=1"), `Post-load untrusted-origin <script> MUST NOT be trusted (got ${badRtCtx})`);
  await vm.runInContext(`Promise.resolve().then(() => { function pwn404() { return window.fetch("/api/pwn2", { method: "POST", body: "{}" }); } return pwn404(); });`, vmBadRt.ctx, { filename: "https://app.example/nonexistent-404.js" });
  assert.ok(badRtCtx.includes("ce=1"), `Same-origin 404 <script> MUST NOT be trusted (got ${badRtCtx})`);

  // 5) MEDIUM #6: JSON objects with { toString: null, valueOf: null } MUST return 403 (ZERO HTTP 500!) on POST /__proxysnare/handshake!
  const up18 = http.createServer((req, res) => {
    if (req.url.startsWith("/_next/image")) {
      res.writeHead(200, { "Content-Type": "image/png" });
      res.end(Buffer.from([137, 80, 78, 71]));
      return;
    }
    if (req.url.startsWith("/fonts/css2")) {
      res.writeHead(200, { "Content-Type": "text/css" });
      res.end("body{}");
      return;
    }
    if (req.url.startsWith("/api/secret")) {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end('{"secret":true}');
      return;
    }
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end("<!doctype html><html><head></head><body>ok</body></html>");
  });
  await new Promise((r) => up18.listen(0, "127.0.0.1", r));
  const srv18 = createProxySnareServer({ target: `http://127.0.0.1:${up18.address().port}`, mode: "strict", protectedPaths: ["/api"] });
  const srv18Wild = createProxySnareServer({ target: `http://127.0.0.1:${up18.address().port}`, mode: "strict", protectedPaths: ["*"] });
  await srv18.listen(0, "127.0.0.1");
  await srv18Wild.listen(0, "127.0.0.1");
  const reqRaw18 = (port, method, pathStr, headers, bodyStr = null) =>
    new Promise((resolve, reject) => {
      const r = http.request({ host: "127.0.0.1", port, method, path: pathStr, headers }, (resp) => {
        const chunks = [];
        resp.on("data", (c) => chunks.push(c));
        resp.on("end", () => resolve({ status: resp.statusCode, headers: resp.headers, text: Buffer.concat(chunks).toString("utf8") }));
      });
      r.on("error", reject);
      if (bodyStr) r.write(bodyStr);
      r.end();
    });
  try {
    const p18 = srv18.server.address().port;
    const rBadBt = await reqRaw18(
      p18,
      "POST",
      "/__proxysnare/handshake",
      makeBrowserHeaders({ "content-type": "application/json", "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty" }),
      JSON.stringify({ bootToken: { toString: null, valueOf: null }, clientPubB64: "A".repeat(88) })
    );
    assert.equal(rBadBt.status, 403, `bootToken={toString:null,valueOf:null} MUST return 403, NOT 500 (got ${rBadBt.status}: ${rBadBt.text})`);

    const rBoot18 = await reqRaw18(p18, "GET", "/__proxysnare/boot", makeBrowserHeaders({ "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty" }));
    const boot18 = JSON.parse(rBoot18.text);
    const rBadPow = await reqRaw18(
      p18,
      "POST",
      "/__proxysnare/handshake",
      makeBrowserHeaders({ "content-type": "application/json", "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "sec-fetch-dest": "empty" }),
      JSON.stringify({ bootToken: boot18.bootToken, powNonce: { toString: null, valueOf: null }, clientPubB64: "A".repeat(88) })
    );
    assert.equal(rBadPow.status, 403, `powNonce={toString:null,valueOf:null} MUST return 403, NOT 500 (got ${rBadPow.status}: ${rBadPow.text})`);

    // Security LOW: Unprotected HTML data-ps-boot MUST NOT be stamped for stripped/Connection:close Chrome UA, MUST be stamped for real Chrome navigation!
    const rSpoofHtml = await reqRaw18(p18, "GET", "/", { "user-agent": CHROME_UA, accept: "text/html", connection: "close" });
    assert.equal(rSpoofHtml.status, 200);
    assert.ok(!rSpoofHtml.text.includes("data-ps-boot="), "Spoofed Chrome UA missing Accept-Language/Sec-Fetch-* MUST NOT be stamped with data-ps-boot!");
    const rRealHtml = await reqRaw18(p18, "GET", "/", makeBrowserHeaders({ accept: "text/html,application/xhtml+xml,*/*;q=0.8", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", "sec-fetch-site": "none" }));
    assert.equal(rRealHtml.status, 200);
    assert.ok(rRealHtml.text.includes("data-ps-boot="), "Real Chrome HTML navigation MUST still receive stamped data-ps-boot!");

    // Avail MEDIUM #3: Safari < 16.4 (no Sec-Fetch-Dest) extensionless /_next/image & /fonts/css2 under wildcard protectedPaths:["*"] return 200, while /api/secret returns 403!
    const p18W = srv18Wild.server.address().port;
    const SAFARI15_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/15.6 Safari/605.1.15";
    const rSafImg = await reqRaw18(p18W, "GET", "/_next/image?url=%2Fhero.png&w=640", { "user-agent": SAFARI15_UA, "accept-language": "en-US,en;q=0.9", accept: "image/webp,image/png,*/*;q=0.8" });
    assert.equal(rSafImg.status, 200, `Safari < 16.4 /_next/image MUST return 200 under wildcard (got ${rSafImg.status})`);
    const rSafCss = await reqRaw18(p18W, "GET", "/fonts/css2?family=Inter", { "user-agent": SAFARI15_UA, "accept-language": "en-US,en;q=0.9", accept: "text/css,*/*;q=0.1" });
    assert.equal(rSafCss.status, 200, `Safari < 16.4 /fonts/css2 MUST return 200 under wildcard (got ${rSafCss.status})`);
    const rSafApi = await reqRaw18(p18W, "GET", "/api/secret", { "user-agent": SAFARI15_UA, "accept-language": "en-US,en;q=0.9", accept: "image/webp,*/*;q=0.8" });
    assert.equal(rSafApi.status, 403, `Safari < 16.4 spoofed Accept: image/webp hitting JSON /api/secret MUST return 403 (got ${rSafApi.status})`);
  } finally {
    await srv18.close();
    await srv18Wild.close();
    await new Promise((r) => up18.close(r));
  }

  // 6) MEDIUM #7: Non-embedded <link rel="prefetch"> without <script src=".../gate.js"> AND 302 redirect MUST be rejected!
  const fakeVbPre18 = `
    const fakeVb = Object.freeze({ collectHandshakeProof: () => ({ v: 3, s: 0, f: 0, cdp: 0, ok: true }) });
    Object.defineProperty(window, Symbol.for("__VEILBREAK_INTERNAL__"), { value: fakeVb, writable: false, configurable: false });
    Object.defineProperty(window, "VeilBreak", { value: fakeVb, writable: false, configurable: false });
  `;
  for (const [label, rt, sSrcs] of [
    ["bare <link rel=prefetch> without <script>", [{ name: "https://app.example/__veilbreak/gate.js", initiatorType: "link", responseStatus: 200, decodedBodySize: 4096 }], []],
    ["302 redirect gate.js", [{ name: "https://app.example/__veilbreak/gate.js", initiatorType: "script", responseStatus: 302, decodedBodySize: 0, transferSize: 300 }], ["/__veilbreak/gate.js"]],
  ]) {
    let seenBp = "unset";
    const vmGateRej = makeVm18({
      guardOpts: { requireVeilBreak: true },
      rtEntries: rt,
      scriptSrcs: sSrcs,
      preLoadHook: fakeVbPre18,
      fetchImpl: async (url, init, VmResponse) => {
        if (String(url).endsWith("/boot")) return new VmResponse(JSON.stringify(eng18.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
        seenBp = JSON.parse(init.body).browserProof;
        return new VmResponse('{"error":"BROWSER_INTEGRITY_FAILED"}', { status: 403, headers: { "content-type": "application/json" } });
      },
    });
    await assert.rejects(() => vmGateRej.ctx.ProxySnare.ready(), /PROXYSNARE_HANDSHAKE_FAILED_403/);
    assert.equal(seenBp, undefined, `${label} MUST reject forged non-embedded VeilBreak!`);
  }

  // 7) Avail HIGH #1: V8 'at async Promise.all (index 0)' (unawaited React useEffect Promise.all) stays 0-FP ce=0 with DevTools open, while Console Promise.all STILL emits ce=1!
  let promAllCtx = "";
  const vmPromAll = makeVm18({
    cdpOpen: true,
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 }],
    fetchImpl: makeHs18((u, init) => { promAllCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`
    async function loadItem() {
      await Promise.resolve();
      return window.fetch("/api/item", { method: "POST", body: "{}" });
    }
    Promise.all([loadItem()]);
  `, vmPromAll.ctx, { filename: "https://app.example/app.js" });
  assert.ok(promAllCtx.includes("ce=0"), `V8 unawaited 'at async Promise.all (index 0)' from app.js with DevTools open MUST stay 0-FP ce=0 (got ${promAllCtx})`);
  await vm.runInContext(`
    Promise.all([(async () => { await Promise.resolve(); return window.fetch("/api/console-item", { method: "POST", body: "{}" }); })()]);
  `, vmPromAll.ctx, { filename: "<anonymous>" });
  assert.ok(promAllCtx.includes("ce=1"), `Console Promise.all async IIFE MUST STILL emit ce=1 (got ${promAllCtx})`);

  // 8) Avail MEDIUM #4: PerformanceObserver.takeRecords() drains pending lazy import() chunk past 250-entry RT buffer cap -> 0-FP ce=0!
  let lazyCtx = "";
  const poQueue = [];
  const vmLazy = makeVm18({
    cdpOpen: true,
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    rtEntries: [], // simulates full 250-entry RT buffer where new lazy chunk is absent from getEntriesByType!
    poPending: poQueue,
    fetchImpl: makeHs18((u, init) => { lazyCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  poQueue.push({ name: "https://app.example/chunks/lazy-123.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 1200 });
  await vm.runInContext(`Promise.resolve().then(() => { function lazyCall() { return window.fetch("/api/lazy", { method: "POST", body: "{}" }); } return lazyCall(); });`, vmLazy.ctx, { filename: "https://app.example/chunks/lazy-123.js" });
  assert.ok(lazyCtx.includes("ce=0"), `Lazy chunk drained via PerformanceObserver.takeRecords() MUST stay 0-FP ce=0 (got ${lazyCtx})`);

  // 9) Avail MEDIUM #5: Pre-loaded Sentry/Datadog RUM wrapping console.debug + fetch + XHR stays 0-FP in balanced (requireGuardIntegrity:false) while blocked in strict!
  const sentryPreload = `
    const _f = window.fetch;
    window.fetch = function sentryFetch(u, i) { return _f.call(this, u, i); };
    const _o = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function sentryOpen() { return _o.apply(this, arguments); };
    const _s = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.send = function sentrySend() { return _s.apply(this, arguments); };
    const _d = console.debug;
    console.debug = function sentryDebug() { return _d.apply(this, arguments); };
  `;
  const vmSentryBal = makeVm18({
    guardOpts: { allowDevTools: true, blockCdpActive: false, blockConsoleEval: false, requireGuardIntegrity: false },
    preLoadHook: sentryPreload,
    fetchImpl: makeHs18(),
  });
  assert.equal(vmSentryBal.ctx.ProxySnare.guardHash(), vmSentryBal.expHash, "Pre-loaded Sentry RUM MUST NOT return TAMPERED_GUARD in balanced (requireGuardIntegrity:false)!");
  assert.equal(await vmSentryBal.ctx.ProxySnare.ready(), true, "Pre-loaded Sentry RUM MUST complete handshake in balanced mode!");
  const vmSentryStrict = makeVm18({
    guardOpts: { requireGuardIntegrity: true },
    preLoadHook: sentryPreload,
    fetchImpl: makeHs18(),
  });
  assert.equal(vmSentryStrict.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", "Pre-loaded fetch/XHR hook MUST STILL return TAMPERED_GUARD in strict (requireGuardIntegrity:true)!");

  // 10) Avail MEDIUM #6: Safari/JSC 'anonymous@' / 'eval code@' with verified parent below stays 0-FP ce=0, while Console 'anonymous@' at bottom emits ce=1!
  let jscCtx = "";
  const vmJsc = makeVm18({
    cdpOpen: true,
    geckoStack: true,
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true, requireGuardIntegrity: false },
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 }],
    preLoadHook: `
      Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({
        get stack() { return globalThis.__fakeJscStack; },
      }, "stack"));
    `,
    fetchImpl: makeHs18((u, init) => { jscCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  vmJsc.ctx.__fakeJscStack = "captureConsoleEvalFlag@https://app.example/__proxysnare/guard.js:1:1\nproxySnareFetch@https://app.example/__proxysnare/guard.js:1:1\nanonymous@\ncompile@https://app.example/app.js:10:5\nglobal code@https://app.example/app.js:12:1";
  await vmJsc.ctx.fetch("/api/jsc-vue", { method: "POST", body: "{}" });
  assert.ok(jscCtx.includes("ce=0"), `Safari/JSC Vue new Function 'anonymous@' with verified app parent below MUST stay 0-FP ce=0 (got ${jscCtx})`);
  vmJsc.ctx.__fakeJscStack = "captureConsoleEvalFlag@https://app.example/__proxysnare/guard.js:1:1\nproxySnareFetch@https://app.example/__proxysnare/guard.js:1:1\nappHelper@https://app.example/app.js:5:1\nanonymous@";
  await vmJsc.ctx.fetch("/api/jsc-console", { method: "POST", body: "{}" });
  assert.ok(jscCtx.includes("ce=1"), `Safari/JSC Web Inspector Console 'anonymous@' at bottom MUST emit ce=1 (got ${jscCtx})`);

  // 11) Parity LOW #1: Mixed-case duplicate User-Agent header concatenation in isAiCrawlerRequest()!
  const { isAiCrawlerRequest } = require("../src/detector.js");
  assert.equal(isAiCrawlerRequest({ "User-Agent": "FirecrawlAgent/1.0", "user-agent": CHROME_UA }), true, "Mixed-case duplicate User-Agent MUST concatenate rather than overwrite!");
});

test("30. Pass-19 Audit Regressions: Safari/JSC 'at ' fn-name Console-Eval spoof blocked, Object.prototype.{writable,value,get}=undefined descriptor-pollution defense, client-side abort before ECDH deriveBits on MITM-rewritten TAMPERED_SUBTLE, HTTP 304 gate.js Resource Timing 0-FP, TAO-enabled cross-origin 302 redirect 0-FP, Origin-without-Host & wildcard Accept-Language boot gating, and Python partial raw_header_lines & non-string pow_nonce parity", async () => {
  const eng19 = createProxySnareEngine({
    mode: "strict",
    protectedPaths: ["/api"],
    handshakePowBits: 0,
    requireGuardIntegrity: true,
    secret: "pass19-regression-secret-32bytes!",
  });

  const makeVm19 = ({
    guardOpts = {},
    rtEntries = [],
    scriptSrcs = [],
    cdpOpen = false,
    fetchImpl = null,
    preLoadHook = null,
    geckoStack = false,
  } = {}) => {
    const src = buildBrowserGuardScript({
      basePath: "/__proxysnare",
      protectedRules: ["/api"],
      serverVerifyPubB64: eng19.serverVerifyPubB64,
      allowDevTools: false,
      blockCdpActive: true,
      blockConsoleEval: true,
      requireGuardIntegrity: true,
      ...guardOpts,
    });
    const sp = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const sMethods = ["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "verify", "sign", "digest"];
    const origEncode = TextEncoder.prototype.encode;
    const origHdrSet = Headers.prototype.set;
    const origHdrGet = Headers.prototype.get;
    const origHdrHas = Headers.prototype.has;
    const origRespJson = Response.prototype.json;
    class VmTextEncoder extends TextEncoder {}
    VmTextEncoder.prototype.encode = origEncode;
    class VmHeaders extends Headers {}
    VmHeaders.prototype.set = origHdrSet;
    VmHeaders.prototype.get = origHdrGet;
    VmHeaders.prototype.has = origHdrHas;
    class VmResponse extends Response {}
    VmResponse.prototype.json = origRespJson;
    class VmPerformance {
      now() { return Date.now(); }
      getEntriesByType(t) { return t === "resource" ? rtEntries : []; }
    }
    const vmFetch = fetchImpl
      ? function fetch(u, init) { return fetchImpl(u, init, VmResponse); }
      : async function fetch() { return new VmResponse("{}"); };
    const vmConsole = {
      debug: function debug(x) { if (cdpOpen && x && typeof x === "object") void x.stack; },
      log() {},
      warn() {},
    };
    const nativeRefs = new Set([
      ...sMethods.map((m) => sp[m]),
      VmTextEncoder.prototype.encode,
      VmHeaders.prototype.set,
      VmHeaders.prototype.get,
      VmHeaders.prototype.has,
      VmResponse.prototype.json,
      VmPerformance.prototype.getEntriesByType,
      vmFetch,
      crypto.webcrypto.getRandomValues,
      vmConsole.debug,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader", "get stack"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return ""; } }, "stack"));' : ""}
        return globalThis;
      })();`,
      ifrCtx
    );
    class ShadowRoot { appendChild(c) { return c; } }
    class HTMLIFrameElement { get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node {
      constructor(attrs = null) { super(); this._attrs = attrs; }
      get shadowRoot() { return null; }
      attachShadow() { return new ShadowRoot(); }
      getAttribute(n) { return this._attrs && Object.prototype.hasOwnProperty.call(this._attrs, n) ? this._attrs[n] : null; }
      remove() {}
    }
    class Document extends Node {
      constructor() {
        super();
        this.currentScript = null;
        this.baseURI = "https://app.example/";
        this.readyState = "complete";
        this._el = new Element();
        this.body = new Element();
        this.location = { href: "https://app.example/" };
      }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : new Element(); }
      querySelectorAll(sel) {
        if (sel.includes("script[src]") && scriptSrcs.length) return scriptSrcs.map((s) => new Element({ src: s }));
        return [];
      }
      querySelector() { return null; }
      addEventListener() {}
    }
    const ctx = vm.createContext({
      crypto: crypto.webcrypto,
      SubtleCrypto: sp.constructor,
      TextEncoder: VmTextEncoder,
      TextDecoder,
      Headers: VmHeaders,
      Response: VmResponse,
      Performance: VmPerformance,
      URL, URLSearchParams, Request, console: vmConsole, setTimeout, clearTimeout,
      performance: new VmPerformance(),
      navigator: { webdriver: false },
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement, ShadowRoot,
      location: { origin: "https://app.example", href: "https://app.example/" },
      fetch: vmFetch,
      addEventListener() {},
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader", "get stack"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return ""; } }, "stack"));' : ""}
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, src };
  };

  const makeHs19 = (onApi) => async (url, init, VmResponse) => {
    const sUrl = String(url);
    if (sUrl.endsWith("/__proxysnare/boot")) {
      return new VmResponse(JSON.stringify(eng19.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (sUrl.endsWith("/__proxysnare/handshake")) {
      const body = JSON.parse(init.body);
      const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|${body.browserProof?.d || ""}`).digest("hex");
      const s = eng19.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
      return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (onApi) onApi(sUrl, init);
    return new VmResponse("{}", { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "a".repeat(32) } });
  };

  // 1) Security HIGH #1: Safari/JSC Console function named "at x https://app.example/app.js:1:1 " MUST STILL emit ce=1!
  let jscAtCtx = "";
  const vmJscAt = makeVm19({
    cdpOpen: true,
    geckoStack: true,
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true, requireGuardIntegrity: false },
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 }],
    preLoadHook: `
      Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({
        get stack() { return globalThis.__jscAtStack; },
      }, "stack"));
    `,
    fetchImpl: makeHs19((u, init) => { jscAtCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  vmJscAt.ctx.__jscAtStack = "captureConsoleEvalFlag@https://app.example/__proxysnare/guard.js:1:1\nproxySnareFetch@https://app.example/__proxysnare/guard.js:1:1\nat x https://app.example/app.js:1:1 @";
  await vmJscAt.ctx.fetch("/api/jsc-at-spoof", { method: "POST", body: "{}" });
  assert.ok(jscAtCtx.includes("ce=1"), `Safari/JSC function named 'at x https://.../app.js:1:1 ' MUST NOT spoof ce=0 (got ${jscAtCtx})`);

  // 2) Security HIGH #2: Object.prototype.writable = undefined / .value = undefined / .get = undefined NEVER blinds detectCdpActive() or blockConsoleEval:true (even with allowDevTools:true)!
  let descPollCtx = "";
  const vmDescPoll = makeVm19({
    cdpOpen: true,
    guardOpts: { allowDevTools: true, blockCdpActive: false, blockConsoleEval: true },
    fetchImpl: makeHs19((u, init) => { descPollCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vmDescPoll.ctx.ProxySnare.ready();
  for (const key of ["writable", "value", "get"]) {
    vm.runInContext(`Object.prototype.${key} = undefined;`, vmDescPoll.ctx);
    assert.equal(vmDescPoll.ctx.ProxySnare.detectCdpActive(), true, `Object.prototype.${key}=undefined MUST NOT blind detectCdpActive()!`);
    assert.equal(vmDescPoll.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", `Object.prototype.${key}=undefined MUST fail guardHash() as TAMPERED_GUARD!`);
    await vm.runInContext(`Promise.resolve().then(() => { const p = window.fetch("/api/dp", { method: "POST", body: "{}" }); delete Object.prototype.${key}; return p; });`, vmDescPoll.ctx, { filename: "<anonymous>" });
    assert.ok(descPollCtx.includes("ce=1"), `Transient Object.prototype.${key}=undefined MUST NOT bypass blockConsoleEval:true (got ${descPollCtx})`);
  }

  // 3) Security MEDIUM #3: Client-side abort BEFORE calling hooked SubtleCrypto.deriveBits() even if MITM rewrites guardHash in /handshake & returns 200 OK!
  let deriveBitsCalled = false;
  const origDeriveBits = Object.getPrototypeOf(crypto.webcrypto.subtle).deriveBits;
  const vmMitmSubtle = makeVm19({
    guardOpts: { requireGuardIntegrity: true },
    preLoadHook: `
      const sp = Object.getPrototypeOf(crypto.subtle);
      const _origDb = sp.deriveBits;
      sp.deriveBits = function hookedDeriveBits() { globalThis.__onDb(); return _origDb.apply(this, arguments); };
    `,
    fetchImpl: async (url, init, VmResponse) => {
      const sUrl = String(url);
      if (sUrl.endsWith("/__proxysnare/boot")) {
        return new VmResponse(JSON.stringify(eng19.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
      }
      if (sUrl.endsWith("/__proxysnare/handshake")) {
        const body = JSON.parse(init.body);
        assert.equal(body.guardHash, "TAMPERED_SUBTLE", "Guard must still submit TAMPERED_SUBTLE telemetry to /handshake");
        const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|`).digest("hex");
        const s = eng19.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
        return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
      }
      return new VmResponse("{}", { status: 200 });
    },
  });
  vmMitmSubtle.ctx.__onDb = () => { deriveBitsCalled = true; };
  try {
    await assert.rejects(() => vmMitmSubtle.ctx.ProxySnare.ready(), /PROXYSNARE_GUARD_TAMPERED/, "Client MUST abort before deriveBits when TAMPERED_SUBTLE + MITM 200 OK!");
    assert.equal(deriveBitsCalled, false, "Hooked SubtleCrypto.deriveBits MUST NEVER be invoked after self-detecting TAMPERED_SUBTLE!");
  } finally {
    Object.getPrototypeOf(crypto.webcrypto.subtle).deriveBits = origDeriveBits;
  }

  // 4) Availability HIGH #1: HTTP 304 Not Modified on /__veilbreak/gate.js passes non-embedded Resource Timing verification!
  let seenBp304 = null;
  const vmGate304 = makeVm19({
    guardOpts: { requireVeilBreak: true },
    rtEntries: [{ name: "https://app.example/__veilbreak/gate.js", initiatorType: "script", responseStatus: 304, decodedBodySize: 0, transferSize: 0 }],
    preLoadHook: `
      const fakeVb = Object.freeze({ collectHandshakeProof: () => ({ v: 3, s: 0, f: 0, cdp: 0, ok: true }) });
      Object.defineProperty(window, Symbol.for("__VEILBREAK_INTERNAL__"), { value: fakeVb, writable: false, configurable: false });
      Object.defineProperty(window, "VeilBreak", { value: fakeVb, writable: false, configurable: false });
    `,
    fetchImpl: async (url, init, VmResponse) => {
      if (String(url).endsWith("/boot")) return new VmResponse(JSON.stringify(eng19.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
      seenBp304 = JSON.parse(init.body).browserProof;
      return new VmResponse('{"error":"DONE"}', { status: 403, headers: { "content-type": "application/json" } });
    },
  });
  await assert.rejects(() => vmGate304.ctx.ProxySnare.ready(), /PROXYSNARE_HANDSHAKE_FAILED_403/);
  assert.ok(seenBp304 && seenBp304.v === 3, "HTTP 304 Not Modified on /__veilbreak/gate.js MUST pass Resource Timing verification!");

  // 5) Availability MEDIUM #2: TAO-enabled same-origin-to-cross-origin 302 redirect (redirectEnd > 0, responseStatus === 0) stays 0-FP ce=0 under strict+blockCdpActive:false with DevTools open!
  let taoXoCtx = "";
  const vmTaoXo = makeVm19({
    cdpOpen: true,
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    rtEntries: [{ name: "https://app.example/latest/app.js", initiatorType: "script", redirectStart: 1, redirectEnd: 8, responseStatus: 0, transferSize: 0, responseStart: 10, encodedBodySize: 1024, decodedBodySize: 4096, responseEnd: 20 }],
    fetchImpl: makeHs19((u, init) => { taoXoCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`Promise.resolve().then(() => { function outer() { return (function inner() { return window.fetch("/api/tao-xo", { method: "POST", body: "{}" }); })(); } return outer(); });`, vmTaoXo.ctx, { filename: "https://cdn.example.net/v2/app.js" });
  assert.ok(taoXoCtx.includes("ce=0"), `TAO-enabled same-origin->cross-origin 302 script redirect MUST stay 0-FP ce=0 (got ${taoXoCtx})`);

  // 6) Security LOW #4: Origin without Host rejected 403 on /boot, and wildcard HTML without Accept-Language omits data-ps-boot!
  const mw19 = createProxySnareMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  let bootNoHostStatus = 0;
  await mw19(
    { method: "GET", url: "/__proxysnare/boot", socket: { remoteAddress: "127.0.0.1" }, headers: { "user-agent": CHROME_UA, origin: "https://evil.invalid", "accept-language": "en-US", "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors" } },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead(st) { bootNoHostStatus = st; this.headersSent = true; }, end() { this.writableEnded = true; } }
  );
  assert.equal(bootNoHostStatus, 403, "Origin header without Host header MUST be rejected with 403 on /boot!");

  const up19 = http.createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end("<!doctype html><html><head></head><body>ok</body></html>");
  });
  await new Promise((r) => up19.listen(0, "127.0.0.1", r));
  const srv19W = createProxySnareServer({ target: `http://127.0.0.1:${up19.address().port}`, mode: "strict", protectedPaths: ["*"] });
  await srv19W.listen(0, "127.0.0.1");
  try {
    const rNoAl = await new Promise((resolve, reject) => {
      const r = http.request(
        { host: "127.0.0.1", port: srv19W.server.address().port, method: "GET", path: "/", headers: { "user-agent": CHROME_UA, accept: "text/html", "sec-fetch-mode": "navigate", "sec-fetch-dest": "document", "sec-fetch-site": "none" } },
        (resp) => { let b = ""; resp.on("data", (c) => (b += c)); resp.on("end", () => resolve({ status: resp.statusCode, text: b })); }
      );
      r.on("error", reject);
      r.end();
    });
    assert.equal(rNoAl.status, 200);
    assert.ok(!rNoAl.text.includes("data-ps-boot="), "Wildcard HTML probe without Accept-Language MUST NOT stamp data-ps-boot!");
  } finally {
    await srv19W.close();
    await new Promise((r) => up19.close(r));
  }

  // 7) Parity MEDIUM #2 & LOW #3 (Python): partial raw_header_lines does NOT wipe X-Original-URL from headers, and non-string pow_nonce rejected!
  const pyOut19 = execFileSync(
    "python3",
    [
      "-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v = ProxySnareVerifier(mode="strict", secret="pass19-py-secret-32-bytes-long!!", protected_paths=["/api"])
r = v.inspect_request(
    method="GET",
    url="/public",
    headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-Original-URL": "/api/admin"},
    raw_header_lines=["Host: app.example"],
    ip="127.0.0.1",
)
assert r.blocked and any(x["code"] == "PROXY_PATH_OVERRIDE_HEADER" for x in r.reasons), f"Partial raw_header_lines wiped X-Original-URL: {r}"
vm = ProxySnareVerifier(mode="monitor", secret="pass19-py-secret-32-bytes-long!!", protected_paths=["/api"])
bt = vm.issue_boot_challenge(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})["bootToken"]
c_bad = vm.consume_boot_challenge_detail(boot_token=bt, pow_nonce=123, ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
assert c_bad == {"ok": False, "error": "HANDSHAKE_POW_INVALID"}, f"Non-string pow_nonce must reject: {c_bad}"
c_bad_bt = vm.consume_boot_challenge_detail(boot_token=123, pow_nonce="", ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
assert c_bad_bt == {"ok": False, "error": "BOOT_TOKEN_INVALID"}, f"Non-string boot_token must reject: {c_bad_bt}"
print("PY19_OK")`,
    ],
    { encoding: "utf8" }
  );
  assert.ok(pyOut19.includes("PY19_OK"));
});

test("31. Pass-20 Audit Regressions: V8 CallSite //# sourceURL=<verified_app_script> Console/eval spoof blocked, stateless boot-token non-saturation & non-evicting usedBootTokens replay immunity (JS+Python), balanced client-side fail-closed SubtleCrypto tamper abort, non-executable JSON/JSON-LD/importmap script filtering, s-maxage=0+Expires & multi-ETag If-None-Match, duplicate Host/CL on /boot, and unified 1-scan CDP/hash sharing", async () => {
  const { buildBrowserGateScript } = require("../../veilbreak/src/browser-sdk.js");
  const eng20 = createProxySnareEngine({
    mode: "strict",
    protectedPaths: ["/api"],
    handshakePowBits: 0,
    requireGuardIntegrity: true,
    secret: "pass20-regression-secret-32bytes!",
  });

  const makeVm20 = ({
    guardOpts = {},
    rtEntries = [],
    inlineScripts = [],
    cdpOpen = false,
    fetchImpl = null,
    preLoadHook = null,
  } = {}) => {
    const src = buildBrowserGuardScript({
      basePath: "/__proxysnare",
      protectedRules: ["/api"],
      serverVerifyPubB64: eng20.serverVerifyPubB64,
      allowDevTools: false,
      blockCdpActive: false,
      blockConsoleEval: true,
      requireGuardIntegrity: true,
      failClosedOnTamper: true,
      ...guardOpts,
    });
    const sp = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const sMethods = ["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "verify", "sign", "digest"];
    const origEncode = TextEncoder.prototype.encode;
    const origHdrSet = Headers.prototype.set;
    const origHdrGet = Headers.prototype.get;
    const origHdrHas = Headers.prototype.has;
    const origRespJson = Response.prototype.json;
    class VmTextEncoder extends TextEncoder {}
    VmTextEncoder.prototype.encode = origEncode;
    class VmHeaders extends Headers {}
    VmHeaders.prototype.set = origHdrSet;
    VmHeaders.prototype.get = origHdrGet;
    VmHeaders.prototype.has = origHdrHas;
    class VmResponse extends Response {}
    VmResponse.prototype.json = origRespJson;
    let dbgCalls = 0;
    class VmPerformance {
      now() { return Date.now(); }
      getEntriesByType(t) { return t === "resource" ? rtEntries : []; }
    }
    const vmFetch = fetchImpl
      ? function fetch(u, init) { return fetchImpl(u, init, VmResponse); }
      : async function fetch() { return new VmResponse("{}"); };
    const vmConsole = {
      debug: function debug(x) { dbgCalls++; if (cdpOpen && x && typeof x === "object") void x.stack; },
      log() {},
      warn() {},
    };
    const nativeRefs = new Set([
      ...sMethods.map((m) => sp[m]),
      VmTextEncoder.prototype.encode,
      VmHeaders.prototype.set,
      VmHeaders.prototype.get,
      VmHeaders.prototype.has,
      VmResponse.prototype.json,
      VmPerformance.prototype.getEntriesByType,
      vmFetch,
      crypto.webcrypto.getRandomValues,
      vmConsole.debug,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader", "get isTrusted", "webdriver", "platform", "userAgent", "toDataURL", "getImageData"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        class Navigator {}
        Object.defineProperty(Navigator.prototype, "webdriver", { configurable: true, get: function webdriver() { return false; } });
        globalThis.Navigator = Navigator;
        globalThis.navigator = Object.create(Navigator.prototype);
        return globalThis;
      })();`,
      ifrCtx
    );
    class ShadowRoot { appendChild(c) { return c; } }
    class HTMLIFrameElement { get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node {
      constructor(attrs = null) { super(); this._attrs = attrs; this.style = {}; }
      get shadowRoot() { return null; }
      attachShadow() { return new ShadowRoot(); }
      getAttribute(n) { return this._attrs && Object.prototype.hasOwnProperty.call(this._attrs, n) ? this._attrs[n] : null; }
      remove() {}
    }
    class Document extends Node {
      constructor() {
        super();
        this.currentScript = null;
        this.baseURI = "https://app.example/";
        this.readyState = "complete";
        this._el = new Element();
        this.body = new Element();
        this.location = { href: "https://app.example/" };
      }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : t === "canvas" ? { width: 32, height: 32, getContext: () => null } : new Element(); }
      querySelectorAll(sel) {
        if (sel === "script:not([src])") return inlineScripts.map((a) => new Element(a));
        return [];
      }
      querySelector() { return null; }
      addEventListener() {}
    }
    const VmEvent = class Event { constructor(t, tr) { this.type = t; this._tr = tr; } get isTrusted() { return this._tr; } }
    class VmNavigator {}
    Object.defineProperty(VmNavigator.prototype, "webdriver", { get: function webdriver() { return false; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "platform", { get: function platform() { return "Linux x86_64"; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "userAgent", { get: function userAgent() { return CHROME_UA; }, configurable: true });
    const navInst = Object.create(VmNavigator.prototype);
    navInst.hardwareConcurrency = 8;
    navInst.maxTouchPoints = 0;
    const ctx = vm.createContext({
      crypto: crypto.webcrypto,
      SubtleCrypto: sp.constructor,
      TextEncoder: VmTextEncoder,
      TextDecoder,
      Headers: VmHeaders,
      Response: VmResponse,
      Performance: VmPerformance,
      Event: VmEvent,
      Navigator: VmNavigator,
      HTMLCanvasElement: { prototype: { toDataURL: function toDataURL() { return ""; } } },
      CanvasRenderingContext2D: { prototype: { getImageData: function getImageData() { return { data: [] }; } } },
      URL, URLSearchParams, Request, console: vmConsole, setTimeout, clearTimeout,
      performance: new VmPerformance(),
      screen: { width: 1440, height: 900, availWidth: 1440, availHeight: 860 },
      innerWidth: 1200, innerHeight: 800, outerWidth: 1200, outerHeight: 880, devicePixelRatio: 1, screenX: 10, screenY: 10,
      navigator: navInst,
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement, ShadowRoot,
      location: { origin: "https://app.example", href: "https://app.example/" },
      fetch: vmFetch,
      addEventListener() {},
      getComputedStyle: () => ({ display: "block", visibility: "visible", opacity: "1" }),
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader", "get isTrusted", "webdriver", "platform", "userAgent", "toDataURL", "getImageData"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, getDbgCalls: () => dbgCalls };
  };

  const makeHs20 = (onApi) => async (url, init, VmResponse) => {
    const sUrl = String(url);
    if (sUrl.endsWith("/__proxysnare/boot")) {
      return new VmResponse(JSON.stringify(eng20.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (sUrl.endsWith("/__proxysnare/handshake")) {
      const body = JSON.parse(init.body);
      const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|${body.browserProof?.d || ""}`).digest("hex");
      const s = eng20.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
      return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (onApi) onApi(sUrl, init);
    return new VmResponse("{}", { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "a".repeat(32) } });
  };

  // 1) Security HIGH #1: V8 //# sourceURL=<verified_app_script> in Console/Runtime.evaluate & eval() MUST emit ce=1, while real app.js with //# sourceURL=bundle.js stays 0-FP ce=0!
  let v8SrcCtx = "";
  const vmV8Src = makeVm20({
    cdpOpen: true,
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 }],
    fetchImpl: makeHs20((u, init) => { v8SrcCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`Promise.resolve().then(function f(){ return window.fetch("/api/spoof-srcurl", { method: "POST", body: "{}" }); });\n//# sourceURL=https://app.example/app.js`, vmV8Src.ctx);
  assert.ok(v8SrcCtx.includes("ce=1"), `Console //# sourceURL=https://app.example/app.js MUST emit ce=1 via CallSite.getFileName() (got ${v8SrcCtx})`);
  await vm.runInContext(`eval('Promise.resolve().then(function g(){ return window.fetch("/api/spoof-eval", { method: "POST", body: "{}" }); });\\n//# sourceURL=https://app.example/app.js');`, vmV8Src.ctx);
  assert.ok(v8SrcCtx.includes("ce=1"), `eval() + //# sourceURL=https://app.example/app.js MUST emit ce=1 (got ${v8SrcCtx})`);
  await vm.runInContext(`Promise.resolve().then(function realApp(){ return window.fetch("/api/real-srcurl", { method: "POST", body: "{}" }); });\n//# sourceURL=bundle.js`, vmV8Src.ctx, { filename: "https://app.example/app.js" });
  assert.ok(v8SrcCtx.includes("ce=0"), `Real loaded app.js with //# sourceURL=bundle.js MUST stay 0-FP ce=0 via CallSite.getFileName() (got ${v8SrcCtx})`);

  // 2) Security HIGH #2 + Performance HIGH #1: Passive boot minting NEVER saturates maxBootTokens, tampered sealed suffix rejected locally, and saturated usedBootTokens NEVER evicts unexpired tokens (JS + Python)!
  const engBootCap = createProxySnareEngine({ mode: "strict", handshakePowBits: 0, maxBootTokens: 3, bootTokenTtlMs: 60_000, secret: "bootcap-secret-32bytes-padding!!" });
  // Mint 50 passive boot tokens with maxBootTokens=3 -> ALL 50 succeed (zero passive saturation!)
  const passiveTokens = [];
  for (let i = 0; i < 50; i++) {
    const b = engBootCap.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA });
    assert.ok(b && b.bootToken, `Passive boot mint #${i} MUST NOT fail on maxBootTokens=3!`);
    passiveTokens.push(b.bootToken);
  }
  // Tampered sealed suffix rejected locally
  const [t0Id, t0Mac] = passiveTokens[0].split(".");
  assert.equal(engBootCap.consumeBootChallenge({ bootToken: `${t0Id}.${t0Mac}.TAMPERED_SEALED_PAYLOAD_123456`, ip: "127.0.0.1", userAgent: CHROME_UA }).error, "BOOT_TOKEN_INVALID");
  // Consume 3 tokens to saturate usedBootTokens (maxBootTokens=3), 4th fails closed with BOOT_CAPACITY_EXCEEDED, AND replaying token 0 STILL fails (never evicted!)
  for (let i = 0; i < 3; i++) {
    assert.equal(engBootCap.consumeBootChallenge({ bootToken: passiveTokens[i], ip: "127.0.0.1", userAgent: CHROME_UA }).ok, true);
  }
  assert.equal(engBootCap.consumeBootChallenge({ bootToken: passiveTokens[3], ip: "127.0.0.1", userAgent: CHROME_UA }).error, "BOOT_CAPACITY_EXCEEDED");
  assert.equal(engBootCap.consumeBootChallenge({ bootToken: passiveTokens[0], ip: "127.0.0.1", userAgent: CHROME_UA }).error, "BOOT_TOKEN_REPLAYED_OR_INVALID");
  assert.equal(engBootCap.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA }), null, "Active minting fails closed ONLY when usedBootTokens is saturated!");

  const pyBootCap = execFileSync(
    "python3",
    [
      "-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v = ProxySnareVerifier(mode="strict", handshake_pow_bits=0, max_boot_tokens=3, boot_token_ttl_ms=60_000, secret="bootcap-secret-32bytes-padding!!")
toks = [v.issue_boot_challenge(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})["bootToken"] for _ in range(20)]
tid, mac, _ = toks[0].split(".")
assert v.consume_boot_challenge_detail(boot_token=f"{tid}.{mac}.TAMPERED_SEALED_PAYLOAD_123456", ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})["error"] == "BOOT_TOKEN_INVALID"
for i in range(3):
    assert v.consume_boot_challenge_detail(boot_token=toks[i], ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})["ok"] is True
assert v.consume_boot_challenge_detail(boot_token=toks[3], ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})["error"] == "BOOT_CAPACITY_EXCEEDED"
assert v.consume_boot_challenge_detail(boot_token=toks[0], ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})["error"] == "BOOT_TOKEN_REPLAYED_OR_INVALID"
print("PY20_BOOT_OK")`,
    ],
    { encoding: "utf8" }
  );
  assert.ok(pyBootCap.includes("PY20_BOOT_OK"));

  // 3) Security MEDIUM #3: Balanced mode (requireGuardIntegrity:false, failClosedOnTamper:true) STILL aborts client-side before deriveBits on TAMPERED_SUBTLE + MITM 200 OK!
  let balDbCalled = false;
  const origDb20 = Object.getPrototypeOf(crypto.webcrypto.subtle).deriveBits;
  const vmBalSubtle = makeVm20({
    guardOpts: { allowDevTools: true, blockCdpActive: false, blockConsoleEval: false, requireGuardIntegrity: false, failClosedOnTamper: true },
    preLoadHook: `
      const sp = Object.getPrototypeOf(crypto.subtle);
      const _origDb = sp.deriveBits;
      sp.deriveBits = function hookedDb() { globalThis.__onBalDb(); return _origDb.apply(this, arguments); };
    `,
    fetchImpl: async (url, init, VmResponse) => {
      const sUrl = String(url);
      if (sUrl.endsWith("/__proxysnare/boot")) return new VmResponse(JSON.stringify(eng20.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
      const body = JSON.parse(init.body);
      const hsBind = crypto.createHash("sha256").update(`UNPINNED_OK|0|`).digest("hex");
      const s = eng20.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
      return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
    },
  });
  vmBalSubtle.ctx.__onBalDb = () => { balDbCalled = true; };
  try {
    await assert.rejects(() => vmBalSubtle.ctx.ProxySnare.ready(), /PROXYSNARE_GUARD_TAMPERED/, "Balanced mode MUST abort client-side on TAMPERED_SUBTLE + MITM 200 OK!");
    assert.equal(balDbCalled, false, "Balanced mode MUST NEVER call hooked deriveBits after TAMPERED_SUBTLE!");
  } finally {
    Object.getPrototypeOf(crypto.webcrypto.subtle).deriveBits = origDb20;
  }

  // 4) Security MEDIUM #4: Non-executable <script type="application/json"> / ld+json / importmap MUST NOT set hasInitialInlineScripts=true!
  let jsonScriptCtx = "";
  const vmJsonData = makeVm20({
    cdpOpen: true,
    inlineScripts: [{ type: "application/json" }, { type: "application/ld+json" }, { type: "importmap" }],
    fetchImpl: makeHs20((u, init) => { jsonScriptCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`Promise.resolve().then(function docSpoof(){ return window.fetch("/api/doc-spoof", { method: "POST", body: "{}" }); });`, vmJsonData.ctx, { filename: "https://app.example/" });
  assert.ok(jsonScriptCtx.includes("ce=1"), `JSON/ld+json/importmap data scripts MUST NOT disable INITIAL_DOC_URL spoof guard (got ${jsonScriptCtx})`);

  // 5) Performance MEDIUM #3: Unified cold handshake shares CDP cache (<= 2 console.debug calls instead of 4!) and caches immutable guardHash permanently!
  const embVb20 = buildBrowserGateScript({ defaultMode: "strict", unified: true, embedded: true, includeTicketPow: false });
  const vmUniPerf = makeVm20({
    guardOpts: { requireVeilBreak: true, embeddedVeilBreakScript: embVb20, allowDevTools: false, blockCdpActive: true, blockConsoleEval: true },
    fetchImpl: makeHs20(),
  });
  await vmUniPerf.ctx.ProxySnare.ready();
  assert.ok(vmUniPerf.getDbgCalls() <= 2, `Unified cold handshake MUST share CDP cache instead of 4 redundant probes (got ${vmUniPerf.getDbgCalls()})`);

  // 6) Avail LOW #1/#2 & Security LOW #6: multi-ETag If-None-Match 304, s-maxage=0 + future Expires keeps SRI, and duplicate Host rejected 403 on /boot!
  const mw20 = createProxySnareMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  let g304Status = 0;
  await mw20(
    { method: "GET", url: "/__proxysnare/guard.js", headers: { "if-none-match": `"old-etag", "${mw20.guardVersion}"` } },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead(st) { g304Status = st; this.headersSent = true; }, end() { this.writableEnded = true; } }
  );
  assert.equal(g304Status, 304, "Multi-ETag If-None-Match list MUST return 304 on /__proxysnare/guard.js!");
  let dupBootStatus = 0;
  await mw20(
    { method: "GET", url: "/__proxysnare/boot", socket: { remoteAddress: "127.0.0.1" }, headers: makeBrowserHeaders(), rawHeaders: ["Host", "a.example", "Host", "b.example"] },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead(st) { dupBootStatus = st; this.headersSent = true; }, end() { this.writableEnded = true; } }
  );
  assert.equal(dupBootStatus, 403, "Duplicate Host rawHeaders MUST be rejected 403 on /__proxysnare/boot!");
});

test("32. Pass-21 Audit Regressions: V8 nested eval(//# sourceURL=)->new Function Console bypass blocked & Alpine new Function + sourceURL 0-FP, Safari bare-URL '@' 0-FP & spoof block, HEAD /health & /guard.js & /gate.js 200 under wildcard/unified, and 403 JSON with X-PS-Next-Canary zero-clone/zero-retry", async () => {
  const eng21 = createProxySnareEngine({
    mode: "strict",
    protectedPaths: ["/api"],
    handshakePowBits: 0,
    requireGuardIntegrity: true,
    secret: "pass21-regression-secret-32bytes!",
  });

  const makeVm21 = ({ guardOpts = {}, rtEntries = [], scriptSrcs = [], cdpOpen = false, geckoStack = false, preLoadHook = null, fetchImpl = null } = {}) => {
    const src = buildBrowserGuardScript({
      basePath: "/__proxysnare",
      protectedRules: ["/api"],
      serverVerifyPubB64: eng21.serverVerifyPubB64,
      allowDevTools: false,
      blockCdpActive: false,
      blockConsoleEval: true,
      requireGuardIntegrity: true,
      ...guardOpts,
    });
    const sp = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const sMethods = ["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "verify", "sign", "digest"];
    const origEncode = TextEncoder.prototype.encode;
    const origHdrSet = Headers.prototype.set;
    const origHdrGet = Headers.prototype.get;
    const origHdrHas = Headers.prototype.has;
    const origRespJson = Response.prototype.json;
    let cloneCalls = 0;
    const origRespClone = Response.prototype.clone;
    class VmTextEncoder extends TextEncoder {}
    VmTextEncoder.prototype.encode = origEncode;
    class VmHeaders extends Headers {}
    VmHeaders.prototype.set = origHdrSet;
    VmHeaders.prototype.get = origHdrGet;
    VmHeaders.prototype.has = origHdrHas;
    class VmResponse extends Response {
      clone() { cloneCalls++; return origRespClone.call(this); }
    }
    VmResponse.prototype.json = origRespJson;
    class VmPerformance {
      now() { return Date.now(); }
      getEntriesByType(t) { return t === "resource" ? rtEntries : []; }
    }
    const vmFetch = fetchImpl
      ? function fetch(u, init) { return fetchImpl(u, init, VmResponse); }
      : async function fetch() { return new VmResponse("{}"); };
    const vmConsole = {
      debug: function debug(x) { if (cdpOpen && x && typeof x === "object") void x.stack; },
      log() {},
      warn() {},
    };
    const nativeRefs = new Set([
      ...sMethods.map((m) => sp[m]),
      VmTextEncoder.prototype.encode,
      VmHeaders.prototype.set,
      VmHeaders.prototype.get,
      VmHeaders.prototype.has,
      VmResponse.prototype.json,
      VmResponse.prototype.clone,
      VmPerformance.prototype.getEntriesByType,
      vmFetch,
      crypto.webcrypto.getRandomValues,
      vmConsole.debug,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader", "get stack"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return ""; } }, "stack"));' : ""}
        return globalThis;
      })();`,
      ifrCtx
    );
    class ShadowRoot { appendChild(c) { return c; } }
    class HTMLIFrameElement { get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node {
      constructor(attrs = null) { super(); this._attrs = attrs; }
      get shadowRoot() { return null; }
      attachShadow() { return new ShadowRoot(); }
      getAttribute(n) { return this._attrs && Object.prototype.hasOwnProperty.call(this._attrs, n) ? this._attrs[n] : null; }
      remove() {}
    }
    class Document extends Node {
      constructor() {
        super();
        this.currentScript = null;
        this.baseURI = "https://app.example/";
        this.readyState = "complete";
        this._el = new Element();
        this.body = new Element();
        this.location = { href: "https://app.example/" };
      }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : new Element(); }
      querySelectorAll(sel) {
        if (sel.includes("script[src]") && scriptSrcs.length) return scriptSrcs.map((s) => new Element({ src: s }));
        return [];
      }
      querySelector() { return null; }
      addEventListener() {}
    }
    const ctx = vm.createContext({
      crypto: crypto.webcrypto,
      SubtleCrypto: sp.constructor,
      TextEncoder: VmTextEncoder,
      TextDecoder,
      Headers: VmHeaders,
      Response: VmResponse,
      Performance: VmPerformance,
      URL, URLSearchParams, Request, console: vmConsole, setTimeout, clearTimeout,
      performance: new VmPerformance(),
      navigator: { webdriver: false },
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement, ShadowRoot,
      location: { origin: "https://app.example", href: "https://app.example/" },
      fetch: vmFetch,
      addEventListener() {},
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader", "get stack"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return ""; } }, "stack"));' : ""}
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, getCloneCalls: () => cloneCalls, resetCloneCalls: () => { cloneCalls = 0; } };
  };

  const makeHs21 = (onApi) => async (url, init, VmResponse) => {
    const sUrl = String(url);
    if (sUrl.endsWith("/__proxysnare/boot")) {
      return new VmResponse(JSON.stringify(eng21.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (sUrl.endsWith("/__proxysnare/handshake")) {
      const body = JSON.parse(init.body);
      const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|${body.browserProof?.d || ""}`).digest("hex");
      const s = eng21.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
      return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (onApi) {
      const custom = onApi(sUrl, init, VmResponse);
      if (custom) return custom;
    }
    return new VmResponse("{}", { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "a".repeat(32) } });
  };

  // 1) Security HIGH #1 & LOW #4: Nested eval(//# sourceURL=app.js) -> new Function -> Promise.then MUST emit ce=1,
  //    while real loaded alpine.js calling new Function('... //# sourceURL=...') stays 0-FP ce=0!
  let evCtx = "";
  const vmEv = makeVm21({
    cdpOpen: true,
    rtEntries: [
      { name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 },
      { name: "https://app.example/alpine.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 },
    ],
    fetchImpl: makeHs21((u, init) => { evCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(
    `const inner = eval('(function appHandler(){ return new Function("return window.fetch(\\'/api/secret\\', { method: \\'POST\\', body: \\'{}\\' });"); })()\\n//# sourceURL=https://app.example/app.js:1:1');
     Promise.resolve().then(inner);`,
    vmEv.ctx
  );
  assert.ok(evCtx.includes("ce=1"), `Nested eval(//# sourceURL=app.js) -> new Function -> Promise.then MUST emit ce=1 (got ${evCtx})`);

  await vm.runInContext(
    `Promise.resolve().then(() => {
      function runAlpine() { return new Function('return window.fetch("/api/data", { method: "POST", body: "{}" });\\n//# sourceURL=https://app.example/alpine.js')(); }
      return runAlpine();
    });`,
    vmEv.ctx,
    { filename: "https://app.example/alpine.js" }
  );
  assert.ok(evCtx.includes("ce=0"), `Real alpine.js new Function() with //# sourceURL= MUST stay 0-FP ce=0 (got ${evCtx})`);

  // 2) Availability HIGH #1: Safari/JSC bare-URL anonymous stack frames with '@' in URL path stay 0-FP ce=0, while spoofed fn@foo.js emits ce=1!
  let safAtCtx = "";
  const vmSafAt = makeVm21({
    cdpOpen: true,
    geckoStack: true,
    guardOpts: { requireGuardIntegrity: false },
    scriptSrcs: ["https://cdn.jsdelivr.net/npm/axios@1.6.0/dist/axios.min.js"],
    rtEntries: [
      { name: "https://cdn.jsdelivr.net/npm/axios@1.6.0/dist/axios.min.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 },
      { name: "https://app.example/@vite/client", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 },
      { name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 },
    ],
    preLoadHook: `
      Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({
        get stack() { return globalThis.__safAtStack; },
      }, "stack"));
    `,
    fetchImpl: makeHs21((u, init) => { safAtCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  for (const bareUrl of [
    "https://cdn.jsdelivr.net/npm/axios@1.6.0/dist/axios.min.js:1:100",
    "https://app.example/@vite/client:42:15",
  ]) {
    vmSafAt.ctx.__safAtStack = `captureConsoleEvalFlag@https://app.example/__proxysnare/guard.js:1:1\nproxySnareFetch@https://app.example/__proxysnare/guard.js:1:1\n${bareUrl}`;
    await vmSafAt.ctx.fetch("/api/saf-ok", { method: "POST", body: "{}" });
    assert.ok(safAtCtx.includes("ce=0"), `Safari bare-URL frame '${bareUrl}' with '@' MUST stay 0-FP ce=0 (got ${safAtCtx})`);
  }
  for (const spoofFrame of [
    "https://app.example/app.js?x=@foo.js:1:1",
    "https://app.example/app.js @foo.js:1:1",
    "https://app.example/app.js@",
  ]) {
    vmSafAt.ctx.__safAtStack = `captureConsoleEvalFlag@https://app.example/__proxysnare/guard.js:1:1\nproxySnareFetch@https://app.example/__proxysnare/guard.js:1:1\n${spoofFrame}`;
    await vmSafAt.ctx.fetch("/api/saf-spoof", { method: "POST", body: "{}" });
    assert.ok(safAtCtx.includes("ce=1"), `Safari spoofed fn-name frame '${spoofFrame}' MUST emit ce=1 (got ${safAtCtx})`);
  }

  // 3) Performance MEDIUM #2: App 403 JSON WITH X-PS-Next-Canary MUST NOT clone/JSON-parse or trigger rehandshake retry!
  let apiCalls = 0;
  const vmApp403 = makeVm21({
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 }],
    fetchImpl: makeHs21((u, init, VmResponse) => {
      apiCalls++;
      return new VmResponse(
        JSON.stringify({ error: "RBAC_DENIED", reasons: ["REPEATER_UNKNOWN_OR_EXPIRED_SESSION"] }),
        { status: 403, headers: { "content-type": "application/json", "x-ps-next-canary": "b".repeat(32) } }
      );
    }),
  });
  await vmApp403.ctx.ProxySnare.ready();
  vmApp403.resetCloneCalls();
  const r403 = await vm.runInContext(
    `function go(){ return window.fetch("/api/rbac", { method: "POST", body: "{}" }); } go();`,
    vmApp403.ctx,
    { filename: "https://app.example/app.js" }
  );
  assert.equal(r403.status, 403);
  assert.equal(apiCalls, 1, "App 403 JSON with X-PS-Next-Canary MUST NOT trigger duplicate rehandshake retry!");
  assert.equal(vmApp403.getCloneCalls(), 0, "App 403 JSON with X-PS-Next-Canary MUST NOT clone/parse body while holding reqChain!");

  // 4) Availability MEDIUM #2: HEAD /health, /guard.js, /gate.js return 200 with Content-Length & empty body under wildcard & unified mode!
  const up21 = http.createServer((req, res) => { res.writeHead(200); res.end("ok"); });
  await new Promise((r) => up21.listen(0, "127.0.0.1", r));
  const uni21 = createUnifiedShield({
    target: `http://127.0.0.1:${up21.address().port}`,
    mode: "strict",
    protectedPaths: ["*"],
    secret: "pass21-unified-head-secret-32b!!",
  });
  await uni21.listen(0, "127.0.0.1");
  try {
    const port = uni21.server.address().port;
    for (const p of ["/__proxysnare/health", "/__proxysnare/guard.js", "/__veilbreak/health", "/__veilbreak/gate.js"]) {
      const hr = await new Promise((resolve, reject) => {
        const r = http.request({ host: "127.0.0.1", port, method: "HEAD", path: p, headers: { "user-agent": "curl/8.5.0" } }, (resp) => {
          let body = "";
          resp.on("data", (c) => (body += c));
          resp.on("end", () => resolve({ status: resp.statusCode, headers: resp.headers, body }));
        });
        r.on("error", reject);
        r.end();
      });
      assert.equal(hr.status, 200, `HEAD ${p} under wildcard+unified MUST return 200 (got ${hr.status})`);
      assert.ok(Number(hr.headers["content-length"]) > 0, `HEAD ${p} MUST report Content-Length > 0`);
      assert.equal(hr.body, "", `HEAD ${p} MUST return empty body`);
    }
  } finally {
    await uni21.close();
    await new Promise((r) => up21.close(r));
  }
});

test("33. Pass-22 Audit Regressions: unified 1-shot Reflect.apply getter bypass blocked, //# sourceURL=webpack:// blocked under allowDevTools+blockConsoleEval, zero-caller-frame Promise.then(fetch) blocked, INITIAL_DOC_URL blocked without inline scripts, Safari '@' in query/fragment 0-FP, active-session replay 0-byte body skip & extStore skip, compacted unified bundle, and Node/Python base64 sig parity", async () => {
  const { buildBrowserGateScript } = require("../../veilbreak/src/browser-sdk.js");
  const eng22 = createProxySnareEngine({
    mode: "strict",
    protectedPaths: ["/api"],
    handshakePowBits: 0,
    requireGuardIntegrity: true,
    secret: "pass22-regression-secret-32bytes!",
  });

  const makeVm22 = ({
    guardOpts = {},
    rtEntries = [],
    scriptSrcs = [],
    inlineScripts = [],
    locHref = "https://app.example/",
    cdpOpen = false,
    geckoStack = false,
    preLoadHook = null,
    fetchImpl = null,
  } = {}) => {
    const src = buildBrowserGuardScript({
      basePath: "/__proxysnare",
      protectedRules: ["/api"],
      serverVerifyPubB64: eng22.serverVerifyPubB64,
      allowDevTools: false,
      blockCdpActive: false,
      blockConsoleEval: true,
      requireGuardIntegrity: true,
      ...guardOpts,
    });
    const sp = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const sMethods = ["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "verify", "sign", "digest"];
    const origEncode = TextEncoder.prototype.encode;
    const origHdrSet = Headers.prototype.set;
    const origHdrGet = Headers.prototype.get;
    const origHdrHas = Headers.prototype.has;
    const origRespJson = Response.prototype.json;
    class VmTextEncoder extends TextEncoder {}
    VmTextEncoder.prototype.encode = origEncode;
    class VmHeaders extends Headers {}
    VmHeaders.prototype.set = origHdrSet;
    VmHeaders.prototype.get = origHdrGet;
    VmHeaders.prototype.has = origHdrHas;
    class VmResponse extends Response {}
    VmResponse.prototype.json = origRespJson;
    class VmPerformance {
      now() { return Date.now(); }
      getEntriesByType(t) { return t === "resource" ? rtEntries : []; }
    }
    const vmFetch = fetchImpl
      ? function fetch(u, init) { return fetchImpl(u, init, VmResponse); }
      : async function fetch() { return new VmResponse("{}"); };
    const vmConsole = {
      debug: function debug(x) { if (cdpOpen && x && typeof x === "object") void x.stack; },
      log() {},
      warn() {},
    };
    const nativeRefs = new Set([
      ...sMethods.map((m) => sp[m]),
      VmTextEncoder.prototype.encode,
      VmHeaders.prototype.set,
      VmHeaders.prototype.get,
      VmHeaders.prototype.has,
      VmResponse.prototype.json,
      VmPerformance.prototype.getEntriesByType,
      vmFetch,
      crypto.webcrypto.getRandomValues,
      vmConsole.debug,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader", "get stack", "get isTrusted", "webdriver", "platform", "userAgent"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        class Navigator {}
        Object.defineProperty(Navigator.prototype, "webdriver", { configurable: true, get: function webdriver() { return false; } });
        globalThis.Navigator = Navigator;
        globalThis.navigator = Object.create(Navigator.prototype);
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return ""; } }, "stack"));' : ""}
        return globalThis;
      })();`,
      ifrCtx
    );
    class ShadowRoot { appendChild(c) { return c; } }
    class HTMLIFrameElement { get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node {
      constructor(attrs = null) { super(); this._attrs = attrs; }
      get shadowRoot() { return null; }
      attachShadow() { return new ShadowRoot(); }
      getAttribute(n) { return this._attrs && Object.prototype.hasOwnProperty.call(this._attrs, n) ? this._attrs[n] : null; }
      remove() {}
    }
    class Document extends Node {
      constructor() {
        super();
        this.currentScript = null;
        this.baseURI = locHref;
        this.readyState = "complete";
        this._el = new Element();
        this.body = new Element();
        this.location = { href: locHref };
      }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : new Element(); }
      querySelectorAll(sel) {
        if (sel.includes("script[src]") && scriptSrcs.length) return scriptSrcs.map((s) => new Element({ src: s }));
        if (sel === "script:not([src])" && inlineScripts.length) return inlineScripts.map((a) => new Element(a));
        return [];
      }
      querySelector() { return null; }
      addEventListener() {}
    }
    class VmNavigator {}
    Object.defineProperty(VmNavigator.prototype, "webdriver", { get: function webdriver() { return false; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "platform", { get: function platform() { return "Linux x86_64"; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "userAgent", { get: function userAgent() { return CHROME_UA; }, configurable: true });
    const navInst = Object.create(VmNavigator.prototype);
    navInst.hardwareConcurrency = 8;
    navInst.maxTouchPoints = 0;
    const ctx = vm.createContext({
      crypto: crypto.webcrypto,
      SubtleCrypto: sp.constructor,
      TextEncoder: VmTextEncoder,
      TextDecoder,
      Headers: VmHeaders,
      Response: VmResponse,
      Performance: VmPerformance,
      Navigator: VmNavigator,
      navigator: navInst,
      HTMLCanvasElement: { prototype: { toDataURL: function toDataURL() { return ""; } } },
      CanvasRenderingContext2D: { prototype: { getImageData: function getImageData() { return { data: [] }; } } },
      URL, URLSearchParams, Request, console: vmConsole, setTimeout, clearTimeout,
      performance: new VmPerformance(),
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement, ShadowRoot,
      location: { origin: new URL(locHref).origin, href: locHref, pathname: new URL(locHref).pathname },
      fetch: vmFetch,
      addEventListener() {},
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader", "get stack", "get isTrusted", "webdriver", "platform", "userAgent", "toDataURL", "getImageData"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return ""; } }, "stack"));' : ""}
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, src };
  };

  const makeHs22 = (onApi) => async (url, init, VmResponse) => {
    const sUrl = String(url);
    if (sUrl.endsWith("/__proxysnare/boot")) {
      return new VmResponse(JSON.stringify(eng22.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (sUrl.endsWith("/__proxysnare/handshake")) {
      const body = JSON.parse(init.body);
      const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|${body.browserProof?.d || ""}`).digest("hex");
      const s = eng22.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
      return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (onApi) onApi(sUrl, init);
    return new VmResponse("{}", { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "a".repeat(32) } });
  };

  // 1) Security HIGH #1 & Performance MEDIUM #3: Unified 1-shot Reflect.apply preload getter MUST fail closed as PROXYSNARE_GUARD_TAMPERED, and unified bundle is compacted!
  const embVb22 = buildBrowserGateScript({ defaultMode: "strict", unified: true, embedded: true, _shareBaseRealm: true, includeTicketPow: false });
  const vmOneShot = makeVm22({
    guardOpts: { requireVeilBreak: true, embeddedVeilBreakScript: embVb22, allowDevTools: false, blockCdpActive: true, blockConsoleEval: true, requireGuardIntegrity: true },
    preLoadHook: `
      const _origApply = Reflect.apply;
      const _spyApply = function apply(t, thisArg, args) { return _origApply(t, thisArg, args); };
      let fired = false;
      Object.defineProperty(Reflect, "apply", {
        configurable: true,
        get() {
          if (!fired) {
            fired = true;
            Object.defineProperty(Reflect, "apply", { value: _origApply, writable: true, configurable: true });
            return _spyApply;
          }
          return _origApply;
        },
      });
    `,
    fetchImpl: makeHs22(),
  });
  assert.ok(vmOneShot.src.length < 245_000, `Compacted unified guard.js MUST be significantly smaller than 282KB (got ${vmOneShot.src.length} bytes)`);
  assert.equal(vmOneShot.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", "1-shot preload Reflect.apply getter MUST fail guardHash()!");
  await assert.rejects(() => vmOneShot.ctx.ProxySnare.ready(), /PROXYSNARE_GUARD_TAMPERED/, "Unified cold boot MUST NOT cache valid guardHash when ProxySnare's _reflectApply was hooked via 1-shot getter!");

  // 2) Security HIGH #2: //# sourceURL=webpack:// MUST emit ce=1 when allowDevTools:true && blockConsoleEval:true!
  let wpBypassCtx = "";
  const vmWpBypass = makeVm22({
    cdpOpen: true,
    guardOpts: { allowDevTools: true, blockCdpActive: false, blockConsoleEval: true },
    fetchImpl: makeHs22((u, init) => { wpBypassCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`Promise.resolve().then(() => window.fetch("/api/wp-bypass", { method: "POST", body: "{}" }));\n//# sourceURL=webpack://x/y.js`, vmWpBypass.ctx);
  assert.ok(wpBypassCtx.includes("ce=1"), `//# sourceURL=webpack:// MUST NOT bypass blockConsoleEval:true when allowDevTools:true (got ${wpBypassCtx})`);

  // 3) Security HIGH #3: Zero-caller-frame Promise.resolve("/api/zero").then(window.fetch) MUST emit ce=1 even when cdpOpen:false!
  let zeroCtx = "";
  const vmZero = makeVm22({
    cdpOpen: false,
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    fetchImpl: makeHs22((u, init) => { zeroCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`Promise.resolve("/api/zero").then(window.fetch);`, vmZero.ctx);
  assert.ok(zeroCtx.includes("ce=1"), `Zero-caller-frame Promise.resolve(url).then(fetch) MUST fail closed to ce=1 (got ${zeroCtx})`);

  // 4) Security MEDIUM #4: INITIAL_DOC_URL with !hasInitialInlineScripts and cdpOpen:false MUST emit ce=1!
  let docNoInlineCtx = "";
  const vmDocNoInline = makeVm22({
    cdpOpen: false,
    inlineScripts: [],
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    fetchImpl: makeHs22((u, init) => { docNoInlineCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`Promise.resolve().then(function go(){ return window.fetch("/api/doc-no-inline", { method: "POST", body: "{}" }); });`, vmDocNoInline.ctx, { filename: "https://app.example/" });
  assert.ok(docNoInlineCtx.includes("ce=1"), `INITIAL_DOC_URL without initial inline scripts MUST emit ce=1 even when !cdpFlagged (got ${docNoInlineCtx})`);

  // 5) Availability HIGH #1: Safari/iOS bare-URL stack frames with '@' in query string or fragment stay 0-FP ce=0 with DevTools closed, while spoofed fn@foo.js emits ce=1!
  for (const [locHref, scriptSrcs, rtEntries, frameLine, label] of [
    ["https://app.example/verify?email=alice@example.com", [], [], "https://app.example/verify?email=alice@example.com:12:18", "query email@"],
    ["https://app.example/profile#user@team", [], [], "https://app.example/profile#user@team:12:18", "fragment #user@team"],
    [
      "https://app.example/",
      ["https://app.example/bundle.js?pkg=@scope/ui"],
      [{ name: "https://app.example/bundle.js?pkg=@scope/ui", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 }],
      "https://app.example/bundle.js?pkg=@scope/ui:42:10",
      "script query ?pkg=@scope/ui",
    ],
  ]) {
    let safQCtx = "";
    const vmSafQ = makeVm22({
      cdpOpen: false,
      geckoStack: true,
      locHref,
      scriptSrcs,
      rtEntries,
      inlineScripts: scriptSrcs.length ? [] : [{}],
      guardOpts: { requireGuardIntegrity: false },
      preLoadHook: `Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return globalThis.__safQStack; } }, "stack"));`,
      fetchImpl: makeHs22((u, init) => { safQCtx = init.headers.get("X-PS-Ctx") || ""; }),
    });
    vmSafQ.ctx.__safQStack = `captureConsoleEvalFlag@https://app.example/__proxysnare/guard.js:1:1\nproxySnareFetch@https://app.example/__proxysnare/guard.js:1:1\n${frameLine}`;
    await vmSafQ.ctx.fetch("/api/saf-q", { method: "POST", body: "{}" });
    assert.ok(safQCtx.includes("ce=0"), `Safari bare-URL with ${label} MUST stay 0-FP ce=0 (got ${safQCtx})`);
  }

  // 6) Performance HIGH #1: Active-session Repeater replay with stale canary / replayed nonce / ce=1 skips 1MB readRequestBody AND extStore.get() skips ce=1 / overrideProtected!
  let storeGets22 = 0;
  const backing22 = new Map();
  const mw22 = createProxySnareMiddleware({
    mode: "strict",
    protectedPaths: ["/api"],
    secret: "pass22-store-secret-32bytes-pad!",
    store: {
      async get(k) { storeGets22++; return backing22.get(k) || null; },
      async set(k, v) { backing22.set(k, v); },
    },
  });
  const cEcdh22 = crypto.createECDH("prime256v1");
  cEcdh22.generateKeys();
  const bt22 = mw22.engine.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const sess22 = mw22.engine.issueSession({
    ip: "127.0.0.1",
    userAgent: CHROME_UA,
    clientPubB64: cEcdh22.getPublicKey().toString("base64"),
    bootToken: bt22.bootToken,
  });
  backing22.set(`ps:sess:${sess22.sessionId}`, mw22.engine.exportSessionRecord(sess22.sessionId));
  // Send a fake Readable stream whose 'data' event throws if readRequestBody tries to buffer the 1MB body!
  const { EventEmitter } = require("node:events");
  const makeUnreadableReq = (extraHdrs = {}, rawHeaders = null) => {
    const req = new EventEmitter();
    let streamRead = false;
    req.method = "POST";
    req.url = "/api/pay";
    req.socket = { remoteAddress: "127.0.0.1" };
    req.headers = makeBrowserHeaders({
      "content-type": "application/json",
      "content-length": "1048576",
      "sec-fetch-site": "same-origin",
      "sec-fetch-mode": "cors",
      "x-ps-session": sess22.sessionId,
      "x-ps-seq": "1",
      "x-ps-ts": String(Date.now()),
      "x-ps-nonce": "0123456789abcdef01234567",
      "x-ps-canary": "f".repeat(32), // STALE CANARY!
      "x-ps-proof": "a".repeat(64),
      ...extraHdrs,
    });
    if (rawHeaders) req.rawHeaders = rawHeaders;
    const origOn = req.on.bind(req);
    req.on = (ev, fn) => { if (ev === "data") streamRead = true; return origOn(ev, fn); };
    req._wasRead = () => streamRead;
    return req;
  };
  let repStatus = 0;
  const reqStale = makeUnreadableReq();
  await mw22(reqStale, { headersSent: false, writableEnded: false, setHeader() {}, writeHead(st) { repStatus = st; this.headersSent = true; }, end() { this.writableEnded = true; } });
  assert.equal(repStatus, 403, "Stale-canary active-session replay MUST return 403!");
  assert.equal(reqStale._wasRead(), false, "Stale-canary active-session replay MUST skip 1MB readRequestBody()!");

  storeGets22 = 0;
  const reqBadSyntax = makeUnreadableReq({ "x-ps-proof": "not-valid-hex" });
  await mw22(reqBadSyntax, { headersSent: false, writableEnded: false, setHeader() {}, writeHead(st) { repStatus = st; this.headersSent = true; }, end() { this.writableEnded = true; } });
  assert.equal(repStatus, 403);
  assert.equal(storeGets22, 0, "Malformed X-PS-Proof MUST skip extStore.get()!");
  assert.equal(reqBadSyntax._wasRead(), false, "Malformed X-PS-Proof MUST skip 1MB readRequestBody()!");

  const reqCe1 = makeUnreadableReq({ "x-ps-canary": sess22.canary, "x-ps-ctx": "ce=1;cdp=1;ug=0;ga=999999" });
  await mw22(reqCe1, { headersSent: false, writableEnded: false, setHeader() {}, writeHead(st) { repStatus = st; this.headersSent = true; }, end() { this.writableEnded = true; } });
  assert.equal(repStatus, 403);
  assert.equal(reqCe1._wasRead(), false, "ce=1 under blockConsoleEval MUST skip 1MB readRequestBody()!");

  // 7) Security LOW #5 + Parity LOW #1: Invalid base64 chars in verifyHandshakeSignature rejected in BOTH Node and Python!
  assert.equal(
    eng22.verifyHandshakeSignature({
      sessionId: sess22.sessionId,
      clientPubB64: cEcdh22.getPublicKey().toString("base64") + "!@#",
      serverPubB64: sess22.serverPubB64,
      saltB64: sess22.saltB64,
      canary: sess22.canary,
      serverSigB64: sess22.serverSigB64,
    }),
    false,
    "Node verifyHandshakeSignature MUST reject invalid Base64 characters!"
  );
  const pySig22 = execFileSync(
    "python3",
    [
      "-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v = ProxySnareVerifier(mode="strict", secret="pass22-py-secret-32bytes-padding!")
assert v.verify_handshake_signature(session_id="s", client_pub_b64="A"*88, server_pub_b64="A"*88, salt_b64="A"*24, canary="a"*32, server_sig_b64="A"*5000) is False
print("PY22_SIG_OK")`,
    ],
    { encoding: "utf8" }
  );
  assert.ok(pySig22.includes("PY22_SIG_OK"));
});

test("34. Pass-23 Audit Regressions: Array.prototype numeric-index setter/getter immunity in captureConsoleEvalFlag & guardHash, threshold>8 pre-body score fail-closed invariant, non-V8 extractFrameLocation extension/sourceURL spoofing fix, app-parented Webpack eval & Safari/JSC nested eval helper 0-FP, and >4KB stale-canary + canonical base64 Node/Python parity", async () => {
  const { buildBrowserGateScript } = require("../../veilbreak/src/browser-sdk.js");
  const eng23 = createProxySnareEngine({
    mode: "strict",
    protectedPaths: ["/api"],
    handshakePowBits: 0,
    requireGuardIntegrity: true,
    secret: "pass23-regression-secret-32bytes!",
  });

  const makeVm23 = ({
    guardOpts = {},
    rtEntries = [],
    scriptSrcs = [],
    inlineScripts = [],
    locHref = "https://app.example/",
    cdpOpen = false,
    geckoStack = false,
    preLoadHook = null,
    fetchImpl = null,
  } = {}) => {
    const src = buildBrowserGuardScript({
      basePath: "/__proxysnare",
      protectedRules: ["/api"],
      serverVerifyPubB64: eng23.serverVerifyPubB64,
      allowDevTools: false,
      blockCdpActive: false,
      blockConsoleEval: true,
      requireGuardIntegrity: true,
      ...guardOpts,
    });
    const sp = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const sMethods = ["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "verify", "sign", "digest"];
    const origEncode = TextEncoder.prototype.encode;
    const origHdrSet = Headers.prototype.set;
    const origHdrGet = Headers.prototype.get;
    const origHdrHas = Headers.prototype.has;
    const origRespJson = Response.prototype.json;
    class VmTextEncoder extends TextEncoder {}
    VmTextEncoder.prototype.encode = origEncode;
    class VmHeaders extends Headers {}
    VmHeaders.prototype.set = origHdrSet;
    VmHeaders.prototype.get = origHdrGet;
    VmHeaders.prototype.has = origHdrHas;
    class VmResponse extends Response {}
    VmResponse.prototype.json = origRespJson;
    class VmPerformance {
      now() { return Date.now(); }
      getEntriesByType(t) { return t === "resource" ? rtEntries : []; }
    }
    const vmFetch = fetchImpl
      ? function fetch(u, init) { return fetchImpl(u, init, VmResponse); }
      : async function fetch() { return new VmResponse("{}"); };
    const vmConsole = {
      debug: function debug(x) { if (cdpOpen && x && typeof x === "object") void x.stack; },
      log() {},
      warn() {},
    };
    const nativeRefs = new Set([
      ...sMethods.map((m) => sp[m]),
      VmTextEncoder.prototype.encode,
      VmHeaders.prototype.set,
      VmHeaders.prototype.get,
      VmHeaders.prototype.has,
      VmResponse.prototype.json,
      VmPerformance.prototype.getEntriesByType,
      vmFetch,
      crypto.webcrypto.getRandomValues,
      vmConsole.debug,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader", "get stack", "get isTrusted", "webdriver", "platform", "userAgent"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        class Navigator {}
        Object.defineProperty(Navigator.prototype, "webdriver", { configurable: true, get: function webdriver() { return false; } });
        globalThis.Navigator = Navigator;
        globalThis.navigator = Object.create(Navigator.prototype);
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return ""; } }, "stack"));' : ""}
        return globalThis;
      })();`,
      ifrCtx
    );
    class ShadowRoot { appendChild(c) { return c; } }
    class HTMLIFrameElement { get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node {
      constructor(attrs = null) { super(); this._attrs = attrs; }
      get shadowRoot() { return null; }
      attachShadow() { return new ShadowRoot(); }
      getAttribute(n) { return this._attrs && Object.prototype.hasOwnProperty.call(this._attrs, n) ? this._attrs[n] : null; }
      remove() {}
    }
    class Document extends Node {
      constructor() {
        super();
        this.currentScript = null;
        this.baseURI = locHref;
        this.readyState = "complete";
        this._el = new Element();
        this.body = new Element();
        this.location = { href: locHref };
      }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : new Element(); }
      querySelectorAll(sel) {
        if (sel.includes("script[src]") && scriptSrcs.length) return scriptSrcs.map((s) => new Element({ src: s }));
        if (sel === "script:not([src])" && inlineScripts.length) return inlineScripts.map((a) => new Element(a));
        return [];
      }
      querySelector() { return null; }
      addEventListener() {}
    }
    class VmNavigator {}
    Object.defineProperty(VmNavigator.prototype, "webdriver", { get: function webdriver() { return false; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "platform", { get: function platform() { return "Linux x86_64"; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "userAgent", { get: function userAgent() { return CHROME_UA; }, configurable: true });
    const navInst = Object.create(VmNavigator.prototype);
    navInst.hardwareConcurrency = 8;
    navInst.maxTouchPoints = 0;
    const ctx = vm.createContext({
      crypto: crypto.webcrypto,
      SubtleCrypto: sp.constructor,
      TextEncoder: VmTextEncoder,
      TextDecoder,
      Headers: VmHeaders,
      Response: VmResponse,
      Performance: VmPerformance,
      Navigator: VmNavigator,
      navigator: navInst,
      HTMLCanvasElement: { prototype: { toDataURL: function toDataURL() { return ""; } } },
      CanvasRenderingContext2D: { prototype: { getImageData: function getImageData() { return { data: [] }; } } },
      URL, URLSearchParams, Request, console: vmConsole, setTimeout, clearTimeout,
      performance: new VmPerformance(),
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement, ShadowRoot,
      location: { origin: new URL(locHref).origin, href: locHref, pathname: new URL(locHref).pathname },
      fetch: vmFetch,
      addEventListener() {},
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader", "get stack", "get isTrusted", "webdriver", "platform", "userAgent", "toDataURL", "getImageData"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return ""; } }, "stack"));' : ""}
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, src };
  };

  const makeHs23 = (onApi) => async (url, init, VmResponse) => {
    const sUrl = String(url);
    if (sUrl.endsWith("/__proxysnare/boot")) {
      return new VmResponse(JSON.stringify(eng23.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (sUrl.endsWith("/__proxysnare/handshake")) {
      const body = JSON.parse(init.body);
      const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|${body.browserProof?.d || ""}`).digest("hex");
      const s = eng23.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
      return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (onApi) onApi(sUrl, init);
    return new VmResponse("{}", { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "a".repeat(32) } });
  };

  // 1) Availability MEDIUM #1 (run before Node http I/O so VM microtask stack stays pure browser-like without node:internal/process/task_queues):
  //    App-parented Webpack eval(//# sourceURL=webpack-internal://...) stays 0-FP ce=0 on V8 under strict + blockCdpActive:false, while unparented Console eval emits ce=1!
  let wpV8Ctx = "";
  const vmWpV8 = makeVm23({
    cdpOpen: true,
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    rtEntries: [{ name: "https://app.example/bundle.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 }],
    fetchImpl: makeHs23((u, init) => { wpV8Ctx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await new Promise((r) => setTimeout(r, 0));
  await vm.runInContext(
    `Promise.resolve().then(function runBundle() {
      return eval('window.fetch("/api/wp-app", { method: "POST", body: "{}" })\\n//# sourceURL=webpack-internal:///./src/api.js');
    });`,
    vmWpV8.ctx,
    { filename: "https://app.example/bundle.js" }
  );
  assert.ok(wpV8Ctx.includes("ce=0"), `V8 app-parented Webpack eval from bundle.js MUST stay 0-FP ce=0 (got ${wpV8Ctx})`);
  await vm.runInContext(
    `eval('window.fetch("/api/wp-console", { method: "POST", body: "{}" })\\n//# sourceURL=webpack-internal:///./src/api.js');`,
    vmWpV8.ctx
  );
  assert.ok(wpV8Ctx.includes("ce=1"), `V8 unparented Console Webpack eval MUST emit ce=1 (got ${wpV8Ctx})`);

  // 1b) Security HIGH #1: Transient Array.prototype["0"]/["1"] setters before Console fetch() & deleted synchronously MUST NOT forge ce=0!
  let apCtx = "";
  const vmAp = makeVm23({
    cdpOpen: true,
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 }],
    fetchImpl: makeHs23((u, init) => { apCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(
    `(() => {
      Error.prepareStackTrace = (_, s) => s;
      const realSite = (function fakeApp(){ return new Error().stack; })()[0];
      Error.prepareStackTrace = undefined;
      Object.defineProperty(Array.prototype, "0", {
        configurable: true,
        get() { return { s: realSite, file: "https://app.example/app.js", isEv: false, isNat: false, isPa: false, isWp: false, isV8AsyncComb: false, isV8Builtin: false, isAnon: false }; },
        set() {},
      });
      Object.defineProperty(Array.prototype, "1", { configurable: true, get() { return undefined; }, set() {} });
      const p = window.fetch("/api/ap-v8", { method: "POST", body: "{}" });
      delete Array.prototype["0"];
      delete Array.prototype["1"];
      return p;
    })();`,
    vmAp.ctx
  );
  assert.ok(apCtx.includes("ce=1"), `Transient Array.prototype["0"] setter MUST NOT spoof ce=0 on V8 CallSite path (got ${apCtx})`);

  // 2) Security HIGH #2: Preload Array.prototype index setter (index 76 standalone, index 11 unified) MUST NOT drop dynamic native checks!
  const vmSet76 = makeVm23({
    preLoadHook: `
      const origF = window.fetch;
      window.fetch = function fetch(u, i) { return origF(u, i); };
      Object.defineProperty(Array.prototype, "76", { configurable: true, get() { return undefined; }, set() {} });
    `,
    fetchImpl: makeHs23(),
  });
  assert.equal(vmSet76.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", "Preload Array.prototype['76'] setter + hooked fetch MUST return TAMPERED_GUARD!");
  const embVb23 = buildBrowserGateScript({ defaultMode: "strict", unified: true, embedded: true, _shareBaseRealm: true, includeTicketPow: false });
  const vmSet11 = makeVm23({
    guardOpts: { requireVeilBreak: true, embeddedVeilBreakScript: embVb23 },
    preLoadHook: `
      const origF = window.fetch;
      window.fetch = function fetch(u, i) { return origF(u, i); };
      Object.defineProperty(Array.prototype, "11", { configurable: true, get() { return undefined; }, set() {} });
    `,
    fetchImpl: makeHs23(),
  });
  assert.equal(vmSet11.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", "Unified preload Array.prototype['11'] setter + hooked fetch MUST return TAMPERED_GUARD!");

  // 3) Security HIGH #3: threshold > 8 (e.g. 10) with invalid X-PS-Seq + forged X-PS-Proof MUST fail closed 403 and NEVER reach backend!
  const mwT10 = createProxySnareMiddleware({ mode: "strict", threshold: 10, protectedPaths: ["/api"], secret: "pass23-t10-secret-32bytes-padded!" });
  let backendReached = false;
  const srvT10 = http.createServer(async (req, res) => {
    if (await mwT10(req, res)) return;
    backendReached = true;
    res.writeHead(200);
    res.end("BYPASSED");
  });
  await new Promise((r) => srvT10.listen(0, "127.0.0.1", r));
  try {
    const port10 = srvT10.address().port;
    const s10 = mwT10.engine.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
    const rBadSeq = await fetch(`http://127.0.0.1:${port10}/api/transfer`, {
      method: "POST",
      headers: makeBrowserHeaders({
        "content-type": "application/json",
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
        "x-ps-session": s10.sessionId,
        "x-ps-seq": "notanumber",
        "x-ps-ts": String(Date.now()),
        "x-ps-nonce": "0123456789abcdef01234567",
        "x-ps-canary": s10.canary,
        "x-ps-proof": "0".repeat(64),
      }),
      body: JSON.stringify({ to: "attacker", amount: 999999 }),
    });
    assert.equal(rBadSeq.status, 403, "Invalid X-PS-Seq + forged X-PS-Proof under threshold:10 MUST return 403 (never 200 bypass!)");
    assert.equal(backendReached, false, "Backend handler MUST NOT be reached on forged POST under threshold:10!");

    // Multi-worker extStore: Worker 2 receives active session ONLY in extStore with bad seq + ce=1/ik=1 + forged proof under threshold:10 ->
    // MUST load session from extStore (never skip extStore.get()!) and fail closed 403!
    const distBacking = new Map();
    const w1Eng = createProxySnareEngine({ mode: "strict", threshold: 10, protectedPaths: ["/api"], secret: "pass23-t10-dist-secret-32bytes!!" });
    const w1Sess = w1Eng.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
    distBacking.set(`ps:sess:${w1Sess.sessionId}`, w1Eng.exportSessionRecord(w1Sess.sessionId));
    const mwW2 = createProxySnareMiddleware({
      mode: "strict",
      threshold: 10,
      protectedPaths: ["/api"],
      secret: "pass23-t10-dist-secret-32bytes!!",
      store: { async get(k) { return distBacking.get(k) || null; }, async set(k, v) { distBacking.set(k, v); } },
    });
    let w2Reached = false;
    const srvW2 = http.createServer(async (req, res) => {
      if (await mwW2(req, res)) return;
      w2Reached = true;
      res.writeHead(200);
      res.end("BYPASSED_W2");
    });
    await new Promise((r) => srvW2.listen(0, "127.0.0.1", r));
    try {
      const rW2 = await fetch(`http://127.0.0.1:${srvW2.address().port}/api/transfer`, {
        method: "POST",
        headers: makeBrowserHeaders({
          "content-type": "application/json",
          "sec-fetch-site": "same-origin",
          "sec-fetch-mode": "cors",
          "x-ps-session": w1Sess.sessionId,
          "x-ps-seq": "notanumber",
          "x-ps-ts": String(Date.now()),
          "x-ps-nonce": "0123456789abcdef01234568",
          "x-ps-canary": w1Sess.canary,
          "x-ps-ctx": "ce=1;cdp=0;ug=0;ga=999999;ik=1",
          "x-ps-proof": "0".repeat(64),
        }),
        body: JSON.stringify({ to: "attacker", amount: 1 }),
      });
      assert.equal(rW2.status, 403, "Multi-worker Worker-2 MUST load extStore session and block 403 under threshold:10!");
      assert.equal(w2Reached, false, "Worker-2 backend MUST NOT be reached!");
    } finally {
      await new Promise((r) => srvW2.close(r));
    }

    // Verify hard fail-closed invariant directly on inspectRequest({ bodySkipped: true, threshold: 10 })
    const rForcedSkip = mwT10.engine.inspectRequest({
      method: "POST",
      url: "/api/transfer",
      body: Buffer.alloc(0),
      bodySkipped: true,
      headers: makeBrowserHeaders({
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
        "x-ps-session": "f".repeat(32),
        "x-ps-seq": "1",
        "x-ps-ts": String(Date.now()),
        "x-ps-nonce": "0123456789abcdef01234569",
        "x-ps-canary": "a".repeat(32),
        "x-ps-proof": "0".repeat(64),
      }),
    });
    assert.equal(rForcedSkip.blocked, true, "inspectRequest with bodySkipped:true in enforcing mode MUST ALWAYS fail closed even when threshold > 8!");
    assert.ok(rForcedSkip.score >= 10);
  } finally {
    await new Promise((r) => srvT10.close(r));
  }

  // 4) Security MEDIUM #4 + Availability MEDIUM #1 (Gecko/WebKit) + Availability LOW #2:
  //    (a) Non-V8 function-name spoofing with moz-extension://, safari-web-extension://, about:blank, bare sourceURL emits ce=1!
  //    (b) Gecko/WebKit app-parented Webpack eval stays 0-FP ce=0 under strict + blockCdpActive:false!
  //    (c) Safari/JSC nested "@" / "foo@" above "eval code@" + verified parent stays 0-FP ce=0!
  let nonV8Ctx = "";
  const vmNonV8 = makeVm23({
    cdpOpen: true,
    geckoStack: true,
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true, requireGuardIntegrity: false },
    rtEntries: [
      { name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 },
      { name: "https://app.example/bundle.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 },
      { name: "https://app.example/@vite/client", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 },
    ],
    preLoadHook: `Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return globalThis.__nv8Stack; } }, "stack"));`,
    fetchImpl: makeHs23((u, init) => { nonV8Ctx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  for (const [label, stackBody] of [
    ["moz-extension spoof", "x@https://app.example/app.js:1:1 @moz-extension://1234/content.js:10:5"],
    ["safari-web-extension spoof", "x@https://app.example/app.js:1:1 @safari-web-extension://1234/c.js:10:5"],
    ["about:blank spoof", "x@https://app.example/app.js:1:1 @about:blank:1:1"],
    ["bare sourceURL space spoof", "x@https://app.example/app.js:1:1 @foo:1:12"],
    ["bare sourceURL query spoof", "x@https://app.example/app.js?a=1@foo:1:12"],
    ["bare sourceURL hash spoof", "x@https://app.example/app.js#a@foo:1:12"],
    ["unparented webpack-internal", "run@webpack-internal:///./src/api.js:5:12"],
    ["unparented JSC arrow", "@\nglobal code@"],
  ]) {
    vmNonV8.ctx.__nv8Stack = `captureConsoleEvalFlag@https://app.example/__proxysnare/guard.js:1:1\nproxySnareFetch@https://app.example/__proxysnare/guard.js:1:1\n${stackBody}`;
    await vmNonV8.ctx.fetch("/api/nv8-block", { method: "POST", body: "{}" });
    assert.ok(nonV8Ctx.includes("ce=1"), `Non-V8 ${label} MUST emit ce=1 (got ${nonV8Ctx})`);
  }
  for (const [label, stackBody] of [
    ["Firefox @vite eval", "anonymous@https://app.example/@vite/client line 10 > eval:1:1\nrun@https://app.example/@vite/client:10:5"],
    ["Gecko app-parented webpack-internal", "fetchData@webpack-internal:///./src/api.js:5:12\nonClick@https://app.example/bundle.js:100:5"],
    ["Safari/JSC nested arrow inside app-parented eval", "@\neval code@\nrun@https://app.example/app.js:10:5"],
    ["Safari/JSC nested named fn inside app-parented new Function", "helper@\nanonymous@\nrun@https://app.example/app.js:10:5"],
  ]) {
    vmNonV8.ctx.__nv8Stack = `captureConsoleEvalFlag@https://app.example/__proxysnare/guard.js:1:1\nproxySnareFetch@https://app.example/__proxysnare/guard.js:1:1\n${stackBody}`;
    await vmNonV8.ctx.fetch("/api/nv8-ok", { method: "POST", body: "{}" });
    assert.ok(nonV8Ctx.includes("ce=0"), `Non-V8 ${label} MUST stay 0-FP ce=0 (got ${nonV8Ctx})`);
  }

  // 5) Parity MEDIUM #1 + Perf LOW #1 + Parity LOW #1: >4KB stale-canary POST has exact Node/Python parity (NO spurious REPEATER_BODY_OR_PATH_TAMPERED!),
  //    AND Python rejects non-canonical base64 trailing unused bits matching Node!
  const bigPayload = "x".repeat(5000);
  for (const mode23 of ["monitor", "strict"]) {
    const eMode = createProxySnareEngine({ mode: mode23, protectedPaths: ["/api"], secret: "pass23-parity-secret-32bytes-pad!" });
    const sMode = eMode.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
    const ts23 = String(Date.now());
    const staleCanary = "f".repeat(32);
    const validProof = eMode.signRequest({
      sessionKeyHex: sMode.sessionKeyHex,
      method: "POST",
      pathWithQuery: "/api/big",
      body: bigPayload,
      seq: "1",
      ts: ts23,
      nonce: "0123456789abcdef01234567",
      canary: staleCanary,
    });
    const rNode = eMode.inspectRequest({
      method: "POST",
      url: "/api/big",
      body: bigPayload,
      headers: makeBrowserHeaders({
        "sec-fetch-site": "same-origin",
        "sec-fetch-mode": "cors",
        "x-ps-session": sMode.sessionId,
        "x-ps-seq": "1",
        "x-ps-ts": ts23,
        "x-ps-nonce": "0123456789abcdef01234567",
        "x-ps-canary": staleCanary,
        "x-ps-proof": validProof,
      }),
    });
    const codes = rNode.reasons.map((r) => r.code);
    assert.equal(rNode.score, 8, `Node ${mode23} 5KB stale-canary POST MUST score 8 (got ${rNode.score}: ${codes})`);
    assert.ok(codes.includes("REPEATER_STALE_CANARY") && !codes.includes("REPEATER_BODY_OR_PATH_TAMPERED"), `Node ${mode23} MUST NOT emit spurious REPEATER_BODY_OR_PATH_TAMPERED (got ${codes})`);
  }

  const py23 = execFileSync(
    "python3",
    [
      "-c",
      `import sys, time; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier, _p256_decode_uncompressed, _p256_encode_uncompressed, _P256_G
for m in ("monitor", "strict"):
    v = ProxySnareVerifier(mode=m, protected_paths=["/api"], secret="pass23-parity-secret-32bytes-pad!")
    s = v.issue_session(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)})
    assert "key_hex" not in v._sessions[s["sessionId"]], "Unused key_hex must not be stored in session dict"
    ts = str(int(time.time() * 1000))
    body = b"x" * 5000
    stale = "f" * 32
    pf = v.sign_request(session_key_hex=s["sessionKeyHex"], method="POST", path_with_query="/api/big", body=body, seq="1", ts=ts, nonce="0123456789abcdef01234567", canary=stale)
    r = v.inspect_request(method="POST", url="/api/big", body=body, headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors", "X-PS-Session": s["sessionId"], "X-PS-Seq": "1", "X-PS-Ts": ts, "X-PS-Nonce": "0123456789abcdef01234567", "X-PS-Canary": stale, "X-PS-Proof": pf})
    codes = [x["code"] for x in r.reasons]
    assert r.score == 8 and "REPEATER_STALE_CANARY" in codes and "REPEATER_BODY_OR_PATH_TAMPERED" not in codes, f"Python {m} mismatch: {r}"
# Canonical base64 trailing-bit rejection parity
b64_ok = _p256_encode_uncompressed(_P256_G)
assert _p256_decode_uncompressed(b64_ok) is not None
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
idx = alphabet.index(b64_ok[86])
b64_bad = b64_ok[:86] + alphabet[idx ^ 1] + b64_ok[87:]
assert _p256_decode_uncompressed(b64_bad) is None, "Non-canonical base64 trailing bit MUST be rejected!"
v2 = ProxySnareVerifier(mode="strict", secret="pass23-parity-secret-32bytes-pad!")
hs = v2.issue_session(ip="127.0.0.1", user_agent=${JSON.stringify(CHROME_UA)}, client_pub_b64=b64_ok, boot_token="bt1")
sig_ok = hs["serverSigB64"]
assert v2.verify_handshake_signature(session_id=hs["sessionId"], client_pub_b64=b64_ok, server_pub_b64=hs["serverPubB64"], salt_b64=hs["saltB64"], boot_token="bt1", server_now_ms=hs["serverNowMs"], canary=hs["canary"], server_sig_b64=sig_ok) is True
s_idx = alphabet.index(sig_ok[85])
sig_bad = sig_ok[:85] + alphabet[s_idx ^ 1] + sig_ok[86:]
assert v2.verify_handshake_signature(session_id=hs["sessionId"], client_pub_b64=b64_ok, server_pub_b64=hs["serverPubB64"], salt_b64=hs["saltB64"], boot_token="bt1", server_now_ms=hs["serverNowMs"], canary=hs["canary"], server_sig_b64=sig_bad) is False, "Non-canonical sig trailing bit MUST be rejected!"
print("PY23_OK")`,
    ],
    { encoding: "utf8" }
  );
  assert.ok(py23.includes("PY23_OK"));
});

test("35. Pass-24 Audit Regressions: mutable global constructor decoys, deleted HTMLIFrameElement/Element, Promise.all combinator-only Console bypass, unified __PS_SYNC_CDP__ TDZ fix, allowDevTools+blockConsoleEval fail-closed, multi-worker blocked valid-HMAC nonce burn, 302 CDN + extension-wrapper 0-FP, aborted cold-handshake session preservation, U+3000 guardHash, onkeydown inline handler & issueSession canonical base64", async () => {
  const { buildBrowserGateScript } = require("../../veilbreak/src/browser-sdk.js");
  const eng24 = createProxySnareEngine({
    mode: "strict",
    protectedPaths: ["/api"],
    handshakePowBits: 0,
    requireGuardIntegrity: true,
    secret: "pass24-regression-secret-32bytes!",
  });

  const makeVm24 = ({
    guardOpts = {},
    rtEntries = [],
    scriptSrcs = [],
    inlineScripts = [],
    hasOnKeyDownEl = false,
    locHref = "https://app.example/",
    cdpOpen = false,
    geckoStack = false,
    preLoadHook = null,
    fetchImpl = null,
    ifrExposeWebIdl = true,
  } = {}) => {
    const src = buildBrowserGuardScript({
      basePath: "/__proxysnare",
      protectedRules: ["/api"],
      serverVerifyPubB64: eng24.serverVerifyPubB64,
      allowDevTools: false,
      blockCdpActive: false,
      blockConsoleEval: true,
      requireGuardIntegrity: true,
      ...guardOpts,
    });
    const sp = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const sMethods = ["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "verify", "sign", "digest"];
    const origEncode = TextEncoder.prototype.encode;
    const origHdrSet = Headers.prototype.set;
    const origHdrGet = Headers.prototype.get;
    const origHdrHas = Headers.prototype.has;
    const origRespJson = Response.prototype.json;
    class VmTextEncoder extends TextEncoder {}
    VmTextEncoder.prototype.encode = origEncode;
    class VmHeaders extends Headers {}
    VmHeaders.prototype.set = origHdrSet;
    VmHeaders.prototype.get = origHdrGet;
    VmHeaders.prototype.has = origHdrHas;
    class VmResponse extends Response {}
    VmResponse.prototype.json = origRespJson;
    class VmPerformance {
      now() { return Date.now(); }
      getEntriesByType(t) { return t === "resource" ? rtEntries : []; }
    }
    const vmFetch = fetchImpl
      ? function fetch(u, init) { return fetchImpl(u, init, VmResponse); }
      : async function fetch() { return new VmResponse("{}"); };
    const vmConsole = {
      debug: function debug(x) { if (cdpOpen && x && typeof x === "object") void x.stack; },
      log() {},
      warn() {},
    };
    const nativeRefs = new Set([
      ...sMethods.map((m) => sp[m]),
      VmTextEncoder.prototype.encode,
      VmHeaders.prototype.set,
      VmHeaders.prototype.get,
      VmHeaders.prototype.has,
      VmResponse.prototype.json,
      VmPerformance.prototype.getEntriesByType,
      vmFetch,
      crypto.webcrypto.getRandomValues,
      vmConsole.debug,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader", "get stack", "get isTrusted", "webdriver", "platform", "userAgent"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        class Navigator {}
        Object.defineProperty(Navigator.prototype, "webdriver", { configurable: true, get: function webdriver() { return false; } });
        globalThis.Navigator = Navigator;
        globalThis.navigator = Object.create(Navigator.prototype);
        ${ifrExposeWebIdl ? `
        class HTMLIFrameElement {}
        class Element { attachShadow() { return {}; } }
        class HTMLCanvasElement { toDataURL() { return ""; } }
        class CanvasRenderingContext2D { getImageData() { return { data: [] }; } }
        globalThis.HTMLIFrameElement = HTMLIFrameElement;
        globalThis.Element = Element;
        globalThis.HTMLCanvasElement = HTMLCanvasElement;
        globalThis.CanvasRenderingContext2D = CanvasRenderingContext2D;
        ` : ""}
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return ""; } }, "stack"));' : ""}
        return globalThis;
      })();`,
      ifrCtx
    );
    class ShadowRoot { appendChild(c) { return c; } }
    class HTMLIFrameElement { get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node {
      constructor(attrs = null) { super(); this._attrs = attrs; }
      get shadowRoot() { return null; }
      attachShadow() { return new ShadowRoot(); }
      getAttribute(n) { return this._attrs && Object.prototype.hasOwnProperty.call(this._attrs, n) ? this._attrs[n] : null; }
      remove() {}
    }
    class Document extends Node {
      constructor() {
        super();
        this.currentScript = null;
        this.baseURI = locHref;
        this.readyState = "complete";
        this._el = new Element();
        this.body = new Element();
        this.location = { href: locHref };
      }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : new Element(); }
      querySelectorAll(sel) {
        if (sel.includes("script[src]") && scriptSrcs.length) return scriptSrcs.map((s) => new Element({ src: s }));
        if (sel === "script:not([src])" && inlineScripts.length) return inlineScripts.map((a) => new Element(a));
        return [];
      }
      querySelector(sel) {
        if (hasOnKeyDownEl && sel.includes("[onkeydown]")) return new Element({ onkeydown: "go()" });
        return null;
      }
      addEventListener() {}
    }
    class VmNavigator {}
    Object.defineProperty(VmNavigator.prototype, "webdriver", { get: function webdriver() { return false; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "platform", { get: function platform() { return "Linux x86_64"; }, configurable: true });
    Object.defineProperty(VmNavigator.prototype, "userAgent", { get: function userAgent() { return CHROME_UA; }, configurable: true });
    const navInst = Object.create(VmNavigator.prototype);
    navInst.hardwareConcurrency = 8;
    navInst.maxTouchPoints = 0;
    class VmCanvas { toDataURL() { return ""; } }
    class VmCtx2d { getImageData() { return { data: [] }; } }
    const ctx = vm.createContext({
      crypto: crypto.webcrypto,
      SubtleCrypto: sp.constructor,
      TextEncoder: VmTextEncoder,
      TextDecoder,
      Headers: VmHeaders,
      Response: VmResponse,
      Performance: VmPerformance,
      Navigator: VmNavigator,
      navigator: navInst,
      HTMLCanvasElement: VmCanvas,
      CanvasRenderingContext2D: VmCtx2d,
      URL, URLSearchParams, Request, DOMException, console: vmConsole, setTimeout, clearTimeout,
      performance: new VmPerformance(),
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement, ShadowRoot,
      location: { origin: new URL(locHref).origin, href: locHref, pathname: new URL(locHref).pathname },
      fetch: vmFetch,
      addEventListener() {},
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader", "get stack", "get isTrusted", "webdriver", "platform", "userAgent", "toDataURL", "getImageData"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return ""; } }, "stack"));' : ""}
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, src };
  };

  const makeHs24 = (onApi, onHs = null) => async (url, init, VmResponse) => {
    const sUrl = String(url);
    if (sUrl.endsWith("/__proxysnare/boot")) {
      return new VmResponse(JSON.stringify(eng24.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (sUrl.endsWith("/__proxysnare/handshake")) {
      if (onHs) await onHs(sUrl, init);
      const body = JSON.parse(init.body);
      const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|${body.browserProof?.d || ""}`).digest("hex");
      const s = eng24.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
      return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (onApi) onApi(sUrl, init);
    return new VmResponse("{}", { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "a".repeat(32) } });
  };

  // 1) Security HIGH #3 + Security MEDIUM #2: Promise.all([Promise.resolve(url).then(fetch)]) combinator-only stack MUST emit ce=1 even when cdpOpen:false,
  //    AND { allowDevTools: true, blockConsoleEval: true } MUST fail closed to ce=1 when cdpOpen:false!
  let combCtx = "";
  const vmComb = makeVm24({
    cdpOpen: false,
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    fetchImpl: makeHs24((u, init) => { combCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`Promise.all([Promise.resolve("/api/comb").then(window.fetch)]);`, vmComb.ctx);
  assert.ok(combCtx.includes("ce=1"), `Promise.all([Promise.resolve(url).then(fetch)]) MUST emit ce=1 (got ${combCtx})`);

  let allowDtCeCtx = "";
  const vmAllowDtCe = makeVm24({
    cdpOpen: false,
    guardOpts: { allowDevTools: true, blockCdpActive: false, blockConsoleEval: true },
    fetchImpl: makeHs24((u, init) => { allowDtCeCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await vm.runInContext(`Promise.all([Promise.resolve("/api/dt-ce").then(window.fetch)]);`, vmAllowDtCe.ctx);
  assert.ok(allowDtCeCtx.includes("ce=1"), `allowDevTools:true + blockConsoleEval:true MUST fail closed ce=1 when CDP probe does not trip (got ${allowDtCeCtx})`);

  // 2) Security HIGH #1: Mutable global constructor decoys (window.Object/Array/RegExp/Symbol/CryptoKey/ArrayBuffer/Response) MUST fail guardHash()!
  const vmDecoy = makeVm24({ fetchImpl: makeHs24() });
  const expDecoyHash = computeGuardIntegrity(vmDecoy.src).guardHash;
  assert.equal(vmDecoy.ctx.ProxySnare.guardHash(), expDecoyHash, "Clean VM MUST produce valid expected guardHash before decoy swap");
  vm.runInContext(`
    const RealObj = Object;
    const realObjProto = RealObj.prototype;
    const DecoyObj = function Object() {};
    DecoyObj.prototype = RealObj.create(null);
    DecoyObj.create = RealObj.create;
    DecoyObj.defineProperty = RealObj.defineProperty;
    DecoyObj.getOwnPropertyNames = RealObj.getOwnPropertyNames;
    DecoyObj.getOwnPropertyDescriptor = RealObj.getOwnPropertyDescriptor;
    DecoyObj.getPrototypeOf = RealObj.getPrototypeOf;
    window.Object = DecoyObj;
    realObjProto.then = function(r) { r(this); };
  `, vmDecoy.ctx);
  assert.equal(vmDecoy.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", "Decoy window.Object + real Object.prototype.then MUST fail closed as TAMPERED_GUARD!");

  const vmSymNull = makeVm24({ fetchImpl: makeHs24() });
  vm.runInContext(`window.Symbol = null;`, vmSymNull.ctx);
  assert.equal(vmSymNull.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", "Setting window.Symbol = null MUST fail closed as TAMPERED_GUARD!");

  // 3) Security HIGH #2: Deleting window.HTMLIFrameElement or window.Element before load MUST fail closed as TAMPERED_GUARD!
  for (const [label, hook] of [
    ["delete window.HTMLIFrameElement", "delete window.HTMLIFrameElement;"],
    ["delete window.Element", "delete window.Element;"],
  ]) {
    const vmDelDom = makeVm24({ preLoadHook: hook, fetchImpl: makeHs24() });
    assert.equal(vmDelDom.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", `Pre-load ${label} MUST fail closed as TAMPERED_GUARD!`);
  }

  // 4) Security MEDIUM #1 + Perf MEDIUM #1: Unified guard.js with autoBlockPage:true + document.readyState==="complete" + active CDP
  //    MUST NOT hit TDZ ReferenceError in __PS_SYNC_CDP__ AND MUST finish wrapping window.fetch synchronously before VeilBreak probes run!
  const embVb24 = buildBrowserGateScript({ defaultMode: "strict", unified: true, embedded: true, _shareBaseRealm: true, autoBlockPage: true, antiCdp: true, allowDevTools: false, includeTicketPow: false });
  let uniCdpCtx = "";
  const vmUniTdz = makeVm24({
    cdpOpen: true,
    guardOpts: { requireVeilBreak: true, embeddedVeilBreakScript: embVb24, allowDevTools: false, blockCdpActive: false, blockConsoleEval: true },
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 }],
    fetchImpl: makeHs24((u, init) => { uniCdpCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  assert.equal(vmUniTdz.ctx.fetch.name, "proxySnareFetch", "Unified guard.js MUST wrap window.fetch synchronously before deferred runPageBlock");
  // Wait for deferred setTimeout(runPageBlock, 0) to sync CDP into ProxySnare without throwing TDZ!
  await new Promise((r) => setTimeout(r, 25));
  assert.equal(vmUniTdz.ctx.ProxySnare.detectCdpActive(false), true, "Unified __PS_SYNC_CDP__ MUST latch active CDP cleanly without TDZ ReferenceError!");

  // 5) Availability MEDIUM #1 + Availability MEDIUM #2 + Availability LOW #1:
  //    (a) 302-redirected CDN scripts (TAO-enabled same-origin 302, TAO-masked cross-origin .js 302, single-frame callback) stay 0-FP ce=0!
  //    (b) Browser extension wrapper frames above verified app frames stay 0-FP ce=0, while unparented extension frames emit ce=1!
  //    (c) Inline [onkeydown] attribute enables INITIAL_DOC_URL verification (0-FP ce=0)!
  let cdnCtx = "";
  const vmCdn = makeVm24({
    cdpOpen: true,
    geckoStack: true,
    hasOnKeyDownEl: true,
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true, requireGuardIntegrity: false },
    scriptSrcs: ["https://app.example/app-latest.js", "https://cdn.example.com/app/latest.js"],
    rtEntries: [
      { name: "https://app.example/app-latest.js", initiatorType: "script", redirectEnd: 0, transferSize: 0, responseStart: 0, encodedBodySize: 0, decodedBodySize: 0, responseEnd: 12 },
      { name: "https://cdn.example.com/app/latest.js", initiatorType: "script", redirectEnd: 0, transferSize: 0, responseStart: 0, encodedBodySize: 0, decodedBodySize: 0, responseEnd: 45 },
      { name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 },
    ],
    preLoadHook: `Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return globalThis.__cdnStack; } }, "stack"));`,
    fetchImpl: makeHs24((u, init) => { cdnCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  for (const [label, stackBody] of [
    ["Gecko/WebKit TAO-masked same-origin 302 to cross-origin CDN (single-frame callback)", "https://other-cdn.example/app.v2.js:12:4"],
    ["cross-origin TAO-masked .js 302 within trusted CDN origin", "go@https://cdn.example.com/app/v2.js:5:10"],
    ["moz-extension wrapper strictly above verified app script", "wrapFetch@moz-extension://1234/inject.js:8:2\nonClick@https://app.example/app.js:20:4"],
    ["chrome-extension wrapper strictly above verified app script", "wrap@chrome-extension://abcd/content.js:4:1\nrun@https://app.example/app.js:15:3"],
    ["inline onkeydown attribute on INITIAL_DOC_URL", "onkeydown@https://app.example/:1:1"],
  ]) {
    vmCdn.ctx.__cdnStack = `captureConsoleEvalFlag@https://app.example/__proxysnare/guard.js:1:1\nproxySnareFetch@https://app.example/__proxysnare/guard.js:1:1\n${stackBody}`;
    await vmCdn.ctx.fetch("/api/cdn-ok", { method: "POST", body: "{}" });
    assert.ok(cdnCtx.includes("ce=0"), `${label} MUST stay 0-FP ce=0 (got ${cdnCtx})`);
  }
  for (const [label, stackBody] of [
    ["unparented moz-extension frame", "inject@moz-extension://1234/content.js:8:2"],
    ["[native code]-only frame", "fetch@[native code]"],
  ]) {
    vmCdn.ctx.__cdnStack = `captureConsoleEvalFlag@https://app.example/__proxysnare/guard.js:1:1\nproxySnareFetch@https://app.example/__proxysnare/guard.js:1:1\n${stackBody}`;
    await vmCdn.ctx.fetch("/api/cdn-bad", { method: "POST", body: "{}" });
    assert.ok(cdnCtx.includes("ce=1"), `${label} MUST emit ce=1 (got ${cdnCtx})`);
  }
  // V8 TAO-enabled same-origin 302 (redirectEnd>0, responseStatus:200, transferSize>0) to cross-origin CDN stays 0-FP ce=0,
  // while Gecko/WebKit formatted stack with only same-origin redirectEnd>0 still rejects unknown origin evil.invalid (ce=1)!
  let v8TaoCtx = "";
  const vmV8Tao = makeVm24({
    cdpOpen: true,
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true, requireGuardIntegrity: false },
    scriptSrcs: ["https://app.example/app-latest.js"],
    rtEntries: [
      { name: "https://app.example/app-latest.js", initiatorType: "script", redirectEnd: 12, responseStatus: 200, transferSize: 1200, decodedBodySize: 1200 },
    ],
    fetchImpl: makeHs24((u, init) => { v8TaoCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  await new Promise((r) => setTimeout(r, 0));
  await vm.runInContext(`Promise.resolve().then(() => window.fetch("/api/v8-tao-cdn", { method: "POST", body: "{}" }));`, vmV8Tao.ctx, { filename: "https://other-cdn.example/app.v2.js" });
  assert.ok(v8TaoCtx.includes("ce=0"), `V8 TAO-enabled same-origin 302 to cross-origin CDN MUST stay 0-FP ce=0 (got ${v8TaoCtx})`);
  let geckoSameRedirCtx = "";
  const vmGeckoSameRedir = makeVm24({
    cdpOpen: true,
    geckoStack: true,
    guardOpts: { allowDevTools: false, blockCdpActive: false, blockConsoleEval: true, requireGuardIntegrity: false },
    rtEntries: [
      { name: "https://app.example/app-latest.js", initiatorType: "script", redirectEnd: 12, responseStatus: 200, transferSize: 1200, decodedBodySize: 1200 },
    ],
    preLoadHook: `Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return globalThis.__gStack; } }, "stack"));`,
    fetchImpl: makeHs24((u, init) => { geckoSameRedirCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  vmGeckoSameRedir.ctx.__gStack = "captureConsoleEvalFlag@https://app.example/__proxysnare/guard.js:1:1\nproxySnareFetch@https://app.example/__proxysnare/guard.js:1:1\nf@https://evil.invalid/pwn.js:1:1";
  await vmGeckoSameRedir.ctx.fetch("/api/gecko-spoof", { method: "POST", body: "{}" });
  assert.ok(geckoSameRedirCtx.includes("ce=1"), `Gecko/WebKit formatted stack with same-origin redirectEnd>0 MUST reject unknown origin evil.invalid (got ${geckoSameRedirCtx})`);

  // 6) Availability MEDIUM #3: Aborting fetch() mid-handshake MUST throw AbortError WITHOUT wiping freshly minted session state!
  let hsCalls24 = 0;
  let apiSid1 = "";
  const ac = new AbortController();
  const vmAbort = makeVm24({
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 }],
    fetchImpl: makeHs24(
      (u, init) => { apiSid1 = init.headers.get("X-PS-Session") || ""; },
      async () => {
        hsCalls24++;
        if (hsCalls24 === 1) ac.abort(); // Abort first fetch WHILE handshake is in flight!
      }
    ),
  });
  await assert.rejects(
    () => vmAbort.ctx.fetch("/api/aborted-cold", { method: "POST", body: "{}", signal: ac.signal }),
    /AbortError/
  );
  assert.equal(hsCalls24, 1, "Cold handshake completed once");
  await vmAbort.ctx.fetch("/api/after-abort", { method: "POST", body: "{}" });
  assert.equal(hsCalls24, 1, "Follow-up fetch MUST reuse the freshly minted session without re-running /handshake!");
  assert.ok(apiSid1.length === 32, "Follow-up fetch MUST send valid X-PS-Session from preserved session");

  // 7) Security MEDIUM #3: Multi-worker extStore burns single-use nonce on blocked valid-HMAC request so Worker B rejects header-fixup replay!
  const clusterStore = new Map();
  const extStore24 = {
    async get(k) { return clusterStore.get(k) || null; },
    async set(k, v) { clusterStore.set(k, v); },
    async setIfNotExists(k, v) { if (clusterStore.has(k)) return false; clusterStore.set(k, v); return true; },
  };
  const sharedSec24 = "pass24-cluster-nonce-burn-32byte!";
  const mwA = createProxySnareMiddleware({ mode: "strict", protectedPaths: ["/api"], secret: sharedSec24, store: extStore24 });
  const mwB = createProxySnareMiddleware({ mode: "strict", protectedPaths: ["/api"], secret: sharedSec24, store: extStore24 });
  const sessA = mwA.engine.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
  clusterStore.set(`ps:sess:${sessA.sessionId}`, mwA.engine.exportSessionRecord(sessA.sessionId));
  const ts24 = String(Date.now());
  const nonce24 = "0123456789abcdef01234567";
  const proof24 = mwA.engine.signRequest({
    sessionKeyHex: sessA.sessionKeyHex,
    method: "POST",
    pathWithQuery: "/api/pay",
    body: '{"amt":10}',
    seq: "1",
    ts: ts24,
    nonce: nonce24,
    canary: sessA.canary,
  });
  const callMw24 = async (mw, extraHdrs) => {
    let status = 200;
    let body = "";
    await mw(
      {
        method: "POST",
        url: "/api/pay",
        socket: { remoteAddress: "127.0.0.1" },
        rawBody: Buffer.from('{"amt":10}', "utf8"),
        headers: makeBrowserHeaders({
          "content-type": "application/json",
          "sec-fetch-site": "same-origin",
          "sec-fetch-mode": "cors",
          "x-ps-session": sessA.sessionId,
          "x-ps-seq": "1",
          "x-ps-ts": ts24,
          "x-ps-nonce": nonce24,
          "x-ps-canary": sessA.canary,
          "x-ps-proof": proof24,
          ...extraHdrs,
        }),
      },
      { headersSent: false, writableEnded: false, setHeader() {}, writeHead(st) { status = st; this.headersSent = true; }, end(b) { body = String(b || ""); this.writableEnded = true; } }
    );
    return { status, body };
  };
  // Worker A blocks valid-HMAC request because proxy leaked X-Caido-Id + X-Burp-Header (+10)
  const rWA = await callMw24(mwA, { "x-caido-id": "1", "x-burp-header": "1" });
  assert.equal(rWA.status, 403, "Worker A MUST block proxy-leak request");
  // Attacker strips proxy leak headers and replays the IDENTICAL valid-HMAC request to Worker B within freshnessMs!
  const rWB = await callMw24(mwB, {});
  assert.equal(rWB.status, 403, "Worker B MUST reject header-fixup replay of blocked valid-HMAC nonce!");
  assert.ok(rWB.body.includes("REPEATER_NONCE_REPLAYED"), `Worker B MUST report REPEATER_NONCE_REPLAYED (got ${rWB.body})`);

  // 8) Security LOW #1 + Parity LOW #1: Non-ASCII Unicode whitespace (\u3000) in protectedPaths has exact server/client guardHash parity,
  //    AND Node issueSession rejects non-canonical base64 trailing bits in clientPubB64!
  const vmU3000 = makeVm24({ guardOpts: { protectedRules: ["/api/\u3000admin"] }, fetchImpl: makeHs24() });
  assert.equal(vmU3000.ctx.ProxySnare.guardHash(), computeGuardIntegrity(vmU3000.src).guardHash, "Non-ASCII \\u3000 in protectedPaths MUST match server guardHash!");
  const ecdh24 = crypto.createECDH("prime256v1");
  ecdh24.generateKeys();
  const pubOk24 = ecdh24.getPublicKey().toString("base64");
  const b64Alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  const pubBad24 = pubOk24.slice(0, 86) + b64Alph[b64Alph.indexOf(pubOk24[86]) ^ 1] + pubOk24.slice(87);
  const badSessRes = eng24.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: pubBad24 });
  assert.equal(badSessRes.error, "INVALID_CLIENT_ECDH_KEY", "Node issueSession MUST reject non-canonical base64 trailing bits in clientPubB64!");
});

test("36. Pass-25 Audit Regressions: !cdpFlagged app-helper Console bypass sealed, precheckSessionHeaders TOCTOU nonce-replay race fixed, mode:'off' no-op guard & skip inject, mode:'monitor' fail-open fetch/XHR, early-load & expanded inline HTML event handlers 0-FP, cross-origin 302 CDN 0-FP, CORS preflight PROXY_HEADER_LEAK (JS+Python), malformed Content-Length fail-closed & userGestureWindowMs validation", async () => {
  const vm = require("node:vm");
  const { PassThrough } = require("node:stream");

  const eng25 = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api"], handshakePowBits: 0 });
  const makeVm25 = ({
    guardOpts = {},
    fetchImpl = null,
    rtEntries = [],
    scriptSrcs = [],
    readyState = "complete",
    inlineSelHit = null,
    cdpOpen = false,
    geckoStack = false,
    hasSubtle = true,
    xhrSendSpy = null,
    preLoadHook = "",
  } = {}) => {
    const src = buildBrowserGuardScript({
      basePath: "/__proxysnare",
      protectedPaths: ["/api"],
      serverVerifyPubB64: eng25.serverVerifyPubB64,
      allowDevTools: false,
      blockCdpActive: false,
      blockConsoleEval: true,
      requireGuardIntegrity: false,
      ...guardOpts,
    });
    class VmHeaders {
      constructor(init) {
        this._m = new Map();
        if (init instanceof VmHeaders) { for (const [k, v] of init._m) this._m.set(k, v); }
        else if (init && typeof init === "object") { for (const [k, v] of Object.entries(init)) this._m.set(k.toLowerCase(), String(v)); }
      }
      set(k, v) { this._m.set(String(k).toLowerCase(), String(v)); }
      get(k) { const v = this._m.get(String(k).toLowerCase()); return v === undefined ? null : v; }
      has(k) { return this._m.has(String(k).toLowerCase()); }
    }
    class VmResponse {
      constructor(body = "", init = {}) {
        this._body = typeof body === "string" ? body : Buffer.from(body).toString("utf8");
        this._status = init.status ?? 200;
        this._headers = new VmHeaders(init.headers || {});
        this._redirected = Boolean(init.redirected);
        this._url = init.url || "https://app.example/api/ok";
        this._type = init.type || "basic";
      }
      get status() { return this._status; }
      get headers() { return this._headers; }
      get redirected() { return this._redirected; }
      get url() { return this._url; }
      get type() { return this._type; }
      clone() { return new VmResponse(this._body, { status: this._status, headers: this._headers, redirected: this._redirected, url: this._url, type: this._type }); }
      async json() { return JSON.parse(this._body); }
      async text() { return this._body; }
      async arrayBuffer() { const b = Buffer.from(this._body, "utf8"); return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength); }
    }
    class VmPerformance {
      now() { return 1000; }
      getEntriesByType(t) { return t === "resource" ? rtEntries : []; }
    }
    const vmFetch = function fetch(url, init) {
      if (fetchImpl) return fetchImpl(url, init, VmResponse);
      return Promise.resolve(new VmResponse("{}", { status: 200 }));
    };
    const vmConsole = {
      debug: function debug(arg) { if (cdpOpen && arg && typeof arg === "object") void arg.stack; },
      warn: function warn() {},
      error: function error() {},
    };
    const sp = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const nativeRefs = new Set([
      vmFetch, vmConsole.debug, TextEncoder.prototype.encode,
      sp.generateKey, sp.exportKey, sp.importKey, sp.deriveBits, sp.deriveKey, sp.verify, sp.sign, sp.digest,
      crypto.webcrypto.getRandomValues,
      VmHeaders.prototype.set, VmHeaders.prototype.get, VmHeaders.prototype.has,
      VmResponse.prototype.json, VmResponse.prototype.clone, VmResponse.prototype.arrayBuffer,
      VmPerformance.prototype.getEntriesByType, VmPerformance.prototype.now,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get stack", "encode", "open", "send", "setRequestHeader", "get readyState", "get responseURL", "getResponseHeader"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return ""; } }, "stack"));' : ""}
        return globalThis;
      })();`,
      ifrCtx
    );
    class ShadowRoot { appendChild(c) { return c; } }
    class HTMLIFrameElement { get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node {
      constructor(attrs = null) { super(); this._attrs = attrs; }
      attachShadow() { return new ShadowRoot(); }
      getAttribute(n) { return this._attrs && Object.prototype.hasOwnProperty.call(this._attrs, n) ? this._attrs[n] : null; }
      remove() {}
    }
    const docState = { readyState, inlineSelHit, scriptsLen: 1 };
    class Document extends Node {
      constructor() {
        super();
        this.currentScript = null;
        this.baseURI = "https://app.example/";
        this._el = new Element();
        this.body = new Element();
        this.location = { href: "https://app.example/" };
      }
      get readyState() { return docState.readyState; }
      get scripts() { return { length: docState.scriptsLen }; }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : new Element(); }
      querySelectorAll(sel) {
        if (sel.includes("script[src]") && scriptSrcs.length) return scriptSrcs.map((s) => new Element({ src: s }));
        return [];
      }
      querySelector(sel) {
        if (docState.inlineSelHit && sel.includes(docState.inlineSelHit)) return new Element();
        return null;
      }
      addEventListener() {}
    }
    const VmXHR = class XMLHttpRequest {
      constructor() {
        this.readyState = 0;
        this.status = 0;
        this.statusText = "";
        this.responseText = "";
        this.response = "";
        this.responseURL = "";
        this.responseType = "";
        this._hdrs = {};
        this._listeners = {};
      }
      open(m, u) { this._m = m; this._u = u; this.readyState = 1; }
      setRequestHeader(k, v) { this._hdrs[k.toLowerCase()] = v; }
      getResponseHeader() { return null; }
      getAllResponseHeaders() { return ""; }
      abort() { this.readyState = 0; }
      addEventListener(t, fn) { (this._listeners[t] ||= []).push(fn); }
      dispatchEvent(ev) {
        const fn = this["on" + ev.type];
        if (typeof fn === "function") fn(ev);
        for (const l of this._listeners[ev.type] || []) l(ev);
      }
      send(body) {
        if (xhrSendSpy) xhrSendSpy(this, body);
        this.readyState = 2;
        this.status = 200;
        this.responseText = '{"ok":true}';
        this.response = '{"ok":true}';
        this.responseURL = this._u;
        if (typeof this.onreadystatechange === "function") this.onreadystatechange();
        this.readyState = 4;
        if (typeof this.onreadystatechange === "function") this.onreadystatechange();
        if (typeof this.onload === "function") this.onload();
      }
    }
    const ctx = vm.createContext({
      crypto: hasSubtle ? crypto.webcrypto : { getRandomValues: (b) => crypto.webcrypto.getRandomValues(b) },
      SubtleCrypto: hasSubtle ? sp.constructor : undefined,
      TextEncoder, TextDecoder, Headers: VmHeaders, Response: VmResponse, Performance: VmPerformance,
      XMLHttpRequest: VmXHR, Event: class Event { constructor(t) { this.type = t; } },
      ProgressEvent: class ProgressEvent { constructor(t) { this.type = t; } },
      URL, URLSearchParams, Request, DOMException, console: vmConsole, setTimeout, clearTimeout,
      performance: new VmPerformance(),
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement, ShadowRoot,
      navigator: { webdriver: false, platform: "Linux x86_64", userAgent: CHROME_UA },
      location: { origin: "https://app.example", href: "https://app.example/", pathname: "/" },
      fetch: vmFetch,
      addEventListener() {},
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get stack", "encode", "open", "send", "setRequestHeader", "get readyState", "get responseURL", "getResponseHeader"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return ""; } }, "stack"));' : ""}
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, src, docState };
  };

  const makeHs25 = (onApi, bootStatus = 200) => async (url, init, VmResponse) => {
    const sUrl = String(url);
    if (sUrl.endsWith("/__proxysnare/boot")) {
      if (bootStatus !== 200) return new VmResponse('{"error":"RATE_LIMIT"}', { status: bootStatus });
      return new VmResponse(JSON.stringify(eng25.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (sUrl.endsWith("/__proxysnare/handshake")) {
      const body = JSON.parse(init.body);
      const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|${body.browserProof?.d || ""}`).digest("hex");
      const s = eng25.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
      return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (onApi) onApi(sUrl, init);
    return new VmResponse('{"ok":true}', { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "a".repeat(32) } });
  };

  // 1) Security HIGH #1: !cdpFlagged (stealth CDP / Safari Web Inspector / deferred timer) Console calls through verified app helper MUST emit ce=1!
  let helperCtx = "";
  const vmHelper = makeVm25({
    cdpOpen: false,
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 }],
    fetchImpl: makeHs25((u, init) => { helperCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  vm.runInContext(`window.appHelper = function appHelper() { return window.fetch("/api/pay", { method: "POST", body: "{}" }); };`, vmHelper.ctx, { filename: "https://app.example/app.js" });
  await new Promise((r) => setTimeout(r, 0));
  await vm.runInContext(`Promise.resolve().then(() => window.appHelper());`, vmHelper.ctx, { filename: "https://app.example/app.js" });
  assert.ok(helperCtx.includes("ce=0"), `Legitimate app call to appHelper() MUST stay 0-FP ce=0 (got ${helperCtx})`);
  await vm.runInContext(`Promise.resolve().then(() => window.appHelper());`, vmHelper.ctx);
  assert.ok(helperCtx.includes("ce=1"), `Anonymous Console call to verified appHelper() when !cdpFlagged MUST emit ce=1 (got ${helperCtx})`);
  await vm.runInContext(`new Function("return window.appHelper()")();`, vmHelper.ctx);
  assert.ok(helperCtx.includes("ce=1"), `Unparented new Function() calling verified appHelper() when !cdpFlagged MUST emit ce=1 (got ${helperCtx})`);
  // Unparented browser extension frame calling appHelper() (extension-initiated) MUST emit ce=1 even when DevTools closed!
  await new Promise((r) => setTimeout(r, 0));
  await vm.runInContext(`Promise.resolve().then(() => window.appHelper());`, vmHelper.ctx, { filename: "chrome-extension://ext123/content.js" });
  assert.ok(helperCtx.includes("ce=1"), `Unparented extension-initiated call to appHelper() MUST emit ce=1 under blockConsoleEval:true (got ${helperCtx})`);

  // 2) Security & Perf HIGH #2: TOCTOU concurrent streaming body MUST NOT bypass REPEATER_NONCE_REPLAYED via stale _preSess!
  const mwRace = createProxySnareMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  const sessRace = mwRace.engine.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const tsRace = String(Date.now());
  const nonceRace = "fedcba9876543210fedcba98";
  const ctxRace = "ce=0;cdp=0;ug=1;ga=100;ik=0";
  const bodyStrRace = '{"amt":42}';
  const proofRace = mwRace.engine.signRequest({
    sessionKeyHex: sessRace.sessionKeyHex,
    method: "POST",
    pathWithQuery: "/api/transfer",
    body: bodyStrRace,
    seq: "1",
    ts: tsRace,
    nonce: nonceRace,
    canary: sessRace.canary,
    ctx: ctxRace,
  });
  const baseRaceHdrs = makeBrowserHeaders({
    "content-type": "application/json",
    "content-length": String(bodyStrRace.length),
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "x-ps-session": sessRace.sessionId,
    "x-ps-seq": "1",
    "x-ps-ts": tsRace,
    "x-ps-nonce": nonceRace,
    "x-ps-canary": sessRace.canary,
    "x-ps-ctx": ctxRace,
    "x-ps-proof": proofRace,
  });
  const makeStreamReq = (extraHdrs = {}, ip = "127.0.0.1") => {
    const s = new PassThrough();
    s.method = "POST";
    s.url = "/api/transfer";
    s.socket = { remoteAddress: ip };
    s.headers = { ...baseRaceHdrs, ...extraHdrs };
    return s;
  };
  const makeResCap = () => {
    const out = { status: 200, body: "" };
    return {
      out,
      res: { headersSent: false, writableEnded: false, setHeader() {}, writeHead(st) { out.status = st; this.headersSent = true; }, end(b) { out.body = String(b || ""); this.writableEnded = true; } },
    };
  };
  // R2 starts streaming and parks inside await readRequestBody() AFTER precheckSessionHeaders ran!
  const req2 = makeStreamReq();
  const cap2 = makeResCap();
  req2.write('{"amt":');
  const p2 = mwRace(req2, cap2.res);
  // While R2 is parked, R1 arrives with the SAME valid-HMAC nonce from a different IP (+6) + Connection:close (+4) -> blocked 403, burning nonce in usedNonces without changing lastSeq/canary!
  const req1 = makeStreamReq({ connection: "close" }, "203.0.113.55");
  const cap1 = makeResCap();
  req1.end(bodyStrRace);
  await mwRace(req1, cap1.res);
  assert.equal(cap1.out.status, 403, "R1 MUST be blocked 403 while burning the valid-HMAC nonce");
  // Now finish R2's final body bytes -> MUST be blocked 403 REPEATER_NONCE_REPLAYED (NOT 200 OK!)
  req2.end("42}");
  await p2;
  assert.equal(cap2.out.status, 403, `Parked R2 MUST NOT bypass REPEATER_NONCE_REPLAYED via stale _preSess (got status=${cap2.out.status})`);
  assert.ok(cap2.out.body.includes("REPEATER_NONCE_REPLAYED"), `R2 body MUST report REPEATER_NONCE_REPLAYED (got ${cap2.out.body})`);

  // 3) Availability HIGH #3: mode:"off" serves tiny no-op guard.js (no fetch/XHR wrapping, works on plain HTTP) & skips HTML injection!
  const vmOff = makeVm25({ guardOpts: { mode: "off" }, hasSubtle: false });
  assert.ok(vmOff.src.length < 2000, `mode:"off" guard.js MUST be a tiny no-op stub (<2KB, got ${vmOff.src.length})`);
  assert.equal(vmOff.ctx.fetch.name, "fetch", "mode:'off' MUST NOT wrap window.fetch!");
  assert.equal(vmOff.ctx.ProxySnare.mode, "off");
  assert.equal(await vmOff.ctx.ProxySnare.ready(), true, "mode:'off' ready() MUST resolve true even on plain HTTP!");
  const upOff = http.createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<!doctype html><html><head></head><body>plain</body></html>");
  });
  await new Promise((r) => upOff.listen(0, "127.0.0.1", r));
  const srvOff = createProxySnareServer({ target: `http://127.0.0.1:${upOff.address().port}`, mode: "off" });
  const urlOff = await srvOff.listen(0, "127.0.0.1");
  try {
    const htmlOff = await (await fetch(`${urlOff}/`, { headers: makeBrowserHeaders({ accept: "text/html" }) })).text();
    assert.ok(!htmlOff.includes("/__proxysnare/guard.js"), "mode:'off' reverse proxy MUST skip HTML guard.js injection!");
  } finally {
    await srvOff.close();
    await new Promise((r) => upOff.close(r));
  }

  // 4) Availability HIGH #4: mode:"monitor" fails open cleanly on both fetch & XHR when crypto.subtle is missing (plain HTTP) or /boot returns 429!
  for (const [label, opts] of [
    ["plain HTTP (no crypto.subtle)", { hasSubtle: false, bootStatus: 200 }],
    ["/boot 429 rate-limited", { hasSubtle: true, bootStatus: 429 }],
  ]) {
    let xhrSent = false;
    const vmMon = makeVm25({
      guardOpts: { mode: "monitor", failClosedOnTamper: false },
      hasSubtle: opts.hasSubtle,
      xhrSendSpy: () => { xhrSent = true; },
      fetchImpl: makeHs25(null, opts.bootStatus),
    });
    const rMon = await vmMon.ctx.fetch("/api/mon", { method: "POST", body: '{"a":1}' });
    assert.equal(rMon.status, 200, `mode:'monitor' fetch MUST fail open with 200 OK under ${label}`);
    const xhrStatus = await new Promise((resolve) => {
      const x = new vmMon.ctx.XMLHttpRequest();
      x.open("POST", "/api/mon-xhr", true);
      x.onload = () => resolve(x.status);
      x.onerror = () => resolve(-1);
      x.send('{"a":1}');
    });
    assert.equal(xhrStatus, 200, `mode:'monitor' XHR MUST fail open with 200 OK under ${label} (got ${xhrStatus})`);
    assert.equal(xhrSent, true);
  }

  // 5) Availability HIGH #5: Early-load (<100ms loading) inline HTML handler & onerror/javascript: href stay 0-FP ce=0!
  let earlyCtx = "";
  const vmEarly = makeVm25({
    cdpOpen: false,
    geckoStack: true,
    readyState: "loading",
    inlineSelHit: null,
    preLoadHook: `Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return globalThis.__eStack; } }, "stack"));`,
    fetchImpl: makeHs25((u, init) => { earlyCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  // Guard ran while readyState==="loading" with 0 inline handlers; <100ms later DOM parses <img onload="..."> (same scripts.length!)
  vmEarly.docState.inlineSelHit = "[onload]";
  vmEarly.ctx.__eStack = "captureConsoleEvalFlag@https://app.example/__proxysnare/guard.js:1:1\nproxySnareFetch@https://app.example/__proxysnare/guard.js:1:1\nonload@https://app.example/:1:1";
  await vmEarly.ctx.fetch("/api/early-onload", { method: "POST", body: "{}" });
  assert.ok(earlyCtx.includes("ce=0"), `Early-load <img onload> within 100ms MUST bypass throttle & stay 0-FP ce=0 (got ${earlyCtx})`);

  for (const attrHit of ["[onerror]", 'a[href^="javascript:"]']) {
    let attrCtx = "";
    const vmAttr = makeVm25({
      cdpOpen: true,
      geckoStack: true,
      readyState: "complete",
      inlineSelHit: attrHit,
      preLoadHook: `Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return globalThis.__aStack; } }, "stack"));`,
      fetchImpl: makeHs25((u, init) => { attrCtx = init.headers.get("X-PS-Ctx") || ""; }),
    });
    vmAttr.ctx.__aStack = "captureConsoleEvalFlag@https://app.example/__proxysnare/guard.js:1:1\nproxySnareFetch@https://app.example/__proxysnare/guard.js:1:1\nhandler@https://app.example/:1:1";
    await vmAttr.ctx.fetch("/api/inline-attr", { method: "POST", body: "{}" });
    assert.ok(attrCtx.includes("ce=0"), `Inline handler ${attrHit} MUST enable INITIAL_DOC_URL verification (got ${attrCtx})`);
  }

  // 6) Availability MEDIUM #3: Same-CDN TAO-masked 302 & TAO-enabled cross-origin 302 stay 0-FP!
  let xRedirCtx = "";
  const vmXClosed = makeVm25({
    cdpOpen: false,
    geckoStack: true,
    scriptSrcs: ["https://cdn.example.com/sdk.js"],
    rtEntries: [{ name: "https://cdn.example.com/sdk.js", initiatorType: "script", redirectEnd: 0, transferSize: 0, responseStart: 0, encodedBodySize: 0, decodedBodySize: 0, responseEnd: 40 }],
    preLoadHook: `Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return globalThis.__xStack; } }, "stack"));`,
    fetchImpl: makeHs25((u, init) => { xRedirCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  vmXClosed.ctx.__xStack = "captureConsoleEvalFlag@https://app.example/__proxysnare/guard.js:1:1\nproxySnareFetch@https://app.example/__proxysnare/guard.js:1:1\nrun@https://cdn.example.com/sdk-v4.js:10:2";
  await vmXClosed.ctx.fetch("/api/xcdn-closed", { method: "POST", body: "{}" });
  assert.ok(xRedirCtx.includes("ce=0"), `Same-CDN TAO-masked .js 302 (DevTools closed) MUST stay 0-FP ce=0 (got ${xRedirCtx})`);

  let xOpenCtx = "";
  const vmXOpen = makeVm25({
    cdpOpen: true,
    geckoStack: true,
    scriptSrcs: ["https://cdn-a.example/sdk.js"],
    rtEntries: [{ name: "https://cdn-a.example/sdk.js", initiatorType: "script", redirectEnd: 15, responseStatus: 200, transferSize: 900, decodedBodySize: 900 }],
    preLoadHook: `Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return globalThis.__xoStack; } }, "stack"));`,
    fetchImpl: makeHs25((u, init) => { xOpenCtx = init.headers.get("X-PS-Ctx") || ""; }),
  });
  vmXOpen.ctx.__xoStack = "captureConsoleEvalFlag@https://app.example/__proxysnare/guard.js:1:1\nproxySnareFetch@https://app.example/__proxysnare/guard.js:1:1\nrun@https://cdn-b.example/sdk-v2.js:10:2";
  await vmXOpen.ctx.fetch("/api/xcdn-open", { method: "POST", body: "{}" });
  assert.ok(xOpenCtx.includes("ce=0"), `TAO-enabled cross-origin 302 across origins (DevTools open, blockCdpActive:false) MUST stay 0-FP ce=0 (got ${xOpenCtx})`);

  // 7) Security MEDIUM #1: CORS OPTIONS preflight with PROXY_HEADER_LEAK MUST be blocked in balanced mode (Node + Python)!
  const balEng25 = createProxySnareEngine({ mode: "balanced", protectedPaths: ["/api"] });
  const preLeakV = balEng25.inspectRequest({
    method: "OPTIONS",
    url: "/api/secret",
    ip: "127.0.0.1",
    headers: makeBrowserHeaders({
      host: "app.example",
      origin: "https://other.example",
      "access-control-request-method": "POST",
      "sec-fetch-mode": "cors",
      "x-caido-id": "1",
    }),
  });
  assert.equal(preLeakV.blocked, true, `Balanced CORS preflight with X-Caido-Id MUST block (score=${preLeakV.score}, threshold=${preLeakV.threshold})`);
  execFileSync(
    "python3",
    [
      "-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v = ProxySnareVerifier(mode="balanced", protected_paths=["/api"])
res = v.inspect_request(method="OPTIONS", url="/api/secret", ip="127.0.0.1", headers={"Host": "app.example", "Origin": "https://other.example", "Access-Control-Request-Method": "POST", "Sec-Fetch-Mode": "cors", "User-Agent": ${JSON.stringify(CHROME_UA)}, "X-Caido-Id": "1"})
assert res.blocked, f"Python balanced CORS preflight with X-Caido-Id MUST block: {res}"`,
    ],
    { encoding: "utf8" }
  );

  // 8) Security MEDIUM #2 + Parity LOW #1: Malformed/array Content-Length fails closed 400 on GET, and invalid userGestureWindowMs throws!
  const mwCl = createProxySnareMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  for (const clVal of ["0, 25", ["0", "25"]]) {
    const capCl = makeResCap();
    await mwCl(
      { method: "GET", url: "/api/secret", socket: { remoteAddress: "127.0.0.1" }, headers: makeBrowserHeaders({ "content-length": clVal }) },
      capCl.res
    );
    assert.equal(capCl.out.status, 400, `Malformed/array Content-Length (${JSON.stringify(clVal)}) on protected GET MUST fail closed 400!`);
  }
  assert.throws(() => createProxySnareEngine({ mode: "strict", userGestureWindowMs: -5 }), /userGestureWindowMs/);
  assert.throws(() => createProxySnareEngine({ mode: "strict", userGestureWindowMs: NaN }), /userGestureWindowMs/);
});

test("37. Pass-26 Audit Regressions: !cdpEverDetected unverified-frame bypass sealed, Firefox/Safari fabricated .js & @-in-path fn-name spoofing blocked, streaming POST live-canary nonce burning before 403, RFC 9112 Connection:close on unread-body 403/413, seedInitialScriptOrigins 100ms throttle & Express pre-parsed flood gate, unified requireBootToken:false binding & Zone.current===null", async () => {
  const vm = require("node:vm");
  const { PassThrough } = require("node:stream");

  const eng26 = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api"], handshakePowBits: 0 });
  const makeVm26 = ({ guardOpts = {}, rtEntries = [], scriptSrcs = [], geckoStack = false, readyState = "complete", qsaCounter = null, preLoadHook = "", fetchImpl = null } = {}) => {
    const src = buildBrowserGuardScript({
      basePath: "/__proxysnare",
      protectedPaths: ["/api"],
      serverVerifyPubB64: eng26.serverVerifyPubB64,
      allowDevTools: false,
      blockCdpActive: false,
      blockConsoleEval: true,
      requireGuardIntegrity: false,
      ...guardOpts,
    });
    class VmHeaders {
      constructor(init) {
        this._m = new Map();
        if (init instanceof VmHeaders) { for (const [k, v] of init._m) this._m.set(k, v); }
        else if (init && typeof init === "object") { for (const [k, v] of Object.entries(init)) this._m.set(k.toLowerCase(), String(v)); }
      }
      set(k, v) { this._m.set(String(k).toLowerCase(), String(v)); }
      get(k) { const v = this._m.get(String(k).toLowerCase()); return v === undefined ? null : v; }
      has(k) { return this._m.has(String(k).toLowerCase()); }
    }
    class VmResponse {
      constructor(body = "", init = {}) {
        this._body = typeof body === "string" ? body : Buffer.from(body).toString("utf8");
        this._status = init.status ?? 200;
        this._headers = new VmHeaders(init.headers || {});
        this._redirected = Boolean(init.redirected);
        this._url = init.url || "https://app.example/api/ok";
        this._type = init.type || "basic";
      }
      get status() { return this._status; }
      get headers() { return this._headers; }
      get redirected() { return this._redirected; }
      get url() { return this._url; }
      get type() { return this._type; }
      clone() { return new VmResponse(this._body, { status: this._status, headers: this._headers, redirected: this._redirected, url: this._url, type: this._type }); }
      async json() { return JSON.parse(this._body); }
      async arrayBuffer() { const b = Buffer.from(this._body, "utf8"); return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength); }
    }
    class VmPerformance {
      now() { return 1000; }
      getEntriesByType(t) { return t === "resource" ? rtEntries : []; }
    }
    const vmFetch = function fetch(url, init) {
      if (fetchImpl) return fetchImpl(url, init, VmResponse);
      return Promise.resolve(new VmResponse("{}", { status: 200 }));
    };
    const vmConsole = { debug: function debug() {}, warn() {}, error() {} };
    const sp = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const nativeRefs = new Set([
      vmFetch, vmConsole.debug, TextEncoder.prototype.encode,
      sp.generateKey, sp.exportKey, sp.importKey, sp.deriveBits, sp.deriveKey, sp.verify, sp.sign, sp.digest,
      crypto.webcrypto.getRandomValues,
      VmHeaders.prototype.set, VmHeaders.prototype.get, VmHeaders.prototype.has,
      VmResponse.prototype.json, VmResponse.prototype.clone, VmResponse.prototype.arrayBuffer,
      VmPerformance.prototype.getEntriesByType, VmPerformance.prototype.now,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get stack", "encode"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return ""; } }, "stack"));' : ""}
        return globalThis;
      })();`,
      ifrCtx
    );
    class ShadowRoot { appendChild(c) { return c; } }
    class HTMLIFrameElement { get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node {
      constructor(attrs = null) { super(); this._attrs = attrs; }
      attachShadow() { return new ShadowRoot(); }
      getAttribute(n) { return this._attrs && Object.prototype.hasOwnProperty.call(this._attrs, n) ? this._attrs[n] : null; }
      remove() {}
    }
    class Document extends Node {
      constructor() {
        super();
        this.currentScript = null;
        this.baseURI = "https://app.example/";
        this.readyState = readyState;
        this.scripts = { length: 1 };
        this._el = new Element();
        this.body = new Element();
        this.location = { href: "https://app.example/" };
      }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : new Element(); }
      querySelectorAll(sel) {
        if (qsaCounter) qsaCounter.n++;
        if (sel.includes("script[src]") && scriptSrcs.length) return scriptSrcs.map((s) => new Element({ src: s }));
        return [];
      }
      querySelector() { return null; }
      addEventListener() {}
    }
    const ctx = vm.createContext({
      crypto: crypto.webcrypto, SubtleCrypto: sp.constructor,
      TextEncoder, TextDecoder, Headers: VmHeaders, Response: VmResponse, Performance: VmPerformance,
      URL, URLSearchParams, Request, DOMException, console: vmConsole, setTimeout, clearTimeout,
      performance: new VmPerformance(), document: new Document(),
      Document, Node, Element, HTMLIFrameElement, ShadowRoot,
      navigator: { webdriver: false, platform: "Linux x86_64", userAgent: CHROME_UA },
      location: { origin: "https://app.example", href: "https://app.example/", pathname: "/" },
      fetch: vmFetch, addEventListener() {}, _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get stack", "encode"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return ""; } }, "stack"));' : ""}
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, src };
  };
  const makeHs26 = (onApi) => async (url, init, VmResponse) => {
    const sUrl = String(url);
    if (sUrl.endsWith("/__proxysnare/boot")) {
      return new VmResponse(JSON.stringify(eng26.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (sUrl.endsWith("/__proxysnare/handshake")) {
      const body = JSON.parse(init.body);
      const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|${body.browserProof?.d || ""}`).digest("hex");
      const s = eng26.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
      return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
    }
    if (onApi) onApi(sUrl, init);
    return new VmResponse('{"ok":true}', { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "a".repeat(32) } });
  };

  // 1) Security HIGH #1: Unverified callers (data:, blob:, rejected evil.invalid, webpack://) laundering through verified appHelper() MUST emit ce=1 even when !cdpEverDetected!
  let ctx1 = "";
  const vm1 = makeVm26({
    rtEntries: [
      { name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 },
      { name: "https://evil.invalid/pwn.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 200 },
    ],
    fetchImpl: makeHs26((u, init) => { ctx1 = init.headers.get("X-PS-Ctx") || ""; }),
  });
  vm.runInContext(`window.appHelper = function appHelper() { return window.fetch("/api/pay", { method: "POST", body: "{}" }); };`, vm1.ctx, { filename: "https://app.example/app.js" });
  for (const [label, fnFile] of [
    ["data: URI", "data:text/javascript,window.appHelper()"],
    ["blob: URI", "blob:https://app.example/uuid-123"],
    ["rejected evil.invalid", "https://evil.invalid/pwn.js"],
    ["disallowed webpack://", "webpack://evil/pwn.js"],
  ]) {
    await new Promise((r) => setTimeout(r, 0));
    await vm.runInContext(`Promise.resolve().then(() => window.appHelper());`, vm1.ctx, { filename: fnFile });
    assert.ok(ctx1.includes("ce=1"), `${label} calling verified appHelper() when !cdpEverDetected MUST emit ce=1 (got ${ctx1})`);
  }

  // 2) Security HIGH #2: Firefox/Safari Console fabricated same-origin .js AND @-in-path spoofed fn names MUST emit ce=1, while real /@vite/client stays 0-FP ce=0!
  let ctx2 = "";
  const vm2 = makeVm26({
    geckoStack: true,
    rtEntries: [
      { name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 },
      { name: "https://app.example/@vite/client", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 },
    ],
    preLoadHook: `Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return globalThis.__s26; } }, "stack"));`,
    fetchImpl: makeHs26((u, init) => { ctx2 = init.headers.get("X-PS-Ctx") || ""; }),
  });
  for (const [label, frame] of [
    ["fabricated same-origin nonexistent.js without redirect", "go@https://app.example/nonexistent.js:1:1"],
    ["spoofed bare URL fn name https://app.example/@x.js", "https://app.example/@x.js:1:45"],
    ["spoofed nested @ fn name a@https://app.example/@x.js", "a@https://app.example/@x.js:1:45"],
  ]) {
    vm2.ctx.__s26 = `captureConsoleEvalFlag@https://app.example/__proxysnare/guard.js:1:1\nproxySnareFetch@https://app.example/__proxysnare/guard.js:1:1\n${frame}`;
    await vm2.ctx.fetch("/api/spoof26", { method: "POST", body: "{}" });
    assert.ok(ctx2.includes("ce=1"), `Firefox/Safari ${label} MUST emit ce=1 (got ${ctx2})`);
  }
  vm2.ctx.__s26 = "captureConsoleEvalFlag@https://app.example/__proxysnare/guard.js:1:1\nproxySnareFetch@https://app.example/__proxysnare/guard.js:1:1\nhttps://app.example/@vite/client:12:4";
  await vm2.ctx.fetch("/api/vite26", { method: "POST", body: "{}" });
  assert.ok(ctx2.includes("ce=0"), `Real RT-registered /@vite/client MUST stay 0-FP ce=0 (got ${ctx2})`);

  // 3) Security HIGH #3: Streaming POST with live 96-bit canary + strippable X-Burp-Header MUST burn single-use nonce so header-fixup replay returns 403!
  const mwBurn = createProxySnareMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  const sBurn = mwBurn.engine.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const tsB = String(Date.now());
  const nonceB = "abcdef0123456789abcdef01";
  const ctxB = "ce=0;cdp=0;ug=1;ga=100;ik=0";
  const bodyB = '{"amount":100}';
  const proofB = mwBurn.engine.signRequest({
    sessionKeyHex: sBurn.sessionKeyHex, method: "POST", pathWithQuery: "/api/transfer", body: bodyB,
    seq: "1", ts: tsB, nonce: nonceB, canary: sBurn.canary, ctx: ctxB,
  });
  const sendStreamPost = async (extraHdrs) => {
    const s = new PassThrough();
    s.method = "POST";
    s.url = "/api/transfer";
    s.socket = { remoteAddress: "127.0.0.1" };
    s.headers = makeBrowserHeaders({
      "content-type": "application/json",
      "content-length": String(bodyB.length),
      "sec-fetch-site": "same-origin",
      "sec-fetch-mode": "cors",
      "x-ps-session": sBurn.sessionId,
      "x-ps-seq": "1",
      "x-ps-ts": tsB,
      "x-ps-nonce": nonceB,
      "x-ps-canary": sBurn.canary,
      "x-ps-ctx": ctxB,
      "x-ps-proof": proofB,
      ...extraHdrs,
    });
    s.end(bodyB);
    let status = 200;
    let body = "";
    await mwBurn(s, { headersSent: false, writableEnded: false, setHeader() {}, writeHead(st) { status = st; this.headersSent = true; }, end(b) { body = String(b || ""); this.writableEnded = true; } });
    return { status, body };
  };
  const rBurn1 = await sendStreamPost({ "x-burp-header": "1", "x-caido-id": "1" });
  assert.equal(rBurn1.status, 403, "Streaming POST with X-Burp-Header + X-Caido-Id MUST return 403");
  const rBurn2 = await sendStreamPost({});
  assert.equal(rBurn2.status, 403, "Stripping X-Burp-Header on streaming POST MUST NOT replay to HTTP 200!");
  assert.ok(rBurn2.body.includes("REPEATER_NONCE_REPLAYED"), `Attempt 2 MUST report REPEATER_NONCE_REPLAYED (got ${rBurn2.body})`);

  // 4) Perf MEDIUM #1: Early unread-body 403 rejection sends RFC 9112 Connection: close!
  const srvConn = http.createServer(async (req, res) => {
    const handled = await mwBurn(req, res);
    if (!handled) { res.writeHead(200); res.end("ok"); }
  });
  await new Promise((r) => srvConn.listen(0, "127.0.0.1", r));
  try {
    const rConn = await new Promise((resolve) => {
      const r = http.request(
        {
          host: "127.0.0.1", port: srvConn.address().port, method: "POST", path: "/api/transfer",
          headers: { "User-Agent": CHROME_UA, "Content-Type": "application/json", "Content-Length": "4096", "Connection": "keep-alive" },
        },
        (resp) => {
          resp.resume();
          resp.on("end", () => resolve({ status: resp.statusCode, conn: String(resp.headers.connection || "").toLowerCase() }));
        }
      );
      r.on("error", () => {});
      r.write('{"partial":true}');
    });
    assert.equal(rConn.status, 403);
    assert.equal(rConn.conn, "close", "Early unread-body 403 MUST send Connection: close (RFC 9112 §9.6)!");
  } finally {
    await new Promise((r) => srvConn.close(r));
  }

  // 5) Perf MEDIUM #2: seedInitialScriptOrigins() 100ms throttle actually prevents repeated full-DOM querySelectorAll scans during loading!
  const qsaCounter = { n: 0 };
  const vmThrot = makeVm26({
    readyState: "loading",
    qsaCounter,
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 }],
    fetchImpl: makeHs26(),
  });
  const afterLoadQsa = qsaCounter.n;
  await new Promise((r) => setTimeout(r, 0));
  await vm.runInContext(`Promise.all([window.fetch("/api/1"), window.fetch("/api/2"), window.fetch("/api/3")]);`, vmThrot.ctx, { filename: "https://app.example/app.js" });
  assert.equal(qsaCounter.n, afterLoadQsa, `100ms throttle MUST avoid repeated querySelectorAll scans during loading (before=${afterLoadQsa}, after=${qsaCounter.n})`);

  // 6) Perf MEDIUM #3: Express pre-parsed req.body skips JSON.stringify re-serialization when pre-body flood gate rejects!
  let stringified = false;
  const evilBody = { toJSON() { stringified = true; return {}; } };
  let expSt = 200;
  await mwBurn(
    { method: "POST", url: "/api/pay", socket: { remoteAddress: "127.0.0.1" }, _body: true, body: evilBody, headers: { "user-agent": "curl/8.0", "content-type": "application/json" } },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead(st) { expSt = st; this.headersSent = true; }, end() { this.writableEnded = true; } }
  );
  assert.equal(expSt, 403);
  assert.equal(stringified, false, "Enforcing-mode pre-body flood gate MUST skip JSON.stringify(req.body) on unsigned curl POST!");

  // 7) Security LOW #1 + Security LOW #2: Unified requireBootToken:false STILL enforces bootToken challenge binding, AND Zone.current === null fails Promise integrity!
  const veilbreak = require("../../veilbreak/src/index.js");
  const uNoBt = createUnifiedMiddleware({ mode: "strict", requireBootToken: false, veilbreak });
  let hsNoBtSt = 0;
  await uNoBt(
    {
      method: "POST", url: "/__proxysnare/handshake", socket: { remoteAddress: "127.0.0.1" },
      headers: makeBrowserHeaders({ "content-type": "application/json", "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "accept-language": "en-US" }),
      rawBody: Buffer.from(JSON.stringify({ protocol: "PS_ECDH_V2", clientPubB64: "A".repeat(88), guardHash: uNoBt.guardHash, browserProof: { v: 3, ch: "static", s: 0, f: 0, p: "Linux x86_64", cdp: 0, wr: "", wk: 1, ms: 2, d: crypto.createHash("sha256").update("VB_HS_V3|static|0|0|Linux x86_64|0||1|2").digest("hex") } }), "utf8"),
    },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead(st) { hsNoBtSt = st; this.headersSent = true; }, end() { this.writableEnded = true; } }
  );
  assert.equal(hsNoBtSt, 403, "Unified enforcing mode with requireBootToken:false MUST still reject missing bootToken so VB_HS_V3 challenge cannot be replayed!");

  const vmZoneNull = makeVm26({ guardOpts: { requireGuardIntegrity: true } });
  vm.runInContext(`
    window.Zone = { current: null };
    Promise.prototype.__zone_symbol__then = Promise.prototype.then;
    Promise.prototype.then = function then(f, r) { return this.__zone_symbol__then(f, r); };
  `, vmZoneNull.ctx);
  assert.equal(vmZoneNull.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", "Zone.current === null MUST NOT be treated as valid Zone.js patch!");
});

test("38. Pass-27 Audit Regressions: V8 CallSite load-time downgrade defense (stackTraceLimit=0 & inherited prepareStackTrace), window.URL intrinsic verification, Safari redirected '@' CDN URLs 0-FP, HEAD redirect recovery & empty 403 body (Node+Python), Python Signal 4 >4KB parity, and U+0130 ASCII-safe HTML injection", async () => {
  const vm = require("node:vm");
  const { injectGuardIntoHtml } = require("../src/middleware.js");

  const eng27 = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api"], handshakePowBits: 0 });
  const makeVm27 = ({ guardOpts = {}, rtEntries = [], initScripts = [], geckoStack = false, preLoadHook = "", fetchImpl = null } = {}) => {
    const src = buildBrowserGuardScript({
      basePath: "/__proxysnare",
      protectedPaths: ["/api"],
      serverVerifyPubB64: eng27.serverVerifyPubB64,
      allowDevTools: false,
      blockCdpActive: false,
      blockConsoleEval: true,
      requireGuardIntegrity: true,
      ...guardOpts,
    });
    class VmHeaders {
      constructor(init) {
        this._m = new Map();
        if (init instanceof VmHeaders) { for (const [k, v] of init._m) this._m.set(k, v); }
        else if (init && typeof init === "object") { for (const [k, v] of Object.entries(init)) this._m.set(k.toLowerCase(), String(v)); }
      }
      set(k, v) { this._m.set(String(k).toLowerCase(), String(v)); }
      get(k) { const v = this._m.get(String(k).toLowerCase()); return v === undefined ? null : v; }
      has(k) { return this._m.has(String(k).toLowerCase()); }
    }
    class VmResponse {
      constructor(body = "", init = {}) {
        this._body = typeof body === "string" ? body : Buffer.from(body).toString("utf8");
        this._status = init.status ?? 200;
        this._headers = new VmHeaders(init.headers || {});
        this._redirected = Boolean(init.redirected);
        this._url = init.url || "https://app.example/api/ok";
        this._type = init.type || "basic";
      }
      get status() { return this._status; }
      get headers() { return this._headers; }
      get redirected() { return this._redirected; }
      get url() { return this._url; }
      get type() { return this._type; }
      clone() { return new VmResponse(this._body, { status: this._status, headers: this._headers, redirected: this._redirected, url: this._url, type: this._type }); }
      async json() { return JSON.parse(this._body); }
      async arrayBuffer() { const b = Buffer.from(this._body, "utf8"); return b.buffer.slice(b.byteOffset, b.byteOffset + b.byteLength); }
    }
    class VmPerformance {
      now() { return 1000; }
      getEntriesByType(t) { return t === "resource" ? rtEntries : []; }
    }
    const vmFetch = function fetch(url, init) {
      if (fetchImpl) return fetchImpl(url, init, VmResponse);
      return Promise.resolve(new VmResponse("{}", { status: 200 }));
    };
    const vmConsole = { debug: function debug() {}, warn() {}, error() {} };
    const sp = Object.getPrototypeOf(crypto.webcrypto.subtle);
    const nativeRefs = new Set([
      vmFetch, vmConsole.debug, TextEncoder.prototype.encode,
      sp.generateKey, sp.exportKey, sp.importKey, sp.deriveBits, sp.deriveKey, sp.verify, sp.sign, sp.digest,
      crypto.webcrypto.getRandomValues,
      VmHeaders.prototype.set, VmHeaders.prototype.get, VmHeaders.prototype.has,
      VmResponse.prototype.json, VmResponse.prototype.clone, VmResponse.prototype.arrayBuffer,
      VmPerformance.prototype.getEntriesByType, VmPerformance.prototype.now,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get stack", "encode"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return ""; } }, "stack"));' : ""}
        return globalThis;
      })();`,
      ifrCtx
    );
    class ShadowRoot { appendChild(c) { return c; } }
    class HTMLIFrameElement { get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node {
      constructor(attrs = null) { super(); this._attrs = attrs; }
      attachShadow() { return new ShadowRoot(); }
      getAttribute(k) { return this._attrs && k in this._attrs ? this._attrs[k] : null; }
      remove() {}
    }
    class Document extends Node {
      constructor() { super(); this.currentScript = null; this.baseURI = "https://app.example/"; this.readyState = "complete"; this._el = new Element(); this.body = new Element(); this.location = { href: "https://app.example/" }; }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : new Element(); }
      querySelectorAll(sel) {
        if (sel.includes("script[src]") && initScripts.length) return initScripts.map((s) => new Element({ src: s }));
        return [];
      }
      querySelector() { return null; }
      addEventListener() {}
    }
    const ctx = vm.createContext({
      crypto: crypto.webcrypto, SubtleCrypto: sp.constructor,
      TextEncoder, TextDecoder, Headers: VmHeaders, Response: VmResponse, Performance: VmPerformance,
      URL, URLSearchParams, Request, DOMException, console: vmConsole, setTimeout, clearTimeout,
      performance: new VmPerformance(), document: new Document(),
      Document, Node, Element, HTMLIFrameElement, ShadowRoot,
      navigator: { webdriver: false, platform: "Linux x86_64", userAgent: CHROME_UA },
      location: { origin: "https://app.example", href: "https://app.example/", pathname: "/" },
      fetch: vmFetch, addEventListener() {}, _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "Event", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get stack", "encode"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return ""; } }, "stack"));' : ""}
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, src };
  };

  // 1) Security HIGH #1: Pre-load Error.stackTraceLimit = 0 still captures CallSite cleanly (and restores 0), while inherited Function.prototype.prepareStackTrace fails closed as TAMPERED_GUARD!
  let stl0Ctx = "";
  const vmStl0 = makeVm27({
    preLoadHook: `Error.stackTraceLimit = 0;`,
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", responseStatus: 200, decodedBodySize: 500 }],
    fetchImpl: async (url, init, VmResponse) => {
      const sUrl = String(url);
      if (sUrl.endsWith("/boot")) return new VmResponse(JSON.stringify(eng27.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
      if (sUrl.endsWith("/handshake")) {
        const b = JSON.parse(init.body);
        const hsBind = crypto.createHash("sha256").update(`${b.guardHash}|${b.cdpActive ? "1" : "0"}|`).digest("hex");
        const s = eng27.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: b.clientPubB64, bootToken: b.bootToken, hsBind });
        return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
      }
      stl0Ctx = init.headers.get("X-PS-Ctx") || "";
      return new VmResponse("{}", { status: 200, headers: { "x-ps-next-canary": "a".repeat(32) } });
    },
  });
  vm.runInContext(`Error.stackTraceLimit = 10;`, vmStl0.ctx);
  await vm.runInContext(`eval('window.fetch("/api/stl0", { method: "POST", body: "{}" })\\n//# sourceURL=https://app.example/app.js');`, vmStl0.ctx);
  assert.ok(stl0Ctx.includes("ce=1"), `Pre-load Error.stackTraceLimit=0 MUST NOT downgrade V8 CallSite capture (got ${stl0Ctx})`);

  const vmInhPst = makeVm27({ preLoadHook: `Function.prototype.prepareStackTrace = undefined;` });
  vm.runInContext(`delete Function.prototype.prepareStackTrace;`, vmInhPst.ctx);
  assert.equal(vmInhPst.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", "Pre-load inherited Function.prototype.prepareStackTrace MUST fail closed as TAMPERED_GUARD even after microtask cleanup!");

  // 2) Security MEDIUM #1: Pre-load window.URL wrapper spoofing .origin MUST fail closed as TAMPERED_GUARD!
  const vmUrlSpoof = makeVm27({
    preLoadHook: `
      const RealURL = window.URL;
      window.URL = function FakeURL(u, b) {
        const inst = new RealURL(u, b);
        Object.defineProperty(inst, "origin", { value: "https://app.example" });
        return inst;
      };
    `,
  });
  assert.equal(vmUrlSpoof.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", "Pre-load window.URL wrapper MUST fail closed as TAMPERED_GUARD!");

  // 3) Availability: Safari/Firefox 302-redirected CDN '@' URLs (alpinejs@3.14.1/dist/cdn.min.js) stay 0-FP ce=0!
  let safRedirAtCtx = "";
  const vmSafAt = makeVm27({
    geckoStack: true,
    guardOpts: { requireGuardIntegrity: false },
    initScripts: ["https://unpkg.com/alpinejs"],
    rtEntries: [{ name: "https://unpkg.com/alpinejs", initiatorType: "script", transferSize: 0, responseStart: 0, encodedBodySize: 0, decodedBodySize: 0, responseEnd: 15 }],
    preLoadHook: `Object.defineProperty(Error.prototype, "stack", Object.getOwnPropertyDescriptor({ get stack() { return globalThis.__atS; } }, "stack"));`,
    fetchImpl: async (url, init, VmResponse) => {
      const sUrl = String(url);
      if (sUrl.endsWith("/boot")) return new VmResponse(JSON.stringify(eng27.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
      if (sUrl.endsWith("/handshake")) {
        const b = JSON.parse(init.body);
        const hsBind = crypto.createHash("sha256").update(`${b.guardHash}|${b.cdpActive ? "1" : "0"}|`).digest("hex");
        const s = eng27.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: b.clientPubB64, bootToken: b.bootToken, hsBind });
        return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
      }
      safRedirAtCtx = init.headers.get("X-PS-Ctx") || "";
      return new VmResponse("{}", { status: 200, headers: { "x-ps-next-canary": "a".repeat(32) } });
    },
  });
  vmSafAt.ctx.__atS = "captureConsoleEvalFlag@https://app.example/__proxysnare/guard.js:1:1\nproxySnareFetch@https://app.example/__proxysnare/guard.js:1:1\nhttps://unpkg.com/alpinejs@3.14.1/dist/cdn.min.js:12:4";
  await vmSafAt.ctx.fetch("/api/alpine-at", { method: "POST", body: "{}" });
  assert.ok(safRedirAtCtx.includes("ce=0"), `Safari 302-redirected CDN '@' URL (alpinejs@3.14.1/dist/cdn.min.js) MUST stay 0-FP ce=0 (got ${safRedirAtCtx})`);

  // 4) Parity MEDIUM #1 + Availability HEAD redirect: Python Signal 4 >4KB matches Node exact score/reasons, and HEAD redirect emits X-PS-Redirect-Get: 1 with empty body!
  const bigBody = "A".repeat(5000);
  let nodeBigV;
  for (let i = 0; i < 4; i++) {
    nodeBigV = eng27.inspectRequest({ method: "POST", url: "/api/upload", ip: "198.51.100.7", headers: makeBrowserHeaders({ "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors" }), body: bigBody });
  }
  const pyBigOut = execFileSync(
    "python3",
    [
      "-c",
      `import sys, json; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v = ProxySnareVerifier(mode="strict", protected_paths=["/api"])
for _ in range(4):
    res = v.inspect_request(method="POST", url="/api/upload", ip="198.51.100.7", headers={"User-Agent": ${JSON.stringify(CHROME_UA)}, "Sec-Fetch-Site": "same-origin", "Sec-Fetch-Mode": "cors"}, body=b"A"*5000)
print(json.dumps({"score": res.score, "reasons": [r["code"] for r in res.reasons]}))`,
    ],
    { encoding: "utf8" }
  );
  const pyBig = JSON.parse(pyBigOut.trim());
  assert.equal(pyBig.score, nodeBigV.score, `Python >4KB Signal 4 score MUST match Node (${pyBig.score} vs ${nodeBigV.score})`);
  assert.deepEqual(pyBig.reasons, nodeBigV.reasons.map((r) => r.code), "Python >4KB Signal 4 reasons MUST match Node!");

  const mwHead = createProxySnareMiddleware({ mode: "strict", protectedPaths: ["/api"] });
  const sHead = mwHead.engine.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
  const tsH = String(Date.now());
  const nonceH = "0123456789abcdef01234567";
  const ctxH = "ce=0;cdp=0;ug=0;ga=999999;ik=0";
  const proofH = mwHead.engine.signRequest({ sessionKeyHex: sHead.sessionKeyHex, method: "HEAD", pathWithQuery: "/api/old", body: "", seq: "1", ts: tsH, nonce: nonceH, canary: sHead.canary, ctx: ctxH });
  const headHdrs = makeBrowserHeaders({ "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "x-ps-session": sHead.sessionId, "x-ps-seq": "1", "x-ps-ts": tsH, "x-ps-nonce": nonceH, "x-ps-canary": sHead.canary, "x-ps-ctx": ctxH, "x-ps-proof": proofH });
  await mwHead({ method: "HEAD", url: "/api/old", socket: { remoteAddress: "127.0.0.1" }, headers: headHdrs }, { headersSent: false, writableEnded: false, setHeader() {}, writeHead() {}, end() {} });
  let headStatus = 0, headBody = "UNSET", headOutHdrs = {};
  await mwHead(
    { method: "HEAD", url: "/api/new", socket: { remoteAddress: "127.0.0.1" }, headers: headHdrs },
    { headersSent: false, writableEnded: false, setHeader() {}, writeHead(st, h) { headStatus = st; headOutHdrs = h || {}; this.headersSent = true; }, end(b) { headBody = b === undefined ? "" : String(b); this.writableEnded = true; } }
  );
  assert.equal(headStatus, 403);
  assert.equal(headOutHdrs["X-PS-Redirect-Get"], "1", "Redirected HEAD MUST emit X-PS-Redirect-Get: 1!");
  assert.equal(headBody, "", "Blocked HEAD 403 MUST send zero body bytes (RFC 9110 §9.3.2)!");

  // 5) Security LOW #1: Turkish U+0130 ('İ') before <head> MUST NOT split <title>!
  const trHtml = "<!doctype html><!-- \u0130stanbul --><head><title>Test</title></head><body></body>";
  const injectedTr = injectGuardIntoHtml(trHtml, "/__proxysnare");
  assert.ok(injectedTr.includes("<head><script src=\"/__proxysnare/guard.js"), "guard.js MUST inject cleanly right after <head>!");
  assert.ok(injectedTr.includes("</script><title>Test</title>"), `U+0130 MUST NOT split <title> (got ${injectedTr})`);
});

test("39. Pass-28 Audit Regressions: delete window.Response/ArrayBuffer/FakeXHR tamper, Safari Sec-Fetch-* bootstrap gating, header-then-hold freshnessMs & bodyReadTimeoutMs, Firefox redirected @version eval 0-FP, buffered PO navCutoff & importmap seeding, fast 4KB/64KB HTML injection, & parseReqBody:false", async () => {
  const { buildBrowserGuardScript, computeGuardIntegrity } = require("../src/browser-guard");
  const { injectGuardIntoHtml } = require("../src/middleware");
  const eng28 = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api"] });

  const makeVm28 = ({
    preLoadHook = "",
    geckoStack = false,
    rtEntries = [],
    navEntries = [],
    readyState = "complete",
    importMaps = [],
    delayPoFlush = false,
    onFetch = null,
  } = {}) => {
    const src = buildBrowserGuardScript({
      mode: "strict",
      serverEcdsaPubB64: eng28.ecdsaPublicKeyB64,
      protectedPaths: ["/api"],
      requireGuardIntegrity: true,
      failClosedOnTamper: true,
      blockConsoleEval: true,
      blockCdpActive: true,
      allowDevTools: false,
    });
    const expHash = computeGuardIntegrity(src).guardHash;
    const sp = crypto.webcrypto.subtle;
    const sMethods = ["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "sign", "verify", "digest"];
    const origTeEncode = TextEncoder.prototype.encode;
    class VmTextEncoder { constructor() { this._te = new TextEncoder(); } encode(s) { return origTeEncode.call(this._te, s); } }
    const origHdrSet = Headers.prototype.set;
    const origHdrGet = Headers.prototype.get;
    const origHdrHas = Headers.prototype.has;
    class VmHeaders {
      constructor(i) { this._h = new Headers(i); }
      set(k, v) { return origHdrSet.call(this._h, k, v); }
      get(k) { return origHdrGet.call(this._h, k); }
      has(k) { return origHdrHas.call(this._h, k); }
    }
    class VmResponse {
      constructor(b, init = {}) { this._r = new Response(b, init); this._st = init.status || 200; this._h = new VmHeaders(init.headers || {}); }
      get status() { return this._st; }
      get headers() { return this._h; }
      get redirected() { return false; }
      get url() { return ""; }
      get type() { return "basic"; }
      json() { return this._r.json(); }
      arrayBuffer() { return this._r.arrayBuffer(); }
      clone() { return new VmResponse(this._r.clone(), { status: this._st }); }
    }
    const VmXHR = class XMLHttpRequest {
      constructor() { this._rs = 0; this._st = 0; this._rUrl = ""; }
      get readyState() { return this._rs; }
      get status() { return this._st; }
      get responseURL() { return this._rUrl; }
      getResponseHeader() { return null; }
      open() {}
      setRequestHeader() {}
      send() {}
      abort() {}
    };
    const vmFetch = async function fetch(url, init) {
      const sUrl = String(url);
      if (sUrl.endsWith("/__proxysnare/boot")) {
        return new VmResponse(JSON.stringify(eng28.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
      }
      if (sUrl.endsWith("/__proxysnare/handshake")) {
        const body = JSON.parse(init.body);
        const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|${body.browserProof?.d || ""}`).digest("hex");
        const s = eng28.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
        return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
      }
      if (onFetch) onFetch(sUrl, init);
      return new VmResponse("{}", { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "a".repeat(32) } });
    };
    const vmConsole = { debug: function debug() {}, error: function error() {}, warn: function warn() {} };
    const vmPerf = {
      now: function now() { return 1000; },
      getEntriesByType: function getEntriesByType(t) {
        if (t === "resource") return rtEntries;
        if (t === "navigation") return navEntries;
        return [];
      },
    };
    let poCb = null;
    class VmPerformanceObserver {
      constructor(cb) { poCb = cb; }
      observe() { if (!delayPoFlush && poCb && rtEntries.length) poCb({ getEntries: () => rtEntries }); }
      takeRecords() { return []; }
      disconnect() {}
    }
    const nativeRefs = new Set([
      ...sMethods.map((m) => sp[m]),
      VmTextEncoder.prototype.encode,
      VmHeaders.prototype.set, VmHeaders.prototype.get, VmHeaders.prototype.has,
      VmResponse.prototype.json, VmResponse.prototype.clone, VmResponse.prototype.arrayBuffer,
      Object.getOwnPropertyDescriptor(VmResponse.prototype, "status").get,
      Object.getOwnPropertyDescriptor(VmResponse.prototype, "headers").get,
      Object.getOwnPropertyDescriptor(VmResponse.prototype, "redirected").get,
      Object.getOwnPropertyDescriptor(VmResponse.prototype, "url").get,
      Object.getOwnPropertyDescriptor(VmResponse.prototype, "type").get,
      VmXHR.prototype.open, VmXHR.prototype.send, VmXHR.prototype.setRequestHeader, VmXHR.prototype.getResponseHeader,
      Object.getOwnPropertyDescriptor(VmXHR.prototype, "readyState").get,
      Object.getOwnPropertyDescriptor(VmXHR.prototype, "status").get,
      Object.getOwnPropertyDescriptor(VmXHR.prototype, "responseURL").get,
      vmFetch, crypto.webcrypto.getRandomValues, vmPerf.getEntriesByType, vmPerf.now, vmConsole.debug,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader", "open", "send", "setRequestHeader", "stack", "get stack"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        class Response { json() {} clone() {} arrayBuffer() {} get status() { return 200; } get headers() { return null; } }
        class XMLHttpRequest {}
        class CryptoKey {}
        class Document {}
        class Node {}
        globalThis.Response = Response;
        globalThis.XMLHttpRequest = XMLHttpRequest;
        globalThis.CryptoKey = CryptoKey;
        globalThis.Document = Document;
        globalThis.Node = Node;
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", { configurable: true, get: function stack() { return ""; } });' : ""}
        return globalThis;
      })();`,
      ifrCtx
    );
    class ShadowRoot { appendChild(c) { return c; } }
    class HTMLIFrameElement { get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node { get shadowRoot() { return null; } attachShadow() { return new ShadowRoot(); } getAttribute() { return null; } remove() {} }
    class Document extends Node {
      constructor() { super(); this.currentScript = null; this.baseURI = "https://app.example/"; this.readyState = readyState; this.scripts = []; this._el = new Element(); }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : new Element(); }
      querySelectorAll(sel) {
        if (sel === 'script[type="importmap"]') return importMaps.map((txt) => ({ textContent: txt }));
        return [];
      }
      querySelector() { return null; }
      addEventListener() {}
    }
    const docInst = new Document();
    const ctx = vm.createContext({
      crypto: crypto.webcrypto,
      SubtleCrypto: sp.constructor,
      CryptoKey: crypto.webcrypto.CryptoKey || class CryptoKey {},
      TextEncoder: VmTextEncoder,
      TextDecoder,
      Headers: VmHeaders,
      Response: VmResponse,
      XMLHttpRequest: VmXHR,
      PerformanceObserver: VmPerformanceObserver,
      URL, URLSearchParams, Request, console: vmConsole, setTimeout, clearTimeout,
      performance: vmPerf,
      navigator: { webdriver: false, userAgent: CHROME_UA },
      document: docInst,
      Document, Node, Element, HTMLIFrameElement, ShadowRoot,
      location: { origin: "https://app.example", href: "https://app.example/", pathname: "/" },
      fetch: vmFetch,
      addEventListener() {},
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader", "open", "send", "setRequestHeader", "stack", "get stack"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", { configurable: true, get: function stack() { return globalThis.__mockStack || ""; } });' : ""}
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, expHash, docInst, flushPo: (ents) => { if (poCb) poCb({ getEntries: () => ents || rtEntries }); } };
  };

  // Baseline clean VM passes guardHash
  const vmClean = makeVm28();
  assert.equal(vmClean.ctx.ProxySnare.guardHash(), vmClean.expHash, "Clean Pass-28 VM MUST match expected guardHash!");

  // 1) Security HIGH #1: Pre-load delete window.Response / delete window.ArrayBuffer / FakeXHR subclass MUST fail closed as TAMPERED_GUARD!
  for (const [label, hook] of [
    ["delete window.Response", `delete window.Response;`],
    ["delete window.ArrayBuffer", `delete window.ArrayBuffer;`],
    ["FakeXHR subclass", `class FakeXHR extends XMLHttpRequest {} window.XMLHttpRequest = FakeXHR;`],
  ]) {
    const v = makeVm28({ preLoadHook: hook });
    assert.equal(v.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", `${label} MUST fail closed as TAMPERED_GUARD!`);
  }

  // 2) Availability HIGH #1: Firefox eval/Function frame from 302-redirected @version CDN script (Alpine.js) MUST emit ce=0 (0-FP)!
  let alpineCtx = "";
  const vmAlpine = makeVm28({
    geckoStack: true,
    rtEntries: [{ name: "https://unpkg.com/alpinejs", initiatorType: "script", redirectEnd: 12, startTime: 10, responseStatus: 200 }],
    navEntries: [{ loadEventStart: 100, loadEventEnd: 120 }],
    onFetch: (_u, init) => { alpineCtx = (typeof init?.headers?.get === "function" ? init.headers.get("X-PS-Ctx") : init?.headers?.["X-PS-Ctx"]) || ""; },
  });
  vmAlpine.ctx.__mockStack =
    "fetch@https://app.example/__proxysnare/guard.js:1:1\n" +
    "anonymous@https://unpkg.com/alpinejs@3.14.1/dist/cdn.min.js line 1 > Function:3:8\n" +
    "init@https://unpkg.com/alpinejs@3.14.1/dist/cdn.min.js:1:200";
  await new Promise((r) => setTimeout(r, 0));
  await vm.runInContext(`Promise.resolve().then(() => fetch("https://app.example/api/data"))`, vmAlpine.ctx);
  assert.ok(alpineCtx.startsWith("ce=0;cdp=0;"), `Firefox 302-redirected Alpine eval frame MUST emit ce=0;cdp=0 (got ${alpineCtx})`);

  // 3) Availability MEDIUM #2A: Buffered PerformanceObserver firing AFTER readyState==="complete" trusts pre-load CDN ES module (startTime<=loadEventEnd) while rejecting post-load injected script (startTime>loadEventEnd)!
  let poCtxPre = "";
  let poCtxPost = "";
  const vmPo = makeVm28({
    geckoStack: true,
    readyState: "complete",
    delayPoFlush: true,
    rtEntries: [
      { name: "https://esm.sh/axios@1.7.0/es2022/axios.mjs", initiatorType: "script", startTime: 25, responseStatus: 200 },
      { name: "https://evil.example/injected.js", initiatorType: "script", startTime: 250, responseStatus: 200 },
    ],
    navEntries: [{ loadEventStart: 100, loadEventEnd: 120 }],
    onFetch: (u, init) => {
      const ctxVal = (typeof init?.headers?.get === "function" ? init.headers.get("X-PS-Ctx") : init?.headers?.["X-PS-Ctx"]) || "";
      if (u.includes("pre")) poCtxPre = ctxVal;
      else poCtxPost = ctxVal;
    },
  });
  // Flush buffered PerformanceObserver AFTER document.readyState is already "complete"!
  vmPo.flushPo();
  vmPo.ctx.__mockStack = "fetch@https://app.example/__proxysnare/guard.js:1:1\nreq@https://esm.sh/axios@1.7.0/es2022/axios.mjs:10:5";
  await new Promise((r) => setTimeout(r, 0));
  await vm.runInContext(`Promise.resolve().then(() => fetch("https://app.example/api/pre"))`, vmPo.ctx);
  assert.ok(poCtxPre.startsWith("ce=0;cdp=0;"), `Pre-load CDN ES module delivered after readyState='complete' MUST stay 0-FP (got ${poCtxPre})`);
  vmPo.ctx.__mockStack = "fetch@https://app.example/__proxysnare/guard.js:1:1\nhack@https://evil.example/injected.js:1:1";
  await new Promise((r) => setTimeout(r, 0));
  await vm.runInContext(`Promise.resolve().then(() => fetch("https://app.example/api/post"))`, vmPo.ctx);
  assert.ok(poCtxPost.startsWith("ce=1;"), `Post-load injected untrusted script (startTime>loadEventEnd) MUST STILL emit ce=1 (got ${poCtxPost})`);

  // 4) Availability MEDIUM #2B: <script type="importmap"> seeds CDN origin for dynamic import() after page load!
  let imCtx = "";
  const vmIm = makeVm28({
    geckoStack: true,
    readyState: "complete",
    importMaps: [JSON.stringify({ imports: { axios: "https://esm.sh/axios@1.7.0/es2022/axios.mjs" } })],
    rtEntries: [{ name: "https://esm.sh/axios@1.7.0/es2022/axios.mjs", initiatorType: "script", startTime: 500, responseStatus: 200 }],
    navEntries: [{ loadEventStart: 100, loadEventEnd: 120 }],
    onFetch: (_u, init) => { imCtx = (typeof init?.headers?.get === "function" ? init.headers.get("X-PS-Ctx") : init?.headers?.["X-PS-Ctx"]) || ""; },
  });
  vmIm.ctx.__mockStack = "fetch@https://app.example/__proxysnare/guard.js:1:1\nrun@https://esm.sh/axios@1.7.0/es2022/axios.mjs:5:2";
  await new Promise((r) => setTimeout(r, 0));
  await vm.runInContext(`Promise.resolve().then(() => fetch("https://app.example/api/im"))`, vmIm.ctx);
  assert.ok(imCtx.startsWith("ce=0;cdp=0;"), `Dynamic import() from <script type="importmap"> origin MUST stay 0-FP (got ${imCtx})`);

  // 5) Security MEDIUM #3: Safari 16.4+ explicit Sec-Fetch-* headers enforced on wildcard '/' reverse proxy!
  const up28 = http.createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
    res.end("<!doctype html><html><head></head><body>home</body></html>");
  });
  await new Promise((r) => up28.listen(0, "127.0.0.1", r));
  const ps28 = createProxySnareServer({
    target: `http://127.0.0.1:${up28.address().port}`,
    mode: "strict",
    protectedPaths: ["/"],
  });
  const ps28Url = await ps28.listen(0, "127.0.0.1");
  const safUa = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15";
  const reqRaw = (headers) => new Promise((resolve, reject) => {
    const u = new URL(`${ps28Url}/`);
    const r = http.request({ hostname: u.hostname, port: u.port, path: "/", method: "GET", headers }, (resp) => {
      const ch = [];
      resp.on("data", (c) => ch.push(c));
      resp.on("end", () => resolve({ status: resp.statusCode, body: Buffer.concat(ch).toString("utf8") }));
    });
    r.on("error", reject);
    r.end();
  });
  try {
    const safNav = await reqRaw({ "User-Agent": safUa, Accept: "text/html", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "document", "Sec-Fetch-Site": "none" });
    assert.equal(safNav.status, 200, "Safari 16.4+ HTML navigation MUST be allowed!");
    const safOld = await reqRaw({ "User-Agent": safUa, Accept: "text/html" });
    assert.equal(safOld.status, 200, "Safari <16.4 HTML navigation without Sec-Fetch-* MUST be allowed!");
    const safCors = await reqRaw({ "User-Agent": safUa, Accept: "text/html", "Sec-Fetch-Mode": "cors", "Sec-Fetch-Dest": "empty", "Sec-Fetch-Site": "same-origin" });
    assert.equal(safCors.status, 403, "Safari 16.4+ Sec-Fetch-Mode:cors on wildcard '/' MUST be blocked (403)!");
    const safXFrame = await reqRaw({ "User-Agent": safUa, Accept: "text/html", "Sec-Fetch-Mode": "navigate", "Sec-Fetch-Dest": "iframe", "Sec-Fetch-Site": "cross-site" });
    assert.equal(safXFrame.status, 403, "Safari 16.4+ cross-site iframe on wildcard '/' MUST be blocked (403)!");
  } finally {
    await ps28.close();
    await new Promise((r) => up28.close(r));
  }

  // 6) Security MEDIUM #4: Header-then-hold streaming POST MUST trigger INTERCEPT_HOLD_OR_STALE_REPLAY & bounded bodyReadTimeoutMs returns 408!
  const mwHold = createProxySnareMiddleware({ mode: "strict", protectedPaths: ["/api"], freshnessMs: 120, bodyReadTimeoutMs: 90, parseReqBody: false });
  const srvHold = http.createServer(async (req, res) => {
    const handled = await mwHold(req, res);
    if (handled) return;
    // Verify parseReqBody:false skipped defining lazy req.body getter while stream still replays!
    const hasOwnBodyDesc = Boolean(Object.getOwnPropertyDescriptor(req, "body"));
    const chunks = [];
    for await (const c of req) chunks.push(c);
    res.writeHead(200, { "Content-Type": "application/json" });
    res.end(JSON.stringify({ ok: true, hasOwnBodyDesc, rawLen: Buffer.concat(chunks).length }));
  });
  await new Promise((r) => srvHold.listen(0, "127.0.0.1", r));
  const holdPort = srvHold.address().port;
  try {
    const sHold = mwHold.engine.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
    const bodyStr = JSON.stringify({ x: 1 });
    // First, fast valid POST verifies parseReqBody:false + stream replay
    const ts1 = String(Date.now());
    const n1 = "111122223333444455556666";
    const ctx1 = "ce=0;cdp=0;ug=1;ga=10;ik=0";
    const p1 = mwHold.engine.signRequest({ sessionKeyHex: sHold.sessionKeyHex, method: "POST", pathWithQuery: "/api/item", body: bodyStr, seq: "1", ts: ts1, nonce: n1, canary: sHold.canary, ctx: ctx1 });
    const fastRes = await new Promise((resolve, reject) => {
      const r = http.request({
        hostname: "127.0.0.1", port: holdPort, path: "/api/item", method: "POST",
        headers: makeBrowserHeaders({ "content-type": "application/json", "content-length": String(Buffer.byteLength(bodyStr)), "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "x-ps-session": sHold.sessionId, "x-ps-seq": "1", "x-ps-ts": ts1, "x-ps-nonce": n1, "x-ps-canary": sHold.canary, "x-ps-ctx": ctx1, "x-ps-proof": p1 }),
      }, (resp) => {
        const ch = []; resp.on("data", (c) => ch.push(c));
        resp.on("end", () => resolve({ status: resp.statusCode, headers: resp.headers, json: JSON.parse(Buffer.concat(ch).toString("utf8")) }));
      });
      r.on("error", reject);
      r.end(bodyStr);
    });
    assert.equal(fastRes.status, 200);
    assert.equal(fastRes.json.hasOwnBodyDesc, false, "parseReqBody:false MUST NOT define lazy req.body getter!");
    assert.equal(fastRes.json.rawLen, Buffer.byteLength(bodyStr), "parseReqBody:false MUST still replay request stream!");

    // Second, send headers immediately with fresh ts2, hold final byte 160ms (>120ms freshnessMs) -> MUST block with INTERCEPT_HOLD_OR_STALE_REPLAY!
    const mwHold2 = createProxySnareMiddleware({ mode: "strict", protectedPaths: ["/api"], freshnessMs: 120, bodyReadTimeoutMs: 500 });
    const srvHold2 = http.createServer(async (req, res) => { if (!(await mwHold2(req, res))) { res.writeHead(200); res.end("ok"); } });
    await new Promise((r) => srvHold2.listen(0, "127.0.0.1", r));
    try {
      const s2 = mwHold2.engine.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA });
      const ts2 = String(Date.now());
      const n2 = "aaaa22223333444455556666";
      const p2 = mwHold2.engine.signRequest({ sessionKeyHex: s2.sessionKeyHex, method: "POST", pathWithQuery: "/api/item", body: bodyStr, seq: "1", ts: ts2, nonce: n2, canary: s2.canary, ctx: ctx1 });
      const heldRes = await new Promise((resolve, reject) => {
        const r = http.request({
          hostname: "127.0.0.1", port: srvHold2.address().port, path: "/api/item", method: "POST",
          headers: makeBrowserHeaders({ "content-type": "application/json", "content-length": String(Buffer.byteLength(bodyStr)), "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "x-ps-session": s2.sessionId, "x-ps-seq": "1", "x-ps-ts": ts2, "x-ps-nonce": n2, "x-ps-canary": s2.canary, "x-ps-ctx": ctx1, "x-ps-proof": p2 }),
        }, (resp) => {
          const ch = []; resp.on("data", (c) => ch.push(c));
          resp.on("end", () => resolve({ status: resp.statusCode, json: JSON.parse(Buffer.concat(ch).toString("utf8")) }));
        });
        r.on("error", reject);
        r.write(bodyStr.slice(0, -1));
        setTimeout(() => r.end(bodyStr.slice(-1)), 160);
      });
      assert.equal(heldRes.status, 403, "Header-then-hold streaming POST MUST NOT bypass freshnessMs!");
      assert.ok(heldRes.json.reasons.includes("INTERCEPT_HOLD_OR_STALE_REPLAY"), `Expected INTERCEPT_HOLD_OR_STALE_REPLAY (got ${JSON.stringify(heldRes.json)})`);
    } finally {
      await new Promise((r) => srvHold2.close(r));
    }

    // Third, stall body past bodyReadTimeoutMs (90ms) -> MUST return 408 REQUEST_BODY_TIMEOUT + Connection: close!
    const nextCanary = fastRes.headers["x-ps-next-canary"];
    const ts3 = String(Date.now());
    const n3 = "bbbb22223333444455556666";
    const p3 = mwHold.engine.signRequest({ sessionKeyHex: sHold.sessionKeyHex, method: "POST", pathWithQuery: "/api/item", body: bodyStr, seq: "2", ts: ts3, nonce: n3, canary: nextCanary, ctx: ctx1 });
    const timeoutRes = await new Promise((resolve, reject) => {
      const r = http.request({
        hostname: "127.0.0.1", port: holdPort, path: "/api/item", method: "POST",
        headers: makeBrowserHeaders({ "content-type": "application/json", "content-length": String(Buffer.byteLength(bodyStr)), "sec-fetch-site": "same-origin", "sec-fetch-mode": "cors", "x-ps-session": sHold.sessionId, "x-ps-seq": "2", "x-ps-ts": ts3, "x-ps-nonce": n3, "x-ps-canary": nextCanary, "x-ps-ctx": ctx1, "x-ps-proof": p3 }),
      }, (resp) => {
        const ch = []; resp.on("data", (c) => ch.push(c));
        resp.on("end", () => resolve({ status: resp.statusCode, conn: resp.headers.connection, json: JSON.parse(Buffer.concat(ch).toString("utf8")) }));
      });
      r.on("error", () => {});
      r.write("{");
    });
    assert.equal(timeoutRes.status, 408, "Stalled body past bodyReadTimeoutMs MUST return 408!");
    assert.equal(timeoutRes.json.error, "REQUEST_BODY_TIMEOUT");
    assert.equal(timeoutRes.conn, "close", "408 unread-body response MUST include Connection: close!");
  } finally {
    await new Promise((r) => srvHold.close(r));
  }

  // 7) Performance MEDIUM #1: 4KB / 64KB / >64KB & Kelvin U+212A + Turkish U+0130 HTML injection parity
  for (const padLen of [100, 6000, 70000]) {
    const htmlPad = `<!doctype html><!-- \u0130\u212A${"x".repeat(padLen)} --><head><title>P</title></head><body></body>`;
    const inj = injectGuardIntoHtml(htmlPad, "/__proxysnare");
    assert.ok(inj.includes('<head><script src="/__proxysnare/guard.js'), `guard.js MUST inject after <head> for padLen=${padLen}`);
    assert.ok(inj.includes("</script><title>P</title>"), `HTML injection MUST NOT split <title> for padLen=${padLen}`);
  }
});

test("40. Pass-29 Audit Regressions: post-load untrusted <script> cannot poison trustedScriptOrigins/redirect heuristics, pre-existing Error.prepareStackTrace V8 0-FP, expanded IPv4-mapped IPv6 trustProxy, macOS Cmd+Option ev.code shortcut, & Vite non-root base", async () => {
  const { buildBrowserGuardScript, computeGuardIntegrity } = require("../src/browser-guard");
  const eng29 = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api"], trustProxy: ["0:0:0:0:0:ffff:10.0.0.1", "::ffff:0a00:0002"] });

  // 1) Security LOW #3: Expanded/hex IPv4-mapped IPv6 trustProxy entries MUST match Node dual-stack ::ffff:10.0.0.x & 10.0.0.x!
  assert.equal(eng29.trustedProxies.has("::ffff:10.0.0.1"), true, "Expanded 0:0:0:0:0:ffff:10.0.0.1 MUST match ::ffff:10.0.0.1");
  assert.equal(eng29.trustedProxies.has("10.0.0.1"), true, "Expanded 0:0:0:0:0:ffff:10.0.0.1 MUST match 10.0.0.1");
  assert.equal(eng29.trustedProxies.has("::ffff:10.0.0.2"), true, "Hex ::ffff:0a00:0002 MUST match ::ffff:10.0.0.2");
  assert.equal(eng29.trustedProxies.has("10.0.0.3"), false, "Unlisted IP MUST remain false");

  const makeVm29 = ({ preLoadHook = "", rtEntries = [], navEntries = [], geckoStack = false, onFetch = null } = {}) => {
    const src = buildBrowserGuardScript({
      mode: "strict",
      serverEcdsaPubB64: eng29.ecdsaPublicKeyB64,
      protectedPaths: ["/api"],
      requireGuardIntegrity: true,
      failClosedOnTamper: true,
      blockConsoleEval: true,
      blockCdpActive: true,
      allowDevTools: false,
    });
    const expHash = computeGuardIntegrity(src).guardHash;
    const sp = crypto.webcrypto.subtle;
    const sMethods = ["generateKey", "exportKey", "importKey", "deriveBits", "deriveKey", "sign", "verify", "digest"];
    const origTeEncode = TextEncoder.prototype.encode;
    class VmTextEncoder { constructor() { this._te = new TextEncoder(); } encode(s) { return origTeEncode.call(this._te, s); } }
    const origHdrSet = Headers.prototype.set;
    const origHdrGet = Headers.prototype.get;
    const origHdrHas = Headers.prototype.has;
    class VmHeaders {
      constructor(i) { this._h = new Headers(i); }
      set(k, v) { return origHdrSet.call(this._h, k, v); }
      get(k) { return origHdrGet.call(this._h, k); }
      has(k) { return origHdrHas.call(this._h, k); }
    }
    class VmResponse {
      constructor(b, init = {}) { this._r = new Response(b, init); this._st = init.status || 200; this._h = new VmHeaders(init.headers || {}); }
      get status() { return this._st; }
      get headers() { return this._h; }
      get redirected() { return false; }
      get url() { return ""; }
      get type() { return "basic"; }
      json() { return this._r.json(); }
      arrayBuffer() { return this._r.arrayBuffer(); }
      clone() { return new VmResponse(this._r.clone(), { status: this._st }); }
    }
    const VmXHR = class XMLHttpRequest {
      constructor() { this._rs = 0; this._st = 0; this._rUrl = ""; }
      get readyState() { return this._rs; }
      get status() { return this._st; }
      get responseURL() { return this._rUrl; }
      getResponseHeader() { return null; }
      open() {}
      setRequestHeader() {}
      send() {}
      abort() {}
    };
    const vmFetch = async function fetch(url, init) {
      const sUrl = String(url);
      if (sUrl.endsWith("/__proxysnare/boot")) {
        return new VmResponse(JSON.stringify(eng29.issueBootChallenge({ ip: "127.0.0.1", userAgent: CHROME_UA })), { status: 200, headers: { "content-type": "application/json" } });
      }
      if (sUrl.endsWith("/__proxysnare/handshake")) {
        const body = JSON.parse(init.body);
        const hsBind = crypto.createHash("sha256").update(`${body.guardHash}|${body.cdpActive ? "1" : "0"}|${body.browserProof?.d || ""}`).digest("hex");
        const s = eng29.issueSession({ ip: "127.0.0.1", userAgent: CHROME_UA, clientPubB64: body.clientPubB64, bootToken: body.bootToken, hsBind });
        return new VmResponse(JSON.stringify({ protocol: "PS_ECDH_V2", sessionId: s.sessionId, serverPubB64: s.serverPubB64, saltB64: s.saltB64, canary: s.canary, serverNowMs: s.serverNowMs, serverSigB64: s.serverSigB64 }), { status: 200, headers: { "content-type": "application/json" } });
      }
      if (onFetch) onFetch(sUrl, init);
      return new VmResponse("{}", { status: 200, headers: { "content-type": "application/json", "x-ps-next-canary": "a".repeat(32) } });
    };
    const vmConsole = { debug: function debug() {}, error: function error() {}, warn: function warn() {} };
    const vmPerf = {
      now: function now() { return 1000; },
      getEntriesByType: function getEntriesByType(t) {
        if (t === "resource") return rtEntries;
        if (t === "navigation") return navEntries;
        return [];
      },
    };
    const listeners = {};
    const nativeRefs = new Set([
      ...sMethods.map((m) => sp[m]),
      VmTextEncoder.prototype.encode,
      VmHeaders.prototype.set, VmHeaders.prototype.get, VmHeaders.prototype.has,
      VmResponse.prototype.json, VmResponse.prototype.clone, VmResponse.prototype.arrayBuffer,
      Object.getOwnPropertyDescriptor(VmResponse.prototype, "status").get,
      Object.getOwnPropertyDescriptor(VmResponse.prototype, "headers").get,
      Object.getOwnPropertyDescriptor(VmResponse.prototype, "redirected").get,
      Object.getOwnPropertyDescriptor(VmResponse.prototype, "url").get,
      Object.getOwnPropertyDescriptor(VmResponse.prototype, "type").get,
      VmXHR.prototype.open, VmXHR.prototype.send, VmXHR.prototype.setRequestHeader, VmXHR.prototype.getResponseHeader,
      Object.getOwnPropertyDescriptor(VmXHR.prototype, "readyState").get,
      Object.getOwnPropertyDescriptor(VmXHR.prototype, "status").get,
      Object.getOwnPropertyDescriptor(VmXHR.prototype, "responseURL").get,
      vmFetch, crypto.webcrypto.getRandomValues, vmPerf.getEntriesByType, vmPerf.now, vmConsole.debug,
    ]);
    const ifrCtx = vm.createContext({ console: { debug: vmConsole.debug }, _nativeRefs: nativeRefs });
    const ifrWin = vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader", "open", "send", "setRequestHeader", "stack", "get stack"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        class Response { json() {} clone() {} arrayBuffer() {} get status() { return 200; } get headers() { return null; } }
        class XMLHttpRequest {}
        class CryptoKey {}
        class Document {}
        class Node {}
        globalThis.Response = Response;
        globalThis.XMLHttpRequest = XMLHttpRequest;
        globalThis.CryptoKey = CryptoKey;
        globalThis.Document = Document;
        globalThis.Node = Node;
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", { configurable: true, get: function stack() { return ""; } });' : ""}
        return globalThis;
      })();`,
      ifrCtx
    );
    class ShadowRoot { appendChild(c) { return c; } }
    class HTMLIFrameElement { get contentWindow() { return ifrWin; } remove() {} }
    class Node { appendChild(c) { return c; } }
    class Element extends Node { get shadowRoot() { return null; } attachShadow() { return new ShadowRoot(); } getAttribute() { return null; } remove() {} }
    class Document extends Node {
      constructor() { super(); this.currentScript = null; this.baseURI = "https://app.example/"; this.readyState = "complete"; this.scripts = []; this._el = new Element(); }
      get documentElement() { return this._el; }
      createElement(t) { return t === "iframe" ? new HTMLIFrameElement() : new Element(); }
      querySelectorAll() { return []; }
      querySelector() { return null; }
      addEventListener() {}
    }
    const ctx = vm.createContext({
      crypto: crypto.webcrypto,
      SubtleCrypto: sp.constructor,
      CryptoKey: crypto.webcrypto.CryptoKey || class CryptoKey {},
      TextEncoder: VmTextEncoder,
      TextDecoder,
      Headers: VmHeaders,
      Response: VmResponse,
      XMLHttpRequest: VmXHR,
      PerformanceObserver: class PO { observe() {} takeRecords() { return []; } disconnect() {} },
      URL, URLSearchParams, Request, console: vmConsole, setTimeout, clearTimeout,
      performance: vmPerf,
      navigator: { webdriver: false, userAgent: CHROME_UA },
      document: new Document(),
      Document, Node, Element, HTMLIFrameElement, ShadowRoot,
      location: { origin: "https://app.example", href: "https://app.example/", pathname: "/" },
      fetch: vmFetch,
      addEventListener(ev, fn) { (listeners[ev] ||= []).push(fn); },
      _nativeRefs: nativeRefs,
    });
    ctx.window = ctx;
    vm.runInContext(
      `(() => {
        const orig = Function.prototype.toString;
        const domOk = new Set(["URL", "get origin", "get pathname", "toString", "createElement", "appendChild", "attachShadow", "get documentElement", "get contentWindow", "getAttribute", "XMLHttpRequest", "debug", "now", "get status", "get headers", "clone", "arrayBuffer", "get redirected", "get url", "get type", "get readyState", "get responseURL", "getResponseHeader", "open", "send", "setRequestHeader", "stack", "get stack"]);
        Function.prototype.toString = function toString() {
          if (typeof this === "function" && (_nativeRefs.has(this) || domOk.has(this.name))) return "function " + this.name + "() { [native code] }";
          return orig.call(this);
        };
        ${geckoStack ? 'Object.defineProperty(Error.prototype, "stack", { configurable: true, get: function stack() { return globalThis.__mockStack || ""; } });' : ""}
      })();`,
      ctx
    );
    if (preLoadHook) vm.runInContext(preLoadHook, ctx);
    vm.runInContext(src, ctx);
    return { ctx, expHash, listeners };
  };

  // 2) Security MEDIUM #2: Pre-existing writable Error.prepareStackTrace (e.g. source-map-support) MUST NOT break V8 detection or produce TAMPERED_GUARD, and MUST be restored intact!
  const vmPst = makeVm29({
    preLoadHook: `
      globalThis.__customPst = function customPst(err, sites) { return ["CUSTOM_FORMAT", sites.length]; };
      Error.prepareStackTrace = globalThis.__customPst;
    `,
  });
  assert.equal(vmPst.ctx.ProxySnare.guardHash(), vmPst.expHash, "Pre-existing writable Error.prepareStackTrace MUST stay 0-FP and match expHash!");
  assert.equal(vm.runInContext(`Error.prepareStackTrace === globalThis.__customPst`, vmPst.ctx), true, "Pre-existing Error.prepareStackTrace MUST be preserved intact after guard.js load!");

  // 2b) Pass-30 Security: Pre-load non-numeric Error.stackTraceLimit = null MUST still capture native V8 CallSites (and locked null MUST fail closed as TAMPERED_GUARD)!
  const vmStlNull = makeVm29({ preLoadHook: `Error.stackTraceLimit = null;` });
  assert.equal(vmStlNull.ctx.ProxySnare.guardHash(), vmStlNull.expHash, "Writable Error.stackTraceLimit = null MUST recover V8 CallSite capture!");
  const vmStlLockedNull = makeVm29({ preLoadHook: `Object.defineProperty(Error, "stackTraceLimit", { value: null, writable: false, configurable: false });` });
  assert.equal(vmStlLockedNull.ctx.ProxySnare.guardHash(), "TAMPERED_GUARD", "Locked non-numeric Error.stackTraceLimit = null MUST fail closed as TAMPERED_GUARD!");

  // 3) Security HIGH #1: Post-load untrusted extensionless cross-origin <script> MUST NOT poison trustedScriptOrigins or redirect heuristics; normal TAO-masked 3rd-party script MUST NOT unlock arbitrary cross-origin or same-origin fabricated .js URLs!
  let ctxPoison = "";
  let ctxCrossFab = "";
  let ctxSameFab = "";
  const vmPoison = makeVm29({
    geckoStack: true,
    rtEntries: [
      // Pre-load normal extensionless third-party TAO-masked script (e.g. googletagmanager/stripe)
      { name: "https://www.googletagmanager.com/gtag/js", initiatorType: "script", startTime: 20, transferSize: 0, responseStart: 0, responseEnd: 40, responseStatus: 200 },
      // Post-load attacker-injected extensionless cross-origin script (startTime 300 > loadEventEnd 100)
      { name: "https://attacker.invalid/seed", initiatorType: "script", startTime: 300, transferSize: 0, responseStart: 0, responseEnd: 320, responseStatus: 200 },
      // Second post-load script from attacker.invalid
      { name: "https://attacker.invalid/pwn.js", initiatorType: "script", startTime: 350, transferSize: 0, responseStart: 0, responseEnd: 370, responseStatus: 200 },
    ],
    navEntries: [{ loadEventStart: 80, loadEventEnd: 100 }],
    onFetch: (u, init) => {
      const c = (typeof init?.headers?.get === "function" ? init.headers.get("X-PS-Ctx") : init?.headers?.["X-PS-Ctx"]) || "";
      if (u.includes("poison")) ctxPoison = c;
      else if (u.includes("crossfab")) ctxCrossFab = c;
      else if (u.includes("samefab")) ctxSameFab = c;
    },
  });
  vmPoison.ctx.__mockStack = "fetch@https://app.example/__proxysnare/guard.js:1:1\nrun@https://attacker.invalid/pwn.js:1:10";
  await new Promise((r) => setTimeout(r, 0));
  await vm.runInContext(`Promise.resolve().then(() => fetch("https://app.example/api/poison"))`, vmPoison.ctx);
  assert.ok(ctxPoison.startsWith("ce=1;"), `Post-load untrusted attacker.invalid/seed MUST NOT poison trustedScriptOrigins for pwn.js (got ${ctxPoison})`);

  vmPoison.ctx.__mockStack = "fetch@https://app.example/__proxysnare/guard.js:1:1\nrun@https://evil.invalid/fab.js:1:10";
  await new Promise((r) => setTimeout(r, 0));
  await vm.runInContext(`Promise.resolve().then(() => fetch("https://app.example/api/crossfab"))`, vmPoison.ctx);
  assert.ok(ctxCrossFab.startsWith("ce=1;"), `Normal TAO-masked 3rd-party script MUST NOT authorize fabricated cross-origin evil.invalid/fab.js (got ${ctxCrossFab})`);

  vmPoison.ctx.__mockStack = "fetch@https://app.example/__proxysnare/guard.js:1:1\nrun@https://app.example/fabricated.js:1:10";
  await new Promise((r) => setTimeout(r, 0));
  await vm.runInContext(`Promise.resolve().then(() => fetch("https://app.example/api/samefab"))`, vmPoison.ctx);
  assert.ok(ctxSameFab.startsWith("ce=1;"), `Normal extensionless 3rd-party script MUST NOT globally unlock fabricated same-origin .js URLs (got ${ctxSameFab})`);

  // 4) Security LOW #4: macOS Cmd+Option+I produces non-ASCII ev.key ("\u02c6"/"Dead") with ev.code "KeyI" -> MUST NOT count as user gesture!
  let macCtx = "";
  const vmMac = makeVm29({
    geckoStack: true,
    rtEntries: [{ name: "https://app.example/app.js", initiatorType: "script", startTime: 10, responseStatus: 200 }],
    navEntries: [{ loadEventStart: 80, loadEventEnd: 100 }],
    onFetch: (_u, init) => { macCtx = (typeof init?.headers?.get === "function" ? init.headers.get("X-PS-Ctx") : init?.headers?.["X-PS-Ctx"]) || ""; },
  });
  for (const fn of (vmMac.listeners.keydown || [])) {
    fn({ type: "keydown", isTrusted: true, metaKey: true, altKey: true, key: "\u02c6", code: "KeyI", repeat: false });
  }
  vmMac.ctx.__mockStack = "fetch@https://app.example/__proxysnare/guard.js:1:1\nrun@https://app.example/app.js:1:1";
  await new Promise((r) => setTimeout(r, 0));
  await vm.runInContext(`Promise.resolve().then(() => fetch("https://app.example/api/mac"))`, vmMac.ctx);
  assert.ok(macCtx.includes(";ug=0;"), `macOS Cmd+Option+I (ev.code=KeyI, non-ASCII ev.key) MUST NOT advance lastTrustedGestureMs (got ${macCtx})`);

  // 5) Availability LOW #1: Vite non-root base path (/app/@vite/client) allowed on wildcard '/' static probe!
  const upVite = http.createServer((req, res) => {
    res.writeHead(200, { "Content-Type": "application/javascript; charset=utf-8" });
    res.end("export const ok = 1;");
  });
  await new Promise((r) => upVite.listen(0, "127.0.0.1", r));
  const psVite = createProxySnareServer({ target: `http://127.0.0.1:${upVite.address().port}`, mode: "strict", protectedPaths: ["*"] });
  const psViteUrl = await psVite.listen(0, "127.0.0.1");
  try {
    const resV = await new Promise((resolve, reject) => {
      const u = new URL(`${psViteUrl}/app/@vite/client`);
      const r = http.request({
        hostname: u.hostname, port: u.port, path: "/app/@vite/client", method: "GET",
        headers: { "User-Agent": CHROME_UA, "Sec-Fetch-Dest": "script", "Sec-Fetch-Mode": "no-cors", "Sec-Fetch-Site": "same-origin" },
      }, (resp) => {
        const ch = []; resp.on("data", (c) => ch.push(c));
        resp.on("end", () => resolve({ status: resp.statusCode, body: Buffer.concat(ch).toString("utf8") }));
      });
      r.on("error", reject);
      r.end();
    });
    assert.equal(resV.status, 200, "Vite non-root /app/@vite/client MUST pass wildcard static probe (0-FP)!");
  } finally {
    await psVite.close();
    await new Promise((r) => upVite.close(r));
  }
});
