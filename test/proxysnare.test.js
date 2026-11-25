"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const http = require("node:http");
const zlib = require("node:zlib");
const { execFileSync } = require("node:child_process");
const path = require("node:path");

const {
  createProxySnareEngine,
  createProxySnareMiddleware,
  createProxySnareServer,
  buildBrowserGuardScript,
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
 * matching browser-guard.js byte-for-byte — verifying zero plaintext sessionKeyHex on wire!
 */
async function performBrowserEcdhHandshake(baseUrl, extraHeaders = {}) {
  const subtle = crypto.webcrypto.subtle;
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

  const hsResp = await fetch(`${baseUrl}/__proxysnare/handshake`, {
    method: "POST",
    headers: makeBrowserHeaders({ "Content-Type": "application/json", ...extraHeaders }),
    body: JSON.stringify({
      protocol: "PS_ECDH_V2",
      clientPubB64,
      bootToken: boot.bootToken,
      powNonce,
      t: Date.now(),
    }),
  });
  assert.equal(hsResp.status, 200, `handshake failed: ${hsResp.status}`);
  const hs = await hsResp.json();
  assert.equal(hs.protocol, "PS_ECDH_V2");
  assert.equal(hs.sessionKeyHex, undefined, "MUST NEVER expose plaintext sessionKeyHex over HTTP!");
  assert.ok(hs.serverPubB64 && hs.saltB64 && hs.sessionId && hs.canary);

  const serverPubKey = await subtle.importKey(
    "raw",
    Buffer.from(hs.serverPubB64, "base64"),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    []
  );
  const sharedBits = await subtle.deriveBits({ name: "ECDH", public: serverPubKey }, kp.privateKey, 256);
  const hkdfKey = await subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
  const info = Buffer.from(`PS_ECDH_V2|${hs.sessionId}|${clientPubB64}|${hs.serverPubB64}`, "utf8");
  const hmacKey = await subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: Buffer.from(hs.saltB64, "base64"), info },
    hkdfKey,
    { name: "HMAC", hash: "SHA-256", length: 256 },
    true,
    ["sign"]
  );
  const derivedHex = Buffer.from(await subtle.exportKey("raw", hmacKey)).toString("hex");
  return { hs, boot, powNonce, clientPubB64, sessionKeyHex: derivedHex };
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
    const htmlResp = await fetch(`${baseUrl}/`, { headers: makeBrowserHeaders() });
    assert.equal(htmlResp.status, 200);
    assert.ok((await htmlResp.text()).includes('<script src="/__proxysnare/guard.js"></script>'));

    const gzResp = await fetch(`${baseUrl}/gzip`, { headers: makeBrowserHeaders() });
    assert.equal(gzResp.status, 200);
    assert.ok((await gzResp.text()).includes('<script src="/__proxysnare/guard.js"></script>'));

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
print(json.dumps({"sid": s["sessionId"], "spub": s["serverPubB64"], "salt": s["saltB64"], "canary": s["canary"], "keyHex": v._sessions[s["sessionId"]]["key_hex"]}))`,
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
  // 1) /guard.js per-IP rate limiting gates boot-token stamping (still serves valid JS!)
  const rlMw = createProxySnareMiddleware({ mode: "strict", maxHandshakesPerMin: 2 });
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
