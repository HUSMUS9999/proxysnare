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
    connection: "keep-alive",
    ...overrides,
  };
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

test("2. Caido / Burp Repeater exact replay, body edit, intercept hold, stale canary & balanced strip are blocked", () => {
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

  // First real request passes
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

  // Attack D: Balanced mode stripping X-PS-* headers MUST still block (no score 5 < 6 bypass!)
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

test("3. Proxy leakage headers, path normalization bypasses, rightmost XFF, CORS preflight, and CL+TE smuggling", () => {
  const engine = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api"], trustProxy: "127.0.0.1" });

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

  // Path normalization defeats case, percent-encoding, double-slash, traversal, matrix params, absolute-form URI
  for (const bypassUrl of [
    "/API/transfer",
    "/%61pi/transfer",
    "//api/transfer",
    "/public/../api/transfer",
    "/api;v=1/transfer",
    "http://victim.example/api/transfer",
  ]) {
    const r = engine.inspectRequest({ method: "POST", url: bypassUrl, headers: makeBrowserHeaders(), body: "{}" });
    assert.equal(r.blocked, true, `Path bypass should be blocked: ${bypassUrl}`);
    assert.ok(r.reasons.some((x) => x.code === "REPEATER_PROOF_MISSING"));
  }

  // CORS preflight OPTIONS passes cleanly
  const rOpts = engine.inspectRequest({
    method: "OPTIONS",
    url: "/api/transfer",
    headers: { "access-control-request-method": "POST", origin: "https://app.example" },
  });
  assert.equal(rOpts.blocked, false);

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

test("5. Reverse-Proxy Shield handles gzip HTML, HEAD, Express pre-parsed handshake, and blocks Repeater replays", async () => {
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
  });
  const baseUrl = await shield.listen(0, "127.0.0.1");
  try {
    // HTML auto-injected cleanly (including when upstream ignores Accept-Encoding and returns gzip!)
    const htmlResp = await fetch(`${baseUrl}/`, { headers: makeBrowserHeaders() });
    assert.equal(htmlResp.status, 200);
    assert.ok((await htmlResp.text()).includes('<script src="/__proxysnare/guard.js"></script>'));

    const gzResp = await fetch(`${baseUrl}/gzip`, { headers: makeBrowserHeaders() });
    assert.equal(gzResp.status, 200);
    assert.ok((await gzResp.text()).includes('<script src="/__proxysnare/guard.js"></script>'));

    // HEAD response must NOT receive injected body
    const headResp = await fetch(`${baseUrl}/`, { method: "HEAD", headers: makeBrowserHeaders() });
    assert.equal(headResp.status, 200);
    assert.equal((await headResp.text()).length, 0);

    // Cross-site handshake rejected (CSRF protection)
    const csrfHs = await fetch(`${baseUrl}/__proxysnare/handshake`, {
      method: "POST",
      headers: makeBrowserHeaders({ "sec-fetch-site": "cross-site", "content-type": "application/json" }),
      body: "{}",
    });
    assert.equal(csrfHs.status, 403);

    // Direct Repeater / curl POST without proof -> 403
    const badResp = await fetch(`${baseUrl}/api/secret`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": CHROME_UA },
      body: '{"x":1}',
    });
    assert.equal(badResp.status, 403);

    // Handshake + valid signed request -> 200 OK + rotated canary
    const hsResp = await fetch(`${baseUrl}/__proxysnare/handshake`, {
      method: "POST",
      headers: makeBrowserHeaders({ "Content-Type": "application/json" }),
      body: "{}",
    });
    const hs = await hsResp.json();
    const body = '{"x":42}';
    const ts = Date.now();
    const nonce = crypto.randomBytes(12).toString("hex");
    const proof = shield.engine.signRequest({
      sessionKeyHex: hs.sessionKeyHex,
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
    assert.ok((await repResp.json()).reasons.includes("REPEATER_NONCE_REPLAYED"));
  } finally {
    await shield.close();
    await new Promise((r) => backend.close(r));
  }

  // Verify Express-style pre-parsed body (express.json before middleware) does NOT hang /handshake!
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
    const hs = await fetch(`http://127.0.0.1:${port}/__proxysnare/handshake`, {
      method: "POST",
      headers: makeBrowserHeaders({ "Content-Type": "application/json" }),
      body: '{"t":1}',
    });
    assert.equal(hs.status, 200);
    assert.ok((await hs.json()).sessionId);
  } finally {
    await new Promise((r) => expressSim.close(r));
  }
});

test("6. NL CLI compiler fixes, browser guard syntax, and Python NaN/parity tests", () => {
  // Slashes in English prose ("caido/burp") must NOT hijack --paths!
  const pSlash = compileNaturalLanguage("block caido/burp repeater on http://localhost:3000 on port 8099 behind nginx");
  assert.equal(pSlash.intent, "protect");
  assert.equal(pSlash.options.mode, "strict");
  assert.equal(pSlash.options.port, 8099);
  assert.deepEqual(pSlash.options.protectedPaths, ["/api"]);
  assert.equal(pSlash.options.trustProxy, "127.0.0.1");

  // Negated monitor & "audit and block" must NOT silently downgrade to monitor!
  const pNoMon = compileNaturalLanguage("audit and block burp on http://localhost:3000");
  assert.equal(pNoMon.options.mode, "strict");
  const pMon = compileNaturalLanguage("watch for burp repeater without blocking on http://localhost:4000");
  assert.equal(pMon.options.mode, "monitor");

  // Browser guard must parse cleanly as valid JS
  new Function(buildBrowserGuardScript({ protectedRules: ["/api", { regex: "^/v\\d+/pay", flags: "i" }] }));

  // Verify Python stdlib verifier matches Node.js signing protocol AND rejects NaN timestamps & path bypasses!
  const nodeEngine = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api"] });
  const pyOut = execFileSync(
    "python3",
    [
      "-c",
      `import sys, time; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v = ProxySnareVerifier(mode="strict")
s = v.issue_session(user_agent="Mozilla/5.0 Chrome/158.0")
ts = int(time.time() * 1000)
p = v.sign_request(session_key_hex=s["sessionKeyHex"], method="POST", path_with_query="/api/go", body=b'{"a":1}', seq=1, ts=ts, nonce="n1", canary=s["canary"])
h = {"User-Agent":"Mozilla/5.0 Chrome/158.0","Sec-Fetch-Site":"same-origin","X-PS-Session":s["sessionId"],"X-PS-Seq":"1","X-PS-Ts":str(ts),"X-PS-Nonce":"n1","X-PS-Canary":s["canary"],"X-PS-Proof":p}
r1 = v.inspect_request(method="POST", url="/api/go", headers=h, body=b'{"a":1}')
r2 = v.inspect_request(method="POST", url="/api/go", headers=h, body=b'{"a":1}')
assert r1.ok and not r1.blocked and r1.score == 0
assert r2.blocked and any(x["code"]=="REPEATER_NONCE_REPLAYED" for x in r2.reasons)
# NaN timestamp bypass check!
h_nan = dict(h, **{"X-PS-Seq": "2", "X-PS-Ts": "NaN", "X-PS-Nonce": "n2", "X-PS-Canary": r1.next_canary})
r_nan = v.inspect_request(method="POST", url="/api/go", headers=h_nan, body=b'{"a":1}')
assert r_nan.blocked and any(x["code"]=="INTERCEPT_HOLD_OR_STALE_REPLAY" for x in r_nan.reasons)
# Path bypass check!
r_case = v.inspect_request(method="POST", url="/%61PI/go", headers={"User-Agent":"Mozilla/5.0 Chrome/158.0","Sec-Fetch-Site":"same-origin"}, body=b'{}')
assert r_case.blocked and any(x["code"]=="REPEATER_PROOF_MISSING" for x in r_case.reasons)
print(p + "|" + s["sessionKeyHex"] + "|" + str(ts) + "|" + s["canary"])`,
    ],
    { encoding: "utf8" }
  ).trim();
  const [pyProof, pyKey, pyTs, pyCanary] = pyOut.split("|");
  // Cross-language Node <-> Python HMAC exact byte parity!
  const nodeProof = nodeEngine.signRequest({
    sessionKeyHex: pyKey,
    method: "POST",
    pathWithQuery: "/api/go",
    body: '{"a":1}',
    seq: 1,
    ts: pyTs,
    nonce: "n1",
    canary: pyCanary,
  });
  assert.equal(nodeProof, pyProof);
});

test("7. v2 CIDR trustProxy, observe alias monitor canary rotation, and modular subpath exports", () => {
  const { createProxySnareEngine } = require("../src/detector.js");
  const engine = createProxySnareEngine({
    mode: "observe",
    trustProxy: ["10.0.0.0/8", "172.16.0.0/12"],
    protectedPaths: ["/api"],
  });
  assert.equal(engine.mode, "monitor");

  // CIDR right-to-left XFF extraction ignores spoofed leftmost IP while stripping trusted ALB/proxy hops
  const realIp = engine.extractClientIp({
    socket: { remoteAddress: "::ffff:10.24.5.9" },
    headers: { "x-forwarded-for": "1.2.3.4, 203.0.113.77, 172.20.1.5" },
  });
  assert.equal(realIp, "203.0.113.77");

  // Monitor mode still advances seq & rotates canary when HMAC proof is valid despite a heuristic hit
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
    headers: {
      "user-agent": "Mozilla/5.0 Chrome/130.0.0.0",
      // Missing Sec-Fetch-* trips heuristic score=4 >= threshold, yet monitor mode should rotate canary!
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
  assert.equal(pkg.exports["./detector"], "./src/detector.js");
  assert.equal(pkg.exports["./middleware"], "./src/middleware.js");
  assert.equal(pkg.exports["."].types, "./src/index.d.ts");
  assert.ok(pkg.files.includes("python/"));
});

test("8. Loop 2 security regressions: ['*'] wildcard, '|' injection, #/%ff bypasses, IPv6 CIDR, Connection strip, capacity 503", async () => {
  // CRIT-06: protectedPaths: ["*"] must protect arbitrary paths!
  const starEngine = createProxySnareEngine({ mode: "strict", protectedPaths: ["*"] });
  assert.equal(starEngine.isPathProtected("/anything/here"), true);
  assert.equal(starEngine.isPathProtected("/"), true);

  // CRIT-06 + Loop 3 CRIT-2/3/HIGH-7: %ff-poisoned runs, %3F query smuggling, pre-hash traversal, absolute-form #
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
  ]) {
    assert.equal(apiEngine.isPathProtected(bypass), true, `Must protect bypass path: ${bypass}`);
  }

  // Loop 3 HIGH-8 & MED-21 + Loop 4 MED-8: trailing-slash CIDR must NOT match arbitrary IPs; ::1/128 works in extractClientIp!
  const badCidrEngine = createProxySnareEngine({ mode: "strict", trustProxy: ["10.0.0.1/", "::1/128"] });
  assert.equal(badCidrEngine.trustedProxies.has("203.0.113.99"), false);
  assert.equal(badCidrEngine.trustedProxies.has("::1"), true);
  assert.equal(
    badCidrEngine.extractClientIp({ socket: { remoteAddress: "::1" }, headers: { "x-forwarded-for": "203.0.113.42" } }),
    "203.0.113.42"
  );

  // Loop 3 CRIT-4, CRIT-5, HIGH-6 Python verifier regressions
  const pyReg = execFileSync(
    "python3",
    [
      "-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v = ProxySnareVerifier(mode="observe")
assert v.mode == "monitor"
v_strict = ProxySnareVerifier(mode="strict", protected_paths=["/api"])
for p in ("//api/transfer", "/%ff%2f../api/secret", "/api%3F", "/api#/../../public", "/public#/../../api"):
    assert v_strict.inspect_request(method="POST", url=p, headers={}, body=b"{}").blocked, f"missed {p}"
v_star = ProxySnareVerifier(mode="strict", protected_paths=["*"])
assert v_star.inspect_request(method="POST", url="/admin/delete", headers={}).blocked
s = v_strict.issue_session(user_agent="Mozilla/5.0 Chrome/158.0")
assert "protectedRules" in s
r_inj = v_strict.inspect_request(method="POST", url="/api/delete", headers={
    "User-Agent": "Mozilla/5.0 Chrome/158.0", "Sec-Fetch-Site": "same-origin",
    "X-PS-Session": s["sessionId"], "X-PS-Seq": "1", "X-PS-Ts": "1",
    "X-PS-Nonce": "n1|evil", "X-PS-Canary": s["canary"], "X-PS-Proof": "a"*64
}, body=b"{}")
assert r_inj.blocked and any(x["code"]=="REPEATER_BODY_OR_PATH_TAMPERED" for x in r_inj.reasons)
print("PY_L3_OK")`,
    ],
    { encoding: "utf8" }
  ).trim();
  assert.equal(pyReg, "PY_L3_OK");

  // HIGH-07: HMAC delimiter '|' injection in X-PS-* headers must be rejected immediately
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

  // MED-08: IPv6 CIDR trustProxy
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

  // MED-08: Live session capacity returns null instead of evicting active users
  const capEngine = createProxySnareEngine({ mode: "strict", maxSessions: 2 });
  assert.ok(capEngine.issueSession({ ip: "127.0.0.1" }));
  assert.ok(capEngine.issueSession({ ip: "127.0.0.2" }));
  assert.equal(capEngine.issueSession({ ip: "127.0.0.3" }), null);

  // HIGH-10 + Loop 4 CRIT-1 & HIGH-4: Connection strip, absolute-form ? before /, and query %20 preservation
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
    // Loop 3 CRIT-3 + Loop 4 HIGH-4: valid %20 in path & query preserved without 500 or %2520 double-encoding!
    const spaceRes = await fetch(`${baseUrl}/public/my%20doc.pdf?q=hello%20world`, { headers: { "User-Agent": CHROME_UA } });
    assert.equal(spaceRes.status, 200);
    assert.equal(seenUrl, "/public/my%20doc.pdf?q=hello%20world");
    // Loop 4 CRIT-1: raw absolute-form `GET http://example.com?x=/api/secret` must NOT forward `/api/secret`!
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
    const res = await fetch(`${baseUrl}/public`, {
      headers: {
        "User-Agent": CHROME_UA,
        Authorization: "Bearer keep-me",
        Connection: "keep-alive, authorization, x-forwarded-for",
      },
    });
    assert.equal(res.status, 200);
    assert.equal(seenAuth, "Bearer keep-me");
    assert.ok(seenXff && seenXff.includes("127.0.0.1"));
  } finally {
    await shield.close();
    await new Promise((r) => backend.close(r));
  }
});
