"use strict";

const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const http = require("node:http");
const { execFileSync } = require("node:child_process");
const path = require("node:path");

const {
  createProxySnareEngine,
  createProxySnareServer,
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

test("2. Caido Repeater / Burp Suite Repeater exact replay, body edit, intercept hold, and stale canary are blocked", () => {
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

  // Attack A: Exact Replay in Caido/Burp Repeater -> REPEATER_NONCE_REPLAYED + SEQ + STALE_CANARY
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

  // Attack C: Request paused in Caido/Burp Intercept tab for 12s (> freshnessMs)
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
});

test("3. Proxy leakage headers, missing Fetch Metadata, Connection:close, and CL+TE smuggling are caught", () => {
  const engine = createProxySnareEngine({ mode: "strict", protectedPaths: ["/api"] });

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

test("5. Standalone Reverse-Proxy Shield auto-injects guard.js, allows signed traffic, and blocks unauthenticated Repeater", async () => {
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
    res.writeHead(200, { "Content-Type": "text/html" });
    res.end("<!doctype html><html><head><title>App</title></head><body>Hello</body></html>");
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
    // HTML auto-injected with /__proxysnare/guard.js
    const htmlResp = await fetch(`${baseUrl}/`, { headers: makeBrowserHeaders() });
    assert.equal(htmlResp.status, 200);
    const html = await htmlResp.text();
    assert.ok(html.includes('<script src="/__proxysnare/guard.js"></script>'));

    // Direct Repeater / curl POST without proof -> 403
    const badResp = await fetch(`${baseUrl}/api/secret`, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": CHROME_UA },
      body: '{"x":1}',
    });
    assert.equal(badResp.status, 403);
    const badJson = await badResp.json();
    assert.equal(badJson.error, "REPEATER_OR_PROXY_BLOCKED");

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
    const okJson = await okResp.json();
    assert.equal(okJson.received, body);

    // Replaying exact same signed request (Caido/Burp Repeater) -> 403!
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
    const repJson = await repResp.json();
    assert.ok(repJson.reasons.includes("REPEATER_NONCE_REPLAYED"));
  } finally {
    await shield.close();
    await new Promise((r) => backend.close(r));
  }
});

test("6. Plain-English Natural-Language CLI compiler + Python wire-compatible verifier", () => {
  const p1 = compileNaturalLanguage("block caido and burp repeater on http://localhost:3000 on port 8099 behind nginx");
  assert.equal(p1.intent, "protect");
  assert.equal(p1.options.mode, "strict");
  assert.equal(p1.options.port, 8099);
  assert.equal(p1.options.trustProxy, "127.0.0.1");

  const p2 = compileNaturalLanguage("watch for burp repeater without blocking on http://localhost:4000");
  assert.equal(p2.options.mode, "monitor");

  // Verify Python stdlib verifier matches Node.js signing protocol
  const pyOut = execFileSync(
    "python3",
    [
      "-c",
      `import sys; sys.path.insert(0, ${JSON.stringify(path.resolve(__dirname, "../python"))});
from proxysnare import ProxySnareVerifier
v = ProxySnareVerifier(mode="strict")
s = v.issue_session(user_agent="Mozilla/5.0 Chrome/158.0")
import time
ts = int(time.time() * 1000)
p = v.sign_request(session_key_hex=s["sessionKeyHex"], method="POST", path_with_query="/api/go", body=b'{"a":1}', seq=1, ts=ts, nonce="n1", canary=s["canary"])
h = {"User-Agent":"Mozilla/5.0 Chrome/158.0","Sec-Fetch-Site":"same-origin","X-PS-Session":s["sessionId"],"X-PS-Seq":"1","X-PS-Ts":str(ts),"X-PS-Nonce":"n1","X-PS-Canary":s["canary"],"X-PS-Proof":p}
r1 = v.inspect_request(method="POST", url="/api/go", headers=h, body=b'{"a":1}')
r2 = v.inspect_request(method="POST", url="/api/go", headers=h, body=b'{"a":1}')
assert r1.ok and not r1.blocked and r1.score == 0
assert r2.blocked and any(x["code"]=="REPEATER_NONCE_REPLAYED" for x in r2.reasons)
print("PY_OK")`,
    ],
    { encoding: "utf8" }
  );
  assert.equal(pyOut.trim(), "PY_OK");
});
