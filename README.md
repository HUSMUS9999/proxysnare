<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/proxysnare-hero-dark.svg" />
    <source media="(prefers-color-scheme: light)" srcset="assets/proxysnare-hero-light.svg" />
    <img src="assets/proxysnare-hero-light.svg" alt="ProxySnare — HTTP Repeater &amp; Intercepting Proxy Defense" width="400" />
  </picture>
</p>

<h1 align="center">ProxySnare</h1>

<p align="center">
  <a href="https://github.com/HUSMUS9999/proxysnare"><img src="assets/badges/version.svg" alt="version: 2.0.0" /></a>
  <a href="#architecture"><img src="assets/badges/protocol.svg" alt="protocol: ECDH P-256 + HMAC" /></a>
  <a href="#features"><img src="assets/badges/defense.svg" alt="defense: rotating canary" /></a>
  <a href="#quickstart"><img src="assets/badges/deps.svg" alt="deps: 0" /></a>
  <a href="LICENSE"><img src="assets/badges/license.svg" alt="license: MIT" /></a>
</p>

<p align="center">
  <a href="#quickstart">Quickstart</a> &middot;
  <a href="#benchmarks">Benchmarks</a> &middot;
  <a href="#architecture">Architecture</a> &middot;
  <a href="#modes--honest-boundaries">Threat Model</a> &middot;
  <a href="#documentation--ecosystem">Docs</a>
</p>

**ProxySnare** is a zero-dependency reverse-proxy shield, Express/Node.js middleware, drop-in browser guard, and pure-stdlib Python verifier for defending browser-driven web APIs against `curl`, HTTP repeaters (Caido, Burp Suite), intercepting proxy replays, and request tampering.

## Problem & Solution

**Problem:** Intercepting HTTP proxies and request repeaters (Caido Repeater, Burp Suite Repeater, mitmproxy) capture a legitimate browser request — preserving its exact session `Cookie`, `Authorization`, `Origin`, `Sec-Fetch-*`, and CSRF token — then pause, edit JSON fields, and replay it at human pace. Standard CSRF guards, Fetch Metadata checks, and rate limiters cannot distinguish those replays from genuine browser clicks.

**Solution:** ProxySnare injects a drop-in guard (`/__proxysnare/guard.js`) that completes an ephemeral **`PS_ECDH_V2` NIST P-256 ECDH + HKDF-SHA256** handshake gated by a single-use `(ip, ua)`-bound boot token and SHA-256 Proof-of-Work (`PS_POW_V2`). The derived session key never crosses HTTP in plaintext and is created directly as a non-extractable WebCrypto `CryptoKey` (`extractable: false`). Every protected `fetch()` and async `XMLHttpRequest` is serialized per tab and signed with a single-use `HMAC-SHA256` Proof-of-Freshness bound to the exact method, path+query, body SHA-256, monotonic sequence number, freshness window, and server-rotated honey-canary (`X-PS-Next-Canary`). Out-of-the-box `curl` requests, Repeater replays, body edits, and intercept holds fail with `403`.

## Features

- **Ephemeral `PS_ECDH_V2` Handshake + Boot PoW (`PS_POW_V2`)**: Browser WebCrypto generates an ephemeral P-256 keypair, solves a lightweight SHA-256 PoW (`12`-bit strict / `10`-bit balanced) against a single-use `(ip, uaHash)`-bound boot token, and derives the `HMAC-SHA256` signing key via `HKDF-SHA256` directly into a non-extractable `CryptoKey` — zero plaintext `sessionKeyHex` over HTTP, with byte-for-byte pure-stdlib P-256 parity in `python/proxysnare.py`.
- **Single-Use Proof-of-Freshness (`PS1|`)**: Drop-in `/__proxysnare/guard.js` transparently wraps `fetch()` and async `XMLHttpRequest` (supporting concurrent `Promise.all` queues, same-origin `GET`/`HEAD` redirects, `abort()` recovery, `FormData`, `Blob`, `URL`, `Request`, and automatic `X-PS-Rehandshake: 1` recovery) to sign `(method, path+query, SHA-256(body), seq, ts, nonce, canary)`.
- **Rotating Honey-Canary (`X-PS-Next-Canary`) & Freshness Window**: Every verified response rotates a per-session canary token; holding a captured request past `freshnessMs` (`8s` strict / `15s` balanced) triggers `INTERCEPT_HOLD_OR_STALE_REPLAY`.
- **Hardened Path Normalization & Wire Scoring**: Expands percent-encoded (`/%61pi`, `/%ff`), double-slash (`//api`), dot-segment (`/api/%2e%2e/secret`), null-byte (`%00`), trailing dot/space (`/api./`, `/api%20/`), fragment, matrix-param, backslash, and absolute-form URIs before matching `protectedPaths`; blocks `CL+TE` smuggling, duplicate `Host`/`Content-Length`, `X-Original-URL`/`X-Rewrite-URL` overrides, cross-site Fetch Metadata, non-CORS `OPTIONS` probing, and CLI/proxy UAs.
- **Modular Subpath Exports, Bundled `.d.ts`, & Natural-Language CLI**: Import `proxysnare/detector`, `proxysnare/middleware`, `proxysnare/browser-guard`, or `proxysnare/nl` with TypeScript declarations, wrap any upstream app with zero code changes (including gzip/deflate/brotli HTML injection and IPv4/IPv6 CIDR `--trust-proxy`), or use the thread-safe pure-stdlib Python verifier (`python/proxysnare.py`).

---

## Quickstart

### 1. Clone & Launch Interactive Demo (Zero Dependencies, Node >= 20)

```bash
git clone https://github.com/HUSMUS9999/proxysnare.git
cd proxysnare
node bin/proxysnare.js demo --port 8088 --mode strict
```

### 2. Natural-Language CLI (`explain` & `ask`)

```bash
# Preview the exact command first (safe dry-run)
node bin/proxysnare.js explain "block caido/burp repeater on http://localhost:3000 on port 8080"

# Shield your running app immediately (auto-injects /__proxysnare/guard.js into HTML)
node bin/proxysnare.js ask "block caido/burp repeater on http://localhost:3000 on port 8080"

# Observe & score traffic without blocking (safe initial rollout)
node bin/proxysnare.js ask "watch for repeaters without blocking on http://localhost:3000 on port 8080"

# Behind Nginx / ALB / Cloudflare reverse proxy (supports IPv4/IPv6 CIDR trust lists)
node bin/proxysnare.js ask "block burp repeater on http://localhost:3000 on port 8080 behind nginx"
```

### 3. Standalone Reverse-Proxy Shield (Zero Code Changes)

Works in front of any backend (Node.js, Python, Go, Rust, PHP, Java) and automatically injects `<script src="/__proxysnare/guard.js"></script>` into HTML responses:

```bash
PROXYSNARE_SECRET="$(openssl rand -hex 32)" \
node bin/proxysnare.js protect \
  --target http://127.0.0.1:3000 \
  --port 8080 \
  --mode strict \
  --paths /api,/auth,/checkout \
  --trust-proxy 127.0.0.1,10.0.0.0/8 \
  --no-debug-headers
```

*Secrets can be supplied via `PROXYSNARE_SECRET` or `--secret-file <path>` (preferred over argv flags).*

### 4. Express / Node.js Middleware & Python Stdlib Verifier

```js
const express = require("express");
const { createProxySnareMiddleware } = require("proxysnare/middleware"); // or require("./src/index.js")

const app = express();

// Works safely before OR after express.json({ verify }), express.urlencoded(), or express.text()
app.use(express.json({ verify: (req, _res, buf) => { req.rawBody = buf; } }));
app.use(
  createProxySnareMiddleware({
    mode: "strict",              // "off" | "monitor" ("observe") | "balanced" | "strict"
    protectedPaths: ["/api", "/checkout"],
    freshnessMs: 8000,
    trustProxy: ["127.0.0.1", "10.0.0.0/8"],
    exposeDebugHeaders: false,   // omit X-ProxySnare-Score / reason arrays in production
    onDetect: (ev) => console.warn("[ProxySnare]", ev.blocked ? "BLOCKED" : "FLAG", ev.reasons),
  })
);
// Include <script src="/__proxysnare/guard.js"></script> in your HTML templates when using direct middleware.
```

```python
import sys
sys.path.insert(0, "python")
from proxysnare import ProxySnareVerifier

verifier = ProxySnareVerifier(mode="strict", protected_paths=["/api"])

# 1. GET /__proxysnare/boot -> boot = verifier.issue_boot_challenge(ip=client_ip, user_agent=ua)
#    if boot is None: return 503, {"error": "BOOT_CAPACITY_EXCEEDED"}
# 2. POST /__proxysnare/handshake ->
#    ok, err = verifier.consume_boot_challenge(boot_token=..., pow_nonce=..., ip=client_ip, user_agent=ua)
#    sess = verifier.issue_session(ip=client_ip, user_agent=ua, origin=origin, client_pub_b64=client_pub_b64)
#    if sess is None: return 503, {"error": "SESSION_CAPACITY_EXCEEDED"}
# 3. On protected routes (thread-safe across Gunicorn/Waitress/FastAPI workers):
verdict = verifier.inspect_request(
    method=request.method,
    url=raw_path_with_query,     # exact path + query string (no trailing '?' if empty)
    headers=dict(request.headers),
    body=raw_body_bytes,
    ip=client_ip,
    raw_header_lines=raw_headers,  # enables duplicate Host / Content-Length / X-PS-* checks
    from_trusted_proxy=is_behind_nginx,
)
if verdict.rehandshake_recommended:
    response.headers["X-PS-Rehandshake"] = "1"
if verdict.blocked:
    return 403, {"error": "REPEATER_OR_PROXY_BLOCKED"}
if verdict.next_canary:
    response.headers["X-PS-Next-Canary"] = verdict.next_canary
```

---

## Benchmarks

Measured live over local TCP/HTTP keep-alive sockets (`node benchmarks/run_unbiased_benchmark.js`, Node `v22.23.2`, raw data in [`benchmarks/results.json`](benchmarks/results.json)): 400-request global pre-warmup + 100 warmup + 300 measured sequential POSTs interleaved across 3 rounds per defense (no client HMAC billed to non-HMAC baselines; ProxySnare uses the full `PS_ECDH_V2` + PoW handshake), plus 2 genuine browser requests and 6 live attack scenarios. **Unique Flood** sends 75 unique fresh valid requests (testing true flood throttling, not duplicate nonce replays).

### 1. Attack Detection Matrix (`0/2` false positives across all defenses)

| Defense | CSRF | Exact Replay | Body Tamper | 8.3s Hold | Proxy Strip | Unique Flood | Blocked |
| :--- | :-: | :-: | :-: | :-: | :-: | :-: | :-: |
| **Unprotected Node.js API** | `200` | `200` | `200` | `200` | `200` | `200` | `0/6` |
| **Double-Submit CSRF Guard** | **403** | `200` | `200` | `200` | `200` | `200` | `1/6` |
| **Rate Limiter (`60/min/IP`)** | `200` | `200` | `200` | `200` | `200` | **429** | `1/6` |
| **Fetch Metadata + Origin** | **403** | `200` | `200` | `200` | **403** | `200` | `2/6` |
| **Stateless HMAC (`30s` TTL)** | **403** | `200` | **403** | `200` | **403** | `200` | `3/6` |
| **HMAC (`8s` TTL) + Nonce Cache** | **403** | **403** | **403** | **403** | **403** | `200` | `5/6` |
| **ProxySnare (`balanced`, `15s`)** | **403** | **403** | **403** | `200`* | **403** | `200` | `4/6` |
| **ProxySnare (`strict`, `8s`)** | **403** | **403** | **403** | **403** | **403** | `200` | `5/6` |

*\*`balanced` deliberately allows an 8.3s hold inside its 15s mobile freshness window. Neither ProxySnare nor HMAC+Nonce is a rate limiter — pair with a rate limiter (`429`) to throttle unique-request floods.*

### 2. Latency, Throughput & Trade-Offs

| Defense | Median / p95 | Throughput | Client JS? | M2M APIs? | Honest Trade-Off |
| :--- | :-: | :-: | :-: | :-: | :--- |
| **Unprotected Node.js API** | `0.075 / 0.134 ms` | `11,392 req/s` | No | **Yes** | Baseline control; zero defense |
| **Double-Submit CSRF Guard** | `0.076 / 0.111 ms` | `11,817 req/s` | No | No | Stops CSRF only; Repeater keeps cookie+header |
| **Rate Limiter (`60/min/IP`)** | `0.076 / 0.103 ms` | **`12,005 req/s`** | No | **Yes** | Stops unique floods (`429`); misses slow Repeater edits |
| **Fetch Metadata + Origin** | `0.080 / 0.122 ms` | `11,654 req/s` | No | No | Zero client JS; misses captured Repeater headers |
| **Stateless HMAC (`30s` TTL)** | `0.111 / 0.172 ms` | `8,997 req/s` | Yes | **Yes** | Fast & M2M-ready; allows exact replay within 30s TTL |
| **HMAC (`8s` TTL) + Nonce** | `0.116 / 0.142 ms` | `8,463 req/s` | Yes | **Yes** | Fast when client/server share a pre-provisioned key; no HTML auto-injection or canary/wire scoring |
| **ProxySnare (`balanced`)** | `0.198 / 0.274 ms` | `4,924 req/s` | Yes | No | Zero-code-change HTML guard + `PS_ECDH_V2` (`3.92 ms` hs+10b PoW); sticky sessions on multi-worker clusters |
| **ProxySnare (`strict`)** | `0.199 / 0.263 ms` | `4,950 req/s` | Yes | No | Zero-code-change browser Repeater defense + `PS_ECDH_V2` (`32.81 ms` hs+12b PoW) + canary/wire checks; pair with rate limiting |

### Live Verification: Real Chrome & Firefox vs. `curl` & Caido Repeater

Verified end-to-end against live `mode=strict` reverse-proxy servers (`127.0.0.1`) with unmodified **Google Chrome 158**, **Mozilla Firefox 153 ESR**, `curl` (raw and spoofed Chrome UA), raw TCP path-bypass probes, and captured real-browser Repeater replays:

| Client / Scenario | Status | Score | Result / Signals |
| :--- | :-: | :-: | :--- |
| **Unmodified Chrome 158 & Firefox 153** (`fetch`, `Promise.all`, `302` redirect, `XHR` + `abort`) | **200** | `0 / 4` | Full `PS_ECDH_V2` key agreement (zero `sessionKeyHex` on wire); canary auto-rotates cleanly |
| **`curl` (raw or spoofed Chrome UA)** on `/api/*`, `/boot`, `/handshake` | **403** | `>= 6 / 4` | `NON_BROWSER_REPLAY_CLIENT` / `FETCH_METADATA_MISSING` / `REPEATER_PROOF_MISSING` |
| **Captured Browser Request — Exact Replay (Caido / Burp Repeater)** | **403** | `32 / 4` | `REPEATER_NONCE_REPLAYED`, `REPEATER_SEQ_REPLAY`, `REPEATER_STALE_CANARY` |
| **Captured Browser Request — Edited Body + Bumped Seq/Nonce** | **403** | `>= 18 / 4` | `REPEATER_STALE_CANARY`, `REPEATER_BODY_OR_PATH_TAMPERED` |
| **Path Bypass Probes** (`/%61pi`, `/api/%2e%2e/secret`, `/api%00`, `/api./`, `/api%20/`, `X-Original-URL`) | **403** | `>= 8 / 4` | Caught by multi-candidate path expansion & override header check |

---

## Architecture

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/proxysnare-arch-dark.svg" />
    <source media="(prefers-color-scheme: light)" srcset="assets/proxysnare-arch-light.svg" />
    <img src="assets/proxysnare-arch-light.svg" alt="ProxySnare Protocol-Level Anti-Repeater Architecture" width="100%" />
  </picture>
</p>

---

## Modes & Honest Boundaries

| Mode | Threshold | Freshness Window | PoW Bits | Action | Recommended Use |
| :--- | :-: | :-: | :-: | :--- | :--- |
| **`monitor`** *(alias: `observe`)* | `6` *(logs only)* | `15,000 ms` | `0` | Scores, rotates canaries, emits `X-PS-Rehandshake`, never blocks | Initial production rollout & SIEM tuning |
| **`balanced`** | `>= 6` | `15,000 ms` | `10` | Blocks replays, tampering, `curl` & missing proofs | Consumer apps with slower mobile networks |
| **`strict`** *(default)* | `>= 4` | `8,000 ms` | `12` | Tightest replay, edit, `curl` & intercept-hold defense | Checkout, auth, high-value browser APIs |
| **`off`** | Disabled | — | `0` | Pass-through | Local dev / automated API tests |

*HTTP operational status codes: `403` (blocked / invalid boot token), `413` (request body exceeds `maxBodyBytes`), `429` (per-IP handshake/boot rate limit exceeded), `503` (session or boot-token capacity limit reached — fails closed rather than evicting active sessions).*

### Important Security & Operational Caveats
- **Active MITM Key Substitution & Custom Automation Clients:** `PS_ECDH_V2` ensures no plaintext `sessionKeyHex` ever crosses HTTP, preventing passive capture of `/handshake` from reconstructing the HMAC key and preventing post-handshake JS from reading the non-extractable WebCrypto key. However, because browsers do not pin application-layer ECDH public keys without TLS pinning, an active MITM proxy rewriting public keys during `/handshake` (or a custom client implementing its own `PS_ECDH_V2` + PoW handshake while forging modern browser Fetch Metadata headers) can establish its own separate session. Always enforce server-side authentication, authorization, and business rules alongside ProxySnare.
- **Secure Context Required:** Browser WebCrypto (`crypto.subtle`) requires `https://` in production (or `http://localhost` / `http://127.0.0.1` locally).
- **Serialized Protected Requests:** `guard.js` queues concurrent protected requests (`Promise.all`) per tab so the single-step rotating canary never self-blocks.
- **Single-Process State & Floods:** Default session, boot-token, and nonce stores live in process-local Maps (enable sticky sessions behind multi-worker load balancers), and unique-request floods require a separate rate limiter.

---

## Testing & Reproducing Benchmarks

```bash
# Run zero-dependency Node.js + Python wire-parity test suite
npm test

# Reproduce the 8-defense live HTTP benchmark (writes benchmarks/results.json)
node benchmarks/run_unbiased_benchmark.js
```

## Documentation & Ecosystem

- **[Beginner's Natural-Language Guide](docs/getting-started-beginners.md)** — Walkthroughs, plain-English CLI recipes, and rollout checklist.
- **[Architecture, Signal Weights & Threat Model](docs/architecture-and-threat-model.md)** — Complete `PS_ECDH_V2` handshake spec, signal reference, and honest boundary analysis.

Companion repositories:
- **[Vibe-Slayer](https://github.com/HUSMUS9999/vibe-slayer)** — Zero-dependency Rust + C99 asset, binary, Web Component, and zero-geometry 3D stream protection platform.
- **[VeilBreak](https://github.com/HUSMUS9999/veilbreak)** — Zero-dependency anti-stealth & multi-engine browser integrity SDK, `<veil-break>` Web Component, middleware, and Python verifier.

---

## License

MIT License — see [LICENSE](LICENSE).
