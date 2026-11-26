# Architecture, Signal Reference & Honest Threat Model

[← Back to README](../README.md) · [Beginner's Guide](./getting-started-beginners.md)

---

## 1. ECDSA-Authenticated `PS_ECDH_V2` + `PS_HS_AUTH_V1` Handshake & Boot PoW

1. **Static SRI Guard (`/__proxysnare/guard.js?v=<hash12>`) & Boot Challenge (`GET /__proxysnare/boot`):**
   - `guard.js` is served statically with `integrity="sha384-..."` (`Cache-Control: public, max-age=31536000, immutable, no-transform` on `?v=<hash12>`, `public, no-cache, no-transform` + `ETag` on unversioned URLs) and pins the server's deterministic ECDSA P-256 verification public key (`SERVER_ECDSA_PUB`) derived from `PROXYSNARE_SECRET`.
   - Per-request boot tokens are delivered via `data-ps-boot` on dynamic uncached HTML responses (per-IP rate-limited via `allowHtmlBoot`) or via `GET /__proxysnare/boot` (rate-limited via `allowBoot`), bound to `(ip, sha256(User-Agent))` and sealed with HMAC (`PS_BOOT_V2S`) so multi-worker clusters sharing `PROXYSNARE_SECRET` can verify boot tokens cross-worker.
2. **Proof-of-Work (`PS_POW_V2`), Full-Closure `guardHash` & Optional Unified VeilBreak Proof (`VB_HS_V3`):**
   - `guard.js` solves `leading_zero_bits(SHA-256("PS_POW_V2|" + challenge + "|" + powNonce)) >= difficulty` (`10` bits `balanced`, `12` bits `strict`, `14` bits `paranoid`, `0` `monitor`).
   - It verifies captured native `SubtleCrypto`, `Promise`, iterator, and load-time I/O intrinsics against a fresh cross-realm `about:blank` iframe isolated inside a **closed `ShadowRoot`** (preventing synchronous Chromium/WebKit light-DOM capture-phase `load` listeners from poisoning the probe realm; failing closed client-side and server-side with `TAMPERED_SUBTLE`/`TAMPERED_GUARD` on pre-load hooks while remaining 0-FP on minified Angular `zone.js` `ZoneAwarePromise`/`ZoneAwareError`, post-load RUM/CMP wrappers, and pre-loaded Sentry/Datadog RUM in `balanced` / `requireGuardIntegrity: false`), hashes the entire `__psGuardMain` closure (`guardHash`), runs active CDP detection (`cdpActive`), and in unified mode collects a challenge-bound VeilBreak `VB_HS_V3` proof (`browserProof`) over a private lexical closure (unreachable from `window` / `Symbol.for` / `MutationObserver`). Non-embedded two-script setups should pass a server-stamped `data-vb-bridge` token or prefer the embedded unified bundle (`createUnifiedShield` / `createUnifiedMiddleware`).
   - Both client and server compute the handshake attestation binding digest `hsBind = SHA-256(guardHash + "|" + (cdpActive ? 1 : 0) + "|" + (browserProof?.d || ""))`.
3. **ECDSA-Signed Ephemeral P-256 ECDH + HKDF-SHA256 (`POST /__proxysnare/handshake`):**
   - Server verifies and atomically consumes `bootToken`, checks `guardHash` (timing-safe), enforces `blockCdpActive` and optional `verifyBrowserIntegrity` (VeilBreak `VB_HS_V3`), generates an ephemeral P-256 ECDH keypair, derives the 32-byte HMAC session key via `HKDF-SHA256(ikm=sharedSecret, salt=random16, info="PS_ECDH_V2|" + sessionId + "|" + clientPubB64 + "|" + serverPubB64 + "|" + hsBind)`, and signs `PS_HS_AUTH_V1|sessionId|clientPubB64|serverPubB64|saltB64|bootToken|serverNowMs|canary|hsBind` with ECDSA P-256 (IEEE-P1363 raw 64-byte signature, `serverSigB64`).
   - Browser verifies `serverSigB64` using captured native `SubtleCrypto.verify` against pinned `SERVER_ECDSA_PUB` BEFORE deriving the non-extractable `HMAC-SHA256` `CryptoKey` — zero plaintext `sessionKeyHex` crosses HTTP, and any in-flight MITM key substitution, clock shift, or `cdpActive`/`browserProof` scrubbing breaks BOTH signature verification and HKDF key agreement. Both Node.js (`src/detector.js`) and pure-stdlib Python (`python/proxysnare.py`, using constant-time 257-bit Montgomery-ladder P-256 arithmetic) are bit-for-bit interoperable.
4. **Per-Request Signed Proof-of-Freshness + Runtime Provenance (`PS2|`):**
   - Protected requests carry `X-PS-Ctx: ce=<0|1>;cdp=<0|1>;ug=<0|1>;ga=<ms>[;ik=<0|1>]` authenticated inside `HMAC-SHA256(sessionKey, "PS2|METHOD|pathWithQuery|sha256(body)|seq|ts|nonce|canary|ctx")` (backward-compatible with `PS1|` when `X-PS-Ctx` is omitted unless `requireSignedContext: true` in `paranoid`).

---

## 2. Complete Signal Weight Table

Every signal below is implemented identically in both Node.js (`src/detector.js`) and Python (`python/proxysnare.py`):

| Signal Code | Weight | Trigger Condition |
| :--- | :---: | :--- |
| `REPEATER_NONCE_REPLAYED` | `+10` | Single-use `X-PS-Nonce` already consumed by an earlier verified request |
| `REPEATER_BODY_OR_PATH_TAMPERED` | `+10` | `HMAC-SHA256` failed over `(method, path+query, sha256(body), seq, ts, nonce, canary[, ctx])`, delimiter injection (`\|`), duplicate `X-PS-*` headers, or malformed lengths |
| `CONSOLE_EVAL_DETECTED` | `+10` (`paranoid`) / `+8` (`strict`) / `+2` (`balanced`) | Signed `X-PS-Ctx` (`ce=1`) indicates DevTools Console or CDP `Runtime.evaluate` call stack |
| `CL_TE_SMUGGLING` | `+10` | Both `Content-Length` and `Transfer-Encoding` headers present (RFC 9112 §6.3) |
| `DUPLICATE_HOST_HEADER` | `+8` | Multiple `Host:` headers in raw HTTP request |
| `DUPLICATE_CONTENT_LENGTH` | `+8` | Multiple `Content-Length:` headers in raw HTTP request |
| `REPEATER_SEQ_REPLAY` | `+8` | `X-PS-Seq` is not a strictly increasing safe positive integer (`> lastSeq`) |
| `REPEATER_STALE_CANARY` | `+8` | `X-PS-Canary` does not match the session's current single-step rotated honey-canary |
| `REPEATER_PROOF_MISSING` | `+8` (`strict`/`paranoid`) / `+6` (`balanced`) | Protected route requested without complete `X-PS-*` Proof-of-Freshness headers |
| `REPEATER_UNKNOWN_OR_EXPIRED_SESSION` | `+8` | `X-PS-Session` does not exist or exceeded `sessionTtlMs` (`30 min` default); sets `X-PS-Rehandshake: 1` |
| `AI_CRAWLER_OR_SCRAPER_DENIED` | `+6` | Firecrawl, Apify, Browserless, Stagehand, GPTBot, ClaudeBot, or `x-firecrawl-*` / `x-browserless-*` scraper header detected |
| `CDP_ACTIVE_DETECTED` | `+4` (`strict`) / `+6` (`paranoid` or `balanced` + `blockCdpActive`) / `+1` (telemetry when `blockCdpActive: false && !allowDevTools`) | Signed `X-PS-Ctx` (`cdp=1`) reports active CDP/debugger session (suppressed when `allowDevTools: true` unless `blockCdpActive: true`) |
| `SYNTHETIC_INTERACTION` | `+6` | Signed `X-PS-Ctx` (`ik=1`, unified VeilBreak mode) reports untrusted synthetic click or repeated teleport click kinematics on a mutating request |
| `MUTATION_WITHOUT_USER_GESTURE` | `+6` | State-changing `POST`/`PUT`/`PATCH`/`DELETE` in `paranoid` mode lacked a recent trusted pointer/keyboard/accessibility gesture (`!ug || ga > userGestureWindowMs`, respecting `gestureExemptPaths`) |
| `CONTEXT_HEADER_MISSING` | `+6` | Signed `X-PS-Ctx` header omitted when `requireSignedContext: true` (`paranoid`) |
| `INTERCEPT_HOLD_OR_STALE_REPLAY` | `+6` | Request arrival timestamp older than `freshnessMs` or further ahead than `min(3s, freshnessMs)` (emits `X-PS-Rehandshake: 1` on valid HMAC clock drift) |
| `REPEATER_UA_SESSION_MISMATCH` | `+6` | `User-Agent` changed relative to `/handshake` |
| `REPEATER_IP_SESSION_MISMATCH` | `+6` | Client IP changed relative to `/handshake` (when `bindIp: true`; emits `X-PS-Rehandshake: 1` on valid HMAC so mobile roaming recovers cleanly) |
| `REPEATER_ORIGIN_MISMATCH` | `+6` | `Origin` changed relative to `/handshake` |
| `CROSS_SITE_REQUEST_BLOCKED` | `+6` | `Sec-Fetch-Site: cross-site` sent to a protected route |
| `PROXY_PATH_OVERRIDE_HEADER` | `+6` | `X-Original-URL` or `X-Rewrite-URL` targets a protected path |
| `NON_BROWSER_REPLAY_CLIENT` | `+6` | Direct CLI/repeater/automation UA (`curl`, `python-requests`, `go-http-client`, `insomnia`, `postman`, `Burp`, `Caido`, `mitmproxy`, `sqlmap`, `ffuf`, `nuclei`, `HeadlessChrome`) on protected route |
| `PROXY_HEADER_LEAK` | `+5` | Exact proxy artifact header present (`Proxy-Connection`, `X-Burp-Header`, `X-Burp-Collaborator`, `X-Caido-Id`, `X-Caido-Replay`, `X-Mitmproxy`) |
| `UA_PLATFORM_CONTRADICTION` | `+5` | `User-Agent` OS contradicts `Sec-CH-UA-Platform` |
| `REPEATER_BURST_REPLAY` | `+5` | Identical unsigned payload replayed `>= 4×` from the same IP in 5 seconds |
| `FETCH_METADATA_MISSING` | `+4` | Modern Chrome (`>= 80`) or Firefox (`>= 90`) UA missing `Sec-Fetch-Site` and `Sec-Fetch-Mode` on protected routes (or with proxy leak headers) |
| `REPEATER_CONNECTION_CLOSE` | `+3` | Modern browser UA sent HTTP/1.1 `Connection: close` on protected routes (automatically skipped when `fromTrustedProxy` is true behind Nginx/ALB) |
| `PROXY_CHUNKED_TINY_BODY` | `+2` | `Transfer-Encoding: chunked` on a tiny `< 512 B` body with a browser UA |

---

## 3. Path Normalization, Wildcards & Concurrency Design

- **Multi-Candidate Path Expansion (`expandPathCandidates`):** Before checking `protectedPaths`, ProxySnare strips absolute-form URI authorities (`http://host/api/...`, `http://host\api\...`), leniently percent-decodes up to 2 passes (`/%61pi`, invalid `%ff` sequences preserved without throwing), collapses and also tests uncollapsed dot-segments (`/api/%2e%2e/secret`), handles null bytes (`%00`), fragments (`#`), encoded queries (`%3F`), trailing dots/spaces (`/api./`, `/api%20/`), matrix params (`/api;v=1`), and matches string prefixes case-insensitively.
- **Reverse-Proxy Wildcard Safety (`protectedPaths: ["*"]`):** In `createProxySnareServer`, initial browser HTML navigations (`Accept: text/html`, `Sec-Fetch-Mode: navigate`, `Sec-Fetch-Dest: document`) are probed against upstream and ONLY passed through if upstream responds with `Content-Type: text/html` — non-HTML API/JSON responses are rejected with `403` before leaking any body bytes.
- **CORS Preflight Hardening:** Only genuine cross-origin `http:`/`https:` `OPTIONS` preflights (`Origin` host != normalized default-port `Host`, non-CLI UA, `Sec-Fetch-Mode: cors`, empty body, no override headers) bypass proof checks; `createProxySnareServer` also blocks unauthenticated `OPTIONS` responses with `403 CORS_PREFLIGHT_NOT_ENABLED` whenever upstream omits `Access-Control-Allow-Origin`.
- **Concurrent Requests, Redirects & `abort()` Recovery:** `guard.js` serializes protected `fetch()` and async `XMLHttpRequest` calls per tab so concurrent `Promise.all` calls advance `seq` and `X-PS-Next-Canary` in strict order, safely retries same-origin `GET`/`HEAD` redirects, and clears stale session state if an in-flight XHR is aborted before headers arrive.

---

## 4. Honest Threat Model & Operational Boundaries

| Threat / Scenario | Behavior | Honest Explanation |
| :--- | :---: | :--- |
| **`curl` (raw or spoofed Chrome UA) & Postman / `ffuf`** | **Blocked (`403`)** | Blocked on `/api/*`, `/boot`, and `/handshake` by CLI UA denial, Fetch Metadata, `Accept-Language`, and Proof-of-Freshness |
| **Caido / Burp Repeater exact replay** | **Blocked (`403`)** | Caught by single-use nonce (`+10`), monotonic seq (`+8`), and rotated canary (`+8`) |
| **Caido / Burp Repeater body/path/query editing** | **Blocked (`403`)** | Caught by canonical `HMAC-SHA256` over `(method, path+query, sha256(body), seq, ts, nonce, canary)` (`+10`) |
| **Caido / Burp Intercept pause past `freshnessMs`** | **Blocked (`403`)** | Holding past `8s` (`strict`) or `15s` (`balanced`) triggers `INTERCEPT_HOLD_OR_STALE_REPLAY` (`+6`) |
| **Passive MITM reading `/handshake`** | **Key never exposed** | `PS_ECDH_V2` derives the HMAC key via ephemeral P-256 ECDH + HKDF; passively recording HTTP traffic cannot recover the session key |
| **DevTools Console `fetch()` / `XHR` (Bypass 1)** | **Blocked in `strict`/`paranoid`** | Caught by signed `X-PS-Ctx` (`ce=1`, `PS2|` HMAC), monotonic clocks, and stack-tamper fail-closed checks; allowed cleanly in `balanced` or `allowDevTools: true` |
| **Caido Match & Replace on `/__proxysnare/guard.js` (Bypass 2)** | **Blocked (`SRI` / `403`)** | Static `sha384` SRI rejects tampered script bytes; runtime `guardHash` + captured native `SubtleCrypto` check catch non-SRI edits and `SubtleCrypto` hooks |
| **Active MITM ECDH substitution or `cdpActive`/`browserProof` scrubbing (Bypass 3)** | **Blocked (`PS_HS_AUTH_V1`)** | Deterministic ECDSA P-256 signature over `serverPubB64`, `serverNowMs`, `canary`, and `hsBind` verified against pinned `SERVER_ECDSA_PUB` before HKDF |
| **Firecrawl / AI crawlers & standalone `PS_ECDH_V2` scripts (Bypass 4)** | **Blocked (`403`)** | AI-crawler UA/header denial plus `createUnifiedShield` requiring challenge-bound VeilBreak `VB_HS_V3` browser physics + Web Worker proof at `/handshake` |
| **Unique-request flood (DDoS / credential stuffing)** | **Not a rate limiter** | ProxySnare stops *replays* and rate-limits `/boot` & `/handshake` (`429`), not high-volume unique fresh API calls. Pair with an API rate limiter (`429`). |
| **Full local-OS / attacker-CA simultaneous HTML+JS rewrite or unmodified real browser with human pointer motion** | **Irreducible client-side boundary** | An adversary who owns the OS/CA and simultaneously rewrites HTML (stripping SRI + replacing `SERVER_ECDSA_PUB`) and `guard.js` — or runs an unmodified headed browser with realistic OS input — operates beyond what HTTP/JS defenses can prohibit. Always enforce server-side auth, RBAC, and business rules. |

### Operational Deployment Notes
- **HTTPS / Localhost Required:** Browser WebCrypto (`crypto.subtle`) only exists in Secure Contexts (`https://` or `http://localhost` / `http://127.0.0.1`).
- **Multi-Worker / Clustered Nodes:** Always configure a shared `PROXYSNARE_SECRET` (env or `secret` option) so every worker derives identical `SERVER_ECDSA_PUB`, `guardSri`, `guardVersion`, `guardHash`, and cross-worker stateless `PS_BOOT_V2S` boot tokens; pass an async `store` adapter (with `get`, `set`, `setIfNotExists`, `delete`) for distributed Redis/KV session & single-use nonce tracking across non-sticky workers, or enable sticky sessions behind your load balancer (`503` fail-closed at capacity).
- **Express / Raw-Node / Fetch Compatibility:** Mounting `createProxySnareMiddleware()` before `express.json()`, `express.urlencoded({ extended: true })`, `express.raw()`, `multer`, or Web Streams (`Readable.toWeb(req)`) automatically restores the readable request stream in both flowing and paused (`read()`/`readable`) modes without setting `req._body = true`; mounting after `express.json()` works cleanly with `express.json({ verify: ps.captureRawBody })`. Express `app.set("trust proxy", ...)` is auto-detected.
- **Trusted Reverse Proxies (`--trust-proxy`):** Accepts exact IPv4/IPv6 addresses and CIDR ranges (`10.0.0.0/8`, `2001:db8::/48`), walks `X-Forwarded-For` right-to-left, and skips `Connection: close` and `PROXY_CHUNKED_TINY_BODY` penalties for requests forwarded by trusted proxies.
- **Hiding Scoring Metadata in Production:** Pass `exposeDebugHeaders: false` (or CLI `--no-debug-headers`) to omit `X-ProxySnare-Score`, `X-ProxySnare-Mode`, and detailed 403 reason arrays while still emitting `X-PS-Rehandshake: 1` for automatic browser recovery.
