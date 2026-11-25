# Architecture, Signal Reference & Honest Threat Model

[← Back to README](../README.md) · [Beginner's Guide](./getting-started-beginners.md)

---

## 1. Ephemeral `PS_ECDH_V2` Key Agreement & Boot Proof-of-Work

1. **Boot Challenge (`/__proxysnare/guard.js` or `GET /__proxysnare/boot`):**
   - When the browser loads `/__proxysnare/guard.js` with `Sec-Fetch-Dest: script` (or calls `GET /__proxysnare/boot` directly), the server enforces CLI/proxy UA denial, Fetch Metadata (`Sec-Fetch-Site: same-origin|same-site`, `Sec-Fetch-Mode`), `Accept-Language`, same-origin `Origin`, and per-IP rate limiting (`maxHandshakesPerMin`).
   - Eligible clients receive a single-use HMAC-authenticated `bootToken` + 128-bit `challenge` bound to `(ip, sha256(User-Agent))` with a short TTL (`60s` default).
2. **Proof-of-Work (`PS_POW_V2`):**
   - `guard.js` solves `leading_zero_bits(SHA-256("PS_POW_V2|" + challenge + "|" + powNonce)) >= difficulty` (`12` bits in `strict`, `10` bits in `balanced`, `0` in `monitor`).
3. **Ephemeral P-256 ECDH + HKDF-SHA256 (`POST /__proxysnare/handshake`):**
   - Browser WebCrypto generates a fresh P-256 ECDH keypair (`extractable: false`) and POSTs `{ protocol: "PS_ECDH_V2", clientPubB64, bootToken, powNonce }`.
   - Server validates and atomically consumes `bootToken`, generates its own ephemeral P-256 keypair, computes the 32-byte ECDH shared secret, and derives the 32-byte session HMAC key using `HKDF-SHA256(ikm=sharedSecret, salt=random16, info="PS_ECDH_V2|" + sessionId + "|" + clientPubB64 + "|" + serverPubB64)`.
   - Server returns `{ protocol: "PS_ECDH_V2", sessionId, serverPubB64, saltB64, canary, freshnessMs, serverNowMs }` — **zero plaintext `sessionKeyHex` crosses HTTP**.
   - Browser derives the exact same 32-byte key directly into a non-extractable WebCrypto `HMAC-SHA256` `CryptoKey`. Both Node.js (`src/detector.js`) and pure-stdlib Python (`python/proxysnare.py`, using Jacobian NIST P-256 arithmetic) produce byte-for-byte identical keys.

---

## 2. Complete Signal Weight Table

Every signal below is implemented identically in both Node.js (`src/detector.js`) and Python (`python/proxysnare.py`):

| Signal Code | Weight | Trigger Condition |
| :--- | :---: | :--- |
| `REPEATER_NONCE_REPLAYED` | `+10` | Single-use `X-PS-Nonce` already consumed by an earlier verified request |
| `REPEATER_BODY_OR_PATH_TAMPERED` | `+10` | `HMAC-SHA256` failed over `(method, path+query, sha256(body), seq, ts, nonce, canary)`, delimiter injection (`\|`), duplicate `X-PS-*` headers, or malformed lengths |
| `CL_TE_SMUGGLING` | `+10` | Both `Content-Length` and `Transfer-Encoding` headers present (RFC 9112 §6.3) |
| `DUPLICATE_HOST_HEADER` | `+8` | Multiple `Host:` headers in raw HTTP request |
| `DUPLICATE_CONTENT_LENGTH` | `+8` | Multiple `Content-Length:` headers in raw HTTP request |
| `REPEATER_SEQ_REPLAY` | `+8` | `X-PS-Seq` is not a strictly increasing safe positive integer (`> lastSeq`) |
| `REPEATER_STALE_CANARY` | `+8` | `X-PS-Canary` does not match the session's current single-step rotated honey-canary |
| `REPEATER_PROOF_MISSING` | `+8` (`strict`) / `+6` (`balanced`) | Protected route requested without complete `X-PS-*` Proof-of-Freshness headers |
| `REPEATER_UNKNOWN_OR_EXPIRED_SESSION` | `+8` | `X-PS-Session` does not exist or exceeded `sessionTtlMs` (`30 min` default); sets `X-PS-Rehandshake: 1` |
| `INTERCEPT_HOLD_OR_STALE_REPLAY` | `+6` | Request timestamp older than `freshnessMs` or further ahead than `min(3s, freshnessMs)` |
| `REPEATER_UA_SESSION_MISMATCH` | `+6` | `User-Agent` changed relative to `/handshake` |
| `REPEATER_IP_SESSION_MISMATCH` | `+6` | Client IP changed relative to `/handshake` (when `bindIp: true`, default) |
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
| **Unique-request flood (DDoS / credential stuffing)** | **Not a rate limiter** | ProxySnare stops *replays* and rate-limits handshakes (`429`), not high-volume unique fresh API calls. Pair with an API rate limiter (`429`). |
| **Active MITM ECDH key substitution or custom `PS_ECDH_V2` client** | **Irreducible browser boundary** | Without TLS certificate pinning, an active MITM proxy rewriting P-256 public keys during `/handshake` (or a custom script forging full modern Fetch Metadata headers and solving PoW + ECDH) can establish a separate session. Always enforce server-side authentication, authorization, and business rules. |

### Operational Deployment Notes
- **HTTPS / Localhost Required:** Browser WebCrypto (`crypto.subtle`) only exists in Secure Contexts (`https://` or `http://localhost` / `http://127.0.0.1`).
- **Multi-Worker / Clustered Nodes:** Default session, boot-token, and nonce maps are process-local (`503` fail-closed at capacity); enable sticky sessions behind load balancers.
- **Trusted Reverse Proxies (`--trust-proxy`):** Accepts exact IPv4/IPv6 addresses and CIDR ranges (`10.0.0.0/8`, `2001:db8::/48`), walks `X-Forwarded-For` right-to-left, and skips `Connection: close` penalties for requests forwarded by trusted proxies (such as Nginx HTTP/1.0 upstream).
- **Hiding Scoring Metadata in Production:** Pass `exposeDebugHeaders: false` (or CLI `--no-debug-headers`) to omit `X-ProxySnare-Score`, `X-ProxySnare-Mode`, and detailed 403 reason arrays while still emitting `X-PS-Rehandshake: 1` for automatic browser recovery.
