# Architecture, Signal Reference & Honest Threat Model

[← Back to README](../README.md) · [Beginner's Guide](./getting-started-beginners.md)

---

## 1. Complete Signal Weight Table

Every signal below is implemented identically in both Node.js (`src/detector.js`) and Python (`python/proxysnare.py`):

| Signal Code | Weight | Trigger Condition |
| :--- | :---: | :--- |
| `REPEATER_NONCE_REPLAYED` | `+10` | Single-use `X-PS-Nonce` already consumed by an earlier verified request |
| `REPEATER_BODY_OR_PATH_TAMPERED` | `+10` | `HMAC-SHA256` signature failed over `(method, path+query, sha256(body), seq, ts, nonce, canary)` or malformed header length |
| `CL_TE_SMUGGLING` | `+10` | Both `Content-Length` and `Transfer-Encoding` headers present (RFC 9112 §6.3) |
| `DUPLICATE_HOST_HEADER` | `+8` | Multiple `Host:` headers in raw HTTP request |
| `REPEATER_SEQ_REPLAY` | `+8` | `X-PS-Seq` is not a strictly increasing safe positive integer (`> lastSeq`) |
| `REPEATER_STALE_CANARY` | `+8` | `X-PS-Canary` does not match the session's current single-step rotated honey-canary |
| `REPEATER_PROOF_MISSING` | `+8` (`strict`) / `+6` (`balanced`) | Protected route requested without complete `X-PS-*` Proof-of-Freshness headers |
| `REPEATER_UNKNOWN_OR_EXPIRED_SESSION` | `+8` | `X-PS-Session` does not exist or exceeded `sessionTtlMs` (30 min default) |
| `INTERCEPT_HOLD_OR_STALE_REPLAY` | `+6` | Request timestamp older than `freshnessMs` or further ahead than `min(3s, freshnessMs)` |
| `REPEATER_UA_SESSION_MISMATCH` | `+6` | `User-Agent` changed relative to the session's `/handshake` |
| `REPEATER_ORIGIN_MISMATCH` | `+6` | `Origin` changed relative to the session's `/handshake` |
| `CROSS_SITE_REQUEST_BLOCKED` | `+6` | `Sec-Fetch-Site: cross-site` sent to a protected route |
| `PROXY_HEADER_LEAK` | `+5` | Exact proxy artifact header present (`Proxy-Connection`, `X-Burp-Header`, `X-Burp-Collaborator`, `X-Caido-Id`, `X-Caido-Replay`, `X-Mitmproxy`) |
| `UA_PLATFORM_CONTRADICTION` | `+5` | `User-Agent` OS contradicts `Sec-CH-UA-Platform` |
| `REPEATER_BURST_REPLAY` | `+5` | Identical unsigned payload replayed `>= 4×` from the same IP in 5 seconds |
| `FETCH_METADATA_MISSING` | `+4` | Modern Chrome (`>= 80`) or Firefox (`>= 90`) UA missing `Sec-Fetch-Site` and `Sec-Fetch-Mode` on protected routes (or with proxy leak headers) |
| `NON_BROWSER_REPLAY_CLIENT` | `+4` | Direct CLI/repeater UA (`curl`, `python-requests`, `go-http-client`, `insomnia`, `postman`, `Burp`, `Caido`, `mitmproxy`, `sqlmap`, `ffuf`, `nuclei`) on protected route |
| `REPEATER_CONNECTION_CLOSE` | `+3` | Modern browser UA sent HTTP/1.1 `Connection: close` on protected routes (or with proxy leak headers) |
| `PROXY_CHUNKED_TINY_BODY` | `+2` | `Transfer-Encoding: chunked` on a tiny `< 512 B` body with a browser UA |

---

## 2. Path Normalization & Concurrency Design

- **Path Normalization (`normalizePathname`):** Before checking `protectedPaths`, ProxySnare strips absolute-form URI authorities (`POST http://host/api/...`), percent-decodes up to 2 passes (`/%61pi/...`), normalizes backslashes, collapses repeated slashes (`//api/...`), resolves `.`/`..` dot-segments (`/x/../api/...`), strips matrix parameters (`/api;v=1/...`), and matches string prefixes case-insensitively (`/API/...`).
- **Concurrent Requests (`Promise.all`):** `guard.js` serializes protected `fetch()` and async `XMLHttpRequest` calls per tab via a lightweight promise chain so concurrent app requests advance `seq` and `X-PS-Next-Canary` in strict order without racing into `REPEATER_STALE_CANARY`.
- **`FormData`, `Blob`, `URL`, `Request`, and CORS Preflight:** `guard.js` serializes `FormData` via `new Response(formData)` (preserving exact multipart boundaries and `Content-Type`), preserves `Request` properties, and automatically exempts `OPTIONS` CORS preflight requests on the server.

---

## 3. Honest Threat Model & Operational Boundaries

| Threat / Scenario | Behavior | Honest Explanation |
| :--- | :---: | :--- |
| **Caido / Burp Repeater exact replay** | **Blocked (`403`)** | Caught by single-use nonce (`+10`), monotonic seq (`+8`), and rotated canary (`+8`) |
| **Caido / Burp Repeater body/path/query editing** | **Blocked (`403`)** | Caught by canonical `HMAC-SHA256` over `(method, path+query, sha256(body), seq, ts, nonce, canary)` (`+10`) |
| **Caido / Burp Intercept pause past `freshnessMs`** | **Blocked (`403`)** | Holding past `8s` (`strict`) or `15s` (`balanced`) triggers `INTERCEPT_HOLD_OR_STALE_REPLAY` (`+6`) |
| **Out-of-the-box Burp Intruder / `ffuf` / `curl` / Postman** | **Blocked (`403`)** | Blocked by missing Proof-of-Freshness (`+8`/`+6`) and non-browser/Fetch-Metadata checks |
| **Unique-request flood (DDoS / credential stuffing)** | **Not a rate limiter** | ProxySnare stops *replays*, not high-volume unique fresh requests. Pair with a dedicated rate limiter (`429`). |
| **Passive MITM proxy reading traffic without replaying** | **Not blocked (by design)** | Passive inspection through a user-installed root CA does not alter HTTP semantics; use certificate pinning on native mobile apps if passive MITM is in scope. |
| **Dedicated attacker scripting `/__proxysnare/handshake` or a custom Caido/Burp live-signing extension** | **Not mathematically unforgeable** | Because `/__proxysnare/handshake` delivers `sessionKeyHex` over the proxied TLS channel before `crypto.subtle.importKey(..., false)` runs, an intercepting proxy can read `sessionKeyHex` in transit (or script a direct `/handshake` call) and compute valid HMAC signatures in a custom extension. `extractable: false` hardens against post-handshake in-page JS extraction, not a custom proxy plugin. Always enforce server-side authorization and business rules alongside ProxySnare. |

### Operational Deployment Notes
- **HTTPS / Localhost Required:** Browser WebCrypto (`crypto.subtle`) only exists in Secure Contexts (`https://` or `http://localhost` / `http://127.0.0.1`).
- **Multi-Worker / Clustered Nodes:** Default session & nonce maps are process-local; enable sticky sessions at your load balancer when running multiple workers behind Nginx/ALB/Kubernetes.
- **Hiding Scoring Metadata in Production:** Pass `exposeDebugHeaders: false` (or CLI `--no-debug-headers`) to omit `X-ProxySnare-Score`, `X-ProxySnare-Mode`, and detailed 403 reason arrays from client responses.
- **Trusted Reverse Proxies:** `--trust-proxy` walks `X-Forwarded-For` right-to-left skipping trusted proxy IPs to prevent leftmost-IP spoofing.
