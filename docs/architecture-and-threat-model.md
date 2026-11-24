# Architecture, Signal Reference & Honest Threat Model

[← Back to README](../README.md) · [Beginner's Guide](./getting-started-beginners.md)

---

## 1. Complete Signal Weight Table

| Signal Code | Weight | Trigger Condition |
| :--- | :---: | :--- |
| `REPEATER_NONCE_REPLAYED` | `+10` | Single-use `X-PS-Nonce` already consumed by an earlier request (exact Repeater replay) |
| `REPEATER_BODY_OR_PATH_TAMPERED` | `+10` | `HMAC-SHA256` signature failed over `(method, path+query, sha256(body), seq, ts, nonce, canary)` |
| `CL_TE_SMUGGLING` | `+10` | Both `Content-Length` and `Transfer-Encoding` headers present (RFC 9112 §6.3) |
| `DUPLICATE_HOST_HEADER` | `+8` | Multiple `Host:` headers in raw HTTP request |
| `REPEATER_SEQ_REPLAY` | `+8` | `X-PS-Seq` is not strictly greater than the session's previous sequence number |
| `REPEATER_STALE_CANARY` | `+8` | `X-PS-Canary` does not match the server's rotated single-step honey-canary |
| `REPEATER_PROOF_MISSING` | `+8` (`strict`) / `+5` (`balanced`) | Protected route requested without `X-PS-*` Proof-of-Freshness headers |
| `REPEATER_UNKNOWN_OR_EXPIRED_SESSION` | `+8` | `X-PS-Session` does not exist or exceeded `sessionTtlMs` |
| `INTERCEPT_HOLD_OR_STALE_REPLAY` | `+6` | `|serverNow - X-PS-Ts| > freshnessMs` (request paused in Intercept or replayed late) |
| `REPEATER_UA_SESSION_MISMATCH` | `+6` | `User-Agent` changed relative to the session's `/handshake` |
| `PROXY_HEADER_LEAK` | `+5` | Proxy headers (`Proxy-Connection`, `X-Burp-*`, `X-Caido-*`, `X-Mitmproxy`) detected |
| `UA_PLATFORM_CONTRADICTION` | `+5` | `User-Agent` OS contradicts `Sec-CH-UA-Platform` |
| `REPEATER_BURST_REPLAY` | `+5` | Identical unsigned payload replayed `>= 4×` from the same IP in 5 seconds |
| `FETCH_METADATA_MISSING` | `+4` | Modern Chrome (`>= 80`) or Firefox (`>= 90`) UA missing `Sec-Fetch-Site` and `Sec-Fetch-Mode` |
| `NON_BROWSER_REPLAY_CLIENT` | `+4` | Direct CLI/repeater UA (`curl`, `python-requests`, `Burp`, `Caido`, `sqlmap`, `ffuf`) on protected route |
| `REPEATER_CONNECTION_CLOSE` | `+3` | Modern browser UA sent HTTP/1.1 `Connection: close` |
| `PROXY_CHUNKED_TINY_BODY` | `+2` | `Transfer-Encoding: chunked` on a tiny `< 512 B` body with a browser UA |

---

## 2. Honest Threat Model (What ProxySnare Blocks vs. Limitations)

| Threat | Blocked by ProxySnare? | Honest Explanation |
| :--- | :---: | :--- |
| **Caido Repeater / Burp Repeater exact replay** | **Yes (100%)** | Killed instantly by single-use nonce (`+10`), monotonic seq (`+8`), and rotated canary (`+8`) |
| **Caido / Burp Repeater body/query/header editing** | **Yes (100%)** | Killed instantly by canonical `HMAC-SHA256` body+path+method binding (`+10`) |
| **Caido / Burp Intercept pause-and-edit** | **Yes** | Holding past `freshnessMs` triggers `+6`; editing body triggers `+10` |
| **Burp Intruder / ffuf / curl / Postman replay** | **Yes (100%)** | Blocked by missing PoF, missing Fetch Metadata, and sequence/nonce checks |
| **MITM proxy reading plaintext traffic passively (without editing/replaying)** | **No (by design)** | Passive observation through a user-installed root CA does not mutate requests; use TLS pinning on mobile/native apps for passive MITM defense |
| **Dedicated attacker writing a custom Caido/Burp plugin that hooks `/__proxysnare/handshake` and re-signs every request live** | **Raises cost significantly, not mathematically impossible** | Because the handshake executes in a browser the attacker controls, an attacker who intercepts `/handshake` before `importKey` can extract `sessionKeyHex` and build a custom live-signing extension. ProxySnare eliminates all standard Repeater/Intruder/curl workflows and pairs well with server-side authorization & **[VeilBreak](https://github.com/HUSMUS9999/veilbreak)** / **[Vibe-Slayer](https://github.com/HUSMUS9999/vibe-slayer)**. |
