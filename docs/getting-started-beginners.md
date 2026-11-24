# Beginner's Guide to ProxySnare

[← Back to README](../README.md) · [Architecture & Threat Model](./architecture-and-threat-model.md)

You do not need to rewrite your app or memorize HTTP cryptography flags to block **Caido Repeater**, **Burp Suite Repeater**, and intercepting proxy replays.

---

## Step 1: Test It Yourself With the Built-In Demo

```bash
node bin/proxysnare.js demo --port 8088
```

1. Open `http://127.0.0.1:8088` in Chrome, Firefox, or Safari.
2. Click **"Send Signed POST /api/transfer"** → returns **`200 OK`** with `X-ProxySnare-Score=0`.
3. Capture that exact request in **Caido** or **Burp Suite**, send it to **Repeater**, and click **Send** → blocked with **`403 REPEATER_OR_PROXY_BLOCKED`**.

---

## Step 2: Protect Your Existing App Using Plain English

Use `explain` first to preview safely (`dry-run`), then `ask` to run:

```bash
# Preview only (dry-run — makes zero changes)
node bin/proxysnare.js explain "block caido and burp repeater on http://localhost:3000 on port 8080"

# Protect your app in strict mode
node bin/proxysnare.js ask "block caido and burp repeater on http://localhost:3000 on port 8080"

# Safe rollout: monitor & score Repeater attempts without blocking real users
node bin/proxysnare.js ask "watch for burp repeater without blocking on http://localhost:3000 on port 8080"

# Protect behind local Nginx / Caddy
node bin/proxysnare.js ask "block caido repeater on http://localhost:3000 on port 8080 behind nginx"
```

ProxySnare's standalone reverse-proxy shield automatically injects `<script src="/__proxysnare/guard.js"></script>` into HTML pages (including gzip/brotli-compressed upstream HTML) so existing `fetch()` and async `XMLHttpRequest` calls sign themselves transparently — including concurrent `Promise.all(...)` calls and `FormData` uploads.

---

## Step 3: Safe Production Rollout Checklist

1. **Serve over HTTPS in production**: Browser WebCrypto (`crypto.subtle`) requires `https://` (or `localhost` for local testing).
2. **Start in `monitor` mode first**: Watch `onDetect` logs and `X-ProxySnare-Score` headers to verify legitimate frontend traffic passes with `score = 0`.
3. **Exclude non-browser webhooks**: Only list browser-called API prefixes in `--paths` (e.g. `/api/checkout,/api/account`); leave server-to-server webhooks (`/webhooks/stripe`) outside `protectedPaths`.
4. **Hide debug headers in production**: Pass `--no-debug-headers` (or `exposeDebugHeaders: false`) once verified so attackers do not see exact scoring breakdowns.
5. **Pair with rate limiting & sticky sessions**: ProxySnare stops replays and tampering, not unique-request floods. Behind load balancers with multiple Node workers, enable sticky sessions so session canaries stay on the issuing worker.
6. **Behind Nginx / Caddy / Load Balancer?** Pass `--trust-proxy <proxy-ip>` (e.g. `127.0.0.1`) so `X-Forwarded-For` is parsed right-to-left safely.
