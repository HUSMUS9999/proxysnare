# Beginner's Guide to ProxySnare

[← Back to README](../README.md) · [Architecture & Threat Model](./architecture-and-threat-model.md)

You don't need to rewrite your app or understand HTTP cryptography to block **Caido Repeater**, **Burp Suite Repeater**, and intercepting proxies.

---

## Step 1: Test It Yourself With the Built-In Demo

```bash
node bin/proxysnare.js demo --port 8088
```

1. Open `http://127.0.0.1:8088` in Chrome, Firefox, or Safari.
2. Click **"Send Signed POST /api/transfer"** → returns **`200 OK`** with `X-ProxySnare-Score=0`.
3. Capture that exact request in **Caido** or **Burp Suite**, send it to **Repeater**, and click **Send** → immediately blocked with **`403 REPEATER_OR_PROXY_BLOCKED`**!

---

## Step 2: Protect Your Existing App Using Plain English

Use `explain` first to preview safely, then `ask` to run:

```bash
# Preview only (dry-run)
node bin/proxysnare.js explain "block caido and burp repeater on http://localhost:3000 on port 8080"

# Protect your app in strict mode
node bin/proxysnare.js ask "block caido and burp repeater on http://localhost:3000 on port 8080"

# Safe rollout: monitor & score Repeater attempts without blocking real users
node bin/proxysnare.js ask "watch for burp repeater without blocking on http://localhost:3000 on port 8080"

# Protect behind Nginx / Caddy / Cloudflare
node bin/proxysnare.js ask "block caido repeater on http://localhost:3000 on port 8080 behind nginx"
```

Because ProxySnare's standalone shield automatically injects `<script src="/__proxysnare/guard.js"></script>` into HTML responses, your existing frontend `fetch()` calls start signing themselves with zero code edits!

---

## Step 3: Safe Production Rollout Checklist

1. **Start in `monitor` mode for 24 hours**: Watch `onDetect` logs and `X-ProxySnare-Score` headers to verify all legitimate frontend calls pass with `score = 0`.
2. **Exclude public non-browser webhooks**: Only list browser-called API prefixes in `--paths` (e.g. `/api/checkout,/api/account`); leave server-to-server webhooks (like `/webhooks/stripe`) outside `protectedPaths`.
3. **Switch to `balanced` or `strict`**: Enable blocking once monitor logs are clean.
4. **Behind a reverse proxy?** Pass `--trust-proxy 127.0.0.1` (or your load balancer IP) so per-IP burst scoring evaluates the real client IP.
