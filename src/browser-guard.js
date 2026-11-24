"use strict";

/**
 * Generates the zero-dependency 1-line browser drop-in guard served at `/__proxysnare/guard.js`.
 * Transparently wraps `window.fetch` and `XMLHttpRequest` to attach non-extractable WebCrypto
 * HMAC-SHA256 Proof-of-Freshness + rotating honey-canary headers on protected routes.
 */
function buildBrowserGuardScript({ basePath = "/__proxysnare", protectedPaths = ["/api"] } = {}) {
  const pathsJson = JSON.stringify(protectedPaths);
  const bpJson = JSON.stringify(basePath);
  return `(() => {
  "use strict";
  if (typeof window === "undefined" || window.__PROXYSNARE_GUARD_LOADED__) return;
  window.__PROXYSNARE_GUARD_LOADED__ = true;

  const BASE = ${bpJson};
  const PROTECTED = ${pathsJson};
  const origFetch = window.fetch.bind(window);
  const encoder = new TextEncoder();

  let state = null;
  let initPromise = null;
  let seq = 0;
  let clockOffsetMs = 0;

  function toHex(buf) {
    const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
    let out = "";
    for (let i = 0; i < u.length; i++) out += u[i].toString(16).padStart(2, "0");
    return out;
  }

  function fromHex(hex) {
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    return out;
  }

  function isProtectedPath(pathname) {
    for (let i = 0; i < PROTECTED.length; i++) {
      const p = PROTECTED[i];
      if (p === "*" || p === "/" || pathname === p || pathname.startsWith(p.endsWith("/") ? p : p + "/")) {
        return true;
      }
    }
    return false;
  }

  async function ensureSession() {
    if (state) return state;
    if (initPromise) return initPromise;
    initPromise = (async () => {
      const resp = await origFetch(BASE + "/handshake", {
        method: "POST",
        credentials: "same-origin",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ t: Date.now() }),
      });
      if (!resp.ok) throw new Error("PROXYSNARE_HANDSHAKE_FAILED_" + resp.status);
      const data = await resp.json();
      const rawKey = fromHex(data.sessionKeyHex);
      const cryptoKey = await crypto.subtle.importKey(
        "raw",
        rawKey,
        { name: "HMAC", hash: "SHA-256" },
        false, // non-extractable inside WebCrypto!
        ["sign"]
      );
      rawKey.fill(0);
      clockOffsetMs = (data.serverNowMs || Date.now()) - Date.now();
      state = {
        sessionId: data.sessionId,
        cryptoKey,
        canary: data.canary,
      };
      return state;
    })();
    try {
      return await initPromise;
    } finally {
      initPromise = null;
    }
  }

  async function signFetchRequest(method, pathWithQuery, bodyBytes) {
    const st = await ensureSession();
    seq += 1;
    const mySeq = seq;
    const ts = Date.now() + clockOffsetMs;
    const nonceBytes = new Uint8Array(12);
    crypto.getRandomValues(nonceBytes);
    const nonce = toHex(nonceBytes);
    const bodyHash = toHex(await crypto.subtle.digest("SHA-256", bodyBytes));
    const canary = st.canary;
    const canonical = "PS1|" + method.toUpperCase() + "|" + pathWithQuery + "|" + bodyHash + "|" + mySeq + "|" + ts + "|" + nonce + "|" + canary;
    const sigBuf = await crypto.subtle.sign("HMAC", st.cryptoKey, encoder.encode(canonical));
    return {
      "X-PS-Session": st.sessionId,
      "X-PS-Seq": String(mySeq),
      "X-PS-Ts": String(ts),
      "X-PS-Nonce": nonce,
      "X-PS-Canary": canary,
      "X-PS-Proof": toHex(sigBuf),
    };
  }

  async function bodyToBytes(body) {
    if (body == null) return new Uint8Array(0);
    if (typeof body === "string") return encoder.encode(body);
    if (body instanceof ArrayBuffer) return new Uint8Array(body);
    if (ArrayBuffer.isView(body)) return new Uint8Array(body.buffer, body.byteOffset, body.byteLength);
    if (body instanceof URLSearchParams) return encoder.encode(body.toString());
    if (typeof Blob !== "undefined" && body instanceof Blob) return new Uint8Array(await body.arrayBuffer());
    return encoder.encode(String(body));
  }

  window.fetch = async function proxySnareFetch(input, init = {}) {
    const reqUrl = new URL(typeof input === "string" ? input : input.url, window.location.href);
    if (reqUrl.origin !== window.location.origin || reqUrl.pathname.startsWith(BASE) || !isProtectedPath(reqUrl.pathname)) {
      return origFetch(input, init);
    }
    const method = (init.method || (typeof input !== "string" && input.method) || "GET").toUpperCase();
    const rawBody = init.body !== undefined ? init.body : (typeof input !== "string" && input.body ? await input.clone().arrayBuffer() : null);
    const bodyBytes = await bodyToBytes(rawBody);
    const pathWithQuery = reqUrl.pathname + reqUrl.search;
    const sigHeaders = await signFetchRequest(method, pathWithQuery, bodyBytes);

    const mergedHeaders = new Headers(typeof input !== "string" ? input.headers : undefined);
    if (init.headers) {
      new Headers(init.headers).forEach((v, k) => mergedHeaders.set(k, v));
    }
    for (const [k, v] of Object.entries(sigHeaders)) mergedHeaders.set(k, v);

    const nextInit = { ...init, method, headers: mergedHeaders };
    if (rawBody !== null && rawBody !== undefined) nextInit.body = bodyBytes;

    const resp = await origFetch(reqUrl.toString(), nextInit);
    const rotated = resp.headers.get("X-PS-Next-Canary");
    if (rotated && state) state.canary = rotated;
    return resp;
  };

  // Transparently instrument async XMLHttpRequest (Axios, jQuery, legacy XHR clients)
  if (typeof XMLHttpRequest !== "undefined") {
    const origOpen = XMLHttpRequest.prototype.open;
    const origSend = XMLHttpRequest.prototype.send;
    XMLHttpRequest.prototype.open = function proxySnareXhrOpen(method, url, asyncFlag = true, user, pass) {
      this._psMeta = { method: String(method || "GET").toUpperCase(), url: String(url || ""), asyncFlag: asyncFlag !== false };
      return origOpen.call(this, method, url, asyncFlag, user, pass);
    };
    XMLHttpRequest.prototype.send = function proxySnareXhrSend(body) {
      const meta = this._psMeta;
      if (!meta || !meta.asyncFlag) return origSend.call(this, body);
      let reqUrl;
      try { reqUrl = new URL(meta.url, window.location.href); } catch { return origSend.call(this, body); }
      if (reqUrl.origin !== window.location.origin || reqUrl.pathname.startsWith(BASE) || !isProtectedPath(reqUrl.pathname)) {
        return origSend.call(this, body);
      }
      this.addEventListener("readystatechange", () => {
        if (this.readyState >= 2) {
          try {
            const rot = this.getResponseHeader("X-PS-Next-Canary");
            if (rot && state) state.canary = rot;
          } catch (_) {}
        }
      });
      bodyToBytes(body)
        .then((bodyBytes) => signFetchRequest(meta.method, reqUrl.pathname + reqUrl.search, bodyBytes))
        .then((sigHeaders) => {
          for (const [k, v] of Object.entries(sigHeaders)) this.setRequestHeader(k, v);
          origSend.call(this, body);
        })
        .catch(() => origSend.call(this, body));
    };
  }

  window.ProxySnare = {
    ready: ensureSession,
    version: "1.0.0",
  };
})();
`;
}

module.exports = { buildBrowserGuardScript };
