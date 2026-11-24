"use strict";

/**
 * Generates the zero-dependency 1-line browser drop-in guard served at `/__proxysnare/guard.js`.
 * Transparently wraps `window.fetch` and `XMLHttpRequest` to attach HMAC-SHA256
 * Proof-of-Freshness + rotating honey-canary headers on protected routes.
 *
 * Concurrency & compatibility guarantees:
 *   - Serializes protected requests per session so `Promise.all([fetch(...), fetch(...)])`
 *     advances the single-step rotating canary without self-blocking.
 *   - Handles `FormData`, `Blob`, `URLSearchParams`, `URL`, and `Request` objects cleanly.
 *   - Auto-rehandshakes once on session expiration (`REPEATER_UNKNOWN_OR_EXPIRED_SESSION`).
 */
function buildBrowserGuardScript({ basePath = "/__proxysnare", protectedPaths = ["/api"], protectedRules = null } = {}) {
  const rules = Array.isArray(protectedRules) && protectedRules.length > 0 ? protectedRules : protectedPaths;
  const rulesJson = JSON.stringify(rules);
  const bpJson = JSON.stringify(basePath);
  return `(() => {
  "use strict";
  if (typeof window === "undefined" || window.__PROXYSNARE_GUARD_LOADED__) return;
  window.__PROXYSNARE_GUARD_LOADED__ = true;

  const BASE = ${bpJson};
  const RAW_RULES = ${rulesJson};
  const RULES = RAW_RULES.map((r) => {
    if (r && typeof r === "object" && typeof r.regex === "string") {
      try { return new RegExp(r.regex, r.flags || ""); } catch { return null; }
    }
    return typeof r === "string" ? r.toLowerCase() : null;
  }).filter(Boolean);

  const origFetch = window.fetch.bind(window);
  const encoder = new TextEncoder();

  let state = null;
  let initPromise = null;
  let seq = 0;
  let clockOffsetMs = 0;
  // Serializes protected requests so concurrent Promise.all calls advance the rotating canary cleanly
  let reqChain = Promise.resolve();

  function enqueueProtected(fn) {
    const run = reqChain.then(fn, fn);
    reqChain = run.then(() => {}, () => {});
    return run;
  }

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
    const lower = String(pathname || "/").toLowerCase();
    for (let i = 0; i < RULES.length; i++) {
      const rule = RULES[i];
      if (rule instanceof RegExp) {
        rule.lastIndex = 0;
        if (rule.test(pathname)) return true;
      } else if (rule === "*" || rule === "/" || lower === rule || lower.startsWith(rule.endsWith("/") ? rule : rule + "/")) {
        return true;
      }
    }
    return false;
  }

  function assertSecureWebCrypto() {
    if (typeof crypto === "undefined" || !crypto.subtle) {
      throw new Error("PROXYSNARE_REQUIRES_SECURE_CONTEXT: WebCrypto (crypto.subtle) requires HTTPS or localhost.");
    }
  }

  async function ensureSession(forceNew = false) {
    assertSecureWebCrypto();
    if (state && !forceNew) return state;
    if (forceNew) {
      state = null;
      seq = 0;
    }
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
        false,
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

  async function signRequestFields(method, pathWithQuery, bodyBytes) {
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

  async function serializeBody(body) {
    if (body == null) return { bytes: new Uint8Array(0), contentType: null };
    if (typeof body === "string") return { bytes: encoder.encode(body), contentType: "text/plain;charset=UTF-8" };
    if (body instanceof ArrayBuffer) return { bytes: new Uint8Array(body), contentType: null };
    if (ArrayBuffer.isView(body)) return { bytes: new Uint8Array(body.buffer, body.byteOffset, body.byteLength), contentType: null };
    if (body instanceof URLSearchParams) {
      return { bytes: encoder.encode(body.toString()), contentType: "application/x-www-form-urlencoded;charset=UTF-8" };
    }
    if (typeof Blob !== "undefined" && body instanceof Blob) {
      return { bytes: new Uint8Array(await body.arrayBuffer()), contentType: body.type || null };
    }
    if ((typeof FormData !== "undefined" && body instanceof FormData) || (typeof ReadableStream !== "undefined" && body instanceof ReadableStream)) {
      const tmp = new Response(body);
      const ct = tmp.headers.get("content-type");
      return { bytes: new Uint8Array(await tmp.arrayBuffer()), contentType: ct };
    }
    return { bytes: encoder.encode(String(body)), contentType: "text/plain;charset=UTF-8" };
  }

  function resolveInputUrl(input) {
    if (typeof input === "string") return new URL(input, window.location.href);
    if (input instanceof URL) return new URL(input.href, window.location.href);
    if (input && typeof input.url === "string") return new URL(input.url, window.location.href);
    return new URL(String(input), window.location.href);
  }

  window.fetch = function proxySnareFetch(input, init) {
    const safeInit = init && typeof init === "object" ? init : {};
    let reqUrl;
    try {
      reqUrl = resolveInputUrl(input);
    } catch {
      return origFetch(input, init);
    }
    if (reqUrl.origin !== window.location.origin || reqUrl.pathname.startsWith(BASE) || !isProtectedPath(reqUrl.pathname)) {
      return origFetch(input, init);
    }

    const isRequestObj = typeof Request !== "undefined" && input instanceof Request;
    const method = (safeInit.method || (isRequestObj ? input.method : "GET") || "GET").toUpperCase();

    return enqueueProtected(async () => {
      const rawBody = safeInit.body !== undefined
        ? safeInit.body
        : (isRequestObj && method !== "GET" && method !== "HEAD" ? await input.clone().arrayBuffer() : null);
      const { bytes: bodyBytes, contentType: inferredCt } = await serializeBody(rawBody);
      const pathWithQuery = reqUrl.pathname + reqUrl.search;

      const executeOnce = async (forceRehandshake) => {
        if (forceRehandshake) await ensureSession(true);
        const sigHeaders = await signRequestFields(method, pathWithQuery, bodyBytes);
        const mergedHeaders = new Headers(isRequestObj ? input.headers : undefined);
        if (safeInit.headers) {
          new Headers(safeInit.headers).forEach((v, k) => mergedHeaders.set(k, v));
        }
        if (inferredCt && !mergedHeaders.has("content-type")) {
          mergedHeaders.set("content-type", inferredCt);
        }
        for (const [k, v] of Object.entries(sigHeaders)) mergedHeaders.set(k, v);

        const nextInit = {
          ...(isRequestObj
            ? {
                credentials: input.credentials,
                mode: input.mode,
                cache: input.cache,
                redirect: input.redirect,
                referrer: input.referrer,
                referrerPolicy: input.referrerPolicy,
                integrity: input.integrity,
                keepalive: input.keepalive,
                signal: input.signal,
              }
            : {}),
          ...safeInit,
          method,
          headers: mergedHeaders,
        };
        if (rawBody !== null && rawBody !== undefined && method !== "GET" && method !== "HEAD") {
          nextInit.body = bodyBytes;
        }
        const resp = await origFetch(reqUrl.toString(), nextInit);
        const rotated = resp.headers.get("X-PS-Next-Canary");
        if (rotated && state) state.canary = rotated;
        return resp;
      };

      const resp = await executeOnce(false);
      // Auto-recover once if a long-idle tab's 30-minute session expired server-side
      if (resp.status === 403 && !(safeInit.signal && safeInit.signal.aborted)) {
        try {
          const clone = await resp.clone().json();
          if (Array.isArray(clone.reasons) && clone.reasons.includes("REPEATER_UNKNOWN_OR_EXPIRED_SESSION")) {
            return await executeOnce(true);
          }
        } catch (_) {}
      }
      return resp;
    });
  };

  // Transparently instrument async XMLHttpRequest (Axios, jQuery, legacy XHR clients)
  if (typeof XMLHttpRequest !== "undefined") {
    const origOpen = XMLHttpRequest.prototype.open;
    const origSend = XMLHttpRequest.prototype.send;
    const origAbort = XMLHttpRequest.prototype.abort;
    const origSetHdr = XMLHttpRequest.prototype.setRequestHeader;

    XMLHttpRequest.prototype.open = function proxySnareXhrOpen(method, url, asyncFlag = true, user, pass) {
      this._psOpId = (this._psOpId || 0) + 1;
      this._psHeaders = Object.create(null);
      this._psMeta = { method: String(method || "GET").toUpperCase(), url: String(url || ""), asyncFlag: asyncFlag !== false };
      if (arguments.length <= 3) return origOpen.call(this, method, url, asyncFlag);
      return origOpen.call(this, method, url, asyncFlag, user, pass);
    };
    XMLHttpRequest.prototype.setRequestHeader = function proxySnareXhrSetHdr(name, val) {
      if (this._psHeaders) this._psHeaders[String(name).toLowerCase()] = true;
      return origSetHdr.call(this, name, val);
    };
    XMLHttpRequest.prototype.abort = function proxySnareXhrAbort() {
      this._psOpId = (this._psOpId || 0) + 1;
      return origAbort.call(this);
    };
    XMLHttpRequest.prototype.send = function proxySnareXhrSend(body) {
      const meta = this._psMeta;
      if (!meta || !meta.asyncFlag) return origSend.call(this, body);
      let reqUrl;
      try { reqUrl = new URL(meta.url, window.location.href); } catch { return origSend.call(this, body); }
      if (reqUrl.origin !== window.location.origin || reqUrl.pathname.startsWith(BASE) || !isProtectedPath(reqUrl.pathname)) {
        return origSend.call(this, body);
      }
      const opId = this._psOpId;
      const self = this;

      enqueueProtected(async () => {
        if (self._psOpId !== opId || self.readyState !== 1) return;
        const { bytes: bodyBytes, contentType: inferredCt } = await serializeBody(body);
        if (self._psOpId !== opId || self.readyState !== 1) return;
        const sigHeaders = await signRequestFields(meta.method, reqUrl.pathname + reqUrl.search, bodyBytes);
        if (self._psOpId !== opId || self.readyState !== 1) return;

        if (inferredCt && (!self._psHeaders || !self._psHeaders["content-type"])) {
          origSetHdr.call(self, "Content-Type", inferredCt);
        }
        for (const [k, v] of Object.entries(sigHeaders)) origSetHdr.call(self, k, v);

        await new Promise((done) => {
          let rotatedCaptured = false;
          const onState = () => {
            if (!rotatedCaptured && self.readyState >= 2) {
              rotatedCaptured = true;
              try {
                const rot = self.getResponseHeader("X-PS-Next-Canary");
                if (rot && state) state.canary = rot;
              } catch (_) {}
            }
            if (self.readyState === 4) {
              self.removeEventListener("readystatechange", onState);
              done();
            }
          };
          self.addEventListener("readystatechange", onState);
          origSend.call(self, body != null && meta.method !== "GET" && meta.method !== "HEAD" ? bodyBytes : body);
        });
      }).catch(() => {
        if (self._psOpId === opId && self.readyState === 1) {
          try { origSend.call(self, body); } catch (_) {}
        }
      });
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
