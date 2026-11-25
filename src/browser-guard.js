"use strict";

const pkgVersion = (() => {
  try {
    return require("../package.json").version || "2.0.0";
  } catch {
    return "2.0.0";
  }
})();

function serializeRulesForScript(raw) {
  return (Array.isArray(raw) ? raw : []).map((r) => {
    if (r instanceof RegExp) return { regex: r.source, flags: r.flags.replace(/[gy]/g, "") };
    return r;
  });
}

function escapeInlineJson(obj) {
  return JSON.stringify(obj)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

/**
 * Generates the zero-dependency 1-line browser drop-in guard served at `/__proxysnare/guard.js`.
 *
 * Security & compatibility guarantees:
 *   - Ephemeral WebCrypto ECDH P-256 + HKDF-SHA256 (`PS_ECDH_V2`) deriving a non-extractable
 *     HMAC-SHA256 key directly inside WebCrypto (zero plaintext session keys ever on the wire!).
 *   - Single-use stamped boot token + lightweight SHA-256 PoW solver (~1–2 ms) with transparent
 *     `/__proxysnare/boot` refresh on 30-min session re-handshake (`X-PS-Rehandshake: 1`).
 *   - Serializes protected `fetch()` and async `XMLHttpRequest` calls without deadlocking on
 *     reused/aborted XHRs, releasing the queue at `HEADERS_RECEIVED`, handling same-origin 3xx
 *     redirects, `FormData`, `Blob`, `Document`, `URLSearchParams`, `ArrayBuffer`, and `Request`.
 */
function buildBrowserGuardScript({
  basePath = "/__proxysnare",
  protectedPaths = ["/api"],
  protectedRules = null,
  initialBoot = null,
} = {}) {
  const normBase = String(basePath || "/__proxysnare").replace(/\/+$/, "") || "/__proxysnare";
  const rules = serializeRulesForScript(
    Array.isArray(protectedRules) && protectedRules.length > 0 ? protectedRules : protectedPaths
  );
  const rulesJson = escapeInlineJson(rules);
  const bpJson = escapeInlineJson(normBase);
  const bootJson = escapeInlineJson(initialBoot || null);
  const verJson = escapeInlineJson(pkgVersion);

  return `(() => {
  "use strict";
  if (typeof window === "undefined" || window.__PROXYSNARE_GUARD_LOADED__) return;
  window.__PROXYSNARE_GUARD_LOADED__ = true;

  const BASE = ${bpJson};
  const VERSION = ${verJson};
  const RAW_RULES = ${rulesJson};
  const RULES = RAW_RULES.map((r) => {
    if (r && typeof r === "object" && typeof r.regex === "string") {
      try { return new RegExp(r.regex, r.flags || ""); } catch { return null; }
    }
    if (typeof r !== "string") return null;
    const t = r.trim();
    if (t === "*") return "*";
    return normalizeClientPath(t).toLowerCase();
  }).filter(Boolean);

  const origFetch = typeof window.fetch === "function" ? window.fetch.bind(window) : null;
  const encoder = new TextEncoder();

  let pendingBoot = ${bootJson};
  let state = null;
  let initPromise = null;
  let sessionGen = 0;
  let seq = 0;
  let clockOffsetMs = 0;
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

  function toBase64(bytes) {
    const u = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    let bin = "";
    for (let i = 0; i < u.length; i++) bin += String.fromCharCode(u[i]);
    return btoa(bin);
  }

  function fromBase64(b64) {
    const norm = String(b64 || "").trim().replace(/-/g, "+").replace(/_/g, "/");
    const bin = atob(norm);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }

  // Compact FIPS 180-4 SHA-256 (used solely for ~1-2ms synchronous handshake PoW)
  const SHA256_K = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ];
  const SHA256_W = new Int32Array(64);
  function sha256Words(str) {
    const bytes = encoder.encode(str);
    let h0=0x6a09e667,h1=0xbb67ae85,h2=0x3c6ef372,h3=0xa54ff53a,h4=0x510e527f,h5=0x9b05688c,h6=0x1f83d9ab,h7=0x5be0cd19;
    const bitLen = bytes.length * 8;
    const padLen = ((bytes.length + 9 + 63) >> 6) << 6;
    const m = new Uint8Array(padLen);
    m.set(bytes);
    m[bytes.length] = 0x80;
    const dv = new DataView(m.buffer);
    dv.setUint32(padLen - 8, Math.floor(bitLen / 0x100000000), false);
    dv.setUint32(padLen - 4, bitLen >>> 0, false);
    for (let o = 0; o < padLen; o += 64) {
      for (let i = 0; i < 16; i++) SHA256_W[i] = dv.getInt32(o + i * 4, false);
      for (let i = 16; i < 64; i++) {
        const s0 = ((SHA256_W[i-15]>>>7)|(SHA256_W[i-15]<<25)) ^ ((SHA256_W[i-15]>>>18)|(SHA256_W[i-15]<<14)) ^ (SHA256_W[i-15]>>>3);
        const s1 = ((SHA256_W[i-2]>>>17)|(SHA256_W[i-2]<<15)) ^ ((SHA256_W[i-2]>>>19)|(SHA256_W[i-2]<<13)) ^ (SHA256_W[i-2]>>>10);
        SHA256_W[i] = (SHA256_W[i-16] + s0 + SHA256_W[i-7] + s1) | 0;
      }
      let a=h0,b=h1,c=h2,d=h3,e=h4,f=h5,g=h6,h=h7;
      for (let i = 0; i < 64; i++) {
        const S1 = ((e>>>6)|(e<<26)) ^ ((e>>>11)|(e<<21)) ^ ((e>>>25)|(e<<7));
        const ch = (e & f) ^ (~e & g);
        const t1 = (h + S1 + ch + SHA256_K[i] + SHA256_W[i]) | 0;
        const S0 = ((a>>>2)|(a<<30)) ^ ((a>>>13)|(a<<19)) ^ ((a>>>22)|(a<<10));
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const t2 = (S0 + maj) | 0;
        h=g; g=f; f=e; e=(d+t1)|0; d=c; c=b; b=a; a=(t1+t2)|0;
      }
      h0=(h0+a)|0; h1=(h1+b)|0; h2=(h2+c)|0; h3=(h3+d)|0; h4=(h4+e)|0; h5=(h5+f)|0; h6=(h6+g)|0; h7=(h7+h)|0;
    }
    return [h0 >>> 0, h1 >>> 0, h2 >>> 0, h3 >>> 0, h4 >>> 0, h5 >>> 0, h6 >>> 0, h7 >>> 0];
  }

  function hasLeadingZeroBits(words, bits) {
    let rem = bits;
    for (let i = 0; i < words.length && rem > 0; i++) {
      const w = words[i];
      if (rem >= 32) {
        if (w !== 0) return false;
        rem -= 32;
      } else {
        return Math.clz32(w) >= rem;
      }
    }
    return true;
  }

  function solvePow(challenge, difficulty) {
    if (!difficulty || difficulty <= 0 || !challenge) return "0";
    const prefix = "PS_POW_V2|" + challenge + "|";
    for (let i = 0; i < 5_000_000; i++) {
      const nonce = i.toString(36);
      if (hasLeadingZeroBits(sha256Words(prefix + nonce), difficulty)) return nonce;
    }
    throw new Error("PROXYSNARE_POW_TIMEOUT");
  }

  function decodePercentSafe(s) {
    return s.replace(/(?:%[0-9a-fA-F]{2})+/g, (run) => {
      let out = "";
      let i = 0;
      while (i < run.length) {
        const b = parseInt(run.slice(i + 1, i + 3), 16);
        if (b === 0) { out += "\\0"; i += 3; continue; }
        if (b >= 1 && b <= 0x7f) { out += String.fromCharCode(b); i += 3; continue; }
        let ok = false;
        for (const n of [2, 3, 4]) {
          if (i + n * 3 <= run.length) {
            try { out += decodeURIComponent(run.slice(i, i + n * 3)); i += n * 3; ok = true; break; } catch {}
          }
        }
        if (!ok) { out += run.slice(i, i + 3); i += 3; }
      }
      return out;
    });
  }

  function normalizeClientPath(raw) {
    let s = String(raw || "/").split("?")[0];
    for (let pass = 0; pass < 2; pass++) {
      const next = decodePercentSafe(s);
      if (next === s) break;
      s = next;
    }
    s = s.replace(/\\0/g, "").replace(/\\\\/g, "/");
    if (!s.startsWith("/")) s = "/" + s;
    const segs = s.split("/").map((seg) => seg.split(";")[0]);
    const stack = [];
    for (let i = 0; i < segs.length; i++) {
      const seg = segs[i];
      if (!seg || seg === ".") continue;
      if (seg === "..") { if (stack.length) stack.pop(); }
      else stack.push(seg);
    }
    return "/" + stack.join("/");
  }

  function isGuardControlPath(pathname) {
    const norm = normalizeClientPath(pathname);
    return (
      norm === BASE + "/handshake" ||
      norm === BASE + "/boot" ||
      norm === BASE + "/guard.js" ||
      norm === BASE + "/health"
    );
  }

  function isProtectedPath(pathname) {
    const raw = String(pathname || "/").split("?")[0];
    const candidates = new Set([normalizeClientPath(raw)]);
    let dec = raw;
    for (let pass = 0; pass < 2; pass++) {
      const next = decodePercentSafe(dec);
      if (next === dec) break;
      dec = next;
    }
    candidates.add(normalizeClientPath(dec));
    const q = dec.indexOf("?");
    if (q >= 0) candidates.add(normalizeClientPath(dec.slice(0, q)));
    const h = dec.indexOf("#");
    if (h >= 0) candidates.add(normalizeClientPath(dec.slice(0, h)));

    for (const cand of candidates) {
      const lower = cand.toLowerCase();
      for (let i = 0; i < RULES.length; i++) {
        const rule = RULES[i];
        if (rule instanceof RegExp) {
          rule.lastIndex = 0;
          if (rule.test(cand)) return true;
        } else if (rule === "*" || rule === "/" || lower === rule || lower.startsWith(rule.endsWith("/") ? rule : rule + "/")) {
          return true;
        }
      }
    }
    return false;
  }

  function assertSecureWebCrypto() {
    if (typeof crypto === "undefined" || !crypto.subtle) {
      throw new Error("PROXYSNARE_REQUIRES_SECURE_CONTEXT: WebCrypto (crypto.subtle) requires HTTPS or localhost.");
    }
  }

  function baseHref() {
    return (typeof document !== "undefined" && document.baseURI) || window.location.href;
  }

  function resolveInputUrl(input) {
    const b = baseHref();
    if (typeof input === "string") return new URL(input, b);
    if (input instanceof URL) return new URL(input.href, b);
    if (input && typeof input.url === "string") return new URL(input.url, b);
    return new URL(String(input), b);
  }

  async function acquireBootChallenge() {
    if (pendingBoot && pendingBoot.bootToken && (!pendingBoot.exp || pendingBoot.exp > Date.now() + 2000)) {
      const b = pendingBoot;
      pendingBoot = null;
      return { boot: b, fromStamped: true };
    }
    pendingBoot = null;
    if (!origFetch) throw new Error("PROXYSNARE_FETCH_UNAVAILABLE");
    const resp = await origFetch(BASE + "/boot", {
      method: "GET",
      credentials: "same-origin",
      cache: "no-store",
    });
    if (!resp.ok) throw new Error("PROXYSNARE_BOOT_FAILED_" + resp.status);
    return { boot: await resp.json(), fromStamped: false };
  }

  async function ensureSession(forceNew = false) {
    assertSecureWebCrypto();
    if (!origFetch) throw new Error("PROXYSNARE_FETCH_UNAVAILABLE");
    if (state && !forceNew) return state;
    if (forceNew) {
      sessionGen += 1;
      state = null;
      initPromise = null;
    }
    if (initPromise) return initPromise;
    const myGen = sessionGen;
    const p = (async () => {
      let { boot, fromStamped } = await acquireBootChallenge();
      const kp = await crypto.subtle.generateKey(
        { name: "ECDH", namedCurve: "P-256" },
        false,
        ["deriveBits"]
      );
      const clientPubRaw = new Uint8Array(await crypto.subtle.exportKey("raw", kp.publicKey));
      const clientPubB64 = toBase64(clientPubRaw);

      const postHandshake = async (activeBoot) => {
        const powNonce = solvePow(activeBoot.challenge, activeBoot.difficulty || 0);
        const t0 = Date.now();
        const resp = await origFetch(BASE + "/handshake", {
          method: "POST",
          credentials: "same-origin",
          cache: "no-store",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({
            protocol: "PS_ECDH_V2",
            clientPubB64,
            bootToken: activeBoot.bootToken,
            powNonce,
            t: t0,
          }),
        });
        return { resp, t0, t1: Date.now() };
      };

      let { resp, t0, t1 } = await postHandshake(boot);
      // If stamped bootToken became stale (clock skew, bfcache restore, or server restart), retry once via fresh /boot!
      if (resp.status === 403 && fromStamped) {
        const fresh = await acquireBootChallenge();
        boot = fresh.boot;
        ({ resp, t0, t1 } = await postHandshake(boot));
      }
      if (!resp.ok) throw new Error("PROXYSNARE_HANDSHAKE_FAILED_" + resp.status);
      const data = await resp.json();
      if (!data.serverPubB64 || !data.saltB64 || !data.sessionId || !data.canary) {
        throw new Error("PROXYSNARE_HANDSHAKE_MALFORMED");
      }

      const serverPubKey = await crypto.subtle.importKey(
        "raw",
        fromBase64(data.serverPubB64),
        { name: "ECDH", namedCurve: "P-256" },
        false,
        []
      );
      const sharedBits = await crypto.subtle.deriveBits(
        { name: "ECDH", public: serverPubKey },
        kp.privateKey,
        256
      );
      const hkdfKey = await crypto.subtle.importKey("raw", sharedBits, "HKDF", false, ["deriveKey"]);
      const infoBytes = encoder.encode("PS_ECDH_V2|" + data.sessionId + "|" + clientPubB64 + "|" + data.serverPubB64);
      const cryptoKey = await crypto.subtle.deriveKey(
        { name: "HKDF", hash: "SHA-256", salt: fromBase64(data.saltB64), info: infoBytes },
        hkdfKey,
        { name: "HMAC", hash: "SHA-256", length: 256 },
        false,
        ["sign"]
      );

      if (typeof data.serverNowMs === "number" && Number.isFinite(data.serverNowMs)) {
        const midpoint = t0 + Math.max(0, t1 - t0) / 2;
        clockOffsetMs = Math.round(data.serverNowMs - midpoint);
      } else {
        clockOffsetMs = 0;
      }

      const nextState = {
        sessionId: data.sessionId,
        cryptoKey,
        canary: data.canary,
      };
      if (myGen === sessionGen) {
        seq = 0;
        state = nextState;
      }
      return state || nextState;
    })();
    initPromise = p;
    try {
      return await p;
    } finally {
      if (initPromise === p) initPromise = null;
    }
  }

  async function signRequestFields(method, pathWithQuery, bodyBytes) {
    const st = await ensureSession(false);
    const bodyHash = toHex(await crypto.subtle.digest("SHA-256", bodyBytes));
    seq += 1;
    const mySeq = seq;
    const ts = Math.max(0, Math.round(Date.now() + clockOffsetMs));
    const nonceBytes = new Uint8Array(12);
    crypto.getRandomValues(nonceBytes);
    const nonce = toHex(nonceBytes);
    const canary = st.canary;
    const canonical = "PS1|" + method.toUpperCase() + "|" + pathWithQuery + "|" + bodyHash + "|" + mySeq + "|" + ts + "|" + nonce + "|" + canary;
    const sigBuf = await crypto.subtle.sign("HMAC", st.cryptoKey, encoder.encode(canonical));
    return {
      sessionId: st.sessionId,
      headers: {
        "X-PS-Session": st.sessionId,
        "X-PS-Seq": String(mySeq),
        "X-PS-Ts": String(ts),
        "X-PS-Nonce": nonce,
        "X-PS-Canary": canary,
        "X-PS-Proof": toHex(sigBuf),
      },
    };
  }

  function snapshotBodySync(body) {
    if (body == null) return { sync: true, bytes: new Uint8Array(0), contentType: null };
    if (typeof body === "string") return { sync: true, bytes: encoder.encode(body), contentType: "text/plain;charset=UTF-8" };
    if (body instanceof ArrayBuffer) {
      const copy = new Uint8Array(body.byteLength);
      copy.set(new Uint8Array(body));
      return { sync: true, bytes: copy, contentType: null };
    }
    if (ArrayBuffer.isView(body)) {
      const copy = new Uint8Array(body.byteLength);
      copy.set(new Uint8Array(body.buffer, body.byteOffset, body.byteLength));
      return { sync: true, bytes: copy, contentType: null };
    }
    if (body instanceof URLSearchParams) {
      return { sync: true, bytes: encoder.encode(body.toString()), contentType: "application/x-www-form-urlencoded;charset=UTF-8" };
    }
    if (typeof Document !== "undefined" && body instanceof Document) {
      const xml = new XMLSerializer().serializeToString(body);
      const isHtml = typeof HTMLDocument !== "undefined" && body instanceof HTMLDocument;
      return { sync: true, bytes: encoder.encode(xml), contentType: (isHtml ? "text/html" : "application/xml") + ";charset=UTF-8" };
    }
    return { sync: false, raw: body };
  }

  async function finalizeBody(snap) {
    if (snap.sync) return { bytes: snap.bytes, contentType: snap.contentType };
    const body = snap.raw;
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

  function shouldRehandshake(resp, cloneBody) {
    if (!resp || resp.status !== 403) return false;
    if (resp.headers.get("X-PS-Rehandshake") === "1") return true;
    return Boolean(
      cloneBody &&
      Array.isArray(cloneBody.reasons) &&
      cloneBody.reasons.includes("REPEATER_UNKNOWN_OR_EXPIRED_SESSION")
    );
  }

  if (origFetch) {
    window.fetch = function proxySnareFetch(input, init) {
      const safeInit = init && typeof init === "object" ? init : {};
      let reqUrl;
      try {
        reqUrl = resolveInputUrl(input);
      } catch {
        return origFetch(input, init);
      }
      if (reqUrl.origin !== window.location.origin || isGuardControlPath(reqUrl.pathname) || !isProtectedPath(reqUrl.pathname)) {
        return origFetch(input, init);
      }

      const isRequestObj = typeof Request !== "undefined" && input instanceof Request;
      const method = (safeInit.method || (isRequestObj ? input.method : "GET") || "GET").toUpperCase();
      const activeSignal = safeInit.signal !== undefined ? safeInit.signal : (isRequestObj ? input.signal : null);
      const hasExplicitBody = safeInit.body !== undefined;
      const eagerSnap = hasExplicitBody ? snapshotBodySync(safeInit.body) : null;

      return enqueueProtected(async () => {
        if (activeSignal && activeSignal.aborted) {
          throw activeSignal.reason || new DOMException("The operation was aborted.", "AbortError");
        }
        let bodyBytes;
        let inferredCt = null;
        if (method === "GET" || method === "HEAD") {
          bodyBytes = new Uint8Array(0);
        } else if (hasExplicitBody) {
          const fin = await finalizeBody(eagerSnap);
          bodyBytes = fin.bytes;
          inferredCt = fin.contentType;
        } else if (isRequestObj) {
          const ab = await input.clone().arrayBuffer();
          bodyBytes = new Uint8Array(ab);
        } else {
          bodyBytes = new Uint8Array(0);
        }

        const requestedRedirect = safeInit.redirect || (isRequestObj ? input.redirect : "follow") || "follow";

        const sendOnce = async (targetUrl, targetMethod, targetBytes, targetCt, forceRehandshake) => {
          if (forceRehandshake) await ensureSession(true);
          const mergedHeaders = new Headers(
            safeInit.headers !== undefined ? safeInit.headers : (isRequestObj ? input.headers : undefined)
          );
          if (targetCt && !mergedHeaders.has("content-type")) {
            mergedHeaders.set("content-type", targetCt);
          }
          const needsSign =
            targetUrl.origin === window.location.origin &&
            !isGuardControlPath(targetUrl.pathname) &&
            isProtectedPath(targetUrl.pathname);

          let usedSessionId = null;
          if (needsSign) {
            const signed = await signRequestFields(targetMethod, targetUrl.pathname + targetUrl.search, targetBytes);
            usedSessionId = signed.sessionId;
            for (const [k, v] of Object.entries(signed.headers)) mergedHeaders.set(k, v);
          }

          const baseOpts = isRequestObj
            ? {
                credentials: input.credentials,
                cache: input.cache,
                referrer: input.referrer,
                referrerPolicy: input.referrerPolicy,
                integrity: input.integrity,
                keepalive: input.keepalive,
                signal: input.signal,
                ...(input.mode && input.mode !== "navigate" ? { mode: input.mode } : {}),
              }
            : {};

          const nextInit = {
            ...baseOpts,
            ...safeInit,
            method: targetMethod,
            headers: mergedHeaders,
            redirect: requestedRedirect,
          };
          if (targetMethod !== "GET" && targetMethod !== "HEAD" && (targetBytes.byteLength > 0 || hasExplicitBody || isRequestObj)) {
            nextInit.body = targetBytes;
          } else {
            delete nextInit.body;
          }

          let resp;
          try {
            resp = await origFetch(targetUrl.toString(), nextInit);
          } catch (err) {
            if (usedSessionId && state && state.sessionId === usedSessionId) {
              state = null;
            }
            throw err;
          }
          const rotated = resp.headers.get("X-PS-Next-Canary");
          const rehs = resp.headers.get("X-PS-Rehandshake") === "1";
          if (usedSessionId && state && state.sessionId === usedSessionId) {
            if (rehs) {
              state = null;
            } else if (rotated) {
              state.canary = rotated;
            } else if (resp.redirected || resp.type === "opaqueredirect" || resp.status === 0) {
              // Server may have rotated canary on the 3xx response hidden by redirect; re-handshake cleanly on next call
              state = null;
            }
          }
          return resp;
        };

        let resp = await sendOnce(reqUrl, method, bodyBytes, inferredCt, false);
        if (resp.status === 403 && !(activeSignal && activeSignal.aborted)) {
          let cloneJson = null;
          try { cloneJson = await resp.clone().json(); } catch (_) {}
          if (shouldRehandshake(resp, cloneJson)) {
            resp = await sendOnce(reqUrl, method, bodyBytes, inferredCt, true);
          } else if (requestedRedirect === "follow" && resp.redirected && resp.url && (method === "GET" || method === "HEAD")) {
            try {
              const finalUrl = new URL(resp.url);
              if (finalUrl.origin === window.location.origin && !isGuardControlPath(finalUrl.pathname)) {
                state = null;
                resp = await sendOnce(finalUrl, method, new Uint8Array(0), null, isProtectedPath(finalUrl.pathname));
              }
            } catch (_) {}
          }
        }
        return resp;
      });
    };
  }

  // Transparently instrument async XMLHttpRequest (Axios, jQuery, legacy XHR clients)
  if (typeof XMLHttpRequest !== "undefined") {
    const origOpen = XMLHttpRequest.prototype.open;
    const origSend = XMLHttpRequest.prototype.send;
    const origAbort = XMLHttpRequest.prototype.abort;
    const origSetHdr = XMLHttpRequest.prototype.setRequestHeader;
    const xhrMeta = new WeakMap();

    function settleXhrQueue(xhr) {
      const m = xhrMeta.get(xhr);
      if (m) {
        if (m.inFlightSessionId) {
          if (state && state.sessionId === m.inFlightSessionId) state = null;
          m.inFlightSessionId = null;
        }
        if (m.releaseQueue) {
          const fn = m.releaseQueue;
          m.releaseQueue = null;
          fn();
        }
      }
    }

    XMLHttpRequest.prototype.open = function proxySnareXhrOpen(method, url, asyncFlag = true) {
      settleXhrQueue(this);
      const prev = xhrMeta.get(this);
      const opId = (prev ? prev.opId : 0) + 1;
      let resolvedUrl = null;
      try { resolvedUrl = new URL(String(url || ""), baseHref()); } catch (_) {}
      xhrMeta.set(this, {
        opId,
        headers: Object.create(null),
        method: String(method || "GET").toUpperCase(),
        url: resolvedUrl,
        asyncFlag: Boolean(asyncFlag),
        queued: false,
        inFlightSessionId: null,
        releaseQueue: null,
      });
      return origOpen.apply(this, arguments);
    };

    XMLHttpRequest.prototype.setRequestHeader = function proxySnareXhrSetHdr(name, val) {
      const m = xhrMeta.get(this);
      if (m) m.headers[String(name).toLowerCase()] = true;
      return origSetHdr.call(this, name, val);
    };

    XMLHttpRequest.prototype.abort = function proxySnareXhrAbort() {
      const m = xhrMeta.get(this);
      const wasQueued = Boolean(m && m.queued);
      if (m) {
        m.opId += 1;
        m.queued = false;
      }
      settleXhrQueue(this);
      const res = origAbort.call(this);
      if (wasQueued && typeof ProgressEvent !== "undefined") {
        try {
          this.dispatchEvent(new ProgressEvent("abort"));
          this.dispatchEvent(new ProgressEvent("loadend"));
        } catch (_) {}
      }
      return res;
    };

    XMLHttpRequest.prototype.send = function proxySnareXhrSend(body) {
      const meta = xhrMeta.get(this);
      if (!meta || !meta.url) return origSend.call(this, body);
      const reqUrl = meta.url;
      if (reqUrl.origin !== window.location.origin || isGuardControlPath(reqUrl.pathname) || !isProtectedPath(reqUrl.pathname)) {
        return origSend.call(this, body);
      }
      if (!meta.asyncFlag) {
        try { console.warn("[ProxySnare] Synchronous XMLHttpRequest to protected route cannot be signed asynchronously:", reqUrl.pathname); } catch (_) {}
        return origSend.call(this, body);
      }

      const opId = meta.opId;
      const self = this;
      const effectiveBody = (meta.method === "GET" || meta.method === "HEAD") ? null : body;
      const eagerSnap = snapshotBodySync(effectiveBody);
      meta.queued = true;

      enqueueProtected(async () => {
        if (xhrMeta.get(self)?.opId !== opId || self.readyState !== 1) return;
        const { bytes: bodyBytes, contentType: inferredCt } = await finalizeBody(eagerSnap);
        if (xhrMeta.get(self)?.opId !== opId || self.readyState !== 1) return;
        const signed = await signRequestFields(meta.method, reqUrl.pathname + reqUrl.search, bodyBytes);
        if (xhrMeta.get(self)?.opId !== opId || self.readyState !== 1) return;

        meta.queued = false;
        if (inferredCt && !meta.headers["content-type"]) {
          origSetHdr.call(self, "Content-Type", inferredCt);
        }
        for (const [k, v] of Object.entries(signed.headers)) origSetHdr.call(self, k, v);

        await new Promise((done) => {
          let settled = false;
          const finish = () => {
            if (settled) return;
            settled = true;
            meta.releaseQueue = null;
            self.removeEventListener("readystatechange", onState);
            self.removeEventListener("loadend", onEnd);
            done();
          };
          meta.releaseQueue = finish;
          meta.inFlightSessionId = signed.sessionId;

          const expectedUrl = reqUrl.origin + reqUrl.pathname + reqUrl.search;
          const onState = () => {
            if (self.readyState >= 2) {
              meta.inFlightSessionId = null;
              try {
                const rot = self.getResponseHeader("X-PS-Next-Canary");
                const rehs = self.getResponseHeader("X-PS-Rehandshake") === "1";
                if (state && state.sessionId === signed.sessionId) {
                  if (rehs || self.status === 0 || (!rot && self.responseURL && self.responseURL !== expectedUrl)) {
                    state = null;
                  } else if (rot) {
                    state.canary = rot;
                  }
                }
              } catch (_) {}
              finish();
            }
          };
          const onEnd = () => {
            meta.inFlightSessionId = null;
            if (self.status === 0 && state && state.sessionId === signed.sessionId) {
              state = null;
            }
            finish();
          };
          self.addEventListener("readystatechange", onState);
          self.addEventListener("loadend", onEnd);
          origSend.call(self, effectiveBody != null ? bodyBytes : null);
        });
      }).catch((err) => {
        meta.queued = false;
        if (xhrMeta.get(self)?.opId === opId) settleXhrQueue(self);
        try { console.error("[ProxySnare] Failed to sign XMLHttpRequest:", err); } catch (_) {}
        if (xhrMeta.get(self)?.opId === opId && self.readyState === 1) {
          try { origAbort.call(self); } catch (_) {}
          if (typeof ProgressEvent !== "undefined") {
            try {
              self.dispatchEvent(new ProgressEvent("error"));
              self.dispatchEvent(new ProgressEvent("loadend"));
            } catch (_) {}
          }
        }
      });
    };
  }

  window.ProxySnare = {
    ready: () => enqueueProtected(() => ensureSession(false)),
    version: VERSION,
  };
})();
`;
}

module.exports = { buildBrowserGuardScript };
