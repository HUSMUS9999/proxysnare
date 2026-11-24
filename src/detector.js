"use strict";

const crypto = require("node:crypto");
const path = require("node:path");

const VALID_MODES = new Set(["off", "monitor", "balanced", "strict"]);

function normalizeMode(mode = "strict") {
  const m = String(mode || "strict").trim().toLowerCase();
  if (!VALID_MODES.has(m)) {
    throw new Error(`Invalid ProxySnare mode '${mode}': expected 'off', 'monitor', 'balanced', or 'strict'`);
  }
  return m;
}

function sha256Hex(input) {
  return crypto.createHash("sha256").update(input || "").digest("hex");
}

function hmacSha256Hex(keyBuf, data) {
  return crypto.createHmac("sha256", keyBuf).update(data).digest("hex");
}

function safeEqualHex(a, b) {
  if (typeof a !== "string" || typeof b !== "string" || a.length !== b.length || a.length === 0) {
    return false;
  }
  const ba = Buffer.from(a, "utf8");
  const bb = Buffer.from(b, "utf8");
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

function getHeader(headers, name) {
  if (!headers || typeof headers !== "object") return "";
  const target = name.toLowerCase();
  for (const [k, v] of Object.entries(headers)) {
    if (k.toLowerCase() === target) {
      return Array.isArray(v) ? v.join(", ") : String(v ?? "");
    }
  }
  return "";
}

function hasHeader(headers, name) {
  if (!headers || typeof headers !== "object") return false;
  const target = name.toLowerCase();
  return Object.keys(headers).some((k) => k.toLowerCase() === target);
}

/**
 * Normalizes an HTTP request-target pathname to defeat case, percent-encoding,
 * absolute-form URI, double-slash, dot-segment, backslash, and matrix-param bypasses.
 */
function normalizePathname(rawUrl) {
  let s = String(rawUrl || "/").trim();
  // Strip absolute-form scheme+authority (RFC 9112 §3.2.2)
  if (/^https?:\/\//i.test(s)) {
    try {
      s = new URL(s).pathname || "/";
    } catch {
      const idx = s.indexOf("/", s.indexOf("://") + 3);
      s = idx >= 0 ? s.slice(idx) : "/";
    }
  }
  // Drop query and fragment
  const qIdx = s.search(/[?#]/);
  if (qIdx >= 0) s = s.slice(0, qIdx);
  if (!s) return "/";

  // Decode percent-encoding up to 2 passes safely (prevents %61pi / %2561pi bypass)
  for (let pass = 0; pass < 2; pass++) {
    try {
      const decoded = decodeURIComponent(s);
      if (decoded === s) break;
      s = decoded;
    } catch {
      break;
    }
  }

  // Normalize Windows backslashes and collapse slashes / dot-segments
  s = s.replace(/\\/g, "/");
  if (!s.startsWith("/")) s = "/" + s;
  // Strip matrix parameters per segment (e.g. /api;v=1/transfer -> /api/transfer)
  s = s
    .split("/")
    .map((seg) => seg.split(";")[0])
    .join("/");
  s = path.posix.normalize(s);
  if (!s.startsWith("/")) s = "/" + s;
  return s;
}

function normalizeProtectedPaths(paths) {
  if (!paths || paths.length === 0) return ["/api"];
  return paths.map((p) => (p instanceof RegExp ? p : normalizePathname(String(p))));
}

function isPathProtected(rawPathname, protectedPaths) {
  const norm = normalizePathname(rawPathname);
  const normLower = norm.toLowerCase();
  for (const rule of protectedPaths) {
    if (rule instanceof RegExp) {
      rule.lastIndex = 0;
      if (rule.test(norm)) return true;
    } else {
      const rLower = String(rule).toLowerCase();
      if (
        rLower === "*" ||
        rLower === "/" ||
        normLower === rLower ||
        normLower.startsWith(rLower.endsWith("/") ? rLower : `${rLower}/`)
      ) {
        return true;
      }
    }
  }
  return false;
}

function normalizeIp(ip) {
  const s = String(ip || "").trim().replace(/^::ffff:/, "");
  return s === "::1" ? "127.0.0.1" : s;
}

function extractClientIp(req, trustedProxies) {
  const remoteRaw = req?.socket?.remoteAddress || req?.ip || "";
  const remote = normalizeIp(remoteRaw);
  if (remote && trustedProxies.size > 0 && trustedProxies.has(remote)) {
    const xff = getHeader(req.headers, "x-forwarded-for");
    if (xff) {
      // Walk right-to-left skipping trusted proxies (defeats leftmost XFF spoofing!)
      const parts = xff.split(",").map((s) => normalizeIp(s)).filter(Boolean);
      for (let i = parts.length - 1; i >= 0; i--) {
        if (!trustedProxies.has(parts[i])) {
          return parts[i];
        }
      }
      if (parts.length > 0) return parts[0];
    }
  }
  return remote || "unknown";
}

function parseBrowserMajorChrome(ua) {
  const m = /Chrome\/(\d+)/i.exec(ua || "");
  return m ? Number(m[1]) : 0;
}

function parseBrowserMajorFirefox(ua) {
  const m = /Firefox\/(\d+)/i.exec(ua || "");
  return m ? Number(m[1]) : 0;
}

function positiveFinite(val, fallback, name) {
  if (val === undefined || val === null) return fallback;
  if (!Number.isFinite(val) || val <= 0) {
    throw new Error(`Invalid ProxySnare option '${name}': expected a positive finite number`);
  }
  return val;
}

/**
 * Core ProxySnare detection engine.
 * Detects and blocks Caido Repeater, Burp Suite Repeater, mitmproxy, and raw HTTP replay/tampering.
 */
function createProxySnareEngine(options = {}) {
  const mode = normalizeMode(options.mode ?? "strict");

  let secret;
  if (options.secret === undefined || options.secret === null) {
    secret = crypto.randomBytes(32);
  } else if (Buffer.isBuffer(options.secret)) {
    if (options.secret.length < 16) {
      throw new Error("Invalid ProxySnare secret: Buffer must be at least 16 bytes");
    }
    secret = Buffer.from(options.secret);
  } else if (typeof options.secret === "string") {
    if (Buffer.byteLength(options.secret, "utf8") < 16) {
      throw new Error("Invalid ProxySnare secret: string must be at least 16 bytes");
    }
    secret = Buffer.from(options.secret, "utf8");
  } else {
    throw new Error("Invalid ProxySnare secret: expected Buffer or string (>= 16 bytes)");
  }

  const threshold = positiveFinite(options.threshold, mode === "strict" ? 4 : 6, "threshold");
  const freshnessMs = positiveFinite(options.freshnessMs, mode === "strict" ? 8_000 : 15_000, "freshnessMs");
  const maxFutureSkewMs = Math.min(3_000, freshnessMs);
  const nonceTtlMs = positiveFinite(options.nonceTtlMs, 300_000, "nonceTtlMs");
  const sessionTtlMs = positiveFinite(options.sessionTtlMs, 1_800_000, "sessionTtlMs");
  const maxSessions = positiveFinite(options.maxSessions, 20_000, "maxSessions");
  const maxNonces = positiveFinite(options.maxNonces, 50_000, "maxNonces");
  const maxHandshakesPerMin = positiveFinite(options.maxHandshakesPerMin, 120, "maxHandshakesPerMin");
  const protectedPaths = normalizeProtectedPaths(options.protectedPaths);
  const trustedProxies = new Set(
    (Array.isArray(options.trustProxy)
      ? options.trustProxy.map((s) => normalizeIp(s))
      : typeof options.trustProxy === "string"
        ? options.trustProxy.split(",").map((s) => normalizeIp(s))
        : []
    ).filter(Boolean)
  );
  const onDetect = typeof options.onDetect === "function" ? options.onDetect : null;

  const sessions = new Map();
  const usedNonces = new Map();
  const ipBursts = new Map();
  const handshakeRates = new Map();
  let inspectCounter = 0;

  function pruneMaps(now) {
    if (sessions.size > maxSessions) {
      // First pass: delete expired sessions
      for (const [k, v] of sessions) {
        if (v.exp <= now) sessions.delete(k);
      }
      // Second pass if still over cap: evict oldest 15%
      if (sessions.size > maxSessions) {
        const target = Math.floor(maxSessions * 0.85);
        for (const k of sessions.keys()) {
          sessions.delete(k);
          if (sessions.size <= target) break;
        }
      }
    }
    if (usedNonces.size > maxNonces) {
      for (const [k, exp] of usedNonces) {
        if (exp <= now) usedNonces.delete(k);
      }
      if (usedNonces.size > maxNonces) {
        const target = Math.floor(maxNonces * 0.85);
        for (const k of usedNonces.keys()) {
          usedNonces.delete(k);
          if (usedNonces.size <= target) break;
        }
      }
    }
    if (ipBursts.size > 10_000) ipBursts.clear();
    if (handshakeRates.size > 10_000) handshakeRates.clear();
  }

  function allowHandshake(ip, now = Date.now()) {
    const key = ip || "unknown";
    const arr = (handshakeRates.get(key) || []).filter((t) => now - t < 60_000);
    if (arr.length >= maxHandshakesPerMin) {
      handshakeRates.set(key, arr);
      return false;
    }
    arr.push(now);
    handshakeRates.set(key, arr);
    return true;
  }

  function mintCanary(sessionId, step) {
    return hmacSha256Hex(secret, `PS_CANARY|${sessionId}|${step}|${crypto.randomBytes(8).toString("hex")}`).slice(0, 24);
  }

  function serializeProtectedPathsForClient() {
    return protectedPaths.map((p) =>
      p instanceof RegExp ? { regex: p.source, flags: p.flags.replace(/[gy]/g, "") } : p
    );
  }

  function issueSession({ ip = "127.0.0.1", userAgent = "", origin = "" } = {}) {
    const now = Date.now();
    pruneMaps(now);
    const sessionId = crypto.randomBytes(16).toString("hex");
    const keyBuf = crypto.randomBytes(32);
    const keyHex = keyBuf.toString("hex");
    const canary = mintCanary(sessionId, 0);
    const record = {
      sessionId,
      keyBuf,
      keyHex,
      lastSeq: 0,
      canary,
      uaHash: sha256Hex(userAgent || ""),
      ip: normalizeIp(ip),
      origin: String(origin || "").trim().toLowerCase(),
      exp: now + sessionTtlMs,
    };
    sessions.set(sessionId, record);
    return {
      sessionId,
      sessionKeyHex: keyHex,
      canary,
      freshnessMs,
      serverNowMs: now,
      protectedPaths: protectedPaths.filter((p) => typeof p === "string"),
      protectedRules: serializeProtectedPathsForClient(),
    };
  }

  /**
   * Computes a valid Proof-of-Freshness signature (used by legitimate browser guard & tests).
   */
  function signRequest({
    sessionKeyHex,
    method,
    pathWithQuery,
    body = "",
    seq,
    ts,
    nonce,
    canary,
  }) {
    const bodyHash = sha256Hex(Buffer.isBuffer(body) ? body : Buffer.from(String(body || ""), "utf8"));
    const canonical = `PS1|${String(method || "GET").toUpperCase()}|${pathWithQuery}|${bodyHash}|${seq}|${ts}|${nonce}|${canary}`;
    return hmacSha256Hex(Buffer.from(sessionKeyHex, "hex"), canonical);
  }

  /**
   * Evaluates an incoming HTTP request for intercepting proxy & Repeater anomalies.
   */
  function inspectRequest({
    method = "GET",
    url = "/",
    headers = {},
    body = Buffer.alloc(0),
    ip = "127.0.0.1",
    now = Date.now(),
    rawHeaderLines = null,
  }) {
    const upperMethod = String(method || "GET").toUpperCase();
    const pathWithQuery = String(url || "/");
    const pathname = normalizePathname(pathWithQuery);
    const bodyBuf = Buffer.isBuffer(body) ? body : Buffer.from(String(body || ""), "utf8");
    const reasons = [];
    let score = 0;

    inspectCounter += 1;
    if ((inspectCounter & 255) === 0 || usedNonces.size > maxNonces) {
      pruneMaps(now);
    }

    function flag(code, weight, detail) {
      score += weight;
      reasons.push({ code, weight, detail });
    }

    if (mode === "off") {
      return { ok: true, blocked: false, score: 0, threshold, mode, reasons: [], nextCanary: null };
    }

    const isProtected = isPathProtected(pathname, protectedPaths);

    // Allow CORS preflight OPTIONS without Proof-of-Freshness (browsers cannot attach custom X-PS-* on preflight)
    if (upperMethod === "OPTIONS" && hasHeader(headers, "access-control-request-method")) {
      return { ok: true, blocked: false, score: 0, threshold, mode, reasons: [], nextCanary: null };
    }

    const ua = getHeader(headers, "user-agent");
    const conn = getHeader(headers, "connection").toLowerCase();
    const te = getHeader(headers, "transfer-encoding").toLowerCase();
    const cl = getHeader(headers, "content-length");
    const secFetchSite = getHeader(headers, "sec-fetch-site").toLowerCase();
    const secFetchMode = getHeader(headers, "sec-fetch-mode").toLowerCase();
    const secChPlatform = getHeader(headers, "sec-ch-ua-platform").replace(/"/g, "").toLowerCase();
    const originHdr = getHeader(headers, "origin").trim().toLowerCase();

    // --- Signal 1: Explicit Proxy Leakage & HTTP Request Smuggling ---
    if (cl && te) {
      flag("CL_TE_SMUGGLING", 10, "Both Content-Length and Transfer-Encoding present (RFC 9112 §6.3)");
    }
    const proxyHeaders = [
      "proxy-connection",
      "x-burp-header",
      "x-burp-collaborator",
      "x-caido-id",
      "x-caido-replay",
      "x-mitmproxy",
    ];
    let hasProxyLeak = false;
    for (const ph of proxyHeaders) {
      if (hasHeader(headers, ph)) {
        hasProxyLeak = true;
        flag("PROXY_HEADER_LEAK", 5, `Proxy artifact header '${ph}' present`);
      }
    }
    if (Array.isArray(rawHeaderLines)) {
      const hostCount = rawHeaderLines.filter((l) => /^host\s*:/i.test(l)).length;
      if (hostCount > 1) {
        flag("DUPLICATE_HOST_HEADER", 8, `Duplicate Host headers (${hostCount}) detected`);
      }
    }

    // --- Signal 2: Browser UA vs. Repeater Wire/Metadata Contradictions ---
    const chromeMajor = parseBrowserMajorChrome(ua);
    const ffMajor = parseBrowserMajorFirefox(ua);
    const claimsModernBrowser = chromeMajor >= 80 || ffMajor >= 90;

    if (claimsModernBrowser) {
      // Only enforce missing Fetch Metadata on protected routes or when explicit proxy leak headers are present
      // (avoids breaking plain LAN HTTP GET / where browsers do not attach Sec-Fetch-*).
      if (!secFetchSite && !secFetchMode && (isProtected || hasProxyLeak)) {
        flag("FETCH_METADATA_MISSING", 4, "Modern browser UA missing Sec-Fetch-Site/Sec-Fetch-Mode metadata");
      }
      if (isProtected && secFetchSite.includes("cross-site")) {
        flag("CROSS_SITE_REQUEST_BLOCKED", 6, "Cross-site Fetch Metadata on protected route");
      }
      if (conn === "close" && (isProtected || hasProxyLeak)) {
        flag("REPEATER_CONNECTION_CLOSE", 3, "Modern browser UA sent HTTP/1.1 Connection: close");
      }
      if (te.includes("chunked") && bodyBuf.length > 0 && bodyBuf.length < 512) {
        flag("PROXY_CHUNKED_TINY_BODY", 2, `Chunked encoding on tiny ${bodyBuf.length}B request with browser UA`);
      }
      if (secChPlatform) {
        const uaLinux = ua.includes("Linux") && !ua.includes("Android");
        const uaWin = ua.includes("Windows NT");
        const uaMac = ua.includes("Macintosh");
        if (
          (uaLinux && (secChPlatform === "windows" || secChPlatform === "macos")) ||
          (uaWin && (secChPlatform === "linux" || secChPlatform === "macos")) ||
          (uaMac && (secChPlatform === "windows" || secChPlatform === "linux"))
        ) {
          flag("UA_PLATFORM_CONTRADICTION", 5, `UA OS contradicts Sec-CH-UA-Platform '${secChPlatform}'`);
        }
      }
    } else if (/burp|caido|mitmproxy|sqlmap|ffuf|nuclei|curl\/|python-requests|go-http-client|insomnia|postman/i.test(ua)) {
      if (isProtected) {
        flag("NON_BROWSER_REPLAY_CLIENT", 4, "Direct replay/CLI client User-Agent on protected route");
      }
    }

    // --- Signal 3: Cryptographic Single-Use Proof-of-Freshness + Rotating Canary ---
    let nextCanary = null;
    const psSid = getHeader(headers, "x-ps-session").trim();
    const psSeqRaw = getHeader(headers, "x-ps-seq").trim();
    const psTsRaw = getHeader(headers, "x-ps-ts").trim();
    const psNonce = getHeader(headers, "x-ps-nonce").trim();
    const psCanary = getHeader(headers, "x-ps-canary").trim();
    const psProof = getHeader(headers, "x-ps-proof").trim();
    const hasAnyPsHeader = Boolean(psSid || psSeqRaw || psTsRaw || psNonce || psProof || psCanary);

    if (isProtected || hasAnyPsHeader) {
      if (!psSid || !psSeqRaw || !psTsRaw || !psNonce || !psProof || !psCanary) {
        if (isProtected) {
          flag(
            "REPEATER_PROOF_MISSING",
            mode === "strict" ? 8 : 6,
            "Missing ProxySnare single-use Proof-of-Freshness headers on protected route"
          );
        }
      } else if (psNonce.length > 128 || psSid.length > 64 || psProof.length > 128) {
        flag("REPEATER_BODY_OR_PATH_TAMPERED", 10, "Malformed Proof-of-Freshness header length");
      } else {
        const sess = sessions.get(psSid);
        if (!sess || sess.exp <= now) {
          flag("REPEATER_UNKNOWN_OR_EXPIRED_SESSION", 8, "Proof references unknown or expired session");
        } else {
          const validSeqFormat = /^\d{1,15}$/.test(psSeqRaw);
          const seq = validSeqFormat ? Number(psSeqRaw) : NaN;
          const validTsFormat = /^\d{1,15}(\.\d{1,4})?$/.test(psTsRaw);
          const ts = validTsFormat ? Number(psTsRaw) : NaN;
          const nonceKey = `${psSid}:${psNonce}`;

          // 3a. Single-use nonce replay check
          const prevNonceExp = usedNonces.get(nonceKey);
          if (prevNonceExp && prevNonceExp > now) {
            flag("REPEATER_NONCE_REPLAYED", 10, `Single-use nonce '${psNonce.slice(0, 12)}...' replayed (Repeater detected)`);
          }

          // 3b. Strict monotonic safe-integer sequence check
          if (!Number.isSafeInteger(seq) || seq <= sess.lastSeq) {
            flag("REPEATER_SEQ_REPLAY", 8, `Non-monotonic sequence ${psSeqRaw} <= last ${sess.lastSeq}`);
          }

          // 3c. Asymmetric freshness / Intercept-hold delay check
          const ageMs = now - ts;
          if (!Number.isFinite(ts) || ageMs > freshnessMs || ageMs < -maxFutureSkewMs) {
            flag(
              "INTERCEPT_HOLD_OR_STALE_REPLAY",
              6,
              `Request age/skew ${Number.isFinite(ageMs) ? Math.round(ageMs) : "NaN"}ms outside [-${maxFutureSkewMs}, +${freshnessMs}]ms window`
            );
          }

          // 3d. Rotating honey-canary verification
          if (!safeEqualHex(psCanary, sess.canary)) {
            flag("REPEATER_STALE_CANARY", 8, "Stale or tampered rotating honey-canary token (Repeater replay)");
          }

          // 3e. Canonical HMAC-SHA256 verification
          const expectedProof = signRequest({
            sessionKeyHex: sess.keyHex,
            method: upperMethod,
            pathWithQuery,
            body: bodyBuf,
            seq: psSeqRaw,
            ts: psTsRaw,
            nonce: psNonce,
            canary: psCanary,
          });
          const proofValid = safeEqualHex(psProof, expectedProof);
          if (!proofValid) {
            flag("REPEATER_BODY_OR_PATH_TAMPERED", 10, "HMAC proof mismatch — request body, path, query, or method was tampered in transit/Repeater");
          }

          // 3f. Session User-Agent & Origin binding
          if (!safeEqualHex(sess.uaHash, sha256Hex(ua || ""))) {
            flag("REPEATER_UA_SESSION_MISMATCH", 6, "User-Agent changed mid-session");
          }
          if (sess.origin && originHdr && sess.origin !== originHdr) {
            flag("REPEATER_ORIGIN_MISMATCH", 6, "Origin changed mid-session");
          }

          // Only burn nonces for requests whose HMAC is authentic (prevents unauthenticated nonce-cache OOM DoS)
          if (proofValid) {
            usedNonces.set(nonceKey, now + nonceTtlMs);
          }
          if (score < threshold) {
            sess.lastSeq = seq;
            sess.canary = mintCanary(sess.sessionId, seq);
            nextCanary = sess.canary;
          }
        }
      }
    }

    // --- Signal 4: Per-IP Rapid Identical Unsigned Replay Burst ---
    if (isProtected && bodyBuf.length > 0 && !hasAnyPsHeader) {
      const sig = sha256Hex(`${upperMethod}|${pathWithQuery}|${sha256Hex(bodyBuf)}`);
      const arr = (ipBursts.get(ip) || []).filter((e) => now - e.ts <= 5_000);
      const sameCount = arr.filter((e) => e.sig === sig).length;
      arr.push({ ts: now, sig });
      ipBursts.set(ip, arr.slice(-30));
      if (sameCount >= 3) {
        flag("REPEATER_BURST_REPLAY", 5, `Identical unsigned payload replayed ${sameCount + 1}x in 5s`);
      }
    }

    const blocked = mode !== "monitor" && score >= threshold;
    const result = {
      ok: !blocked,
      blocked,
      score,
      threshold,
      mode,
      reasons,
      nextCanary,
    };
    if ((blocked || score > 0) && onDetect) {
      try {
        onDetect({ ...result, ip, method: upperMethod, path: pathname, sessionId: psSid || null });
      } catch {
        // never crash request pipeline on user telemetry hook
      }
    }
    return result;
  }

  return {
    mode,
    threshold,
    freshnessMs,
    protectedPaths,
    trustedProxies,
    isPathProtected: (p) => isPathProtected(p, protectedPaths),
    allowHandshake,
    issueSession,
    signRequest,
    inspectRequest,
    serializeProtectedPathsForClient,
    extractClientIp: (req) => extractClientIp(req, trustedProxies),
  };
}

module.exports = {
  createProxySnareEngine,
  normalizeMode,
  normalizePathname,
  sha256Hex,
  hmacSha256Hex,
};
