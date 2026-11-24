"use strict";

const crypto = require("node:crypto");

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

function normalizeProtectedPaths(paths) {
  if (!paths || paths.length === 0) return ["/api"];
  return paths.map((p) => (p instanceof RegExp ? p : String(p)));
}

function isPathProtected(pathname, protectedPaths) {
  for (const rule of protectedPaths) {
    if (rule instanceof RegExp) {
      if (rule.test(pathname)) return true;
    } else if (rule === "*" || rule === "/" || pathname === rule || pathname.startsWith(rule.endsWith("/") ? rule : `${rule}/`) || pathname.startsWith(`${rule}?`)) {
      return true;
    }
  }
  return false;
}

function extractClientIp(req, trustedProxies) {
  const remote = String(req?.socket?.remoteAddress || req?.ip || "127.0.0.1").replace(/^::ffff:/, "");
  if (trustedProxies.size > 0 && trustedProxies.has(remote)) {
    const xff = getHeader(req.headers, "x-forwarded-for");
    if (xff) {
      const first = xff.split(",")[0].trim();
      if (first) return first;
    }
  }
  return remote;
}

function parseBrowserMajorChrome(ua) {
  const m = /Chrome\/(\d+)/i.exec(ua || "");
  return m ? Number(m[1]) : 0;
}

function parseBrowserMajorFirefox(ua) {
  const m = /Firefox\/(\d+)/i.exec(ua || "");
  return m ? Number(m[1]) : 0;
}

/**
 * Core ProxySnare detection engine.
 * Detects and blocks Caido Repeater, Burp Suite Repeater, mitmproxy, and raw HTTP replay/tampering.
 */
function createProxySnareEngine(options = {}) {
  const mode = normalizeMode(options.mode ?? "strict");
  const secret = Buffer.isBuffer(options.secret)
    ? Buffer.from(options.secret)
    : typeof options.secret === "string" && options.secret.length >= 16
      ? Buffer.from(options.secret, "utf8")
      : crypto.randomBytes(32);

  const threshold = Number.isFinite(options.threshold)
    ? options.threshold
    : mode === "strict"
      ? 4
      : 6;
  const freshnessMs = Number.isFinite(options.freshnessMs)
    ? options.freshnessMs
    : mode === "strict"
      ? 8_000
      : 15_000;
  const nonceTtlMs = Number.isFinite(options.nonceTtlMs) ? options.nonceTtlMs : 300_000;
  const sessionTtlMs = Number.isFinite(options.sessionTtlMs) ? options.sessionTtlMs : 1_800_000;
  const maxSessions = Number.isFinite(options.maxSessions) ? options.maxSessions : 20_000;
  const maxNonces = Number.isFinite(options.maxNonces) ? options.maxNonces : 50_000;
  const protectedPaths = normalizeProtectedPaths(options.protectedPaths);
  const trustedProxies = new Set(
    Array.isArray(options.trustProxy)
      ? options.trustProxy.map((s) => String(s).trim()).filter(Boolean)
      : typeof options.trustProxy === "string"
        ? options.trustProxy.split(",").map((s) => s.trim()).filter(Boolean)
        : []
  );
  const onDetect = typeof options.onDetect === "function" ? options.onDetect : null;

  // Bounded session store: sessionId -> { keyHex, keyBuf, lastSeq, canary, prevCanary, uaHash, ip, origin, exp }
  const sessions = new Map();
  // Bounded nonce replay cache: nonceKey -> expiryMs
  const usedNonces = new Map();
  // Per-IP short-window burst tracker: ip -> [{ ts, sig }]
  const ipBursts = new Map();

  function pruneMaps(now) {
    if (sessions.size > maxSessions) {
      for (const [k, v] of sessions) {
        if (v.exp <= now || sessions.size > maxSessions) sessions.delete(k);
        if (sessions.size <= maxSessions * 0.85) break;
      }
    }
    if (usedNonces.size > maxNonces) {
      for (const [k, exp] of usedNonces) {
        if (exp <= now || usedNonces.size > maxNonces) usedNonces.delete(k);
        if (usedNonces.size <= maxNonces * 0.85) break;
      }
    }
    if (ipBursts.size > 10_000) {
      ipBursts.clear();
    }
  }

  function mintCanary(sessionId, step) {
    return hmacSha256Hex(secret, `PS_CANARY|${sessionId}|${step}|${crypto.randomBytes(8).toString("hex")}`).slice(0, 24);
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
      ip,
      origin: origin || "",
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
    const pathname = String(url || "/").split("?")[0] || "/";
    const pathWithQuery = String(url || "/");
    const bodyBuf = Buffer.isBuffer(body) ? body : Buffer.from(String(body || ""), "utf8");
    const reasons = [];
    let score = 0;

    function flag(code, weight, detail) {
      score += weight;
      reasons.push({ code, weight, detail });
    }

    if (mode === "off") {
      return { ok: true, blocked: false, score: 0, threshold, mode, reasons: [], nextCanary: null };
    }

    const ua = getHeader(headers, "user-agent");
    const conn = getHeader(headers, "connection").toLowerCase();
    const te = getHeader(headers, "transfer-encoding").toLowerCase();
    const cl = getHeader(headers, "content-length");
    const secFetchSite = getHeader(headers, "sec-fetch-site");
    const secFetchMode = getHeader(headers, "sec-fetch-mode");
    const secChPlatform = getHeader(headers, "sec-ch-ua-platform").replace(/"/g, "").toLowerCase();

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
    for (const ph of proxyHeaders) {
      if (hasHeader(headers, ph)) {
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
      // Real Chrome >= 80 & Firefox >= 90 always attach Sec-Fetch-Site/Mode on same-origin & cross-site fetches
      if (!secFetchSite && !secFetchMode) {
        flag("FETCH_METADATA_MISSING", 4, "Modern browser UA missing Sec-Fetch-Site/Sec-Fetch-Mode metadata");
      }
      // Caido/Burp Repeater frequently forces Connection: close on HTTP/1.1 replays
      if (conn === "close") {
        flag("REPEATER_CONNECTION_CLOSE", 3, "Modern browser UA sent HTTP/1.1 Connection: close");
      }
      // Tiny chunked JSON POSTs from browser UAs indicate proxy/repeater re-framing
      if (te.includes("chunked") && bodyBuf.length > 0 && bodyBuf.length < 512) {
        flag("PROXY_CHUNKED_TINY_BODY", 2, `Chunked encoding on tiny ${bodyBuf.length}B request with browser UA`);
      }
      // OS platform contradiction between UA and Client Hints
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
      if (isPathProtected(pathname, protectedPaths)) {
        flag("NON_BROWSER_REPLAY_CLIENT", 4, `Direct replay/CLI client User-Agent on protected route`);
      }
    }

    // --- Signal 3: Cryptographic Single-Use Proof-of-Freshness + Rotating Canary ---
    let nextCanary = null;
    const isProtected = isPathProtected(pathname, protectedPaths);
    const psSid = getHeader(headers, "x-ps-session");
    const psSeqRaw = getHeader(headers, "x-ps-seq");
    const psTsRaw = getHeader(headers, "x-ps-ts");
    const psNonce = getHeader(headers, "x-ps-nonce");
    const psCanary = getHeader(headers, "x-ps-canary");
    const psProof = getHeader(headers, "x-ps-proof");
    const hasAnyPsHeader = Boolean(psSid || psSeqRaw || psTsRaw || psNonce || psProof || psCanary);

    if (isProtected || hasAnyPsHeader) {
      if (!psSid || !psSeqRaw || !psTsRaw || !psNonce || !psProof || !psCanary) {
        if (isProtected) {
          flag(
            "REPEATER_PROOF_MISSING",
            mode === "strict" ? 8 : 5,
            "Missing ProxySnare single-use Proof-of-Freshness headers on protected route"
          );
        }
      } else {
        const sess = sessions.get(psSid);
        if (!sess || sess.exp <= now) {
          flag("REPEATER_UNKNOWN_OR_EXPIRED_SESSION", 8, "Proof references unknown or expired session");
        } else {
          const seq = Number(psSeqRaw);
          const ts = Number(psTsRaw);
          const nonceKey = `${psSid}:${psNonce}`;

          // 3a. Single-use nonce replay check (kills Caido/Burp Repeater "Send" replay immediately!)
          const prevNonceExp = usedNonces.get(nonceKey);
          if (prevNonceExp && prevNonceExp > now) {
            flag("REPEATER_NONCE_REPLAYED", 10, `Single-use nonce '${psNonce.slice(0, 12)}...' replayed (Repeater detected)`);
          }

          // 3b. Monotonic sequence number check
          if (!Number.isInteger(seq) || seq <= sess.lastSeq) {
            flag("REPEATER_SEQ_REPLAY", 8, `Non-monotonic sequence ${psSeqRaw} <= last ${sess.lastSeq}`);
          }

          // 3c. Freshness / Intercept-hold delay check
          const driftMs = Math.abs(now - ts);
          if (!Number.isFinite(ts) || driftMs > freshnessMs) {
            flag(
              "INTERCEPT_HOLD_OR_STALE_REPLAY",
              6,
              `Request age/drift ${Number.isFinite(driftMs) ? Math.round(driftMs) : "NaN"}ms exceeds ${freshnessMs}ms freshness window`
            );
          }

          // 3d. Rotating honey-canary verification
          if (!safeEqualHex(psCanary, sess.canary)) {
            flag("REPEATER_STALE_CANARY", 8, "Stale or tampered rotating honey-canary token (Repeater replay)");
          }

          // 3e. Canonical HMAC-SHA256 verification over method + path + query + SHA256(body) + seq + ts + nonce + canary
          const expectedProof = signRequest({
            sessionKeyHex: sess.keyHex,
            method,
            pathWithQuery,
            body: bodyBuf,
            seq: psSeqRaw,
            ts: psTsRaw,
            nonce: psNonce,
            canary: psCanary,
          });
          if (!safeEqualHex(psProof, expectedProof)) {
            flag("REPEATER_BODY_OR_PATH_TAMPERED", 10, "HMAC proof mismatch — request body, path, query, or method was tampered in transit/Repeater");
          }

          // 3f. Session User-Agent binding (catches copying session headers into a different tool)
          if (sess.uaHash !== sha256Hex(ua || "")) {
            flag("REPEATER_UA_SESSION_MISMATCH", 6, "User-Agent changed mid-session");
          }

          // Always burn the nonce if valid session, and advance sequence + rotate canary when request is clean
          usedNonces.set(nonceKey, now + nonceTtlMs);
          if (score < threshold) {
            sess.lastSeq = seq;
            sess.canary = mintCanary(sess.sessionId, seq);
            nextCanary = sess.canary;
          }
        }
      }
    }

    // --- Signal 4: Per-IP Rapid Identical Replay Burst ---
    if (isProtected && bodyBuf.length > 0) {
      const sig = sha256Hex(`${method}|${pathWithQuery}|${sha256Hex(bodyBuf)}`);
      const arr = (ipBursts.get(ip) || []).filter((e) => now - e.ts <= 5_000);
      const sameCount = arr.filter((e) => e.sig === sig).length;
      arr.push({ ts: now, sig });
      ipBursts.set(ip, arr.slice(-30));
      if (sameCount >= 3 && !hasAnyPsHeader) {
        flag("REPEATER_BURST_REPLAY", 5, `Identical unauthenticated payload replayed ${sameCount + 1}x in 5s`);
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
        onDetect({ ...result, ip, method, path: pathname, sessionId: psSid || null });
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
    issueSession,
    signRequest,
    inspectRequest,
    extractClientIp: (req) => extractClientIp(req, trustedProxies),
  };
}

module.exports = {
  createProxySnareEngine,
  normalizeMode,
  sha256Hex,
  hmacSha256Hex,
};
