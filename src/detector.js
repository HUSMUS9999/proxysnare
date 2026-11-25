"use strict";

const crypto = require("node:crypto");
const path = require("node:path");

const VALID_MODES = new Set(["off", "monitor", "observe", "balanced", "strict"]);

const CLI_OR_PROXY_UA_RE =
  /burp|caido|mitmproxy|sqlmap|ffuf|nuclei|curl\/|wget\/|python-requests|python-urllib|python-httpx|aiohttp|go-http-client|httpie|libwww-perl|java\/|okhttp|axios\/|node-fetch|undici|insomnia|postman|headlesschrome|playwright|puppeteer|phantomjs|slimerjs/i;

const PROXY_LEAK_HEADERS = [
  "proxy-connection",
  "x-burp-header",
  "x-burp-collaborator",
  "x-caido-id",
  "x-caido-replay",
  "x-mitmproxy",
];

function normalizeMode(mode = "strict") {
  const raw = String(mode || "strict").trim().toLowerCase();
  if (!VALID_MODES.has(raw)) {
    throw new Error(`Invalid ProxySnare mode '${mode}': expected 'off', 'monitor', 'observe', 'balanced', or 'strict'`);
  }
  return raw === "observe" ? "monitor" : raw;
}

function sha256Buf(input) {
  return crypto.createHash("sha256").update(input || "").digest();
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

function countLeadingZeroBits(buf) {
  let bits = 0;
  for (let i = 0; i < buf.length; i++) {
    const byte = buf[i];
    if (byte === 0) {
      bits += 8;
      continue;
    }
    bits += Math.clz32(byte) - 24;
    break;
  }
  return bits;
}

function verifyPowSolution(prefix, challenge, powNonce, difficulty) {
  if (!Number.isInteger(difficulty) || difficulty <= 0) return true;
  if (typeof challenge !== "string" || !challenge || typeof powNonce !== "string") return false;
  if (!/^[A-Za-z0-9_-]{1,64}$/.test(powNonce)) return false;
  const digest = sha256Buf(`${prefix}|${challenge}|${powNonce}`);
  return countLeadingZeroBits(digest) >= difficulty;
}

function solvePowChallenge(prefix, challenge, difficulty) {
  if (!Number.isInteger(difficulty) || difficulty <= 0) return "0";
  for (let i = 0; i < 10_000_000; i++) {
    const nonce = i.toString(36);
    if (countLeadingZeroBits(sha256Buf(`${prefix}|${challenge}|${nonce}`)) >= difficulty) {
      return nonce;
    }
  }
  throw new Error("POW_SOLVE_EXCEEDED_LIMIT");
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

function isCliOrProxyUa(ua, secChUa = "") {
  const s = String(ua || "").trim();
  if (!s) return true;
  if (CLI_OR_PROXY_UA_RE.test(s)) return true;
  if (/HeadlessChrome/i.test(String(secChUa || ""))) return true;
  return false;
}

/**
 * Normalizes an HTTP request-target pathname to defeat case, percent-encoding,
 * absolute-form URI, double-slash, dot-segment, backslash, null-byte, and matrix-param bypasses.
 */
function decodePercentLenient(s) {
  return s.replace(/(?:%[0-9a-fA-F]{2})+/g, (run) => {
    let out = "";
    let i = 0;
    while (i < run.length) {
      const b = parseInt(run.slice(i + 1, i + 3), 16);
      if (b === 0x00) {
        out += "\0";
        i += 3;
        continue;
      }
      if (b >= 0x01 && b <= 0x7f) {
        out += String.fromCharCode(b);
        i += 3;
        continue;
      }
      let matched = false;
      for (const n of [2, 3, 4]) {
        if (i + n * 3 <= run.length) {
          const sub = run.slice(i, i + n * 3);
          try {
            out += decodeURIComponent(sub);
            i += n * 3;
            matched = true;
            break;
          } catch {}
        }
      }
      if (!matched) {
        out += run.slice(i, i + 3);
        i += 3;
      }
    }
    return out;
  });
}

function stripSchemeAndAuthority(rawUrl) {
  let s = String(rawUrl || "/").trimStart();
  if (!s) return "/";
  if (/^https?:\/\//i.test(s)) {
    const afterScheme = s.indexOf("://") + 3;
    const slashIdx = s.indexOf("/", afterScheme);
    const backslashIdx = s.indexOf("\\", afterScheme);
    const qIdx = s.indexOf("?", afterScheme);
    const hIdx = s.indexOf("#", afterScheme);
    const cuts = [slashIdx, backslashIdx, qIdx, hIdx].filter((i) => i >= 0);
    if (cuts.length === 0) return "/";
    const first = Math.min(...cuts);
    if (s[first] === "/") s = s.slice(first);
    else if (s[first] === "\\") s = "/" + s.slice(first + 1);
    else s = "/" + s.slice(first);
  }
  return s;
}

function cleanPathNoCollapse(rawPath) {
  let s = String(rawPath || "/").replace(/\\/g, "/").replace(/\0.*$/, "");
  if (!s.startsWith("/")) s = "/" + s;
  s = s
    .split("/")
    .map((seg) => seg.split(";")[0])
    .join("/")
    .replace(/\/+/g, "/");
  if (s.length > 1) s = s.replace(/\/+$/, "");
  return s || "/";
}

function trimSegmentNoise(normPath) {
  let s = String(normPath || "/")
    .split("/")
    .map((seg) => seg.replace(/[\s.]+$/, ""))
    .join("/")
    .replace(/\/+/g, "/");
  if (!s.startsWith("/")) s = "/" + s;
  if (s.length > 1) s = s.replace(/\/+$/, "");
  return s || "/";
}

function normalizePathname(rawUrl) {
  let s = stripSchemeAndAuthority(rawUrl);
  const qIdx = s.indexOf("?");
  if (qIdx >= 0) s = s.slice(0, qIdx);
  if (!s) return "/";

  for (let pass = 0; pass < 2; pass++) {
    const decoded = decodePercentLenient(s);
    if (decoded === s) break;
    s = decoded;
  }

  s = s.replace(/\0/g, "").replace(/\\/g, "/");
  if (!s.startsWith("/")) s = "/" + s;
  s = s
    .split("/")
    .map((seg) => seg.split(";")[0])
    .join("/");
  s = path.posix.normalize(s);
  if (!s.startsWith("/")) s = "/" + s;
  if (s.length > 1) s = s.replace(/\/+$/, "");
  s = s.replace(/\?/g, "%3F");
  return s;
}

function expandPathCandidates(rawUrl) {
  const raw = stripSchemeAndAuthority(rawUrl);
  const qIdx = raw.indexOf("?");
  const rawPath = qIdx >= 0 ? raw.slice(0, qIdx) : raw;
  const set = new Set();

  const addAll = (val) => {
    const n1 = normalizePathname(val);
    const n2 = cleanPathNoCollapse(val);
    set.add(n1);
    set.add(n2);
    set.add(trimSegmentNoise(n1));
    set.add(trimSegmentNoise(n2));
  };

  addAll(rawPath);

  const rawHash = rawPath.indexOf("#");
  if (rawHash >= 0) {
    addAll(rawPath.slice(0, rawHash));
  }

  let dec = rawPath;
  for (let pass = 0; pass < 2; pass++) {
    const next = decodePercentLenient(dec);
    if (next === dec) break;
    dec = next;
  }
  addAll(dec);

  const nullIdx = dec.indexOf("\0");
  if (nullIdx >= 0) addAll(dec.slice(0, nullIdx));

  const decQ = dec.indexOf("?");
  if (decQ >= 0) addAll(dec.slice(0, decQ));
  const decH = dec.indexOf("#");
  if (decH >= 0) addAll(dec.slice(0, decH));

  return Array.from(set);
}

function normalizeProtectedPaths(paths) {
  if (!paths || paths.length === 0) return ["/api"];
  return paths.map((p) => {
    if (p instanceof RegExp) return p;
    const raw = String(p).trim();
    if (raw === "*") return "*";
    return normalizePathname(raw);
  });
}

function isPathProtected(rawUrl, protectedPaths) {
  const candidates = expandPathCandidates(rawUrl);
  for (const norm of candidates) {
    const normLower = norm.toLowerCase();
    for (const rule of protectedPaths) {
      if (rule instanceof RegExp) {
        rule.lastIndex = 0;
        if (rule.test(norm)) return true;
      } else {
        const rLower = String(rule).trim().toLowerCase();
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
  }
  return false;
}

function normalizeIp(ip) {
  const s = String(ip || "").trim().toLowerCase().replace(/^::ffff:/, "");
  return s === "::1" ? "127.0.0.1" : s;
}

function parseIpv4Int(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let n = 0;
  for (const p of parts) {
    if (!/^\d{1,3}$/.test(p)) return null;
    const v = Number(p);
    if (v < 0 || v > 255) return null;
    n = (n << 8) | v;
  }
  return n >>> 0;
}

function parseIpv6BigInt(ip) {
  let s = String(ip || "").trim().toLowerCase();
  if (!s.includes(":")) return null;
  const lastColon = s.lastIndexOf(":");
  if (lastColon >= 0 && s.slice(lastColon + 1).includes(".")) {
    const v4 = parseIpv4Int(s.slice(lastColon + 1));
    if (v4 === null) return null;
    const hi = ((v4 >>> 16) & 0xffff).toString(16);
    const lo = (v4 & 0xffff).toString(16);
    s = `${s.slice(0, lastColon + 1)}${hi}:${lo}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(":") : [];
  const right = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - (left.length + right.length);
  if (halves.length === 1 && missing !== 0) return null;
  if (halves.length === 2 && missing < 0) return null;
  const groups = [...left, ...Array(Math.max(0, missing)).fill("0"), ...right];
  if (groups.length !== 8) return null;
  let acc = 0n;
  for (const g of groups) {
    if (!/^[0-9a-f]{1,4}$/i.test(g)) return null;
    acc = (acc << 16n) | BigInt(parseInt(g, 16));
  }
  return acc;
}

function compileTrustedProxies(spec) {
  const rawList = Array.isArray(spec)
    ? spec
    : typeof spec === "string"
      ? spec.split(",")
      : [];
  const exact = new Set();
  const cidrsV4 = [];
  const cidrsV6 = [];
  for (const item of rawList) {
    const entry = String(item || "").trim().toLowerCase();
    if (!entry) continue;
    const slash = entry.indexOf("/");
    if (slash > 0) {
      const baseRaw = entry.slice(0, slash);
      const bitsStr = entry.slice(slash + 1);
      if (!/^\d{1,3}$/.test(bitsStr)) continue;
      const bits = Number(bitsStr);
      const baseV6 = parseIpv6BigInt(baseRaw);
      if (baseV6 !== null && bits >= 0 && bits <= 128) {
        const mask = bits === 0 ? 0n : (((1n << BigInt(bits)) - 1n) << BigInt(128 - bits));
        cidrsV6.push({ net: baseV6 & mask, mask });
        continue;
      }
      const baseInt = parseIpv4Int(baseRaw);
      if (baseInt !== null && bits >= 0 && bits <= 32) {
        const mask = bits === 0 ? 0 : (~0 << (32 - bits)) >>> 0;
        cidrsV4.push({ net: (baseInt & mask) >>> 0, mask });
        continue;
      }
      continue;
    }
    const rawV6 = parseIpv6BigInt(entry);
    if (rawV6 !== null) exact.add(`v6:${rawV6.toString(16)}`);
    exact.add(normalizeIp(entry));
  }
  return {
    size: exact.size + cidrsV4.length + cidrsV6.length,
    has(ip) {
      const raw = String(ip || "").trim().toLowerCase();
      const norm = normalizeIp(raw);
      if (exact.has(norm)) return true;
      const rawV6 = parseIpv6BigInt(raw);
      if (rawV6 !== null) {
        if (exact.has(`v6:${rawV6.toString(16)}`)) return true;
        for (const c of cidrsV6) {
          if ((rawV6 & c.mask) === c.net) return true;
        }
      }
      const v4 = parseIpv4Int(norm);
      if (v4 !== null) {
        for (const c of cidrsV4) {
          if (((v4 & c.mask) >>> 0) === c.net) return true;
        }
        if (cidrsV6.length > 0) {
          const mappedV6 = (0xffffn << 32n) | BigInt(v4);
          for (const c of cidrsV6) {
            if ((mappedV6 & c.mask) === c.net) return true;
          }
        }
      }
      return false;
    },
  };
}

function extractClientIp(req, trustedProxies) {
  const remoteRaw = String(req?.socket?.remoteAddress || req?.ip || "").trim();
  if (remoteRaw && trustedProxies.size > 0 && trustedProxies.has(remoteRaw)) {
    const xff = getHeader(req.headers, "x-forwarded-for");
    if (xff) {
      const rawParts = xff.split(",").map((s) => s.trim()).filter(Boolean);
      for (let i = rawParts.length - 1; i >= 0; i--) {
        if (!trustedProxies.has(rawParts[i])) {
          return normalizeIp(rawParts[i]);
        }
      }
      if (rawParts.length > 0) return normalizeIp(rawParts[0]);
    }
  }
  return normalizeIp(remoteRaw) || "unknown";
}

function normalizeHostDefaultPort(hostRaw, protocol = "") {
  const h = String(hostRaw || "").trim().toLowerCase();
  if (!h) return "";
  if (protocol === "http:" && h.endsWith(":80")) return h.slice(0, -3);
  if (protocol === "https:" && h.endsWith(":443")) return h.slice(0, -4);
  if (!protocol) {
    if (h.endsWith(":80")) return h.slice(0, -3);
    if (h.endsWith(":443")) return h.slice(0, -4);
  }
  return h;
}

function parseHttpOriginHost(originRaw) {
  const s = String(originRaw || "").trim();
  if (!s) return "";
  try {
    const u = new URL(s);
    if ((u.protocol !== "http:" && u.protocol !== "https:") || u.username || u.password) return "";
    return normalizeHostDefaultPort(u.host, u.protocol);
  } catch {
    return "";
  }
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

function nonNegativeInt(val, fallback, name, maxVal = 24) {
  if (val === undefined || val === null) return fallback;
  if (!Number.isInteger(val) || val < 0 || val > maxVal) {
    throw new Error(`Invalid ProxySnare option '${name}': expected an integer in 0..${maxVal}`);
  }
  return val;
}

/**
 * Core ProxySnare detection engine (v2: PS_ECDH_V2 ephemeral P-256 ECDH + HKDF-SHA256,
 * single-use boot tokens + SHA-256 PoW, Proof-of-Freshness HMAC-SHA256 + rotating canary).
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
  const bootTokenTtlMs = positiveFinite(options.bootTokenTtlMs, 120_000, "bootTokenTtlMs");
  const maxSessions = positiveFinite(options.maxSessions, 20_000, "maxSessions");
  const maxNonces = positiveFinite(options.maxNonces, 50_000, "maxNonces");
  const maxBootTokens = positiveFinite(options.maxBootTokens, 30_000, "maxBootTokens");
  const maxHandshakesPerMin = positiveFinite(options.maxHandshakesPerMin, 120, "maxHandshakesPerMin");
  const handshakePowBits = nonNegativeInt(
    options.handshakePowBits,
    mode === "strict" ? 12 : mode === "balanced" ? 10 : 0,
    "handshakePowBits",
    22
  );
  const requireBootToken = options.requireBootToken !== false;
  const bindIp = options.bindIp !== false;
  const protectedPaths = normalizeProtectedPaths(options.protectedPaths);
  const trustedProxies = compileTrustedProxies(options.trustProxy);
  const onDetect = typeof options.onDetect === "function" ? options.onDetect : null;

  const sessions = new Map();
  const usedNonces = new Map();
  const bootTokens = new Map();
  const ipBursts = new Map();
  const handshakeRates = new Map();
  let inspectCounter = 0;

  function pruneMaps(now) {
    if (sessions.size > maxSessions) {
      for (const [k, v] of sessions) {
        if (v.exp <= now) sessions.delete(k);
      }
    }
    if (bootTokens.size > maxBootTokens) {
      for (const [k, v] of bootTokens) {
        if (v.exp <= now) bootTokens.delete(k);
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
    if (ipBursts.size > 10_000) {
      for (const [k, arr] of ipBursts) {
        const fresh = arr.filter((e) => now - e.ts <= 5_000);
        if (fresh.length === 0) ipBursts.delete(k);
      }
      if (ipBursts.size > 10_000) {
        const drop = ipBursts.size - 8_500;
        let i = 0;
        for (const k of ipBursts.keys()) {
          ipBursts.delete(k);
          if (++i >= drop) break;
        }
      }
    }
    if (handshakeRates.size > 10_000) {
      for (const [k, arr] of handshakeRates) {
        const fresh = arr.filter((t) => now - t < 60_000);
        if (fresh.length === 0) handshakeRates.delete(k);
      }
      if (handshakeRates.size > 10_000) {
        const drop = handshakeRates.size - 8_500;
        let i = 0;
        for (const k of handshakeRates.keys()) {
          handshakeRates.delete(k);
          if (++i >= drop) break;
        }
      }
    }
  }

  function allowHandshake(ip, now = Date.now()) {
    if (handshakeRates.size >= 10_000) {
      pruneMaps(now);
    }
    const key = ip || "unknown";
    const arr = (handshakeRates.get(key) || []).filter((t) => now - t < 60_000);
    handshakeRates.delete(key);
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

  /**
   * Issues a single-use, (ip, uaHash)-bound boot token + SHA-256 PoW challenge
   * stamped into `/__proxysnare/guard.js` or served at `/__proxysnare/boot`.
   */
  function issueBootChallenge({ ip = "127.0.0.1", userAgent = "" } = {}) {
    const now = Date.now();
    if (bootTokens.size >= maxBootTokens) {
      for (const [k, v] of bootTokens) {
        if (v.exp <= now) bootTokens.delete(k);
      }
      if (bootTokens.size >= maxBootTokens) {
        return null;
      }
    }
    const tokenId = crypto.randomBytes(16).toString("hex");
    const challenge = crypto.randomBytes(16).toString("hex");
    const normIp = normalizeIp(ip);
    const uaHash = sha256Hex(userAgent || "");
    const exp = now + bootTokenTtlMs;
    const mac = hmacSha256Hex(
      secret,
      `PS_BOOT_V2|${tokenId}|${normIp}|${uaHash}|${challenge}|${handshakePowBits}|${exp}`
    ).slice(0, 32);
    const bootToken = `${tokenId}.${mac}`;
    bootTokens.set(tokenId, {
      ip: normIp,
      uaHash,
      challenge,
      difficulty: handshakePowBits,
      exp,
      mac,
    });
    return {
      bootToken,
      challenge,
      difficulty: handshakePowBits,
      exp,
    };
  }

  function consumeBootChallenge({ bootToken = "", powNonce = "", ip = "127.0.0.1", userAgent = "" } = {}) {
    const now = Date.now();
    const raw = String(bootToken || "").trim();
    const dot = raw.indexOf(".");
    if (dot <= 0) return { ok: false, error: "BOOT_TOKEN_INVALID" };
    const tokenId = raw.slice(0, dot);
    const mac = raw.slice(dot + 1);
    if (!/^[a-f0-9]{32}$/i.test(tokenId) || !/^[a-f0-9]{32}$/i.test(mac)) {
      return { ok: false, error: "BOOT_TOKEN_INVALID" };
    }
    const rec = bootTokens.get(tokenId);
    if (!rec) return { ok: false, error: "BOOT_TOKEN_REPLAYED_OR_INVALID" };
    bootTokens.delete(tokenId);
    if (rec.exp <= now) return { ok: false, error: "BOOT_TOKEN_EXPIRED" };
    if (!safeEqualHex(mac.toLowerCase(), rec.mac.toLowerCase())) {
      return { ok: false, error: "BOOT_TOKEN_INVALID" };
    }
    if (bindIp && rec.ip !== normalizeIp(ip)) {
      return { ok: false, error: "BOOT_TOKEN_IP_MISMATCH" };
    }
    if (!safeEqualHex(rec.uaHash, sha256Hex(userAgent || ""))) {
      return { ok: false, error: "BOOT_TOKEN_UA_MISMATCH" };
    }
    if (!verifyPowSolution("PS_POW_V2", rec.challenge, String(powNonce || ""), rec.difficulty)) {
      return { ok: false, error: "HANDSHAKE_POW_INVALID" };
    }
    return { ok: true };
  }

  /**
   * Issues a session.
   * - When `clientPubB64` (uncompressed 65-byte P-256 public key) is supplied, performs
   *   ephemeral ECDH P-256 + HKDF-SHA256 (`PS_ECDH_V2`) and NEVER returns `sessionKeyHex`!
   * - When `clientPubB64` is omitted (direct in-process library/unit test call), generates
   *   a random 32-byte key and returns `sessionKeyHex` in-process.
   */
  function issueSession({ ip = "127.0.0.1", userAgent = "", origin = "", clientPubB64 = null } = {}) {
    const now = Date.now();
    pruneMaps(now);
    if (sessions.size >= maxSessions) {
      for (const [k, v] of sessions) {
        if (v.exp <= now) sessions.delete(k);
      }
      if (sessions.size >= maxSessions) {
        return null;
      }
    }

    const sessionId = crypto.randomBytes(16).toString("hex");
    const canary = mintCanary(sessionId, 0);
    let keyBuf;
    let ecdhMeta = null;

    if (clientPubB64 !== null && clientPubB64 !== undefined) {
      if (typeof clientPubB64 !== "string" || !/^[A-Za-z0-9+/=_-]{80,120}$/.test(clientPubB64.trim())) {
        return { error: "INVALID_CLIENT_ECDH_KEY" };
      }
      const normB64 = clientPubB64.trim().replace(/-/g, "+").replace(/_/g, "/");
      let clientPubBuf;
      try {
        clientPubBuf = Buffer.from(normB64, "base64");
      } catch {
        return { error: "INVALID_CLIENT_ECDH_KEY" };
      }
      if (clientPubBuf.length !== 65 || clientPubBuf[0] !== 0x04) {
        return { error: "INVALID_CLIENT_ECDH_KEY" };
      }
      const canonicalClientB64 = clientPubBuf.toString("base64");
      const ecdh = crypto.createECDH("prime256v1");
      ecdh.generateKeys();
      let sharedSecret;
      try {
        sharedSecret = ecdh.computeSecret(clientPubBuf);
      } catch {
        return { error: "INVALID_CLIENT_ECDH_KEY" };
      }
      const serverPubBuf = ecdh.getPublicKey();
      const serverPubB64 = serverPubBuf.toString("base64");
      const salt = crypto.randomBytes(16);
      const saltB64 = salt.toString("base64");
      const info = Buffer.from(`PS_ECDH_V2|${sessionId}|${canonicalClientB64}|${serverPubB64}`, "utf8");
      keyBuf = Buffer.from(crypto.hkdfSync("sha256", sharedSecret, salt, info, 32));
      sharedSecret.fill(0);
      ecdhMeta = { serverPubB64, saltB64 };
    } else {
      keyBuf = crypto.randomBytes(32);
    }

    const keyHex = keyBuf.toString("hex");
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

    const baseResponse = {
      sessionId,
      canary,
      freshnessMs,
      serverNowMs: now,
      protectedPaths: protectedPaths.filter((p) => typeof p === "string"),
      protectedRules: serializeProtectedPathsForClient(),
    };

    if (ecdhMeta) {
      return {
        protocol: "PS_ECDH_V2",
        ...baseResponse,
        serverPubB64: ecdhMeta.serverPubB64,
        saltB64: ecdhMeta.saltB64,
      };
    }

    return {
      protocol: "PS_LOCAL_V1",
      ...baseResponse,
      sessionKeyHex: keyHex,
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
   * Evaluates an incoming HTTP request for intercepting proxy, CLI/curl & Repeater anomalies.
   */
  function inspectRequest({
    method = "GET",
    url = "/",
    headers = {},
    body = Buffer.alloc(0),
    ip = "127.0.0.1",
    now = Date.now(),
    rawHeaderLines = null,
    fromTrustedProxy = false,
  }) {
    const upperMethod = String(method || "GET").toUpperCase();
    const pathWithQuery = String(url || "/");
    const pathname = normalizePathname(pathWithQuery);
    const bodyBuf = Buffer.isBuffer(body) ? body : Buffer.from(String(body || ""), "utf8");
    const normIp = normalizeIp(ip);
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
      return {
        ok: true,
        blocked: false,
        score: 0,
        threshold,
        mode,
        reasons: [],
        nextCanary: null,
        rehandshakeRecommended: false,
      };
    }

    const overrideUrls = [];
    if (headers && typeof headers === "object") {
      for (const [k, v] of Object.entries(headers)) {
        const kl = k.toLowerCase();
        if (kl === "x-original-url" || kl === "x-rewrite-url") {
          for (const item of Array.isArray(v) ? v : [v]) {
            if (typeof item === "string" && item.trim() !== "") overrideUrls.push(item);
          }
        }
      }
    }
    const overrideTargetsProtected = overrideUrls.some((u) => isPathProtected(u, protectedPaths));
    const isProtected = isPathProtected(pathWithQuery, protectedPaths) || overrideTargetsProtected;

    const methodOverride =
      getHeader(headers, "x-http-method-override") ||
      getHeader(headers, "x-method-override") ||
      getHeader(headers, "x-http-method");

    const ua = getHeader(headers, "user-agent");
    const secChUa = getHeader(headers, "sec-ch-ua");
    const conn = getHeader(headers, "connection").toLowerCase();
    const te = getHeader(headers, "transfer-encoding").toLowerCase();
    const cl = getHeader(headers, "content-length");
    const secFetchSite = getHeader(headers, "sec-fetch-site").toLowerCase();
    const secFetchMode = getHeader(headers, "sec-fetch-mode").toLowerCase();
    const secChPlatform = getHeader(headers, "sec-ch-ua-platform").replace(/"/g, "").toLowerCase();
    const originHdr = getHeader(headers, "origin").trim().toLowerCase();

    // --- Signal 1: Explicit Proxy Leakage, Path Override & HTTP Request Smuggling (runs BEFORE OPTIONS exemption!) ---
    if (cl && te) {
      flag("CL_TE_SMUGGLING", 10, "Both Content-Length and Transfer-Encoding present (RFC 9112 §6.3)");
    }
    if (overrideTargetsProtected) {
      flag("PROXY_PATH_OVERRIDE_HEADER", 6, "X-Original-URL / X-Rewrite-URL targets a protected route");
    }
    let hasProxyLeak = false;
    for (const ph of PROXY_LEAK_HEADERS) {
      if (hasHeader(headers, ph)) {
        hasProxyLeak = true;
        flag("PROXY_HEADER_LEAK", 5, `Proxy artifact header '${ph}' present`);
      }
    }
    if (Array.isArray(rawHeaderLines)) {
      let hostCount = 0;
      let clCount = 0;
      const psCounts = Object.create(null);
      for (const ln of rawHeaderLines) {
        const colon = ln.indexOf(":");
        if (colon <= 0) continue;
        const name = ln.slice(0, colon).trim().toLowerCase();
        if (name === "host") hostCount += 1;
        else if (name === "content-length") clCount += 1;
        else if (name.startsWith("x-ps-")) psCounts[name] = (psCounts[name] || 0) + 1;
      }
      if (hostCount > 1) {
        flag("DUPLICATE_HOST_HEADER", 8, `Duplicate Host headers (${hostCount}) detected`);
      }
      if (clCount > 1) {
        flag("DUPLICATE_CONTENT_LENGTH", 8, `Duplicate Content-Length headers (${clCount}) detected`);
      }
      if (Object.values(psCounts).some((c) => c > 1)) {
        flag("REPEATER_BODY_OR_PATH_TAMPERED", 10, "Duplicate X-PS-* Proof-of-Freshness header detected");
      }
    }

    // Strict CORS preflight exemption (cross-origin http/https only, non-CLI UA, requires Sec-Fetch-Mode: cors on modern browsers)
    const hostHdr = normalizeHostDefaultPort(getHeader(headers, "host"));
    const originHost = parseHttpOriginHost(originHdr);
    const isSameOriginPreflight = Boolean(originHost && hostHdr && originHost === hostHdr);
    const chromeMajorPre = parseBrowserMajorChrome(ua);
    const ffMajorPre = parseBrowserMajorFirefox(ua);
    const modernUaPre = (chromeMajorPre >= 80 || ffMajorPre >= 90) && !isCliOrProxyUa(ua, secChUa);
    const isCorsPreflight =
      upperMethod === "OPTIONS" &&
      hasHeader(headers, "access-control-request-method") &&
      Boolean(originHost) &&
      !isSameOriginPreflight &&
      bodyBuf.length === 0 &&
      !methodOverride &&
      !isCliOrProxyUa(ua, secChUa) &&
      (!modernUaPre || (secFetchMode === "cors" && (fromTrustedProxy || conn !== "close")));

    if (isCorsPreflight) {
      const blocked = mode !== "monitor" && score >= threshold;
      const preRes = {
        ok: !blocked,
        blocked,
        score,
        threshold,
        mode,
        reasons,
        nextCanary: null,
        rehandshakeRecommended: false,
      };
      if ((blocked || score > 0) && onDetect) {
        try { onDetect({ ...preRes, ip: normIp, method: upperMethod, path: pathname, sessionId: null }); } catch {}
      }
      return preRes;
    }

    // --- Signal 2: Browser UA vs. Repeater / CLI Wire & Metadata Contradictions ---
    const chromeMajor = parseBrowserMajorChrome(ua);
    const ffMajor = parseBrowserMajorFirefox(ua);
    const claimsModernBrowser = (chromeMajor >= 80 || ffMajor >= 90) && !isCliOrProxyUa(ua, secChUa);

    if (claimsModernBrowser) {
      if (!secFetchSite && !secFetchMode && (isProtected || hasProxyLeak)) {
        flag("FETCH_METADATA_MISSING", 4, "Modern browser UA missing Sec-Fetch-Site/Sec-Fetch-Mode metadata");
      }
      if (isProtected && secFetchSite.includes("cross-site")) {
        flag("CROSS_SITE_REQUEST_BLOCKED", 6, "Cross-site Fetch Metadata on protected route");
      }
      if (!fromTrustedProxy && conn === "close" && (isProtected || hasProxyLeak)) {
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
    } else if (isProtected && isCliOrProxyUa(ua, secChUa)) {
      flag("NON_BROWSER_REPLAY_CLIENT", 6, "Direct replay/CLI/automation client User-Agent on protected route");
    }

    // --- Signal 3: Cryptographic Single-Use Proof-of-Freshness + Rotating Canary ---
    let nextCanary = null;
    let rehandshakeRecommended = false;
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
      } else if (
        !/^[A-Za-z0-9_-]{8,64}$/.test(psNonce) ||
        !/^[a-fA-F0-9]{16,64}$/.test(psSid) ||
        !/^[a-fA-F0-9]{64}$/.test(psProof) ||
        !/^[a-fA-F0-9]{16,64}$/.test(psCanary) ||
        psSeqRaw.includes("|") ||
        psTsRaw.includes("|") ||
        upperMethod.includes("|")
      ) {
        flag("REPEATER_BODY_OR_PATH_TAMPERED", 10, "Malformed Proof-of-Freshness header syntax");
      } else {
        const sess = sessions.get(psSid);
        if (!sess || sess.exp <= now) {
          flag("REPEATER_UNKNOWN_OR_EXPIRED_SESSION", 8, "Proof references unknown or expired session");
          rehandshakeRecommended = true;
        } else {
          const validSeqFormat = /^\d{1,15}$/.test(psSeqRaw);
          const seq = validSeqFormat ? Number(psSeqRaw) : NaN;
          const validTsFormat = /^\d{1,15}(\.\d{1,4})?$/.test(psTsRaw);
          const ts = validTsFormat ? Number(psTsRaw) : NaN;
          const nonceKey = `${psSid}:${psNonce}`;

          const prevNonceExp = usedNonces.get(nonceKey);
          if (prevNonceExp && prevNonceExp > now) {
            flag("REPEATER_NONCE_REPLAYED", 10, `Single-use nonce '${psNonce.slice(0, 12)}...' replayed (Repeater detected)`);
          }

          if (!Number.isSafeInteger(seq) || seq <= sess.lastSeq) {
            flag("REPEATER_SEQ_REPLAY", 8, `Non-monotonic sequence ${psSeqRaw} <= last ${sess.lastSeq}`);
          }

          const ageMs = now - ts;
          if (!Number.isFinite(ts) || ageMs > freshnessMs || ageMs < -maxFutureSkewMs) {
            flag(
              "INTERCEPT_HOLD_OR_STALE_REPLAY",
              6,
              `Request age/skew ${Number.isFinite(ageMs) ? Math.round(ageMs) : "NaN"}ms outside [-${maxFutureSkewMs}, +${freshnessMs}]ms window`
            );
          }

          if (!safeEqualHex(psCanary, sess.canary)) {
            flag("REPEATER_STALE_CANARY", 8, "Stale or tampered rotating honey-canary token (Repeater replay)");
          }

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

          if (!safeEqualHex(sess.uaHash, sha256Hex(ua || ""))) {
            flag("REPEATER_UA_SESSION_MISMATCH", 6, "User-Agent changed mid-session");
          }
          if (bindIp && sess.ip && normIp && sess.ip !== normIp) {
            flag("REPEATER_IP_SESSION_MISMATCH", 6, "Client IP changed mid-session");
          }
          if (sess.origin && originHdr && sess.origin !== originHdr) {
            flag("REPEATER_ORIGIN_MISMATCH", 6, "Origin changed mid-session");
          }

          if (proofValid) {
            usedNonces.set(nonceKey, now + nonceTtlMs);
          }
          const validAdvance =
            proofValid &&
            Number.isSafeInteger(seq) &&
            seq > sess.lastSeq &&
            safeEqualHex(psCanary, sess.canary);
          if (validAdvance && (score < threshold || mode === "monitor")) {
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
      const arr = (ipBursts.get(normIp) || []).filter((e) => now - e.ts <= 5_000);
      const sameCount = arr.filter((e) => e.sig === sig).length;
      arr.push({ ts: now, sig });
      ipBursts.delete(normIp);
      ipBursts.set(normIp, arr.slice(-30));
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
      rehandshakeRecommended,
    };
    if ((blocked || score > 0) && onDetect) {
      try {
        onDetect({ ...result, ip: normIp, method: upperMethod, path: pathname, sessionId: psSid || null });
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
    handshakePowBits,
    requireBootToken,
    bindIp,
    protectedPaths,
    trustedProxies,
    isPathProtected: (p) => isPathProtected(p, protectedPaths),
    allowHandshake,
    issueBootChallenge,
    consumeBootChallenge,
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
  stripSchemeAndAuthority,
  isCliOrProxyUa,
  verifyPowSolution,
  solvePowChallenge,
  sha256Hex,
  hmacSha256Hex,
};
