"use strict";

const crypto = require("node:crypto");
const path = require("node:path");
const { normalizeMode, resolvePreset } = require("./presets.js");

const P256_N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n;

const CLI_OR_PROXY_UA_RE =
  /burp|caido|mitmproxy|sqlmap|ffuf|nuclei|curl\/|wget\/|python-requests|python-urllib|python-httpx|aiohttp|go-http-client|httpie|libwww-perl|java\/|okhttp|axios\/|node-fetch|undici|insomnia|postman|headlesschrome|playwright|puppeteer|phantomjs|slimerjs/i;

const AI_CRAWLER_UA_RE =
  /firecrawl|mendable|apify|crawlee|browserless|scrapingbee|zenrows|brightdata|oxylabs|stagehand|browser-?use|steel-?browser|gptbot|oai-searchbot|chatgpt-user|claudebot|claude-web|anthropic-ai|perplexitybot|ccbot|bytespider|diffbot|scrapy|colly|zyte|phantombuster|hyperbrowser|browserbase/i;

const CRAWLER_HEADER_PREFIXES = ["x-firecrawl-", "x-apify-", "x-browserless-", "x-scrapingbee-"];

const MUTATING_METHODS = new Set(["POST", "PUT", "PATCH", "DELETE"]);

const PROXY_LEAK_HEADERS = [
  "proxy-connection",
  "x-burp-header",
  "x-burp-collaborator",
  "x-caido-id",
  "x-caido-replay",
  "x-mitmproxy",
];

function deriveDeterministicSigningKeyPair(secretBuf) {
  const h = crypto.createHmac("sha256", secretBuf).update("PS_ECDSA_SIGN_KEY_V1").digest();
  const dBig = 1n + (BigInt("0x" + h.toString("hex")) % (P256_N - 1n));
  const dBuf = Buffer.from(dBig.toString(16).padStart(64, "0"), "hex");
  const ecdh = crypto.createECDH("prime256v1");
  ecdh.setPrivateKey(dBuf);
  const pubUncompressed = ecdh.getPublicKey();
  const x = pubUncompressed.subarray(1, 33).toString("base64url");
  const y = pubUncompressed.subarray(33, 65).toString("base64url");
  const d = dBuf.toString("base64url");
  dBuf.fill(0);
  const privateKey = crypto.createPrivateKey({ key: { kty: "EC", crv: "P-256", d, x, y }, format: "jwk" });
  const publicKey = crypto.createPublicKey({ key: { kty: "EC", crv: "P-256", x, y }, format: "jwk" });
  return { privateKey, publicKey, publicKeyRawB64: pubUncompressed.toString("base64") };
}

function resolveSigningKeyPair(secretBuf, customPair) {
  if (!customPair) return deriveDeterministicSigningKeyPair(secretBuf);
  const privateKey =
    typeof customPair.privateKey === "string" || Buffer.isBuffer(customPair.privateKey)
      ? crypto.createPrivateKey(customPair.privateKey)
      : customPair.privateKey;
  const publicKey = customPair.publicKey
    ? typeof customPair.publicKey === "string" || Buffer.isBuffer(customPair.publicKey)
      ? crypto.createPublicKey(customPair.publicKey)
      : customPair.publicKey
    : crypto.createPublicKey(privateKey);
  const jwk = publicKey.export({ format: "jwk" });
  if (jwk.kty !== "EC" || jwk.crv !== "P-256" || !jwk.x || !jwk.y) {
    throw new Error("Invalid ProxySnare signingKeyPair: expected NIST P-256 EC keypair");
  }
  const pubUncompressed = Buffer.concat([
    Buffer.from([0x04]),
    Buffer.from(jwk.x, "base64url"),
    Buffer.from(jwk.y, "base64url"),
  ]);
  return { privateKey, publicKey, publicKeyRawB64: pubUncompressed.toString("base64") };
}

const EMPTY_SHA256_HEX = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

function sha256Buf(input) {
  return crypto.createHash("sha256").update(input || "").digest();
}

function sha256Hex(input) {
  if (!input || input.length === 0) return EMPTY_SHA256_HEX;
  return crypto.createHash("sha256").update(input).digest("hex");
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

const PROXY_LEAK_SET = new Set(PROXY_LEAK_HEADERS);

const PS_NONCE_RE = /^[A-Za-z0-9_-]{8,64}$/;
const PS_SID_RE = /^[a-fA-F0-9]{16,64}$/;
const PS_PROOF_RE = /^[a-fA-F0-9]{64}$/;
const PS_CANARY_RE = /^[a-fA-F0-9]{16,64}$/;
const PS_CTX_RE = /^ce=([01]);cdp=([01]);ug=([01]);ga=(\d{1,7})(?:;ik=([01]))?$/;

function hasValidPsProofSyntax(headers) {
  if (!headers || typeof headers !== "object") return false;
  const sid = String(headers["x-ps-session"] || "").trim();
  const seq = String(headers["x-ps-seq"] || "").trim();
  const ts = String(headers["x-ps-ts"] || "").trim();
  const nonce = String(headers["x-ps-nonce"] || "").trim();
  const canary = String(headers["x-ps-canary"] || "").trim();
  const proof = String(headers["x-ps-proof"] || "").trim();
  if (!sid || !seq || !ts || !nonce || !canary || !proof) return false;
  if (!PS_SID_RE.test(sid) || !PS_NONCE_RE.test(nonce) || !PS_CANARY_RE.test(canary) || !PS_PROOF_RE.test(proof)) return false;
  if (seq.includes("|") || ts.includes("|")) return false;
  const ctx = String(headers["x-ps-ctx"] || "").trim();
  if (ctx && !PS_CTX_RE.test(ctx)) return false;
  return true;
}

const CANONICAL_PS_HEADERS = new Set([
  "x-ps-session",
  "x-ps-seq",
  "x-ps-ts",
  "x-ps-nonce",
  "x-ps-canary",
  "x-ps-proof",
  "x-ps-ctx",
]);
const METHOD_OVERRIDE_HEADER_NAMES = ["x-http-method-override", "x-method-override", "x-http-method"];
const EMPTY_BUF = Buffer.alloc(0);
const INSPECTED_HEADERS = new Set([
  "access-control-request-method",
  "connection",
  "content-length",
  "host",
  "origin",
  "sec-ch-ua",
  "sec-ch-ua-platform",
  "sec-fetch-mode",
  "sec-fetch-site",
  "transfer-encoding",
  "user-agent",
  "x-forwarded-host",
  "x-http-method",
  "x-http-method-override",
  "x-method-override",
  "x-ps-canary",
  "x-ps-ctx",
  "x-ps-nonce",
  "x-ps-proof",
  "x-ps-seq",
  "x-ps-session",
  "x-ps-ts",
]);

function countDuplicateSensitiveHeaders(rawHeaders, rawHeaderNames, rawHeaderLines) {
  let hostCount = 0;
  let clCount = 0;
  // 7-bit bitmask for canonical x-ps-* headers (zero object allocation on signed requests!); fallback dict only for non-canonical x-ps-* names.
  let psMask = 0;
  let extraPsCounts = null;
  let hasDupPs = false;
  const recordName = (name) => {
    if (name === "host") hostCount += 1;
    else if (name === "content-length") clCount += 1;
    else if (!hasDupPs && name.startsWith("x-ps-")) {
      let bit = 0;
      if (name === "x-ps-session") bit = 1;
      else if (name === "x-ps-seq") bit = 2;
      else if (name === "x-ps-ts") bit = 4;
      else if (name === "x-ps-nonce") bit = 8;
      else if (name === "x-ps-canary") bit = 16;
      else if (name === "x-ps-proof") bit = 32;
      else if (name === "x-ps-ctx") bit = 64;
      if (bit) {
        if (psMask & bit) hasDupPs = true;
        else psMask |= bit;
      } else {
        if (!extraPsCounts) extraPsCounts = Object.create(null);
        const next = (extraPsCounts[name] || 0) + 1;
        extraPsCounts[name] = next;
        if (next > 1) hasDupPs = true;
      }
    }
  };
  if (Array.isArray(rawHeaders)) {
    for (let i = 0; i < rawHeaders.length; i += 2) {
      const rawKey = rawHeaders[i];
      if (typeof rawKey !== "string") continue;
      const klLen = rawKey.length;
      if (klLen !== 4 && klLen !== 14 && !(klLen >= 6 && (rawKey.charCodeAt(0) | 32) === 120)) continue;
      recordName(rawKey.toLowerCase());
    }
    return { hostCount, clCount, hasDupPs };
  }
  if (Array.isArray(rawHeaderNames)) {
    for (let i = 0; i < rawHeaderNames.length; i++) {
      const name = rawHeaderNames[i];
      if (name) recordName(String(name).toLowerCase());
    }
    return { hostCount, clCount, hasDupPs };
  }
  if (Array.isArray(rawHeaderLines)) {
    for (let i = 0; i < rawHeaderLines.length; i++) {
      const ln = rawHeaderLines[i];
      const colon = ln.indexOf(":");
      if (colon > 0) recordName(ln.slice(0, colon).trim().toLowerCase());
    }
  }
  return { hostCount, clCount, hasDupPs };
}

function isCrawlerHeaderName(kl) {
  if (!kl.startsWith("x-")) return false;
  for (let i = 0; i < CRAWLER_HEADER_PREFIXES.length; i++) {
    if (kl.startsWith(CRAWLER_HEADER_PREFIXES[i])) return true;
  }
  return false;
}

const MAX_OVERRIDE_PARTS = 16;

function appendOverrideCandidatesBounded(dest, raw) {
  if (raw === undefined || raw === null) return false;
  if (Array.isArray(raw)) {
    for (let i = 0; i < raw.length; i++) {
      if (appendOverrideCandidatesBounded(dest, raw[i])) return true;
    }
    return false;
  }
  if (typeof raw !== "string") return false;
  const trimmed = raw.trim();
  if (!trimmed) return false;
  if (dest.length >= MAX_OVERRIDE_PARTS) return true;
  dest.push(trimmed);
  let comma = trimmed.indexOf(",");
  if (comma >= 0) {
    let start = 0;
    let partsSeen = 0;
    let commasSeen = 0;
    while (start <= trimmed.length) {
      if (comma >= 0 && ++commasSeen > MAX_OVERRIDE_PARTS) return true;
      const end = comma >= 0 ? comma : trimmed.length;
      const pt = trimmed.slice(start, end).trim();
      if (pt) {
        partsSeen += 1;
        if (partsSeen > MAX_OVERRIDE_PARTS || dest.length >= MAX_OVERRIDE_PARTS) return true;
        dest.push(pt);
      }
      if (comma < 0) break;
      start = comma + 1;
      comma = trimmed.indexOf(",", start);
    }
  }
  return false;
}

function hasProtectedOverrideHeader(headers, compiledRules) {
  if (!headers || typeof headers !== "object") return false;
  const orig = headers["x-original-url"];
  const rew = headers["x-rewrite-url"];
  if (orig === undefined && rew === undefined) return false;
  const list = [];
  if (appendOverrideCandidatesBounded(list, orig) || appendOverrideCandidatesBounded(list, rew)) {
    return true; // Fail closed on > MAX_OVERRIDE_PARTS comma-split DoS payload!
  }
  for (let i = 0; i < list.length; i++) {
    if (isPathProtected(list[i], compiledRules, true)) return true;
  }
  return false;
}

const EMPTY_ARR = Object.freeze([]);

function normalizeHeaderInfo(headers, skipOverrides = false) {
  const map = Object.create(null);
  let proxyLeaks = EMPTY_ARR;
  let overrideUrls = EMPTY_ARR;
  let overrideExcessive = false;
  let hasCrawlerPrefix = false;
  let hasAnyPsHeader = false;
  if (!headers || typeof headers !== "object") {
    return { map, proxyLeaks, overrideUrls, overrideExcessive, hasCrawlerPrefix, hasAnyPsHeader };
  }
  for (const k in headers) {
    if (!Object.prototype.hasOwnProperty.call(headers, k)) continue;
    const kl = k.toLowerCase();
    if (PROXY_LEAK_SET.has(kl)) {
      if (proxyLeaks === EMPTY_ARR) proxyLeaks = [kl];
      else proxyLeaks.push(kl);
    }
    if (!skipOverrides && !overrideExcessive && (kl === "x-original-url" || kl === "x-rewrite-url")) {
      if (overrideUrls === EMPTY_ARR) overrideUrls = [];
      if (appendOverrideCandidatesBounded(overrideUrls, headers[k])) {
        overrideExcessive = true;
      }
    }
    if (!INSPECTED_HEADERS.has(kl)) {
      if (!hasCrawlerPrefix && isCrawlerHeaderName(kl)) {
        hasCrawlerPrefix = true;
      }
      continue;
    }
    const raw = headers[k];
    const val = Array.isArray(raw) ? raw.join(", ") : String(raw ?? "");
    if (map[kl] === undefined) map[kl] = val;
    else if (val) map[kl] = map[kl] ? `${map[kl]}, ${val}` : val;
    if (!hasAnyPsHeader && CANONICAL_PS_HEADERS.has(kl) && val.trim() !== "") {
      hasAnyPsHeader = true;
    }
  }
  return { map, proxyLeaks, overrideUrls, overrideExcessive, hasCrawlerPrefix, hasAnyPsHeader };
}

function getHeader(headers, name) {
  if (!headers || typeof headers !== "object") return "";
  const target = name.toLowerCase();
  if (Object.prototype.hasOwnProperty.call(headers, target)) {
    const v = headers[target];
    return Array.isArray(v) ? v.join(", ") : String(v ?? "");
  }
  for (const k in headers) {
    if (Object.prototype.hasOwnProperty.call(headers, k) && k.toLowerCase() === target) {
      const v = headers[k];
      return Array.isArray(v) ? v.join(", ") : String(v ?? "");
    }
  }
  return "";
}

function isAiCrawlerRequest(headers) {
  if (!headers || typeof headers !== "object") return false;
  let ua = "";
  let secChUa = "";
  for (const k in headers) {
    if (!Object.prototype.hasOwnProperty.call(headers, k)) continue;
    const kl = k.toLowerCase();
    if (kl === "user-agent") {
      const v = headers[k];
      const s = Array.isArray(v) ? v.join(", ") : String(v ?? "");
      ua = ua ? (s ? `${ua}, ${s}` : ua) : s;
    } else if (kl === "sec-ch-ua") {
      const v = headers[k];
      const s = Array.isArray(v) ? v.join(", ") : String(v ?? "");
      secChUa = secChUa ? (s ? `${secChUa}, ${s}` : secChUa) : s;
    } else if (isCrawlerHeaderName(kl)) {
      return true;
    }
  }
  return AI_CRAWLER_UA_RE.test(ua.trim()) || AI_CRAWLER_UA_RE.test(secChUa);
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
function hexNibble(code) {
  if (code >= 0x30 && code <= 0x39) return code - 0x30;
  if (code >= 0x41 && code <= 0x46) return code - 0x37;
  if (code >= 0x61 && code <= 0x66) return code - 0x57;
  return -1;
}

function hexByteAt(s, idx) {
  return (hexNibble(s.charCodeAt(idx + 1)) << 4) | hexNibble(s.charCodeAt(idx + 2));
}

function decodePercentLenient(s) {
  if (s.indexOf("%") < 0) return s;
  return s.replace(/(?:%[0-9a-fA-F]{2})+/g, (run) => {
    let out = "";
    let i = 0;
    const len = run.length;
    while (i < len) {
      const b = hexByteAt(run, i);
      if (b === 0x00) {
        out += "\0";
        i += 3;
        continue;
      }
      if (b <= 0x7f) {
        out += String.fromCharCode(b);
        i += 3;
        continue;
      }
      // Zero-exception RFC 3629 UTF-8 leading-byte decoder (exact parity with strict UTF-8 / decodeURIComponent)
      if (b >= 0xc2 && b <= 0xdf && i + 6 <= len) {
        const b2 = hexByteAt(run, i + 3);
        if ((b2 & 0xc0) === 0x80) {
          out += String.fromCharCode(((b & 0x1f) << 6) | (b2 & 0x3f));
          i += 6;
          continue;
        }
      } else if (b >= 0xe0 && b <= 0xef && i + 9 <= len) {
        const b2 = hexByteAt(run, i + 3);
        const b3 = hexByteAt(run, i + 6);
        const validB2 = b === 0xe0 ? (b2 >= 0xa0 && b2 <= 0xbf) : b === 0xed ? (b2 >= 0x80 && b2 <= 0x9f) : ((b2 & 0xc0) === 0x80);
        if (validB2 && (b3 & 0xc0) === 0x80) {
          out += String.fromCharCode(((b & 0x0f) << 12) | ((b2 & 0x3f) << 6) | (b3 & 0x3f));
          i += 9;
          continue;
        }
      } else if (b >= 0xf0 && b <= 0xf4 && i + 12 <= len) {
        const b2 = hexByteAt(run, i + 3);
        const b3 = hexByteAt(run, i + 6);
        const b4 = hexByteAt(run, i + 9);
        const validB2 = b === 0xf0 ? (b2 >= 0x90 && b2 <= 0xbf) : b === 0xf4 ? (b2 >= 0x80 && b2 <= 0x8f) : ((b2 & 0xc0) === 0x80);
        if (validB2 && (b3 & 0xc0) === 0x80 && (b4 & 0xc0) === 0x80) {
          const cp = ((b & 0x07) << 18) | ((b2 & 0x3f) << 12) | ((b3 & 0x3f) << 6) | (b4 & 0x3f);
          out += String.fromCodePoint(cp);
          i += 12;
          continue;
        }
      }
      out += run.slice(i, i + 3);
      i += 3;
    }
    return out;
  });
}

function stripSchemeAndAuthority(rawUrl) {
  let s = String(rawUrl || "/").trimStart();
  if (!s) return "/";
  if (s.charCodeAt(0) === 47) return s;
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
  let s = String(rawPath || "/").replace(/\\/g, "/");
  const nul = s.indexOf("\0");
  if (nul >= 0) s = s.slice(0, nul);
  if (!s.startsWith("/")) s = "/" + s;
  s = s
    .split("/")
    .map((seg) => seg.split(";")[0])
    .join("/")
    .replace(/\/+/g, "/");
  if (s.length > 1) s = s.replace(/\/+$/, "");
  return s || "/";
}

function stripTrailingSpacesAndDots(seg) {
  let end = seg.length;
  while (end > 0) {
    const code = seg.charCodeAt(end - 1);
    if (code === 0x2e || code === 0x20 || code === 0x09 || code === 0x0a || code === 0x0d || code === 0x0b || code === 0x0c) {
      end--;
    } else {
      break;
    }
  }
  return end === seg.length ? seg : seg.slice(0, end);
}

function trimSegmentNoise(normPath) {
  let s = String(normPath || "/")
    .split("/")
    .map(stripTrailingSpacesAndDots)
    .join("/")
    .replace(/\/+/g, "/");
  if (!s.startsWith("/")) s = "/" + s;
  if (s.length > 1) s = s.replace(/\/+$/, "");
  return s || "/";
}

// Strictly linear DFA allowing internal dots (e.g. /api/v1.2/users, /app.bundle.js) while routing '.', '..', '.x', 'x.', '%', ';', '#', '\', '//' to slow path
const CLEAN_ASCII_PATH_RE =
  /^\/(?:[A-Za-z0-9_~:@!$&'()*+,=-]+(?:\.[A-Za-z0-9_~:@!$&'()*+,=-]+)*(?:\/[A-Za-z0-9_~:@!$&'()*+,=-]+(?:\.[A-Za-z0-9_~:@!$&'()*+,=-]+)*)*)?\/?$/;

function decodePercent2(s) {
  let out = s;
  for (let pass = 0; pass < 2; pass++) {
    const next = decodePercentLenient(out);
    if (next === out) break;
    out = next;
  }
  return out;
}

function normalizeDecodedPathname(decodedNoQuery) {
  let s = String(decodedNoQuery || "/").replace(/\0/g, "").replace(/\\/g, "/");
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

function normalizePathname(rawUrl) {
  let s = stripSchemeAndAuthority(rawUrl);
  const qIdx = s.indexOf("?");
  if (qIdx >= 0) s = s.slice(0, qIdx);
  if (!s) return "/";
  if (CLEAN_ASCII_PATH_RE.test(s)) {
    return s.length > 1 && s.endsWith("/") ? s.slice(0, -1) : s;
  }
  return normalizeDecodedPathname(decodePercent2(s));
}

function expandPathCandidates(rawUrl) {
  const raw = stripSchemeAndAuthority(rawUrl);
  const qIdx = raw.indexOf("?");
  const rawPath = qIdx >= 0 ? raw.slice(0, qIdx) : raw;
  if (CLEAN_ASCII_PATH_RE.test(rawPath)) {
    const clean = rawPath.length > 1 && rawPath.endsWith("/") ? rawPath.slice(0, -1) : rawPath || "/";
    return [clean];
  }
  const set = new Set();

  const addRawOnly = (val) => {
    const n2 = cleanPathNoCollapse(val);
    set.add(n2);
    set.add(trimSegmentNoise(n2));
  };

  const addDecoded = (decVal) => {
    const n1 = normalizeDecodedPathname(decVal);
    const n2 = cleanPathNoCollapse(decVal);
    set.add(n1);
    set.add(n2);
    set.add(trimSegmentNoise(n1));
    set.add(trimSegmentNoise(n2));
  };

  addRawOnly(rawPath);

  // Decode rawPath in at most 2 passes total (splitting on literal '#' decodes disjoint halves with zero overlap!)
  const rawHash = rawPath.indexOf("#");
  let dec;
  if (rawHash >= 0) {
    const rawBefore = rawPath.slice(0, rawHash);
    addRawOnly(rawBefore);
    const decBefore = decodePercent2(rawBefore);
    addDecoded(decBefore);
    const decAfter = decodePercent2(rawPath.slice(rawHash + 1));
    dec = `${decBefore}#${decAfter}`;
  } else {
    dec = decodePercent2(rawPath);
  }
  addDecoded(dec);

  const nullIdx = dec.indexOf("\0");
  if (nullIdx >= 0) addDecoded(dec.slice(0, nullIdx));

  const decQ = dec.indexOf("?");
  if (decQ >= 0) addDecoded(dec.slice(0, decQ));
  const decH = dec.indexOf("#");
  if (decH >= 0) addDecoded(dec.slice(0, decH));

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

function compileProtectedRules(paths) {
  const compiled = paths.map((rule) => {
    if (rule instanceof RegExp) return rule;
    const lower = String(rule).trim().toLowerCase();
    return {
      lower,
      prefix: lower === "*" || lower === "/" ? lower : (lower.endsWith("/") ? lower : `${lower}/`),
    };
  });
  compiled.matchAll = compiled.some((r) => !(r instanceof RegExp) && (r.lower === "*" || r.lower === "/"));
  return compiled;
}

function matchesCompiledRules(candidates, rules) {
  if (rules && rules.matchAll) return true;
  for (let ci = 0; ci < candidates.length; ci++) {
    const norm = candidates[ci];
    const normLower = norm.toLowerCase();
    for (let ri = 0; ri < rules.length; ri++) {
      const rule = rules[ri];
      if (rule instanceof RegExp) {
        rule.lastIndex = 0;
        if (rule.test(norm)) return true;
      } else if (
        rule.lower === "*" ||
        rule.lower === "/" ||
        normLower === rule.lower ||
        normLower.startsWith(rule.prefix)
      ) {
        return true;
      }
    }
  }
  return false;
}

function isPathProtected(rawUrl, protectedPaths, preCompiled = false) {
  const rules = preCompiled ? protectedPaths : compileProtectedRules(protectedPaths);
  if (rules.matchAll) return true;
  return matchesCompiledRules(expandPathCandidates(rawUrl), rules);
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
  let exactV6Count = 0;
  const V4_MAPPED_PREFIX = 0xffffn << 32n;
  const V4_MAPPED_MASK = ((1n << 96n) - 1n) << 32n;
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
    if (rawV6 !== null) {
      exact.add(`v6:${rawV6.toString(16)}`);
      exactV6Count++;
      if ((rawV6 & V4_MAPPED_MASK) === V4_MAPPED_PREFIX) {
        const v4 = Number(rawV6 & 0xffffffffn);
        exact.add(`${(v4 >>> 24) & 255}.${(v4 >>> 16) & 255}.${(v4 >>> 8) & 255}.${v4 & 255}`);
      }
    }
    exact.add(normalizeIp(entry));
  }
  const hasV6Rules = exactV6Count > 0 || cidrsV6.length > 0;
  const hasMappedV6Cidrs = cidrsV6.some((c) => (c.net & V4_MAPPED_MASK) === (V4_MAPPED_PREFIX & c.mask));
  return {
    size: exact.size + cidrsV4.length + cidrsV6.length,
    has(ip) {
      const raw = String(ip || "").trim().toLowerCase();
      const norm = normalizeIp(raw);
      if (exact.has(norm)) return true;
      // Fast IPv4 / ::ffff:-mapped IPv4 path: skip BigInt & IPv6 CIDR loops unless a configured IPv6 CIDR actually overlaps ::ffff:0:0/96!
      if (!norm.includes(":") && (raw === norm || raw.startsWith("::ffff:"))) {
        if (cidrsV4.length > 0 || hasMappedV6Cidrs) {
          const v4 = parseIpv4Int(norm);
          if (v4 !== null) {
            for (let i = 0; i < cidrsV4.length; i++) {
              const c = cidrsV4[i];
              if (((v4 & c.mask) >>> 0) === c.net) return true;
            }
            if (hasMappedV6Cidrs) {
              const mappedV6 = V4_MAPPED_PREFIX | BigInt(v4);
              for (let i = 0; i < cidrsV6.length; i++) {
                const c = cidrsV6[i];
                if ((mappedV6 & c.mask) === c.net) return true;
              }
            }
          }
        }
        return false;
      }
      if (hasV6Rules) {
        const rawV6 = parseIpv6BigInt(raw);
        if (rawV6 !== null) {
          if (exact.has(`v6:${rawV6.toString(16)}`)) return true;
          for (let i = 0; i < cidrsV6.length; i++) {
            const c = cidrsV6[i];
            if ((rawV6 & c.mask) === c.net) return true;
          }
        }
      }
      return false;
    },
  };
}

function extractClientIp(req, trustedProxies, expressTrustsProxy = null, precheckedTrustedProxy = null) {
  const remoteRaw = String(req?.socket?.remoteAddress || req?.ip || "").trim();
  const trustedByList =
    precheckedTrustedProxy !== null
      ? Boolean(precheckedTrustedProxy && trustedProxies.size > 0)
      : Boolean(remoteRaw && trustedProxies.size > 0 && trustedProxies.has(remoteRaw));
  if (remoteRaw && trustedByList) {
    const xff = getHeader(req.headers, "x-forwarded-for");
    if (xff) {
      // Zero-array right-to-left scan of X-Forwarded-For (only inspects rightmost hops!)
      let end = xff.length;
      let firstNonEmpty = "";
      while (end > 0) {
        const comma = xff.lastIndexOf(",", end - 1);
        const hop = xff.slice(comma + 1, end).trim();
        if (hop) {
          firstNonEmpty = hop;
          if (!trustedProxies.has(hop)) return normalizeIp(hop);
        }
        if (comma < 0) break;
        end = comma;
      }
      if (firstNonEmpty) return normalizeIp(firstNonEmpty);
    }
  }
  const trustsExpress =
    expressTrustsProxy !== null
      ? Boolean(expressTrustsProxy)
      : Boolean(req?.app && typeof req.app.get === "function" && req.app.get("trust proxy"));
  if (trustsExpress && trustedProxies.size === 0 && req?.ip) {
    return normalizeIp(req.ip);
  }
  return normalizeIp(remoteRaw) || "unknown";
}

function normalizeHostDefaultPort(hostRaw, protocol = "") {
  let h = String(hostRaw || "").trim().toLowerCase();
  if (!h) return "";
  if (h.startsWith("[")) {
    try {
      const scheme = protocol === "https:" ? "https:" : "http:";
      h = new URL(`${scheme}//${h}`).host.toLowerCase();
    } catch {
      // keep raw bracketed host if unparseable
    }
  }
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
  if (!s || !/^https?:\/\/[^/\\]/i.test(s) || s.includes("?") || s.includes("#") || s.includes("@")) return "";
  try {
    const u = new URL(s);
    if ((u.protocol !== "http:" && u.protocol !== "https:") || u.username || u.password) return "";
    if (u.pathname !== "/" || u.search || u.hash || s.endsWith("/")) return "";
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
  if (options.userGestureWindowMs !== undefined && options.userGestureWindowMs !== null) {
    positiveFinite(options.userGestureWindowMs, 15_000, "userGestureWindowMs");
  }
  const preset = resolvePreset(options.mode ?? "strict", options);
  const mode = preset.mode;

  let secret;
  const envSecret =
    options.secret === undefined && typeof process !== "undefined" && process.env && process.env.PROXYSNARE_SECRET
      ? String(process.env.PROXYSNARE_SECRET)
      : null;
  if (envSecret !== null && Buffer.byteLength(envSecret, "utf8") < 16) {
    throw new Error("Invalid PROXYSNARE_SECRET: must be at least 16 bytes");
  }
  const rawSecret = options.secret !== undefined && options.secret !== null ? options.secret : envSecret;
  const hasPersistentSecret = rawSecret !== null || Boolean(options.signingKeyPair);
  if (rawSecret === null) {
    secret = crypto.randomBytes(32);
  } else if (Buffer.isBuffer(rawSecret)) {
    if (rawSecret.length < 16) {
      throw new Error("Invalid ProxySnare secret: Buffer must be at least 16 bytes");
    }
    secret = Buffer.from(rawSecret);
  } else if (typeof rawSecret === "string") {
    if (Buffer.byteLength(rawSecret, "utf8") < 16) {
      throw new Error("Invalid ProxySnare secret: string must be at least 16 bytes");
    }
    secret = Buffer.from(rawSecret, "utf8");
  } else {
    throw new Error("Invalid ProxySnare secret: expected Buffer or string (>= 16 bytes)");
  }

  const signingKeys = resolveSigningKeyPair(secret, options.signingKeyPair);
  // If options.signingKeyPair is supplied without options.secret (e.g., multi-worker { store, signingKeyPair }),
  // derive a deterministic shared boot/HMAC secret from the shared ECDSA private key so cross-worker boot tokens verify!
  if (rawSecret === null && options.signingKeyPair) {
    const privDer = signingKeys.privateKey.export({ format: "der", type: "pkcs8" });
    secret = crypto.createHash("sha256").update("PS_BOOT_SECRET_V1|").update(privDer).digest();
  }
  const threshold = positiveFinite(options.threshold, preset.threshold, "threshold");
  const freshnessMs = positiveFinite(options.freshnessMs, preset.freshnessMs, "freshnessMs");
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
    preset.handshakePowBits,
    "handshakePowBits",
    22
  );
  const requireBootToken = options.requireBootToken !== false;
  const bindIp = preset.bindIp;
  const blockAiCrawlers = preset.blockAiCrawlers;
  const blockConsoleEval = preset.blockConsoleEval;
  const blockCdpActive = preset.blockCdpActive;
  const allowDevTools = preset.allowDevTools;
  const blockAutomationOnAllRoutes = Boolean(options.blockAutomationOnAllRoutes);
  const requireUserGestureOnMutate = preset.requireUserGestureOnMutate;
  const gestureExemptPaths = Array.isArray(options.gestureExemptPaths) && options.gestureExemptPaths.length > 0
    ? compileProtectedRules(normalizeProtectedPaths(options.gestureExemptPaths))
    : null;
  const gestureProtectedPaths = Array.isArray(options.gestureProtectedPaths) && options.gestureProtectedPaths.length > 0
    ? compileProtectedRules(normalizeProtectedPaths(options.gestureProtectedPaths))
    : null;
  const requireSignedContext = preset.requireSignedContext;
  const requireGuardIntegrity = preset.requireGuardIntegrity;
  const ecdsaHandshakeAuth = preset.ecdsaHandshakeAuth;
  const sri = preset.sri;
  const userGestureWindowMs = preset.userGestureWindowMs;
  const protectedPaths = normalizeProtectedPaths(options.protectedPaths);
  const compiledProtectedPaths = compileProtectedRules(protectedPaths);
  const trustedProxies = compileTrustedProxies(options.trustProxy);
  const onDetect = typeof options.onDetect === "function" ? options.onDetect : null;

  const sessions = new Map();
  const usedNonces = new Map();
  const usedBootTokens = new Map();
  const ipBursts = new Map();
  const handshakeRates = new Map();
  const bootRates = new Map();
  const htmlBootRates = new Map();
  let inspectCounter = 0;

  function checkSlidingRate(rateMap, ip, limit, now = Date.now()) {
    const key = ip || "unknown";
    if (!rateMap.has(key) && rateMap.size >= 10_000) {
      for (const [k, arr] of rateMap) {
        if (arr.length === 0 || now - arr[arr.length - 1] >= 60_000) rateMap.delete(k);
        else break;
      }
      if (rateMap.size >= 10_000) {
        const drop = rateMap.size - 8_500;
        let i = 0;
        for (const k of rateMap.keys()) {
          rateMap.delete(k);
          if (++i >= drop) break;
        }
      }
    }
    let arr = rateMap.get(key);
    let start = 0;
    if (!arr) {
      arr = [];
    } else {
      while (start < arr.length && now - arr[start] >= 60_000) start++;
      if (start > 0) arr = arr.slice(start);
    }
    // Check limit BEFORE deleting from Map so rejected requests preserve strict insertion-order monotonicity for O(1) head-pruning!
    if (arr.length >= limit) {
      if (start > 0) rateMap.set(key, arr);
      return false;
    }
    rateMap.delete(key);
    arr.push(now);
    rateMap.set(key, arr);
    return true;
  }

  // O(1) amortized head-pruning exploiting Map insertion order for fixed-TTL & LRU structures
  function pruneMaps(now) {
    if (usedNonces.size >= maxNonces) {
      for (const [k, exp] of usedNonces) {
        if (exp <= now) usedNonces.delete(k);
        else break;
      }
      if (usedNonces.size >= maxNonces) {
        const target = Math.floor(maxNonces * 0.85);
        for (const k of usedNonces.keys()) {
          usedNonces.delete(k);
          if (usedNonces.size <= target) break;
        }
      }
    }
    if (usedBootTokens.size >= maxBootTokens) {
      // NEVER evict unexpired entries from usedBootTokens (prevents stateless PS_BOOT_V2S replay under saturation)!
      for (const [k, exp] of usedBootTokens) {
        if (exp <= now) usedBootTokens.delete(k);
        else break;
      }
    }
    if (ipBursts.size >= 10_000) {
      for (const [k, arr] of ipBursts) {
        if (arr.length === 0 || now - arr[arr.length - 1].ts > 5_000) ipBursts.delete(k);
        else break;
      }
      if (ipBursts.size >= 10_000) {
        const drop = ipBursts.size - 8_500;
        let i = 0;
        for (const k of ipBursts.keys()) {
          ipBursts.delete(k);
          if (++i >= drop) break;
        }
      }
    }
  }

  function allowHandshake(ip, now = Date.now()) {
    return checkSlidingRate(handshakeRates, ip, maxHandshakesPerMin, now);
  }

  function allowBoot(ip, now = Date.now()) {
    return checkSlidingRate(bootRates, ip, maxHandshakesPerMin, now);
  }

  function allowHtmlBoot(ip, now = Date.now()) {
    return checkSlidingRate(htmlBootRates, ip, maxHandshakesPerMin, now);
  }

  function mintCanary() {
    return crypto.randomBytes(12).toString("hex");
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
    if (usedBootTokens.size >= maxBootTokens) {
      for (const [k, exp] of usedBootTokens) {
        if (exp <= now) usedBootTokens.delete(k);
        else break;
      }
      if (usedBootTokens.size >= maxBootTokens) {
        return null;
      }
    }
    const tokenId = crypto.randomBytes(16).toString("hex");
    const challenge = crypto.randomBytes(16).toString("hex");
    const normIp = normalizeIp(ip);
    const uaHash = sha256Hex(userAgent || "");
    const exp = now + bootTokenTtlMs;
    const sealed = Buffer.from(
      JSON.stringify({ c: challenge, d: handshakePowBits, e: exp, i: normIp, u: uaHash }),
      "utf8"
    ).toString("base64url");
    const mac = hmacSha256Hex(
      secret,
      `PS_BOOT_V2S|${tokenId}|${sealed}`
    ).slice(0, 32);
    const bootToken = `${tokenId}.${mac}.${sealed}`;
    return {
      bootToken,
      challenge,
      difficulty: handshakePowBits,
      exp,
    };
  }

  function consumeBootChallenge({ bootToken = "", powNonce = "", ip = "127.0.0.1", userAgent = "" } = {}) {
    const now = Date.now();
    if (typeof bootToken !== "string") return { ok: false, error: "BOOT_TOKEN_INVALID" };
    if (powNonce !== undefined && powNonce !== null && typeof powNonce !== "string") {
      return { ok: false, error: "HANDSHAKE_POW_INVALID" };
    }
    const raw = bootToken.trim();
    const parts = raw.split(".");
    if (parts.length !== 3) return { ok: false, error: "BOOT_TOKEN_INVALID" };
    const tokenId = parts[0];
    const mac = parts[1];
    const sealed = parts[2];
    if (!/^[a-f0-9]{32}$/i.test(tokenId) || !/^[a-f0-9]{32}$/i.test(mac) || !/^[A-Za-z0-9_-]{16,512}$/.test(sealed)) {
      return { ok: false, error: "BOOT_TOKEN_INVALID" };
    }
    const prevUsed = usedBootTokens.get(tokenId);
    if (prevUsed && prevUsed > now) {
      return { ok: false, error: "BOOT_TOKEN_REPLAYED_OR_INVALID" };
    }
    const expectedMac = hmacSha256Hex(secret, `PS_BOOT_V2S|${tokenId}|${sealed}`).slice(0, 32);
    if (!safeEqualHex(mac.toLowerCase(), expectedMac.toLowerCase())) {
      return { ok: false, error: "BOOT_TOKEN_INVALID" };
    }
    let rec;
    try {
      const parsed = JSON.parse(Buffer.from(sealed, "base64url").toString("utf8"));
      if (!parsed || typeof parsed.c !== "string" || typeof parsed.e !== "number" || typeof parsed.d !== "number") {
        return { ok: false, error: "BOOT_TOKEN_INVALID" };
      }
      rec = {
        ip: String(parsed.i || ""),
        uaHash: String(parsed.u || ""),
        challenge: parsed.c,
        difficulty: parsed.d,
        exp: parsed.e,
      };
    } catch {
      return { ok: false, error: "BOOT_TOKEN_INVALID" };
    }
    if (rec.exp <= now) return { ok: false, error: "BOOT_TOKEN_EXPIRED" };
    if (usedBootTokens.size >= maxBootTokens) {
      for (const [k, exp] of usedBootTokens) {
        if (exp <= now) usedBootTokens.delete(k);
        else break;
      }
      if (usedBootTokens.size >= maxBootTokens) {
        return { ok: false, error: "BOOT_CAPACITY_EXCEEDED" };
      }
    }
    // Monotonic fixed expiry >= rec.exp preserves strict insertion-order == expiry-order for O(1) head-pruning without EVER evicting unexpired tokens!
    usedBootTokens.set(tokenId, now + Math.max(60_000, bootTokenTtlMs));
    if (bindIp && rec.ip !== normalizeIp(ip)) {
      return { ok: false, error: "BOOT_TOKEN_IP_MISMATCH" };
    }
    if (!safeEqualHex(rec.uaHash, sha256Hex(userAgent || ""))) {
      return { ok: false, error: "BOOT_TOKEN_UA_MISMATCH" };
    }
    if (!verifyPowSolution("PS_POW_V2", rec.challenge, powNonce || "", rec.difficulty)) {
      return { ok: false, error: "HANDSHAKE_POW_INVALID" };
    }
    return { ok: true, tokenId: tokenId.toLowerCase(), challenge: rec.challenge, difficulty: rec.difficulty };
  }

  function verifyHandshakeSignature({
    sessionId,
    clientPubB64,
    serverPubB64,
    saltB64,
    bootToken = "",
    serverNowMs = "",
    canary = "",
    hsBind = "",
    serverSigB64 = "",
  }) {
    if (typeof serverSigB64 !== "string" || !serverSigB64.trim()) return false;
    const sidStr = typeof sessionId === "string" ? sessionId : "";
    const saltStr = typeof saltB64 === "string" ? saltB64 : "";
    const canaryStr = typeof canary === "string" ? canary : "";
    if (!sidStr || !saltStr || !canaryStr) return false;
    const bindStr = typeof hsBind === "string" ? hsBind.trim() : "";
    const bootStr = String(bootToken || "");
    const nowStr = String(serverNowMs ?? "");
    try {
      const sigTrim = serverSigB64.trim();
      const clientTrim = typeof clientPubB64 === "string" ? clientPubB64.trim() : "";
      const serverTrim = typeof serverPubB64 === "string" ? serverPubB64.trim() : "";
      if (
        !/^[A-Za-z0-9+/=_-]{80,104}$/.test(sigTrim) ||
        !/^[A-Za-z0-9+/=_-]{80,120}$/.test(clientTrim) ||
        !/^[A-Za-z0-9+/=_-]{80,120}$/.test(serverTrim)
      ) {
        return false;
      }
      const sigNorm = sigTrim.replace(/-/g, "+").replace(/_/g, "/");
      const sigBuf = Buffer.from(sigNorm, "base64");
      if (sigBuf.length !== 64 || sigBuf.toString("base64").replace(/=+$/, "") !== sigNorm.replace(/=+$/, "")) return false;
      const clientNorm = clientTrim.replace(/-/g, "+").replace(/_/g, "/");
      const serverNorm = serverTrim.replace(/-/g, "+").replace(/_/g, "/");
      const clientBuf = Buffer.from(clientNorm, "base64");
      const serverBuf = Buffer.from(serverNorm, "base64");
      if (
        clientBuf.length !== 65 ||
        clientBuf[0] !== 0x04 ||
        serverBuf.length !== 65 ||
        serverBuf[0] !== 0x04 ||
        clientBuf.toString("base64").replace(/=+$/, "") !== clientNorm.replace(/=+$/, "") ||
        serverBuf.toString("base64").replace(/=+$/, "") !== serverNorm.replace(/=+$/, "")
      ) {
        return false;
      }
      const canonClient = clientBuf.toString("base64");
      const canonServer = serverBuf.toString("base64");
      if (
        sidStr.includes("|") ||
        canonClient.includes("|") ||
        canonServer.includes("|") ||
        saltStr.includes("|") ||
        bootStr.includes("|") ||
        nowStr.includes("|") ||
        canaryStr.includes("|") ||
        bindStr.includes("|")
      ) {
        return false;
      }
      const bindSuffix = bindStr ? `|${bindStr}` : "";
      const transcript = `PS_HS_AUTH_V1|${sidStr}|${canonClient}|${canonServer}|${saltStr}|${bootStr}|${nowStr}|${canaryStr}${bindSuffix}`;
      return crypto.verify(
        "sha256",
        Buffer.from(transcript, "utf8"),
        { key: signingKeys.publicKey, dsaEncoding: "ieee-p1363" },
        sigBuf
      );
    } catch {
      return false;
    }
  }

  let hasImportedSessions = false;
  let lastFullSessionSweepMs = 0;

  function sweepExpiredSessions(now) {
    lastFullSessionSweepMs = now;
    for (const [k, v] of sessions) {
      if (v.exp <= now) sessions.delete(k);
    }
  }

  function issueSession({ ip = "127.0.0.1", userAgent = "", origin = "", clientPubB64 = null, bootToken = "", hsBind = "" } = {}) {
    const now = Date.now();
    if (sessions.size >= maxSessions) {
      for (const [k, v] of sessions) {
        if (v.exp <= now) sessions.delete(k);
        else break;
      }
      // Throttled fallback full sweep ONLY when importSessionRecord has inserted out-of-order TTLs
      if (sessions.size >= maxSessions && hasImportedSessions && now - lastFullSessionSweepMs >= 5_000) {
        sweepExpiredSessions(now);
      }
      if (sessions.size >= maxSessions) {
        return null;
      }
    }

    const sessionId = crypto.randomBytes(16).toString("hex");
    const canary = mintCanary();
    const bindStr = typeof hsBind === "string" ? hsBind.trim() : "";
    const bootStr = String(bootToken || "");
    if (bindStr.includes("|") || bootStr.includes("|")) {
      return { error: "INVALID_HANDSHAKE_PARAMETERS" };
    }
    const bindSuffix = bindStr ? `|${bindStr}` : "";
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
      if (
        clientPubBuf.length !== 65 ||
        clientPubBuf[0] !== 0x04 ||
        clientPubBuf.toString("base64").replace(/=+$/, "") !== normB64.replace(/=+$/, "")
      ) {
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
      const info = Buffer.from(`PS_ECDH_V2|${sessionId}|${canonicalClientB64}|${serverPubB64}${bindSuffix}`, "utf8");
      keyBuf = Buffer.from(crypto.hkdfSync("sha256", sharedSecret, salt, info, 32));
      sharedSecret.fill(0);
      ecdhMeta = { serverPubB64, saltB64 };
      if (ecdsaHandshakeAuth) {
        const authTranscript = `PS_HS_AUTH_V1|${sessionId}|${canonicalClientB64}|${serverPubB64}|${saltB64}|${String(bootToken || "")}|${now}|${canary}${bindSuffix}`;
        const sigBuf = crypto.sign("sha256", Buffer.from(authTranscript, "utf8"), {
          key: signingKeys.privateKey,
          dsaEncoding: "ieee-p1363",
        });
        ecdhMeta.serverSigB64 = sigBuf.toString("base64");
      }
    } else {
      keyBuf = crypto.randomBytes(32);
    }

    const record = {
      sessionId,
      keyBuf,
      lastSeq: 0,
      canary,
      ua: String(userAgent || ""),
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
        ...(ecdhMeta.serverSigB64 ? { serverSigB64: ecdhMeta.serverSigB64 } : {}),
      };
    }

    return {
      protocol: "PS_LOCAL_V1",
      ...baseResponse,
      sessionKeyHex: keyBuf.toString("hex"),
    };
  }

  /**
   * Computes a valid Proof-of-Freshness signature (used by legitimate browser guard & tests).
   * Uses `PS2|` when signed runtime context (`ctx`) is supplied, and `PS1|` otherwise.
   */
  function signRequest({
    sessionKeyHex,
    sessionKeyBuf = null,
    method,
    pathWithQuery,
    body = "",
    seq,
    ts,
    nonce,
    canary,
    ctx = "",
  }) {
    const bodyHash = sha256Hex(Buffer.isBuffer(body) ? body : Buffer.from(String(body || ""), "utf8"));
    const safeCtx = typeof ctx === "string" ? ctx.trim() : "";
    const canonical = safeCtx
      ? `PS2|${String(method || "GET").toUpperCase()}|${pathWithQuery}|${bodyHash}|${seq}|${ts}|${nonce}|${canary}|${safeCtx}`
      : `PS1|${String(method || "GET").toUpperCase()}|${pathWithQuery}|${bodyHash}|${seq}|${ts}|${nonce}|${canary}`;
    const keyBuf = Buffer.isBuffer(sessionKeyBuf) ? sessionKeyBuf : Buffer.from(sessionKeyHex, "hex");
    return hmacSha256Hex(keyBuf, canonical);
  }

  /**
   * Evaluates an incoming HTTP request for intercepting proxy, CLI/curl & Repeater anomalies.
   */
  function inspectRequest({
    method = "GET",
    url = "/",
    headers = {},
    body = EMPTY_BUF,
    ip = "127.0.0.1",
    now = Date.now(),
    rawHeaderLines = null,
    rawHeaderNames = null,
    rawHeaders = null,
    fromTrustedProxy = false,
    getFromTrustedProxy = null,
    precheckedProtected = null,
    precomputedOverrideProtected = null,
    precomputedPathname = null,
    precomputedPathCands = null,
    precomputedNormIp = null,
    getNormIp = null,
    precomputedHdrInfo = null,
    bodySkipped = false,
  }) {
    if (mode === "off") {
      return {
        ok: true,
        blocked: false,
        score: 0,
        threshold,
        mode,
        reasons: [],
        nextCanary: null,
        canaryAck: null,
        rehandshakeRecommended: false,
        redirectGetHint: false,
      };
    }

    const upperMethod = String(method || "GET").toUpperCase();
    const pathWithQuery = String(url || "/");
    const pathname = precomputedPathname || normalizePathname(pathWithQuery);
    const bodyBuf = Buffer.isBuffer(body) ? body : (body ? Buffer.from(String(body), "utf8") : EMPTY_BUF);
    let _normIpCache = typeof precomputedNormIp === "string" ? precomputedNormIp : null;
    const resolveNormIp = () => {
      if (_normIpCache === null) {
        _normIpCache = typeof getNormIp === "function" ? String(getNormIp() || "unknown") : normalizeIp(ip);
      }
      return _normIpCache;
    };
    let _trustedProxyCache = typeof getFromTrustedProxy === "function" ? null : Boolean(fromTrustedProxy);
    const isFromTrustedProxy = () => {
      if (_trustedProxyCache === null) _trustedProxyCache = Boolean(getFromTrustedProxy());
      return _trustedProxyCache;
    };
    const reasons = [];
    let score = 0;

    inspectCounter += 1;
    if ((inspectCounter & 255) === 0 || usedNonces.size >= maxNonces) {
      pruneMaps(now);
    }

    function flag(code, weight, detail) {
      score += weight;
      reasons.push({ code, weight, detail });
    }

    // Single-pass O(H) header scan eliminates repeated absent-header scans
    const hdrInfo = precomputedHdrInfo || normalizeHeaderInfo(headers, precomputedOverrideProtected !== null);
    const h = hdrInfo.map;
    const overrideTargetsProtected =
      precomputedOverrideProtected !== null
        ? Boolean(precomputedOverrideProtected)
        : (Boolean(hdrInfo.overrideExcessive) ||
          (hdrInfo.overrideUrls.length > 0 &&
            hdrInfo.overrideUrls.some((u) => isPathProtected(u, compiledProtectedPaths, true))));
    let cachedPathCands = Array.isArray(precomputedPathCands) ? precomputedPathCands : null;
    const getPathCands = () => {
      if (!cachedPathCands) cachedPathCands = expandPathCandidates(pathWithQuery);
      return cachedPathCands;
    };
    const isProtected =
      (precheckedProtected !== null
        ? Boolean(precheckedProtected)
        : (compiledProtectedPaths.matchAll || matchesCompiledRules(getPathCands(), compiledProtectedPaths))) ||
      overrideTargetsProtected;

    // Evaluate all 3 HTTP method-override headers independently (reuses pre-body scan when available!)
    let overrideCount = 0;
    let overrideMismatch = false;
    let overrideMutating = false;
    let overrideDisplay = "";
    if (isProtected || hdrInfo.hasAnyPsHeader || upperMethod === "OPTIONS") {
      if (hdrInfo.methodOverride && hdrInfo.methodOverride.method === upperMethod) {
        overrideCount = hdrInfo.methodOverride.count;
        overrideMismatch = hdrInfo.methodOverride.mismatch;
        overrideMutating = hdrInfo.methodOverride.mutating;
        overrideDisplay = hdrInfo.methodOverride.display;
      } else {
        for (let i = 0; i < METHOD_OVERRIDE_HEADER_NAMES.length; i++) {
          const ovVal = (h[METHOD_OVERRIDE_HEADER_NAMES[i]] || "").trim().toUpperCase();
          if (!ovVal) continue;
          overrideCount += 1;
          if (!overrideDisplay) overrideDisplay = ovVal;
          if (ovVal !== upperMethod) {
            overrideMismatch = true;
            overrideDisplay = ovVal;
          }
          if (MUTATING_METHODS.has(ovVal)) overrideMutating = true;
        }
      }
    }
    const hasAnyMethodOverride = overrideCount > 0;
    const methodOverrideConflict = overrideCount > 1 || overrideMismatch;
    const ua = h["user-agent"] || "";
    const secChUa = h["sec-ch-ua"] || "";
    const conn = (h["connection"] || "").toLowerCase();
    const te = (h["transfer-encoding"] || "").toLowerCase();
    const cl = h["content-length"] || "";
    const secFetchSite = (h["sec-fetch-site"] || "").toLowerCase();
    const secFetchMode = (h["sec-fetch-mode"] || "").toLowerCase();
    const secChPlatform = (h["sec-ch-ua-platform"] || "").replace(/"/g, "").toLowerCase();
    const originHdr = (h["origin"] || "").trim().toLowerCase();

    // --- Signal 1: Explicit Proxy Leakage, Path Override & HTTP Request Smuggling (runs BEFORE OPTIONS exemption!) ---
    if (cl && te) {
      flag("CL_TE_SMUGGLING", 10, "Both Content-Length and Transfer-Encoding present (RFC 9112 §6.3)");
    }
    if (overrideTargetsProtected) {
      flag("PROXY_PATH_OVERRIDE_HEADER", 6, "X-Original-URL / X-Rewrite-URL targets a protected route");
    }
    if (isProtected && hasAnyMethodOverride && methodOverrideConflict) {
      flag("METHOD_OVERRIDE_DENIED", 6, `Unauthenticated HTTP method override header '${overrideDisplay}' on protected route`);
    }
    const hasProxyLeak = hdrInfo.proxyLeaks.length > 0;
    for (let i = 0; i < hdrInfo.proxyLeaks.length; i++) {
      flag("PROXY_HEADER_LEAK", 5, `Proxy artifact header '${hdrInfo.proxyLeaks[i]}' present`);
    }
    if (rawHeaders || rawHeaderNames || rawHeaderLines) {
      const { hostCount, clCount, hasDupPs } =
        hdrInfo.dupCounts && rawHeaders && !rawHeaderNames && !rawHeaderLines
          ? hdrInfo.dupCounts
          : countDuplicateSensitiveHeaders(rawHeaders, rawHeaderNames, rawHeaderLines);
      if (hostCount > 1) flag("DUPLICATE_HOST_HEADER", 8, `Duplicate Host headers (${hostCount}) detected`);
      if (clCount > 1) flag("DUPLICATE_CONTENT_LENGTH", 8, `Duplicate Content-Length headers (${clCount}) detected`);
      if (hasDupPs) flag("REPEATER_BODY_OR_PATH_TAMPERED", 10, "Duplicate X-PS-* Proof-of-Freshness header detected");
    }

    const cliUa = typeof hdrInfo.cliUa === "boolean" ? hdrInfo.cliUa : isCliOrProxyUa(ua, secChUa);
    const isAiCrawler =
      typeof hdrInfo.isAiCrawler === "boolean"
        ? hdrInfo.isAiCrawler
        : blockAiCrawlers && (hdrInfo.hasCrawlerPrefix || AI_CRAWLER_UA_RE.test(ua.trim()) || AI_CRAWLER_UA_RE.test(secChUa));
    const claimsModernBrowser =
      !cliUa &&
      !isAiCrawler &&
      (parseBrowserMajorChrome(ua) >= 80 || parseBrowserMajorFirefox(ua) >= 90);

    // Strict CORS preflight exemption (parsed ONLY when method === OPTIONS with non-empty ACRM & zero body/CL/TE!)
    if (upperMethod === "OPTIONS" && Boolean((h["access-control-request-method"] || "").trim())) {
      const hostHdr = normalizeHostDefaultPort(h["host"] || "");
      const xfhFirst = isFromTrustedProxy()
        ? normalizeHostDefaultPort(String(h["x-forwarded-host"] || "").split(",")[0] || "")
        : "";
      const originHost = parseHttpOriginHost(originHdr);
      const isSameOriginPreflight = Boolean(
        originHost && ((hostHdr && originHost === hostHdr) || (xfhFirst && originHost === xfhFirst))
      );
      const clTrimPre = Array.isArray(cl) ? cl.join(",").trim() : String(cl || "").trim();
      const hasBodyHdrPre = Boolean(te) || (clTrimPre !== "" && !/^0+$/.test(clTrimPre));
      const isCorsPreflight =
        Boolean(originHost) &&
        !isSameOriginPreflight &&
        bodyBuf.length === 0 &&
        !hasBodyHdrPre &&
        !hasAnyMethodOverride &&
        !hasProxyLeak &&
        !hdrInfo.hasAnyPsHeader &&
        !cliUa &&
        !isAiCrawler &&
        (!claimsModernBrowser || (secFetchMode === "cors" && (conn !== "close" || isFromTrustedProxy())));

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
          canaryAck: null,
          rehandshakeRecommended: false,
          redirectGetHint: false,
        };
        if ((blocked || score > 0) && onDetect) {
          try { onDetect({ ...preRes, ip: resolveNormIp(), method: upperMethod, path: pathname, sessionId: null }); } catch {}
        }
        return preRes;
      }
    }

    // --- Signal 2: Firecrawl/AI-Crawler, Browser UA vs. Repeater / CLI Wire & Metadata Contradictions ---
    if (isAiCrawler) {
      flag("AI_CRAWLER_OR_SCRAPER_DENIED", 6, "Firecrawl / AI crawler or scraping proxy signature detected");
    }

    if (claimsModernBrowser) {
      if (!secFetchSite && !secFetchMode && (isProtected || hasProxyLeak)) {
        flag("FETCH_METADATA_MISSING", 4, "Modern browser UA missing Sec-Fetch-Site/Sec-Fetch-Mode metadata");
      }
      if (isProtected && secFetchSite.includes("cross-site")) {
        flag("CROSS_SITE_REQUEST_BLOCKED", 6, "Cross-site Fetch Metadata on protected route");
      }
      if (conn === "close" && (isProtected || hasProxyLeak) && !isFromTrustedProxy()) {
        flag("REPEATER_CONNECTION_CLOSE", 3, "Modern browser UA sent HTTP/1.1 Connection: close");
      }
      if (bodyBuf.length > 0 && bodyBuf.length < 512 && te.includes("chunked") && !isFromTrustedProxy()) {
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
    } else if (cliUa && (isProtected || blockAutomationOnAllRoutes)) {
      flag("NON_BROWSER_REPLAY_CLIENT", 6, "Direct replay/CLI/automation client User-Agent detected");
    }

    // --- Signal 3: Cryptographic Single-Use Proof-of-Freshness + Rotating Canary + Signed Runtime Context ---
    let nextCanary = null;
    let canaryAck = null;
    let rehandshakeRecommended = false;
    let redirectGetHint = false;
    let nonceBurned = false;
    const hasAnyPsHeader = hdrInfo.hasAnyPsHeader;
    let psSid = "";

    if (isProtected || hasAnyPsHeader) {
      psSid = (h["x-ps-session"] || "").trim();
      const psSeqRaw = (h["x-ps-seq"] || "").trim();
      const psTsRaw = (h["x-ps-ts"] || "").trim();
      const psNonce = (h["x-ps-nonce"] || "").trim();
      const psCanary = (h["x-ps-canary"] || "").trim();
      const psProof = (h["x-ps-proof"] || "").trim();
      const psCtx = (h["x-ps-ctx"] || "").trim();
      const ctxMatch = hdrInfo.psCtxChecked ? hdrInfo.ctxMatch : (psCtx ? PS_CTX_RE.exec(psCtx) : null);
      if (!psSid || !psSeqRaw || !psTsRaw || !psNonce || !psProof || !psCanary) {
        if (isProtected) {
          flag(
            "REPEATER_PROOF_MISSING",
            mode === "strict" || mode === "paranoid" ? 8 : 6,
            "Missing ProxySnare single-use Proof-of-Freshness headers on protected route"
          );
        }
      } else if (
        hdrInfo.psSyntaxChecked
          ? (!hdrInfo.psSyntaxOk || upperMethod.includes("|"))
          : (
              !PS_NONCE_RE.test(psNonce) ||
              !PS_SID_RE.test(psSid) ||
              !PS_PROOF_RE.test(psProof) ||
              !PS_CANARY_RE.test(psCanary) ||
              (psCtx && !ctxMatch) ||
              psSeqRaw.includes("|") ||
              psTsRaw.includes("|") ||
              upperMethod.includes("|")
            )
      ) {
        flag("REPEATER_BODY_OR_PATH_TAMPERED", 10, "Malformed Proof-of-Freshness header syntax");
      } else {
        const sess = sessions.get(psSid);
        if (!sess || sess.exp <= now) {
          flag("REPEATER_UNKNOWN_OR_EXPIRED_SESSION", 8, "Proof references unknown or expired session");
          rehandshakeRecommended = true;
        } else {
          const pre =
            hdrInfo._preSess &&
            hdrInfo._preSess.sess === sess &&
            hdrInfo._preSess.canary === sess.canary &&
            hdrInfo._preSess.lastSeq === sess.lastSeq
              ? hdrInfo._preSess
              : null;
          const seq = pre ? pre.seq : (/^\d{1,15}$/.test(psSeqRaw) ? Number(psSeqRaw) : NaN);
          const validTsFormat = /^\d{1,15}(\.\d{1,4})?$/.test(psTsRaw);
          const ts = validTsFormat ? Number(psTsRaw) : NaN;
          const nonceKey = pre ? pre.nonceKey : `${psSid}:${psNonce}`;

          const prevNonceExp = usedNonces.get(nonceKey);
          const prevNonceUsed = Boolean(prevNonceExp && prevNonceExp > now);
          if (prevNonceUsed) {
            flag("REPEATER_NONCE_REPLAYED", 10, `Single-use nonce '${psNonce.slice(0, 12)}...' replayed (Repeater detected)`);
          }

          if (!Number.isSafeInteger(seq) || seq <= sess.lastSeq) {
            flag("REPEATER_SEQ_REPLAY", 8, `Non-monotonic sequence ${psSeqRaw} <= last ${sess.lastSeq}`);
          }

          const ageMs = now - ts;
          const staleOrDrift = !Number.isFinite(ts) || ageMs > freshnessMs || ageMs < -maxFutureSkewMs;
          if (staleOrDrift) {
            flag(
              "INTERCEPT_HOLD_OR_STALE_REPLAY",
              6,
              `Request age/skew ${Number.isFinite(ageMs) ? Math.round(ageMs) : "NaN"}ms outside [-${maxFutureSkewMs}, +${freshnessMs}]ms window`
            );
          }

          const canaryOk = pre ? pre.canaryOk : safeEqualHex(psCanary, sess.canary);
          if (!canaryOk) {
            flag("REPEATER_STALE_CANARY", 8, "Stale or tampered rotating honey-canary token (Repeater replay)");
          }

          // Skip 1MB body SHA-256 hashing when body was skipped by pre-body replay/header gate OR (in enforcing mode) when >4KB non-GET payload already failed nonce/canary!
          const skipSignProof =
            Boolean(bodySkipped) ||
            (mode !== "monitor" && bodyBuf.length > 4096 && upperMethod !== "GET" && upperMethod !== "HEAD" && (prevNonceUsed || !canaryOk));
          let proofValid = false;
          if (!skipSignProof) {
            const expectedProof = signRequest({
              sessionKeyBuf: sess.keyBuf,
              method: upperMethod,
              pathWithQuery,
              body: bodyBuf,
              seq: psSeqRaw,
              ts: psTsRaw,
              nonce: psNonce,
              canary: psCanary,
              ctx: psCtx,
            });
            proofValid = safeEqualHex(psProof, expectedProof);
          }
          if (!proofValid && !skipSignProof) {
            flag("REPEATER_BODY_OR_PATH_TAMPERED", 10, "HMAC proof mismatch — request body, path, query, context, or method was tampered in transit/Repeater");
          }

          let ugOk = false;
          let gaVal = 999_999;
          if (!psCtx && requireSignedContext) {
            flag("CONTEXT_HEADER_MISSING", 6, "Signed X-PS-Ctx runtime provenance header required in current security preset");
          } else if (ctxMatch) {
            const ce = ctxMatch[1] === "1";
            const cdp = ctxMatch[2] === "1";
            ugOk = ctxMatch[3] === "1";
            gaVal = Number(ctxMatch[4]);
            const ik = ctxMatch[5] === "1";
            if (ce) {
              flag(
                "CONSOLE_EVAL_DETECTED",
                blockConsoleEval ? (mode === "paranoid" ? 10 : 8) : 2,
                "Request originated from DevTools Console or CDP Runtime.evaluate stack"
              );
            }
            if (cdp && (blockCdpActive || !allowDevTools)) {
              const cdpW = blockCdpActive
                ? (mode === "strict" ? 4 : 6)
                : 1;
              flag(
                "CDP_ACTIVE_DETECTED",
                cdpW,
                "Active Chrome DevTools Protocol / debugger session detected in browser"
              );
            }
            if (ik) {
              flag(
                "SYNTHETIC_INTERACTION",
                6,
                "Synthetic or teleported click kinematics detected on triggering interaction"
              );
            }
          }
          // Enforce requireUserGestureOnMutate even when X-PS-Ctx is omitted (PS1| signing) so attackers cannot strip X-PS-Ctx to bypass gesture checks!
          const effectiveMutating = MUTATING_METHODS.has(upperMethod) || overrideMutating;
          let gestureApplies = requireUserGestureOnMutate && effectiveMutating;
          if (gestureApplies && (gestureExemptPaths || gestureProtectedPaths)) {
            const pathCands = getPathCands();
            // Exclusion lists MUST require ALL expanded path variants to match (prevents /api/telemetry/../transfer traversal bypass!)
            if (gestureExemptPaths && pathCands.length > 0 && pathCands.every((c) => matchesCompiledRules([c], gestureExemptPaths))) {
              gestureApplies = false;
            } else if (gestureProtectedPaths && !matchesCompiledRules(pathCands, gestureProtectedPaths)) {
              gestureApplies = false;
            }
          }
          if (gestureApplies && (!ctxMatch || !ugOk || gaVal > userGestureWindowMs)) {
            flag(
              "MUTATION_WITHOUT_USER_GESTURE",
              6,
              `State-changing ${upperMethod} lacked a recent trusted pointer/keyboard gesture (age=${gaVal}ms)`
            );
          }

          const uaMatches = pre
            ? pre.uaMatches
            : (typeof sess.ua === "string"
                ? sess.ua === (ua || "")
                : safeEqualHex(sess.uaHash, sha256Hex(ua || "")));
          if (!uaMatches) {
            flag("REPEATER_UA_SESSION_MISMATCH", 6, "User-Agent changed mid-session");
          }
          const clientNormIp = bindIp && sess.ip ? resolveNormIp() : "";
          const ipMismatch = Boolean(bindIp && sess.ip && clientNormIp && sess.ip !== clientNormIp);
          if (ipMismatch) {
            flag("REPEATER_IP_SESSION_MISMATCH", 6, "Client IP changed mid-session");
          }
          if (sess.origin && originHdr && sess.origin !== originHdr) {
            flag("REPEATER_ORIGIN_MISMATCH", 6, "Origin changed mid-session");
          }

          // Detect Post-Redirect-Get (POST -> 302/303 -> GET): browser re-sent the immediately preceding POST's X-PS-* headers on a redirected GET
          // Checks seq === sess.lastSeq > 0 so multi-worker deployments also emit X-PS-Redirect-Get even when GET lands on a different worker!
          if (
            (upperMethod === "GET" || upperMethod === "HEAD") &&
            !proofValid &&
            uaMatches &&
            !ipMismatch &&
            Number.isSafeInteger(seq) &&
            seq > 0 &&
            seq === sess.lastSeq
          ) {
            redirectGetHint = true;
          }

          // Allow legitimate mobile Wi-Fi<->5G roaming & post-sleep clock resync to recover transparently
          // ONLY when the client proved knowledge of the valid session key (and wasn't replaying a nonce/canary)
          if (proofValid && canaryOk && !prevNonceUsed && (ipMismatch || staleOrDrift)) {
            rehandshakeRecommended = true;
          }

          if (proofValid) {
            if (prevNonceExp !== undefined) usedNonces.delete(nonceKey);
            usedNonces.set(nonceKey, now + nonceTtlMs);
            nonceBurned = true;
          }
          const validAdvance =
            proofValid &&
            Number.isSafeInteger(seq) &&
            seq > sess.lastSeq &&
            canaryOk;
          if (validAdvance && (score < threshold || mode === "monitor")) {
            sess.lastSeq = seq;
            sess.canary = mintCanary();
            nextCanary = sess.canary;
            canaryAck = `${sess.sessionId.slice(0, 8)}:${seq}`;
          }
        }
      }
    }

    // --- Signal 4: Per-IP Rapid Identical Unsigned Replay Burst ---
    if (isProtected && bodyBuf.length > 0 && !hasAnyPsHeader && !(mode !== "monitor" && score >= threshold && bodyBuf.length > 4096)) {
      const burstIp = resolveNormIp();
      const sig = sha256Hex(`${upperMethod}|${pathWithQuery}|${sha256Hex(bodyBuf)}`);
      const arr = (ipBursts.get(burstIp) || []).filter((e) => now - e.ts <= 5_000);
      const sameCount = arr.filter((e) => e.sig === sig).length;
      arr.push({ ts: now, sig });
      ipBursts.delete(burstIp);
      ipBursts.set(burstIp, arr.slice(-30));
      if (sameCount >= 3) {
        flag("REPEATER_BURST_REPLAY", 5, `Identical unsigned payload replayed ${sameCount + 1}x in 5s`);
      }
    }

    // Hard fail-closed invariant: if the request body stream was skipped before HMAC verification in enforcing mode, never allow HTTP 200!
    if (bodySkipped && mode !== "monitor" && score < threshold) {
      flag(
        "REPEATER_BODY_OR_PATH_TAMPERED",
        Math.max(10, threshold - score),
        "Request body was skipped by pre-body gate before cryptographic proof verification"
      );
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
      canaryAck,
      rehandshakeRecommended,
      redirectGetHint,
    };
    Object.defineProperty(result, "_nonceBurned", { value: nonceBurned });
    if ((blocked || score > 0) && onDetect) {
      try {
        onDetect({ ...result, ip: resolveNormIp(), method: upperMethod, path: pathname, sessionId: psSid || null });
      } catch {
        // never crash request pipeline on user telemetry hook
      }
    }
    return result;
  }

  function exportSessionRecord(sid) {
    const rec = sessions.get(sid);
    if (!rec || rec.exp <= Date.now()) return null;
    return {
      sessionId: rec.sessionId,
      keyB64: rec.keyBuf.toString("base64"),
      lastSeq: rec.lastSeq,
      canary: rec.canary,
      ua: typeof rec.ua === "string" ? rec.ua : undefined,
      uaHash: rec.uaHash,
      ip: rec.ip,
      origin: rec.origin,
      exp: rec.exp,
    };
  }

  function importSessionRecord(snap) {
    if (!snap || typeof snap !== "object" || typeof snap.sessionId !== "string" || typeof snap.keyB64 !== "string") return false;
    const now = Date.now();
    if (!Number.isFinite(snap.exp) || snap.exp <= now) return false;
    const keyBuf = Buffer.from(snap.keyB64, "base64");
    if (keyBuf.length !== 32) return false;
    hasImportedSessions = true;
    // Delete existing entry first so re-insertion refreshes LRU tail order and enforces maxSessions bound in O(1) amortized!
    sessions.delete(snap.sessionId);
    if (sessions.size >= maxSessions) {
      if (now - lastFullSessionSweepMs >= 5_000) {
        sweepExpiredSessions(now);
      }
      if (sessions.size >= maxSessions) {
        const target = Math.floor(maxSessions * 0.85);
        for (const k of sessions.keys()) {
          sessions.delete(k);
          if (sessions.size <= target) break;
        }
      }
    }
    sessions.set(snap.sessionId, {
      sessionId: snap.sessionId,
      keyBuf,
      lastSeq: Number(snap.lastSeq || 0),
      canary: String(snap.canary || ""),
      ua: typeof snap.ua === "string" ? snap.ua : null,
      uaHash: String(snap.uaHash || ""),
      ip: String(snap.ip || ""),
      origin: String(snap.origin || ""),
      exp: snap.exp,
    });
    return true;
  }

  return {
    mode,
    preset,
    threshold,
    freshnessMs,
    handshakePowBits,
    requireBootToken,
    bindIp,
    blockAiCrawlers,
    blockConsoleEval,
    blockCdpActive,
    allowDevTools,
    blockAutomationOnAllRoutes,
    requireUserGestureOnMutate,
    requireSignedContext,
    requireGuardIntegrity,
    ecdsaHandshakeAuth,
    sri,
    hasPersistentSecret,
    sessionTtlMs,
    nonceTtlMs,
    bootTokenTtlMs,
    userGestureWindowMs,
    serverVerifyPubB64: signingKeys.publicKeyRawB64,
    protectedPaths,
    trustedProxies,
    isPathProtected: (p) => isPathProtected(p, compiledProtectedPaths, true),
    inspectPathProtection: (rawUrl, preCleanPath = null) => {
      if (compiledProtectedPaths.matchAll) return { protected: true, cands: null };
      if (preCleanPath !== null) {
        const cands = [preCleanPath];
        return { protected: matchesCompiledRules(cands, compiledProtectedPaths), cands };
      }
      const cands = expandPathCandidates(rawUrl);
      return { protected: matchesCompiledRules(cands, compiledProtectedPaths), cands };
    },
    hasProtectedOverrideHeader: (hdrs) => hasProtectedOverrideHeader(hdrs, compiledProtectedPaths),
    allowHandshake,
    allowBoot,
    allowHtmlBoot,
    issueBootChallenge,
    consumeBootChallenge,
    issueSession,
    verifyHandshakeSignature,
    signRequest,
    inspectRequest,
    hasActiveSession: (sid, now = Date.now()) => {
      const s = sessions.get(sid);
      return Boolean(s && s.exp > now);
    },
    // O(1) read-only active-session header replay precheck BEFORE 1MB body buffering (strictly disjoint from evaluatePreBodyMinScore; preserves ipMismatch/staleOrDrift proof recovery!)
    precheckSessionHeaders: (hdrInfo, now = Date.now()) => {
      const h = hdrInfo && hdrInfo.map ? hdrInfo.map : {};
      const psSid = (h["x-ps-session"] || "").trim();
      const sess = sessions.get(psSid);
      if (!sess || sess.exp <= now) return { pen: 8, hasLiveCanaryNonce: false };
      let pen = 0;
      const psSeqRaw = (h["x-ps-seq"] || "").trim();
      const psNonce = (h["x-ps-nonce"] || "").trim();
      const psCanary = (h["x-ps-canary"] || "").trim();
      const psCtx = (h["x-ps-ctx"] || "").trim();
      const nonceKey = `${psSid}:${psNonce}`;
      const prevNonceExp = usedNonces.get(nonceKey);
      const prevNonceUsed = Boolean(prevNonceExp && prevNonceExp > now);
      if (prevNonceUsed) pen += 10;
      const canaryOk = safeEqualHex(psCanary, sess.canary);
      if (!canaryOk) pen += 8;
      const validSeq = /^\d{1,15}$/.test(psSeqRaw);
      const seqNum = validSeq ? Number(psSeqRaw) : NaN;
      const seqOk = Number.isSafeInteger(seqNum) && seqNum > sess.lastSeq;
      if (!seqOk) pen += 8;
      if (!psCtx && requireSignedContext) {
        pen += 6;
      } else {
        const ctxMatch = hdrInfo && hdrInfo.psCtxChecked ? hdrInfo.ctxMatch : (psCtx ? PS_CTX_RE.exec(psCtx) : null);
        if (ctxMatch) {
          if (ctxMatch[1] === "1") pen += blockConsoleEval ? (mode === "paranoid" ? 10 : 8) : 2;
          if (ctxMatch[2] === "1" && (blockCdpActive || !allowDevTools)) {
            pen += blockCdpActive ? (mode === "strict" ? 4 : 6) : 1;
          }
          if (ctxMatch[5] === "1") pen += 6;
        }
      }
      const ua = h["user-agent"] || "";
      const uaMatches = typeof sess.ua === "string" ? sess.ua === ua : safeEqualHex(sess.uaHash, sha256Hex(ua));
      if (!uaMatches) pen += 6;
      const originHdr = (h["origin"] || "").trim().toLowerCase();
      if (sess.origin && originHdr && sess.origin !== originHdr) pen += 6;
      if (hdrInfo) {
        // Never cache mutable usedNonces state across await readRequestBody() (prevents TOCTOU single-use nonce replay & expiry-order drift!)
        hdrInfo._preSess = { now, sess, canary: sess.canary, lastSeq: sess.lastSeq, nonceKey, canaryOk, seq: seqNum, uaMatches };
      }
      return { pen, hasLiveCanaryNonce: Boolean(canaryOk && !prevNonceUsed && seqOk) };
    },
    exportSessionRecord,
    importSessionRecord,
    serializeProtectedPathsForClient,
    extractClientIp: (req, expressTrustsProxy = null, precheckedTrustedProxy = null) =>
      extractClientIp(req, trustedProxies, expressTrustsProxy, precheckedTrustedProxy),
  };
}

function evaluatePreBodyMinScore(
  headers,
  {
    mode,
    blockAiCrawlers,
    blockAutomationOnAllRoutes = false,
    hasSession = null,
    isProtected = true,
    overrideProtected = false,
    method = "",
    rawHeaders = null,
    skipOverrides = false,
    now = Date.now(),
  }
) {
  const hdrInfo = normalizeHeaderInfo(headers, skipOverrides);
  const h = hdrInfo.map;
  const psSid = (h["x-ps-session"] || "").trim();
  const psSeq = (h["x-ps-seq"] || "").trim();
  const psTs = (h["x-ps-ts"] || "").trim();
  const psNonce = (h["x-ps-nonce"] || "").trim();
  const psCanary = (h["x-ps-canary"] || "").trim();
  const psProof = (h["x-ps-proof"] || "").trim();
  const psCtx = (h["x-ps-ctx"] || "").trim();
  const hasRequiredPsProofHdrs = Boolean(psSid && psSeq && psTs && psNonce && psCanary && psProof);
  let guaranteed = 0;
  if (overrideProtected) guaranteed += 6;
  if (isProtected && method) {
    const upperM = String(method).toUpperCase();
    let ovCnt = 0;
    let ovMis = false;
    let ovMut = false;
    let ovDisp = "";
    for (let i = 0; i < METHOD_OVERRIDE_HEADER_NAMES.length; i++) {
      const ovVal = (h[METHOD_OVERRIDE_HEADER_NAMES[i]] || "").trim().toUpperCase();
      if (!ovVal) continue;
      ovCnt += 1;
      if (!ovDisp) ovDisp = ovVal;
      if (ovVal !== upperM) {
        ovMis = true;
        ovDisp = ovVal;
      }
      if (MUTATING_METHODS.has(ovVal)) ovMut = true;
    }
    hdrInfo.methodOverride = { method: upperM, count: ovCnt, mismatch: ovMis, mutating: ovMut, display: ovDisp };
    if (ovCnt > 1 || ovMis) guaranteed += 6;
  }
  if (Array.isArray(rawHeaders) && rawHeaders.length > 0) {
    const dupCounts = countDuplicateSensitiveHeaders(rawHeaders, null, null);
    hdrInfo.dupCounts = dupCounts;
    if (dupCounts.hostCount > 1) guaranteed += 8;
    if (dupCounts.clCount > 1) guaranteed += 8;
    if (dupCounts.hasDupPs) guaranteed += 10;
  }
  if (!hasRequiredPsProofHdrs) {
    if (isProtected) guaranteed += mode === "strict" || mode === "paranoid" ? 8 : 6;
  } else {
    const ctxMatch = psCtx ? PS_CTX_RE.exec(psCtx) : null;
    hdrInfo.psCtxChecked = true;
    hdrInfo.ctxMatch = ctxMatch;
    const syntaxOk =
      PS_SID_RE.test(psSid) &&
      PS_NONCE_RE.test(psNonce) &&
      PS_CANARY_RE.test(psCanary) &&
      PS_PROOF_RE.test(psProof) &&
      (!psCtx || Boolean(ctxMatch)) &&
      !psSeq.includes("|") &&
      !psTs.includes("|");
    hdrInfo.psSyntaxChecked = true;
    hdrInfo.psSyntaxOk = syntaxOk;
    if (!syntaxOk) {
      // Malformed X-PS-* syntax immediately fails in inspectRequest without hashing bodyBuf (prevents 6x 1-byte dummy header 1MB buffering DoS!)
      guaranteed += 10;
    } else if (typeof hasSession === "function" && !hasSession(psSid, now)) {
      // Unknown/expired session immediately fails with X-PS-Rehandshake: 1 without hashing bodyBuf (session-dependent psSeq/ctx checks live in precheckSessionHeaders!)
      guaranteed += 8;
    }
  }
  if (h["content-length"] && h["transfer-encoding"]) guaranteed += 10;
  guaranteed += hdrInfo.proxyLeaks.length * 5;
  const ua = h["user-agent"] || "";
  const secChUa = h["sec-ch-ua"] || "";
  const isAi =
    Boolean(blockAiCrawlers) &&
    (hdrInfo.hasCrawlerPrefix || AI_CRAWLER_UA_RE.test(ua.trim()) || AI_CRAWLER_UA_RE.test(secChUa));
  const cliUa = isCliOrProxyUa(ua, secChUa);
  hdrInfo.isAiCrawler = isAi;
  hdrInfo.cliUa = cliUa;
  if (isAi) guaranteed += 6;
  if (cliUa && (isProtected || blockAutomationOnAllRoutes)) guaranteed += 6;
  if (
    isProtected &&
    !cliUa &&
    !isAi &&
    (h["sec-fetch-site"] || "").toLowerCase().includes("cross-site") &&
    (parseBrowserMajorChrome(ua) >= 80 || parseBrowserMajorFirefox(ua) >= 90)
  ) {
    guaranteed += 6;
  }
  return { hdrInfo, guaranteed };
}

module.exports = {
  PROXY_LEAK_HEADERS,
  createProxySnareEngine,
  normalizeMode,
  resolvePreset,
  normalizePathname,
  CLEAN_ASCII_PATH_RE,
  stripSchemeAndAuthority,
  normalizeHostDefaultPort,
  parseHttpOriginHost,
  parseBrowserMajorChrome,
  parseBrowserMajorFirefox,
  isCliOrProxyUa,
  isAiCrawlerRequest,
  countDuplicateSensitiveHeaders,
  hasValidPsProofSyntax,
  evaluatePreBodyMinScore,
  verifyPowSolution,
  solvePowChallenge,
  sha256Hex,
  safeEqualHex,
  hmacSha256Hex,
};
