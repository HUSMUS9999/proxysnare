"""
ProxySnare Python Verifier (Zero Dependencies, Python >= 3.10).
Wire- and scoring-compatible with the Node.js `proxysnare` v2 engine and browser guard:
  - Ephemeral NIST P-256 ECDH + HKDF-SHA256 (`PS_ECDH_V2`) in pure Python stdlib
  - Single-use `(ip, uaHash)`-bound HMAC boot tokens + SHA-256 PoW verification
  - Single-use `PS1|` HMAC-SHA256 Proof-of-Freshness + rotating honey-canary
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import json
import math
import os
import posixpath
import re
import secrets
import threading
import time
from dataclasses import dataclass, field
from urllib.parse import urlsplit

# NIST P-256 (secp256r1 / prime256v1) curve parameters (FIPS 186-4)
_P256_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
_P256_A = _P256_P - 3
_P256_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
_P256_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
_P256_G = (
    0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296,
    0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5,
)

_CLI_OR_PROXY_UA_RE = re.compile(
    r"burp|caido|mitmproxy|sqlmap|ffuf|nuclei|curl/|wget/|python-requests|python-urllib|"
    r"python-httpx|aiohttp|go-http-client|httpie|libwww-perl|java/|okhttp|axios/|"
    r"node-fetch|undici|insomnia|postman|headlesschrome|playwright|puppeteer|phantomjs|slimerjs",
    re.I,
)

_AI_CRAWLER_UA_RE = re.compile(
    r"firecrawl|mendable|apify|crawlee|browserless|scrapingbee|zenrows|brightdata|"
    r"oxylabs|stagehand|browser-?use|steel-?browser|gptbot|oai-searchbot|chatgpt-user|"
    r"claudebot|claude-web|anthropic-ai|perplexitybot|ccbot|bytespider|diffbot|scrapy|"
    r"colly|zyte|phantombuster|hyperbrowser|browserbase",
    re.I,
)

_CRAWLER_HEADER_PREFIXES = ("x-firecrawl-", "x-apify-", "x-browserless-", "x-scrapingbee-")
_MUTATING_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})
_CTX_RE = re.compile(r"^ce=([01]);cdp=([01]);ug=([01]);ga=([0-9]{1,7})(?:;ik=([01]))?$")


def _p256_on_curve(pt: tuple[int, int]) -> bool:
    x, y = pt
    if not (0 <= x < _P256_P and 0 <= y < _P256_P):
        return False
    return (y * y - (x * x * x + _P256_A * x + _P256_B)) % _P256_P == 0


def _p256_jac_double(pt: tuple[int, int, int]) -> tuple[int, int, int]:
    x1, y1, z1 = pt
    if z1 == 0 or y1 == 0:
        return (0, 1, 0)
    p = _P256_P
    s = (4 * x1 * y1 * y1) % p
    z2 = (z1 * z1) % p
    # a = -3 shortcut: m = 3*(x1 - z1^2)*(x1 + z1^2)
    m = (3 * (x1 - z2) * (x1 + z2)) % p
    x3 = (m * m - 2 * s) % p
    y3 = (m * (s - x3) - 8 * pow(y1, 4, p)) % p
    z3 = (2 * y1 * z1) % p
    return (x3, y3, z3)


def _p256_jac_add(p1: tuple[int, int, int], p2: tuple[int, int, int]) -> tuple[int, int, int]:
    x1, y1, z1 = p1
    x2, y2, z2 = p2
    if z1 == 0:
        return p2
    if z2 == 0:
        return p1
    p = _P256_P
    z1_2 = (z1 * z1) % p
    z2_2 = (z2 * z2) % p
    u1 = (x1 * z2_2) % p
    u2 = (x2 * z1_2) % p
    s1 = (y1 * z2_2 * z2) % p
    s2 = (y2 * z1_2 * z1) % p
    if u1 == u2:
        if s1 != s2:
            return (0, 1, 0)
        return _p256_jac_double(p1)
    h = (u2 - u1) % p
    r = (s2 - s1) % p
    h2 = (h * h) % p
    h3 = (h2 * h) % p
    x3 = (r * r - h3 - 2 * u1 * h2) % p
    y3 = (r * (u1 * h2 - x3) - s1 * h3) % p
    z3 = (h * z1 * z2) % p
    return (x3, y3, z3)


def _p256_scalar_mul(k: int, pt: tuple[int, int]) -> tuple[int, int] | None:
    if k <= 0 or k >= _P256_N:
        return None
    res = (0, 1, 0)
    addend = (pt[0], pt[1], 1)
    n = k
    while n > 0:
        if n & 1:
            res = _p256_jac_add(res, addend)
        addend = _p256_jac_double(addend)
        n >>= 1
    if res[2] == 0:
        return None
    z_inv = pow(res[2], -1, _P256_P)
    z_inv2 = (z_inv * z_inv) % _P256_P
    z_inv3 = (z_inv2 * z_inv) % _P256_P
    return ((res[0] * z_inv2) % _P256_P, (res[1] * z_inv3) % _P256_P)


def _p256_decode_uncompressed(b64_str: object) -> tuple[tuple[int, int], str] | None:
    if not isinstance(b64_str, str):
        return None
    raw_s = b64_str.strip()
    if not re.fullmatch(r"[A-Za-z0-9+/=_-]{80,120}", raw_s):
        return None
    norm = raw_s.replace("-", "+").replace("_", "/")
    pad = (-len(norm)) % 4
    try:
        buf = base64.b64decode(norm + ("=" * pad), validate=True)
    except Exception:
        return None
    if len(buf) != 65 or buf[0] != 0x04:
        return None
    canon = base64.b64encode(buf).decode("ascii")
    if canon.rstrip("=") != norm.rstrip("="):
        return None
    pt = (int.from_bytes(buf[1:33], "big"), int.from_bytes(buf[33:65], "big"))
    if not _p256_on_curve(pt):
        return None
    return pt, canon


def _p256_encode_uncompressed(pt: tuple[int, int]) -> str:
    raw = b"\x04" + pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")
    return base64.b64encode(raw).decode("ascii")


def _p256_scalar_mul_consttime(k: int, pt: tuple[int, int]) -> tuple[int, int] | None:
    """
    Fixed-257-bit constant-work Montgomery ladder over Jacobian coordinates to prevent
    Minerva/CVE-2019-1547 bit-length and Hamming-weight timing leaks on secret scalars.
    """
    if k <= 0 or k >= _P256_N:
        return None
    # Normalize scalar to an exact 257-bit representation (k_eff === k mod N)
    k_eff = k + _P256_N
    if k_eff.bit_length() == 256:
        k_eff += _P256_N
    r0 = (0, 1, 0)
    r1 = (pt[0], pt[1], 1)
    for bit_idx in range(256, -1, -1):
        bit = (k_eff >> bit_idx) & 1
        sum_pt = _p256_jac_add(r0, r1)
        if bit == 0:
            r1 = sum_pt
            r0 = _p256_jac_double(r0)
        else:
            r0 = sum_pt
            r1 = _p256_jac_double(r1)
    if r0[2] == 0:
        return None
    z_inv = pow(r0[2], -1, _P256_P)
    z_inv2 = (z_inv * z_inv) % _P256_P
    z_inv3 = (z_inv2 * z_inv) % _P256_P
    return ((r0[0] * z_inv2) % _P256_P, (r0[1] * z_inv3) % _P256_P)


def _p256_ecdsa_sign_raw(priv_d: int, msg: bytes) -> bytes:
    """Pure-stdlib NIST P-256 ECDSA IEEE-P1363 raw 64-byte (r||s) signature (Minerva-hardened)."""
    z = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    for _ in range(64):
        k = 1 + secrets.randbelow(_P256_N - 1)
        pt = _p256_scalar_mul_consttime(k, _P256_G)
        if pt is None:
            continue
        r = pt[0] % _P256_N
        if r == 0:
            continue
        s = (pow(k, -1, _P256_N) * (z + r * priv_d)) % _P256_N
        if s == 0:
            continue
        return r.to_bytes(32, "big") + s.to_bytes(32, "big")
    raise RuntimeError("ECDSA_SIGN_FAILED")


def _p256_ecdsa_verify_raw(pub_pt: tuple[int, int], msg: bytes, sig_raw: bytes) -> bool:
    if len(sig_raw) != 64:
        return False
    r = int.from_bytes(sig_raw[:32], "big")
    s = int.from_bytes(sig_raw[32:], "big")
    if not (1 <= r < _P256_N and 1 <= s < _P256_N):
        return False
    z = int.from_bytes(hashlib.sha256(msg).digest(), "big")
    w = pow(s, -1, _P256_N)
    u1 = (z * w) % _P256_N
    u2 = (r * w) % _P256_N
    p1 = _p256_scalar_mul(u1, _P256_G) if u1 != 0 else None
    p2 = _p256_scalar_mul(u2, pub_pt) if u2 != 0 else None
    if p1 is None and p2 is None:
        return False
    if p1 is None:
        res = p2
    elif p2 is None:
        res = p1
    else:
        jac = _p256_jac_add((p1[0], p1[1], 1), (p2[0], p2[1], 1))
        if jac[2] == 0:
            return False
        zi = pow(jac[2], -1, _P256_P)
        zi2 = (zi * zi) % _P256_P
        zi3 = (zi2 * zi) % _P256_P
        res = ((jac[0] * zi2) % _P256_P, (jac[1] * zi3) % _P256_P)
    assert res is not None
    return (res[0] % _P256_N) == r


_MAX_OVERRIDE_PARTS = 16
_EMPTY_SHA256_HEX = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"


def _append_override_candidates(dest: list[str], raw: object) -> bool:
    if isinstance(raw, (list, tuple)):
        for item in raw:
            if _append_override_candidates(dest, item):
                return True
        return False
    if not isinstance(raw, str):
        return False
    s = raw.strip()
    if not s:
        return False
    if len(dest) >= _MAX_OVERRIDE_PARTS:
        return True
    dest.append(s)
    if "," in s:
        parts = s.split(",", _MAX_OVERRIDE_PARTS + 1)
        if len(parts) > _MAX_OVERRIDE_PARTS + 1:
            return True
        seen = 0
        for part in parts:
            pt = part.strip()
            if pt:
                seen += 1
                if seen > _MAX_OVERRIDE_PARTS or len(dest) >= _MAX_OVERRIDE_PARTS:
                    return True
                dest.append(pt)
    return False


def _normalize_headers(headers: object | None) -> tuple[dict[str, str], list[str], bool, bool]:
    if headers is None or not callable(getattr(headers, "items", None)):
        return {}, [], False, False
    hdr: dict[str, str] = {}
    override_urls: list[str] = []
    override_excessive = False
    has_crawler_prefix = False
    for k, v in headers.items():
        kl = str(k).lower()
        if not has_crawler_prefix and kl.startswith(_CRAWLER_HEADER_PREFIXES):
            has_crawler_prefix = True
        if not override_excessive and kl in ("x-original-url", "x-rewrite-url"):
            if _append_override_candidates(override_urls, v):
                override_excessive = True
        val = ", ".join("" if x is None else str(x) for x in v) if isinstance(v, (list, tuple)) else ("" if v is None else str(v))
        if kl in hdr:
            if val:
                hdr[kl] = f"{hdr[kl]}, {val}" if hdr[kl] else val
        else:
            hdr[kl] = val
    return hdr, override_urls, override_excessive, has_crawler_prefix


def _is_ai_crawler_norm(hdr: dict[str, str], has_crawler_prefix: bool | None = None) -> bool:
    if has_crawler_prefix is True:
        return True
    if has_crawler_prefix is None and any(k.startswith(_CRAWLER_HEADER_PREFIXES) for k in hdr):
        return True
    ua = hdr.get("user-agent", "")
    sec_ch = hdr.get("sec-ch-ua", "")
    return bool(_AI_CRAWLER_UA_RE.search(ua) or _AI_CRAWLER_UA_RE.search(sec_ch))


def is_ai_crawler_request(headers: object | None) -> bool:
    if not headers:
        return False
    hdr, _, _, has_crawler_prefix = _normalize_headers(headers)
    return _is_ai_crawler_norm(hdr, has_crawler_prefix)


def _canonicalize_host_port(host_raw: str) -> str:
    s = str(host_raw or "").strip().lower()
    if not s:
        return ""
    if s.startswith("["):
        end_b = s.find("]")
        if end_b < 0:
            return s
        ip_part = s[1:end_b]
        rest = s[end_b + 1 :]
        try:
            ip_part = str(ipaddress.IPv6Address(ip_part))
        except ValueError:
            pass
        if rest in (":80", ":443"):
            rest = ""
        return f"[{ip_part}]{rest}"
    if s.endswith(":80"):
        return s[:-3]
    if s.endswith(":443"):
        return s[:-4]
    return s


def _hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int = 32) -> bytes:
    prk = hmac.new(salt if salt else bytes(32), ikm, hashlib.sha256).digest()
    okm = bytearray()
    t = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm.extend(t)
        counter += 1
    return bytes(okm[:length])


def _sha256_bytes(data: bytes | str) -> bytes:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).digest()


def _sha256_hex(data: bytes | str) -> str:
    if not data:
        return _EMPTY_SHA256_HEX
    return _sha256_bytes(data).hex()


def _hmac_hex(key: bytes, msg: str) -> str:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).hexdigest()


def _count_leading_zero_bits(buf: bytes) -> int:
    bits = 0
    for byte in buf:
        if byte == 0:
            bits += 8
            continue
        bits += 8 - byte.bit_length()
        break
    return bits


def verify_pow_solution(prefix: str, challenge: str, pow_nonce: str, difficulty: int) -> bool:
    if not isinstance(difficulty, int) or isinstance(difficulty, bool) or difficulty <= 0:
        return True
    if not challenge or not isinstance(pow_nonce, str):
        return False
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", pow_nonce):
        return False
    digest = _sha256_bytes(f"{prefix}|{challenge}|{pow_nonce}")
    return _count_leading_zero_bits(digest) >= difficulty


_HEADLESS_RE = re.compile(r"HeadlessChrome", re.I)
_CHROME_VER_RE = re.compile(r"Chrome/([0-9]+)", re.I)
_FIREFOX_VER_RE = re.compile(r"Firefox/([0-9]+)", re.I)
_PS_NONCE_RE = re.compile(r"[A-Za-z0-9_-]{8,64}")
_PS_SID_RE = re.compile(r"[a-fA-F0-9]{16,64}")
_PS_PROOF_RE = re.compile(r"[a-fA-F0-9]{64}")
_PS_CANARY_RE = re.compile(r"[a-fA-F0-9]{16,64}")
_PS_SEQ_RE = re.compile(r"[0-9]{1,15}")
_PS_TS_RE = re.compile(r"[0-9]{1,15}(?:\.[0-9]{1,4})?")
_ORIGIN_NETLOC_RE = re.compile(r"[a-z0-9._\-:\[\]]+", re.I)
_IPV4_PART_RE = re.compile(r"(?:0x[0-9a-f]*|0[0-7]*|[1-9][0-9]*)")
_IPV4_LAST_NUMERIC_RE = re.compile(r"(?:0x[0-9a-f]*|[0-9]+)")
_ZEROS_RE = re.compile(r"0+")


def is_cli_or_proxy_ua(ua: str, sec_ch_ua: str = "") -> bool:
    s = str(ua or "").strip()
    if not s:
        return True
    if _CLI_OR_PROXY_UA_RE.search(s):
        return True
    if _HEADLESS_RE.search(str(sec_ch_ua or "")):
        return True
    return False


def _normalize_ip(ip: str) -> str:
    s = str(ip or "").strip().lower()
    if s.startswith("::ffff:"):
        s = s[7:]
    return "127.0.0.1" if s == "::1" else s


_PCT_RUN_RE = re.compile(r"(?:%[0-9a-fA-F]{2})+")
_HEX_VAL = {
    **{ord(str(d)): d for d in range(10)},
    **{ord(c): 10 + i for i, c in enumerate("abcdef")},
    **{ord(c): 10 + i for i, c in enumerate("ABCDEF")},
}


def _hex_byte(s: str, idx: int) -> int:
    return (_HEX_VAL[ord(s[idx + 1])] << 4) | _HEX_VAL[ord(s[idx + 2])]


def _decode_percent_lenient(s: str) -> str:
    if "%" not in s:
        return s

    def _repl(match: re.Match[str]) -> str:
        run = match.group(0)
        out: list[str] = []
        i = 0
        n_run = len(run)
        while i < n_run:
            b = _hex_byte(run, i)
            if b == 0x00:
                out.append("\0")
                i += 3
                continue
            if b <= 0x7F:
                out.append(chr(b))
                i += 3
                continue
            # Zero-exception RFC 3629 UTF-8 leading-byte decoder
            if 0xC2 <= b <= 0xDF and i + 6 <= n_run:
                b2 = _hex_byte(run, i + 3)
                if (b2 & 0xC0) == 0x80:
                    out.append(chr(((b & 0x1F) << 6) | (b2 & 0x3F)))
                    i += 6
                    continue
            elif 0xE0 <= b <= 0xEF and i + 9 <= n_run:
                b2 = _hex_byte(run, i + 3)
                b3 = _hex_byte(run, i + 6)
                valid_b2 = (
                    (0xA0 <= b2 <= 0xBF)
                    if b == 0xE0
                    else ((0x80 <= b2 <= 0x9F) if b == 0xED else ((b2 & 0xC0) == 0x80))
                )
                if valid_b2 and (b3 & 0xC0) == 0x80:
                    out.append(chr(((b & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F)))
                    i += 9
                    continue
            elif 0xF0 <= b <= 0xF4 and i + 12 <= n_run:
                b2 = _hex_byte(run, i + 3)
                b3 = _hex_byte(run, i + 6)
                b4 = _hex_byte(run, i + 9)
                valid_b2 = (
                    (0x90 <= b2 <= 0xBF)
                    if b == 0xF0
                    else ((0x80 <= b2 <= 0x8F) if b == 0xF4 else ((b2 & 0xC0) == 0x80))
                )
                if valid_b2 and (b3 & 0xC0) == 0x80 and (b4 & 0xC0) == 0x80:
                    out.append(chr(((b & 0x07) << 18) | ((b2 & 0x3F) << 12) | ((b3 & 0x3F) << 6) | (b4 & 0x3F)))
                    i += 12
                    continue
            out.append(run[i : i + 3])
            i += 3
        return "".join(out)

    return _PCT_RUN_RE.sub(_repl, s)


_HTTP_SCHEME_RE = re.compile(r"^https?://", re.I)


def _strip_scheme_and_authority(raw_url: str) -> str:
    s = str(raw_url or "/").lstrip()
    if not s:
        return "/"
    if s[0] == "/":
        return s
    if _HTTP_SCHEME_RE.match(s):
        after = s.find("://") + 3
        cuts = [
            idx
            for idx in (s.find("/", after), s.find("\\", after), s.find("?", after), s.find("#", after))
            if idx >= 0
        ]
        if not cuts:
            return "/"
        first = min(cuts)
        if s[first] == "/":
            s = s[first:]
        elif s[first] == "\\":
            s = "/" + s[first + 1 :]
        else:
            s = "/" + s[first:]
    return s


def _clean_path_no_collapse(raw_path: str) -> str:
    s = str(raw_path or "/").replace("\\", "/").split("\0", 1)[0]
    if not s.startswith("/"):
        s = "/" + s
    s = "/".join(seg.split(";", 1)[0] for seg in s.split("/"))
    s = re.sub(r"/+", "/", s)
    if len(s) > 1:
        s = s.rstrip("/")
    return s or "/"


def _strip_trailing_spaces_and_dots(seg: str) -> str:
    end = len(seg)
    while end > 0 and seg[end - 1] in (".", " ", "\t", "\n", "\r", "\x0b", "\x0c"):
        end -= 1
    return seg if end == len(seg) else seg[:end]


def _trim_segment_noise(norm_path: str) -> str:
    s = "/".join(_strip_trailing_spaces_and_dots(seg) for seg in str(norm_path or "/").split("/"))
    s = re.sub(r"/+", "/", s)
    if not s.startswith("/"):
        s = "/" + s
    if len(s) > 1:
        s = s.rstrip("/")
    return s or "/"


_CLEAN_ASCII_PATH_RE = re.compile(
    r"\A/(?:[A-Za-z0-9_~:@!$&'()*+,=-]+(?:\.[A-Za-z0-9_~:@!$&'()*+,=-]+)*(?:/[A-Za-z0-9_~:@!$&'()*+,=-]+(?:\.[A-Za-z0-9_~:@!$&'()*+,=-]+)*)*)?/?\Z"
)


def _decode_percent_2(s: str) -> str:
    out = s
    for _ in range(2):
        nxt = _decode_percent_lenient(out)
        if nxt == out:
            break
        out = nxt
    return out


def _normalize_decoded_pathname(decoded_no_query: str) -> str:
    s = str(decoded_no_query or "/").replace("\0", "").replace("\\", "/")
    if not s.startswith("/"):
        s = "/" + s
    s = "/".join(seg.split(";", 1)[0] for seg in s.split("/"))
    s = posixpath.normpath(s)
    s = re.sub(r"^/+", "/", s)
    if not s.startswith("/"):
        s = "/" + s
    if len(s) > 1:
        s = s.rstrip("/")
    s = s.replace("?", "%3F")
    return s


def normalize_pathname(raw_url: str) -> str:
    s = _strip_scheme_and_authority(raw_url)
    q_idx = s.find("?")
    if q_idx >= 0:
        s = s[:q_idx]
    if not s:
        return "/"
    if _CLEAN_ASCII_PATH_RE.fullmatch(s):
        return s[:-1] if len(s) > 1 and s.endswith("/") else s
    return _normalize_decoded_pathname(_decode_percent_2(s))


def _expand_path_candidates(raw_url: str) -> list[str]:
    raw = _strip_scheme_and_authority(raw_url)
    q_idx = raw.find("?")
    raw_path = raw[:q_idx] if q_idx >= 0 else raw
    if _CLEAN_ASCII_PATH_RE.fullmatch(raw_path):
        clean = raw_path[:-1] if len(raw_path) > 1 and raw_path.endswith("/") else (raw_path or "/")
        return [clean]
    seen_set: set[str] = set()
    seen: list[str] = []

    def _push(cand: str) -> None:
        if cand not in seen_set:
            seen_set.add(cand)
            seen.append(cand)

    def _add_raw(val: str) -> None:
        n2 = _clean_path_no_collapse(val)
        _push(n2)
        _push(_trim_segment_noise(n2))

    def _add_decoded(dec_val: str) -> None:
        n1 = _normalize_decoded_pathname(dec_val)
        n2 = _clean_path_no_collapse(dec_val)
        _push(n1)
        _push(n2)
        _push(_trim_segment_noise(n1))
        _push(_trim_segment_noise(n2))

    _add_raw(raw_path)
    raw_h = raw_path.find("#")
    if raw_h >= 0:
        raw_before = raw_path[:raw_h]
        _add_raw(raw_before)
        dec_before = _decode_percent_2(raw_before)
        _add_decoded(dec_before)
        dec_after = _decode_percent_2(raw_path[raw_h + 1 :])
        dec = f"{dec_before}#{dec_after}"
    else:
        dec = _decode_percent_2(raw_path)
    _add_decoded(dec)
    null_idx = dec.find("\0")
    if null_idx >= 0:
        _add_decoded(dec[:null_idx])
    dec_q = dec.find("?")
    if dec_q >= 0:
        _add_decoded(dec[:dec_q])
    dec_h = dec.find("#")
    if dec_h >= 0:
        _add_decoded(dec[:dec_h])
    return seen


@dataclass
class InspectionResult:
    ok: bool
    blocked: bool
    score: int
    threshold: int | float
    mode: str
    reasons: list[dict] = field(default_factory=list)
    next_canary: str | None = None
    canary_ack: str | None = None
    rehandshake_recommended: bool = False
    redirect_get_hint: bool = False


class ProxySnareVerifier:
    def __init__(
        self,
        *,
        mode: str | None = "strict",
        secret: bytes | str | None = None,
        threshold: int | None = None,
        freshness_ms: int | None = None,
        nonce_ttl_ms: int = 300_000,
        session_ttl_ms: int = 1_800_000,
        boot_token_ttl_ms: int = 120_000,
        max_sessions: int = 20_000,
        max_nonces: int = 50_000,
        max_boot_tokens: int = 30_000,
        handshake_pow_bits: int | None = None,
        bind_ip: bool | None = None,
        block_ai_crawlers: bool | None = None,
        block_console_eval: bool | None = None,
        block_cdp_active: bool | None = None,
        allow_devtools: bool | None = None,
        block_automation_on_all_routes: bool = False,
        require_user_gesture_on_mutate: bool | None = None,
        require_signed_context: bool | None = None,
        ecdsa_handshake_auth: bool | None = None,
        user_gesture_window_ms: int = 15_000,
        protected_paths: list[str | re.Pattern] | None = None,
        gesture_exempt_paths: list[str | re.Pattern] | None = None,
        gesture_protected_paths: list[str | re.Pattern] | None = None,
    ) -> None:
        m = str("strict" if mode is None else mode).strip().lower()
        if m not in ("off", "monitor", "observe", "balanced", "strict", "paranoid"):
            raise ValueError(f"Unsupported mode: {mode}")
        self.mode = "monitor" if m == "observe" else m
        env_secret = os.environ.get("PROXYSNARE_SECRET") if secret is None else None
        raw_secret = secret if secret is not None else (env_secret if env_secret else None)
        if raw_secret is None:
            self.secret = secrets.token_bytes(32)
        else:
            if not isinstance(raw_secret, (bytes, bytearray, memoryview, str)):
                raise TypeError("secret must be bytes-like or str")
            sec_b = raw_secret.encode("utf-8") if isinstance(raw_secret, str) else bytes(raw_secret)
            if len(sec_b) < 16:
                raise ValueError("Invalid PROXYSNARE_SECRET: must be at least 16 bytes" if secret is None else "secret must be at least 16 bytes")
            self.secret = sec_b

        # Deterministic P-256 ECDSA signing keypair matching Node.js deriveDeterministicSigningKeyPair bit-for-bit!
        sign_h = hmac.new(self.secret, b"PS_ECDSA_SIGN_KEY_V1", hashlib.sha256).digest()
        self._sign_priv = 1 + (int.from_bytes(sign_h, "big") % (_P256_N - 1))
        pub_pt = _p256_scalar_mul_consttime(self._sign_priv, _P256_G)
        assert pub_pt is not None
        self._sign_pub_pt = pub_pt
        self.server_verify_pub_b64 = _p256_encode_uncompressed(pub_pt)

        def _pos_finite(val: object, name: str) -> float | int:
            if not isinstance(val, (int, float)) or isinstance(val, bool) or not math.isfinite(val) or val <= 0:
                raise ValueError(f"{name} must be a positive finite number")
            return val

        def _pos_int(val: object, name: str) -> int:
            if not isinstance(val, int) or isinstance(val, bool) or val < 1:
                raise ValueError(f"{name} must be a positive integer")
            return val

        default_thresh = 4 if self.mode in ("strict", "paranoid") else 6
        default_fresh = 5000 if self.mode == "paranoid" else (8000 if self.mode == "strict" else 15000)
        self.threshold = _pos_finite(threshold if threshold is not None else default_thresh, "threshold")
        self.freshness_ms = _pos_finite(freshness_ms if freshness_ms is not None else default_fresh, "freshness_ms")
        self.max_future_skew_ms = min(3000, self.freshness_ms)
        self.nonce_ttl_ms = _pos_finite(nonce_ttl_ms, "nonce_ttl_ms")
        self.session_ttl_ms = _pos_finite(session_ttl_ms, "session_ttl_ms")
        self.boot_token_ttl_ms = _pos_finite(boot_token_ttl_ms, "boot_token_ttl_ms")
        self.max_sessions = _pos_int(max_sessions, "max_sessions")
        self.max_nonces = _pos_int(max_nonces, "max_nonces")
        self.max_boot_tokens = _pos_int(max_boot_tokens, "max_boot_tokens")
        if handshake_pow_bits is None:
            self.handshake_pow_bits = (
                14 if self.mode == "paranoid" else (12 if self.mode == "strict" else (10 if self.mode == "balanced" else 0))
            )
        else:
            if not isinstance(handshake_pow_bits, int) or isinstance(handshake_pow_bits, bool) or not (0 <= handshake_pow_bits <= 22):
                raise ValueError("handshake_pow_bits must be an integer in 0..22")
            self.handshake_pow_bits = handshake_pow_bits
        self.bind_ip = (self.mode in ("strict", "paranoid")) if bind_ip is None else bool(bind_ip)
        self.block_ai_crawlers = (self.mode != "off") if block_ai_crawlers is None else bool(block_ai_crawlers)
        if allow_devtools is not None:
            self.allow_devtools = bool(allow_devtools)
        elif block_cdp_active is not None and bool(block_cdp_active):
            self.allow_devtools = False
        else:
            self.allow_devtools = self.mode not in ("strict", "paranoid")
        self.block_cdp_active = (
            (False if (self.allow_devtools or self.mode in ("off", "monitor")) else True)
            if block_cdp_active is None
            else bool(block_cdp_active)
        )
        self.block_console_eval = (
            (False if self.allow_devtools else (self.mode in ("strict", "paranoid")))
            if block_console_eval is None
            else bool(block_console_eval)
        )
        self.block_automation_on_all_routes = bool(block_automation_on_all_routes)
        self.require_user_gesture_on_mutate = (
            (self.mode == "paranoid") if require_user_gesture_on_mutate is None else bool(require_user_gesture_on_mutate)
        )
        self.require_signed_context = (
            (self.mode == "paranoid") if require_signed_context is None else bool(require_signed_context)
        )
        self.ecdsa_handshake_auth = (self.mode != "off") if ecdsa_handshake_auth is None else bool(ecdsa_handshake_auth)
        self.user_gesture_window_ms = _pos_finite(user_gesture_window_ms, "user_gesture_window_ms")

        def _norm_rule_list(raw_list: list[str | re.Pattern]) -> list[str | re.Pattern]:
            out: list[str | re.Pattern] = []
            for p in raw_list:
                if isinstance(p, re.Pattern):
                    out.append(p)
                else:
                    raw_p = str(p).strip()
                    out.append("*" if raw_p == "*" else normalize_pathname(raw_p))
            return out

        self.protected_paths: list[str | re.Pattern] = _norm_rule_list(protected_paths or ["/api"])
        self.gesture_exempt_paths: list[str | re.Pattern] | None = (
            _norm_rule_list(gesture_exempt_paths) if gesture_exempt_paths else None
        )
        self.gesture_protected_paths: list[str | re.Pattern] | None = (
            _norm_rule_list(gesture_protected_paths) if gesture_protected_paths else None
        )

        def _compile_rules(rules: list[str | re.Pattern]) -> list[tuple]:
            compiled: list[tuple] = []
            for r in rules:
                if isinstance(r, re.Pattern):
                    compiled.append(("regex", r, ""))
                else:
                    rl = r.lower()
                    if rl in ("*", "/"):
                        compiled.append(("wild", "", ""))
                    else:
                        compiled.append(("prefix", rl, rl if rl.endswith("/") else rl + "/"))
            return compiled

        self._protected_compiled = _compile_rules(self.protected_paths)
        self._protected_match_all = any(k == "wild" for k, _, _ in self._protected_compiled)
        self._gesture_exempt_compiled = _compile_rules(self.gesture_exempt_paths) if self.gesture_exempt_paths else None
        self._gesture_exempt_match_all = bool(
            self._gesture_exempt_compiled and any(k == "wild" for k, _, _ in self._gesture_exempt_compiled)
        )
        self._gesture_protected_compiled = (
            _compile_rules(self.gesture_protected_paths) if self.gesture_protected_paths else None
        )
        self._gesture_protected_match_all = bool(
            self._gesture_protected_compiled and any(k == "wild" for k, _, _ in self._gesture_protected_compiled)
        )
        self._sessions: dict[str, dict] = {}
        self._used_nonces: dict[str, float] = {}
        self._used_boot_tokens: dict[str, float] = {}
        self._ip_bursts: dict[str, list[tuple[float, str]]] = {}
        self._inspect_counter = 0
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        if len(self._sessions) >= self.max_sessions:
            while self._sessions:
                k, v = next(iter(self._sessions.items()))
                if v["exp"] <= now:
                    self._sessions.pop(k, None)
                else:
                    break
        if len(self._used_boot_tokens) >= self.max_boot_tokens:
            # NEVER evict unexpired entries from _used_boot_tokens (prevents stateless PS_BOOT_V2S replay under saturation)!
            while self._used_boot_tokens:
                k, exp = next(iter(self._used_boot_tokens.items()))
                if exp <= now:
                    self._used_boot_tokens.pop(k, None)
                else:
                    break
        if len(self._used_nonces) > self.max_nonces:
            while self._used_nonces:
                k, exp = next(iter(self._used_nonces.items()))
                if exp <= now:
                    self._used_nonces.pop(k, None)
                else:
                    break
            if len(self._used_nonces) > self.max_nonces:
                target = int(self.max_nonces * 0.85)
                while len(self._used_nonces) > target:
                    self._used_nonces.pop(next(iter(self._used_nonces)), None)
        if len(self._ip_bursts) > 10_000:
            while self._ip_bursts:
                k, arr = next(iter(self._ip_bursts.items()))
                if not arr or (now - arr[-1][0] > 5000.0):
                    self._ip_bursts.pop(k, None)
                else:
                    break
            if len(self._ip_bursts) > 10_000:
                while len(self._ip_bursts) > 8_500:
                    self._ip_bursts.pop(next(iter(self._ip_bursts)), None)

    @staticmethod
    def _matches_cands(cands: list[str], compiled_rules: list[tuple]) -> bool:
        for norm in cands:
            low = norm.lower()
            for kind, a, b in compiled_rules:
                if kind == "wild":
                    return True
                if kind == "regex":
                    if a.search(norm):
                        return True
                elif low == a or low.startswith(b):
                    return True
        return False

    @staticmethod
    def _matches_cands_all(cands: list[str], compiled_rules: list[tuple]) -> bool:
        if not cands:
            return False
        for norm in cands:
            low = norm.lower()
            hit = False
            for kind, a, b in compiled_rules:
                if kind == "wild":
                    hit = True
                    break
                if kind == "regex":
                    if a.search(norm):
                        hit = True
                        break
                elif low == a or low.startswith(b):
                    hit = True
                    break
            if not hit:
                return False
        return True

    @staticmethod
    def _matches_compiled(raw_url: str, compiled_rules: list[tuple]) -> bool:
        if any(k == "wild" for k, _, _ in compiled_rules):
            return True
        return ProxySnareVerifier._matches_cands(_expand_path_candidates(raw_url), compiled_rules)

    @staticmethod
    def _matches_rules(raw_url: str, rules: list[str | re.Pattern]) -> bool:
        for norm in _expand_path_candidates(raw_url):
            low = norm.lower()
            for rule in rules:
                if isinstance(rule, re.Pattern):
                    if rule.search(norm):
                        return True
                else:
                    rl = rule.lower()
                    if rl in ("*", "/") or low == rl or low.startswith(rl if rl.endswith("/") else rl + "/"):
                        return True
        return False

    @staticmethod
    def _matches_compiled_all(raw_url: str, compiled_rules: list[tuple]) -> bool:
        if any(k == "wild" for k, _, _ in compiled_rules):
            return True
        return ProxySnareVerifier._matches_cands_all(_expand_path_candidates(raw_url), compiled_rules)

    def is_path_protected(self, raw_url: str) -> bool:
        if self._protected_match_all:
            return True
        return self._matches_cands(_expand_path_candidates(raw_url), self._protected_compiled)

    def serialize_protected_rules(self) -> list[str | dict]:
        rules: list[str | dict] = []
        for p in self.protected_paths:
            if isinstance(p, re.Pattern):
                flags = (
                    ("i" if (p.flags & re.IGNORECASE) else "")
                    + ("m" if (p.flags & re.MULTILINE) else "")
                    + ("s" if (p.flags & re.DOTALL) else "")
                )
                rules.append({"regex": p.pattern, "flags": flags})
            else:
                rules.append(p)
        return rules

    def issue_boot_challenge(self, *, ip: str = "127.0.0.1", user_agent: str = "") -> dict | None:
        with self._lock:
            now = time.time() * 1000.0
            if len(self._used_boot_tokens) >= self.max_boot_tokens:
                while self._used_boot_tokens:
                    k, exp = next(iter(self._used_boot_tokens.items()))
                    if exp <= now:
                        self._used_boot_tokens.pop(k, None)
                    else:
                        break
                if len(self._used_boot_tokens) >= self.max_boot_tokens:
                    return None
            tid = secrets.token_hex(16)
            challenge = secrets.token_hex(16)
            norm_ip = _normalize_ip(ip)
            ua_hash = _sha256_hex(user_agent)
            exp = int(now + self.boot_token_ttl_ms)
            sealed_json = json.dumps(
                {"c": challenge, "d": self.handshake_pow_bits, "e": exp, "i": norm_ip, "u": ua_hash},
                separators=(",", ":"),
            ).encode("utf-8")
            sealed = base64.urlsafe_b64encode(sealed_json).rstrip(b"=").decode("ascii")
            mac = _hmac_hex(self.secret, f"PS_BOOT_V2S|{tid}|{sealed}")[:32]
            return {
                "bootToken": f"{tid}.{mac}.{sealed}",
                "challenge": challenge,
                "difficulty": self.handshake_pow_bits,
                "exp": exp,
            }

    def consume_boot_challenge_detail(
        self,
        *,
        boot_token: str,
        pow_nonce: str = "",
        ip: str = "127.0.0.1",
        user_agent: str = "",
    ) -> dict:
        with self._lock:
            now = time.time() * 1000.0
            if not isinstance(boot_token, str):
                return {"ok": False, "error": "BOOT_TOKEN_INVALID"}
            if pow_nonce is not None and not isinstance(pow_nonce, str):
                return {"ok": False, "error": "HANDSHAKE_POW_INVALID"}
            raw = boot_token.strip()
            parts = raw.split(".")
            if len(parts) != 3:
                return {"ok": False, "error": "BOOT_TOKEN_INVALID"}
            tid, mac, sealed = parts
            if (
                not re.fullmatch(r"[a-fA-F0-9]{32}", tid)
                or not re.fullmatch(r"[a-fA-F0-9]{32}", mac)
                or not re.fullmatch(r"[A-Za-z0-9_-]{16,512}", sealed)
            ):
                return {"ok": False, "error": "BOOT_TOKEN_INVALID"}
            prev_used = self._used_boot_tokens.get(tid)
            if prev_used is not None and prev_used > now:
                return {"ok": False, "error": "BOOT_TOKEN_REPLAYED_OR_INVALID"}
            expected_mac = _hmac_hex(self.secret, f"PS_BOOT_V2S|{tid}|{sealed}")[:32]
            if not hmac.compare_digest(mac.lower(), expected_mac.lower()):
                return {"ok": False, "error": "BOOT_TOKEN_INVALID"}
            try:
                pad = (-len(sealed)) % 4
                parsed = json.loads(base64.urlsafe_b64decode(sealed + ("=" * pad)).decode("utf-8"))
                if (
                    not isinstance(parsed, dict)
                    or not isinstance(parsed.get("c"), str)
                    or not isinstance(parsed.get("e"), (int, float))
                    or isinstance(parsed.get("e"), bool)
                    or not isinstance(parsed.get("d"), int)
                    or isinstance(parsed.get("d"), bool)
                ):
                    return {"ok": False, "error": "BOOT_TOKEN_INVALID"}
                rec = {
                    "ip": str(parsed.get("i") or ""),
                    "ua_hash": str(parsed.get("u") or ""),
                    "challenge": parsed["c"],
                    "difficulty": parsed["d"],
                    "exp": float(parsed["e"]),
                }
            except Exception:
                return {"ok": False, "error": "BOOT_TOKEN_INVALID"}
            if rec["exp"] <= now:
                return {"ok": False, "error": "BOOT_TOKEN_EXPIRED"}
            if len(self._used_boot_tokens) >= self.max_boot_tokens:
                while self._used_boot_tokens:
                    k, exp = next(iter(self._used_boot_tokens.items()))
                    if exp <= now:
                        self._used_boot_tokens.pop(k, None)
                    else:
                        break
                if len(self._used_boot_tokens) >= self.max_boot_tokens:
                    return {"ok": False, "error": "BOOT_CAPACITY_EXCEEDED"}
            self._used_boot_tokens[tid] = now + max(60_000.0, float(self.boot_token_ttl_ms))
            if self.bind_ip and rec["ip"] != _normalize_ip(ip):
                return {"ok": False, "error": "BOOT_TOKEN_IP_MISMATCH"}
            if not hmac.compare_digest(rec["ua_hash"], _sha256_hex(user_agent)):
                return {"ok": False, "error": "BOOT_TOKEN_UA_MISMATCH"}
            if not verify_pow_solution("PS_POW_V2", rec["challenge"], pow_nonce or "", rec["difficulty"]):
                return {"ok": False, "error": "HANDSHAKE_POW_INVALID"}
            return {"ok": True, "tokenId": tid.lower(), "challenge": rec["challenge"], "difficulty": rec["difficulty"]}

    def consume_boot_challenge(
        self,
        *,
        boot_token: str,
        pow_nonce: str = "",
        ip: str = "127.0.0.1",
        user_agent: str = "",
    ) -> tuple[bool, str | None]:
        res = self.consume_boot_challenge_detail(
            boot_token=boot_token,
            pow_nonce=pow_nonce,
            ip=ip,
            user_agent=user_agent,
        )
        return (True, None) if res["ok"] else (False, res["error"])

    def verify_handshake_signature(
        self,
        *,
        session_id: str,
        client_pub_b64: str,
        server_pub_b64: str,
        salt_b64: str,
        boot_token: str = "",
        server_now_ms: int | str = "",
        canary: str = "",
        hs_bind: str = "",
        server_sig_b64: str = "",
    ) -> bool:
        if not isinstance(server_sig_b64, str) or not server_sig_b64.strip():
            return False
        if (
            not isinstance(session_id, str) or not session_id
            or not isinstance(client_pub_b64, str) or not client_pub_b64
            or not isinstance(server_pub_b64, str) or not server_pub_b64
            or not isinstance(salt_b64, str) or not salt_b64
            or not isinstance(canary, str) or not canary
        ):
            return False
        sig_trim = server_sig_b64.strip()
        if not re.fullmatch(r"[A-Za-z0-9+/=_-]{80,104}", sig_trim):
            return False
        norm = sig_trim.replace("-", "+").replace("_", "/")
        pad = (-len(norm)) % 4
        try:
            sig_raw = base64.b64decode(norm + ("=" * pad), validate=True)
        except Exception:
            return False
        if len(sig_raw) != 64 or base64.b64encode(sig_raw).decode("ascii").rstrip("=") != norm.rstrip("="):
            return False
        parsed_client = _p256_decode_uncompressed(client_pub_b64)
        parsed_server = _p256_decode_uncompressed(server_pub_b64)
        if parsed_client is None or parsed_server is None:
            return False
        canon_client = parsed_client[1]
        canon_server = parsed_server[1]
        bind_s = hs_bind.strip() if isinstance(hs_bind, str) else ""
        bt_s = "" if boot_token is None else str(boot_token)
        now_s = "" if server_now_ms is None else str(server_now_ms)
        if any("|" in f for f in (session_id, canon_client, canon_server, salt_b64, bt_s, now_s, canary, bind_s)):
            return False
        bind_suffix = f"|{bind_s}" if bind_s else ""
        transcript = (
            f"PS_HS_AUTH_V1|{session_id}|{canon_client}|{canon_server}|{salt_b64}|"
            f"{bt_s}|{now_s}|{canary}{bind_suffix}"
        ).encode("utf-8")
        return _p256_ecdsa_verify_raw(self._sign_pub_pt, transcript, sig_raw)

    def issue_session(
        self,
        *,
        ip: str = "127.0.0.1",
        user_agent: str = "",
        origin: str = "",
        client_pub_b64: str | None = None,
        boot_token: str = "",
        hs_bind: str = "",
    ) -> dict | None:
        now = time.time() * 1000.0
        # Fast O(1) capacity pre-check BEFORE running expensive pure-Python P-256 ECDH/ECDSA crypto!
        with self._lock:
            if len(self._sessions) >= self.max_sessions:
                self._prune(now)
                if len(self._sessions) >= self.max_sessions:
                    return None
        # Run expensive pure-Python P-256 ECDH & ECDSA crypto OUTSIDE self._lock so concurrent inspect_request() traffic never stalls!
        now_int = int(now)
        sid = secrets.token_hex(16)
        canary = secrets.token_hex(12)
        bind_s = hs_bind.strip() if isinstance(hs_bind, str) else ""
        bt_s = "" if boot_token is None else str(boot_token)
        if "|" in bind_s or "|" in bt_s:
            return {"error": "INVALID_HANDSHAKE_PARAMETERS"}
        bind_suffix = f"|{bind_s}" if bind_s else ""
        ecdh_meta: dict[str, str] | None = None

        if client_pub_b64 is not None:
            parsed = _p256_decode_uncompressed(client_pub_b64)
            if parsed is None:
                return {"error": "INVALID_CLIENT_ECDH_KEY"}
            client_pt, canonical_client_b64 = parsed
            priv = 1 + secrets.randbelow(_P256_N - 1)
            server_pt = _p256_scalar_mul_consttime(priv, _P256_G)
            shared_pt = _p256_scalar_mul_consttime(priv, client_pt)
            if server_pt is None or shared_pt is None:
                return {"error": "INVALID_CLIENT_ECDH_KEY"}
            server_pub_b64 = _p256_encode_uncompressed(server_pt)
            shared_secret = shared_pt[0].to_bytes(32, "big")
            salt = secrets.token_bytes(16)
            salt_b64 = base64.b64encode(salt).decode("ascii")
            info = f"PS_ECDH_V2|{sid}|{canonical_client_b64}|{server_pub_b64}{bind_suffix}".encode("utf-8")
            key = _hkdf_sha256(shared_secret, salt, info, 32)
            ecdh_meta = {"serverPubB64": server_pub_b64, "saltB64": salt_b64}
            if self.ecdsa_handshake_auth:
                auth_msg = (
                    f"PS_HS_AUTH_V1|{sid}|{canonical_client_b64}|{server_pub_b64}|{salt_b64}|"
                    f"{bt_s}|{now_int}|{canary}{bind_suffix}"
                ).encode("utf-8")
                sig_raw = _p256_ecdsa_sign_raw(self._sign_priv, auth_msg)
                ecdh_meta["serverSigB64"] = base64.b64encode(sig_raw).decode("ascii")
        else:
            key = secrets.token_bytes(32)

        ua_str = str(user_agent or "")
        record = {
            "key": key,
            "last_seq": 0,
            "canary": canary,
            "ua": ua_str,
            "ua_hash": _sha256_hex(ua_str),
            "ip": _normalize_ip(ip),
            "origin": str(origin or "").strip().lower(),
            "exp": now + float(self.session_ttl_ms),
        }
        with self._lock:
            self._prune(now)
            if len(self._sessions) >= self.max_sessions:
                return None
            self._sessions[sid] = record

        base = {
            "sessionId": sid,
            "canary": canary,
            "freshnessMs": self.freshness_ms,
            "serverNowMs": now_int,
            "protectedPaths": [p for p in self.protected_paths if isinstance(p, str)],
            "protectedRules": self.serialize_protected_rules(),
        }
        if ecdh_meta is not None:
            return {"protocol": "PS_ECDH_V2", **base, **ecdh_meta}
        return {"protocol": "PS_LOCAL_V1", **base, "sessionKeyHex": key.hex()}

    @staticmethod
    def sign_request(
        *,
        session_key_hex: str,
        method: str,
        path_with_query: str,
        body: bytes | str = b"",
        seq: int | str,
        ts: int | str,
        nonce: str,
        canary: str,
        ctx: str = "",
    ) -> str:
        body_hash = _sha256_hex(body)
        safe_ctx = str(ctx or "").strip()
        if safe_ctx:
            canonical = f"PS2|{method.upper()}|{path_with_query}|{body_hash}|{seq}|{ts}|{nonce}|{canary}|{safe_ctx}"
        else:
            canonical = f"PS1|{method.upper()}|{path_with_query}|{body_hash}|{seq}|{ts}|{nonce}|{canary}"
        return _hmac_hex(bytes.fromhex(session_key_hex), canonical)

    def inspect_request(
        self,
        *,
        method: str,
        url: str,
        headers: dict[str, object],
        body: bytes | str = b"",
        ip: str = "127.0.0.1",
        now_ms: float | None = None,
        raw_header_lines: list[str] | None = None,
        from_trusted_proxy: bool = False,
    ) -> InspectionResult:
        if self.mode == "off":
            return InspectionResult(True, False, 0, self.threshold, self.mode)
        # Stateless request parsing, path matching, UA/crawler regexes, and body SHA-256 run OUTSIDE self._lock!
        now = now_ms if now_ms is not None else time.time() * 1000.0
        upper_method = str(method or "GET").upper()
        url_str = str(url or "/")
        body_b = body.encode("utf-8") if isinstance(body, str) else bytes(body or b"")
        norm_ip = _normalize_ip(ip)
        hdr, override_urls, override_excessive, has_crawler_prefix = _normalize_headers(headers)
        raw_host_count = 0
        raw_cl_count = 0
        raw_ps_dup = False
        if raw_header_lines:
            # Single-pass scan over raw_header_lines (overrides + duplicate Host/CL/X-PS-* checks)
            raw_override_urls: list[str] = []
            raw_override_excessive = False
            saw_raw_override = False
            raw_ps_counts: dict[str, int] = {}
            for ln in raw_header_lines:
                if ":" not in ln:
                    continue
                rname, rval = ln.split(":", 1)
                rl = rname.strip().lower()
                if rl in ("x-original-url", "x-rewrite-url"):
                    saw_raw_override = True
                    if not raw_override_excessive and _append_override_candidates(raw_override_urls, rval):
                        raw_override_excessive = True
                elif rl == "host":
                    raw_host_count += 1
                elif rl == "content-length":
                    raw_cl_count += 1
                elif rl.startswith("x-ps-"):
                    c = raw_ps_counts.get(rl, 0) + 1
                    raw_ps_counts[rl] = c
                    if c > 1:
                        raw_ps_dup = True
            if saw_raw_override:
                override_urls = raw_override_urls
                override_excessive = raw_override_excessive

        reasons: list[dict] = []
        score = 0

        def flag(code: str, weight: int, detail: str) -> None:
            nonlocal score
            score += weight
            reasons.append({"code": code, "weight": weight, "detail": detail})

        override_prot = override_excessive or (
            bool(override_urls)
            and (self._protected_match_all or any(self._matches_cands(_expand_path_candidates(u), self._protected_compiled) for u in override_urls))
        )
        url_cands: list[str] | None = None
        if self._protected_match_all:
            is_prot = True
        elif override_prot:
            is_prot = True
        else:
            url_cands = _expand_path_candidates(url_str)
            is_prot = self._matches_cands(url_cands, self._protected_compiled)
        # Evaluate all 3 HTTP method-override headers independently (never short-circuit with `or` to prevent shadowing bypass!)
        ov_count = 0
        ov_mismatch = False
        ov_mutating = False
        ov_display = ""
        for ov_k in ("x-http-method-override", "x-method-override", "x-http-method"):
            ov_v = hdr.get(ov_k, "").strip().upper()
            if not ov_v:
                continue
            ov_count += 1
            if not ov_display:
                ov_display = ov_v
            if ov_v != upper_method:
                ov_mismatch = True
                ov_display = ov_v
            if ov_v in _MUTATING_METHODS:
                ov_mutating = True
        has_any_method_override = ov_count > 0
        if is_prot and has_any_method_override and (ov_count > 1 or ov_mismatch):
            flag("METHOD_OVERRIDE_DENIED", 6, f"Method override header '{ov_display}' mismatches {upper_method}")

        # Signal 1: Smuggling, path overrides & proxy header leaks (runs BEFORE CORS OPTIONS exemption)
        if hdr.get("content-length") and hdr.get("transfer-encoding"):
            flag("CL_TE_SMUGGLING", 10, "Both Content-Length and Transfer-Encoding present")
        if override_prot:
            flag("PROXY_PATH_OVERRIDE_HEADER", 6, "X-Original-URL / X-Rewrite-URL targets a protected route")
        has_proxy_leak = False
        for ph in (
            "proxy-connection",
            "x-burp-header",
            "x-burp-collaborator",
            "x-caido-id",
            "x-caido-replay",
            "x-mitmproxy",
        ):
            if ph in hdr:
                has_proxy_leak = True
                flag("PROXY_HEADER_LEAK", 5, f"Proxy artifact header '{ph}'")
        if raw_header_lines:
            if raw_host_count > 1:
                flag("DUPLICATE_HOST_HEADER", 8, f"Duplicate Host headers ({raw_host_count})")
            if raw_cl_count > 1:
                flag("DUPLICATE_CONTENT_LENGTH", 8, f"Duplicate Content-Length headers ({raw_cl_count})")
            if raw_ps_dup:
                flag("REPEATER_BODY_OR_PATH_TAMPERED", 10, "Duplicate X-PS-* Proof-of-Freshness header")

        ua = hdr.get("user-agent", "")
        sec_ch_ua = hdr.get("sec-ch-ua", "")
        is_cli_ua = is_cli_or_proxy_ua(ua, sec_ch_ua)
        is_ai_crawler = self.block_ai_crawlers and _is_ai_crawler_norm(hdr, has_crawler_prefix)

        def _parse_major(pat: re.Pattern[str]) -> int:
            m = pat.search(ua)
            if not m:
                return 0
            digits = m.group(1).lstrip("0")
            if not digits:
                return 0
            return 999_999 if len(digits) > 6 else int(digits)

        claims_modern_base = (_parse_major(_CHROME_VER_RE) >= 80) or (_parse_major(_FIREFOX_VER_RE) >= 90)

        if upper_method == "OPTIONS" and bool(hdr.get("access-control-request-method", "").strip()):
            host_pre = _canonicalize_host_port(hdr.get("host", ""))
            xfh_pre = (
                _canonicalize_host_port(hdr.get("x-forwarded-host", "").split(",", 1)[0])
                if from_trusted_proxy
                else ""
            )
            orig_pre = hdr.get("origin", "").strip()
            orig_host = ""
            if orig_pre and "?" not in orig_pre and "#" not in orig_pre and "@" not in orig_pre:
                try:
                    u = urlsplit(orig_pre)
                    if (
                        u.scheme.lower() in ("http", "https")
                        and u.hostname
                        and not u.username
                        and not u.password
                        and not u.path
                        and not u.query
                        and not u.fragment
                        and _ORIGIN_NETLOC_RE.fullmatch(u.netloc)
                    ):
                        port = u.port
                        hn = u.hostname.lower()
                        invalid_orig = False
                        if ":" in hn:
                            try:
                                hn = f"[{ipaddress.IPv6Address(hn.strip('[]'))}]"
                            except ValueError:
                                invalid_orig = True
                        else:
                            # WHATWG URL IPv4 canonicalization: strip at most one trailing dot, and reject
                            # invalid IPv4-shaped hosts whose final non-empty label is numeric/hex/octal!
                            hn_v4 = hn[:-1] if hn.endswith(".") else hn
                            ipv4_parts = hn_v4.split(".")
                            last_lbl = ipv4_parts[-1] if ipv4_parts else ""
                            ends_in_num = bool(last_lbl and _IPV4_LAST_NUMERIC_RE.fullmatch(last_lbl))
                            if ends_in_num:
                                if 1 <= len(ipv4_parts) <= 4 and all(_IPV4_PART_RE.fullmatch(pt) for pt in ipv4_parts):
                                    try:
                                        nums = [
                                            (0 if pt == "0x" else int(pt, 16))
                                            if pt.startswith("0x")
                                            else (int(pt, 8) if len(pt) > 1 and pt.startswith("0") else int(pt, 10))
                                            for pt in ipv4_parts
                                        ]
                                        if all(n < 256 for n in nums[:-1]) and nums[-1] < (256 ** (5 - len(nums))):
                                            val = nums[-1]
                                            for idx_n, n in enumerate(nums[:-1]):
                                                val += n * (256 ** (3 - idx_n))
                                            hn = str(ipaddress.IPv4Address(val))
                                        else:
                                            invalid_orig = True
                                    except ValueError:
                                        invalid_orig = True
                                else:
                                    invalid_orig = True
                        if not invalid_orig:
                            if port is None or (u.scheme.lower() == "http" and port == 80) or (u.scheme.lower() == "https" and port == 443):
                                orig_host = hn
                            else:
                                orig_host = f"{hn}:{port}"
                except ValueError:
                    orig_host = ""
            same_orig_pre = bool(orig_host and ((host_pre and orig_host == host_pre) or (xfh_pre and orig_host == xfh_pre)))
            modern_pre = claims_modern_base and not is_cli_ua
            cl_pre = hdr.get("content-length", "").strip()
            has_body_hdr_pre = bool(hdr.get("transfer-encoding")) or (bool(cl_pre) and not _ZEROS_RE.fullmatch(cl_pre))
            has_any_ps_pre = any(
                hdr.get(pk, "").strip()
                for pk in ("x-ps-session", "x-ps-seq", "x-ps-ts", "x-ps-nonce", "x-ps-canary", "x-ps-proof", "x-ps-ctx")
            )
            if (
                bool(orig_host)
                and not same_orig_pre
                and len(body_b) == 0
                and not has_body_hdr_pre
                and not has_any_method_override
                and not has_proxy_leak
                and not has_any_ps_pre
                and not is_cli_ua
                and not is_ai_crawler
                and (
                    not modern_pre
                    or (hdr.get("sec-fetch-mode", "").lower() == "cors" and (from_trusted_proxy or hdr.get("connection", "").lower() != "close"))
                )
            ):
                blocked = self.mode != "monitor" and score >= self.threshold
                return InspectionResult(not blocked, blocked, score, self.threshold, self.mode, reasons)

        # Signal 2: Firecrawl/AI-Crawler & Browser UA vs Repeater / CLI wire contradictions
        if is_ai_crawler:
            flag("AI_CRAWLER_OR_SCRAPER_DENIED", 6, "Firecrawl / AI crawler or scraping proxy signature detected")

        claims_modern = claims_modern_base and not is_cli_ua and not is_ai_crawler
        sfs = hdr.get("sec-fetch-site", "").lower()
        sfm = hdr.get("sec-fetch-mode", "").lower()
        te = hdr.get("transfer-encoding", "").lower()
        sec_ch_plat = hdr.get("sec-ch-ua-platform", "").replace('"', "").lower()
        origin_hdr = hdr.get("origin", "").strip().lower()

        if claims_modern:
            if not sfs and not sfm and (is_prot or has_proxy_leak):
                flag("FETCH_METADATA_MISSING", 4, "Modern browser UA missing Sec-Fetch metadata")
            if is_prot and "cross-site" in sfs:
                flag("CROSS_SITE_REQUEST_BLOCKED", 6, "Cross-site Fetch Metadata on protected route")
            if not from_trusted_proxy and hdr.get("connection", "").lower() == "close" and (is_prot or has_proxy_leak):
                flag("REPEATER_CONNECTION_CLOSE", 3, "Modern browser UA sent Connection: close")
            if not from_trusted_proxy and "chunked" in te and 0 < len(body_b) < 512:
                flag("PROXY_CHUNKED_TINY_BODY", 2, f"Chunked encoding on tiny {len(body_b)}B request")
            if sec_ch_plat:
                ua_linux = "Linux" in ua and "Android" not in ua
                ua_win = "Windows NT" in ua
                ua_mac = "Macintosh" in ua
                if (
                    (ua_linux and sec_ch_plat in ("windows", "macos"))
                    or (ua_win and sec_ch_plat in ("linux", "macos"))
                    or (ua_mac and sec_ch_plat in ("windows", "linux"))
                ):
                    flag("UA_PLATFORM_CONTRADICTION", 5, f"UA OS contradicts Sec-CH-UA-Platform '{sec_ch_plat}'")
        elif (is_prot or self.block_automation_on_all_routes) and is_cli_ua:
            flag("NON_BROWSER_REPLAY_CLIENT", 6, "Direct replay/CLI/automation client User-Agent detected")

        # Signal 3: Proof-of-Freshness + Rotating Canary + Signed Runtime Context
        ps_sid = hdr.get("x-ps-session", "").strip()
        ps_seq = hdr.get("x-ps-seq", "").strip()
        ps_ts = hdr.get("x-ps-ts", "").strip()
        ps_nonce = hdr.get("x-ps-nonce", "").strip()
        ps_canary = hdr.get("x-ps-canary", "").strip()
        ps_proof = hdr.get("x-ps-proof", "").strip()
        ps_ctx = hdr.get("x-ps-ctx", "").strip()
        has_any_ps = any((ps_sid, ps_seq, ps_ts, ps_nonce, ps_canary, ps_proof, ps_ctx))
        cm_ctx = _CTX_RE.fullmatch(ps_ctx) if ps_ctx else None
        ps_syntax_ok = (
            all((ps_sid, ps_seq, ps_ts, ps_nonce, ps_canary, ps_proof))
            and bool(_PS_NONCE_RE.fullmatch(ps_nonce))
            and bool(_PS_SID_RE.fullmatch(ps_sid))
            and bool(_PS_PROOF_RE.fullmatch(ps_proof))
            and bool(_PS_CANARY_RE.fullmatch(ps_canary))
            and (not ps_ctx or cm_ctx is not None)
            and "|" not in ps_seq
            and "|" not in ps_ts
            and "|" not in upper_method
        )
        # Defer SHA-256(body_b) until PS headers pass completeness/syntax checks AND session exists —
        # skip pre-lock entirely for empty bodies (constant _EMPTY_SHA256_HEX) and run OpenSSL SHA-256 OUTSIDE self._lock!
        guaranteed_unsigned_score = score + (8 if self.mode in ("strict", "paranoid") else 6)
        skip_burst_hash = self.mode != "monitor" and len(body_b) > 4096 and guaranteed_unsigned_score >= self.threshold
        burst_sig = (
            _sha256_hex(f"{upper_method}|{url_str}|{_sha256_hex(body_b)}")
            if (is_prot and len(body_b) > 0 and not has_any_ps and not skip_burst_hash)
            else ""
        )
        body_hash_hex = _EMPTY_SHA256_HEX if len(body_b) == 0 else ""
        if len(body_b) > 0 and (is_prot or has_any_ps) and ps_syntax_ok:
            with self._lock:
                s_pre = self._sessions.get(ps_sid)
                has_live_sess = bool(s_pre and s_pre["exp"] > now)
                skip_pre_hash = False
                if has_live_sess and self.mode != "monitor" and len(body_b) > 4096 and upper_method not in ("GET", "HEAD"):
                    pre_nonce_used = self._used_nonces.get(f"{ps_sid}:{ps_nonce}", 0.0) > now
                    pre_canary_ok = hmac.compare_digest(ps_canary, s_pre["canary"])
                    if pre_nonce_used or not pre_canary_ok:
                        skip_pre_hash = True
            if has_live_sess and not skip_pre_hash:
                body_hash_hex = _sha256_hex(body_b)

        # Precompute gesture path applicability OUTSIDE self._lock (reusing url_cands at most once!)
        gesture_applies = False
        if (is_prot or has_any_ps) and self.require_user_gesture_on_mutate and (upper_method in _MUTATING_METHODS or ov_mutating):
            exempt_hit = False
            if self._gesture_exempt_compiled:
                if self._gesture_exempt_match_all:
                    exempt_hit = True
                else:
                    if url_cands is None:
                        url_cands = _expand_path_candidates(url_str)
                    exempt_hit = self._matches_cands_all(url_cands, self._gesture_exempt_compiled)
            if not exempt_hit:
                if not self._gesture_protected_compiled or self._gesture_protected_match_all:
                    gesture_applies = True
                else:
                    if url_cands is None:
                        url_cands = _expand_path_candidates(url_str)
                    gesture_applies = self._matches_cands(url_cands, self._gesture_protected_compiled)

        next_canary = None
        canary_ack = None
        rehandshake_recommended = False
        redirect_get_hint = False

        # Acquire lock ONLY for stateful session/nonce/burst checks & mutation (zero lock contention on unprotected routes)!
        if is_prot or has_any_ps or burst_sig:
            with self._lock:
                self._inspect_counter += 1
                if (
                    (self._inspect_counter & 255) == 0
                    or len(self._used_nonces) > self.max_nonces
                    or len(self._ip_bursts) > 10_000
                ):
                    self._prune(now)

                if is_prot or has_any_ps:
                    if not all((ps_sid, ps_seq, ps_ts, ps_nonce, ps_canary, ps_proof)):
                        if is_prot:
                            flag("REPEATER_PROOF_MISSING", 8 if self.mode in ("strict", "paranoid") else 6, "Missing Proof-of-Freshness headers")
                    elif not ps_syntax_ok:
                        flag("REPEATER_BODY_OR_PATH_TAMPERED", 10, "Malformed Proof-of-Freshness header syntax")
                    else:
                        sess = self._sessions.get(ps_sid)
                        if not sess or sess["exp"] <= now:
                            flag("REPEATER_UNKNOWN_OR_EXPIRED_SESSION", 8, "Unknown or expired session")
                            rehandshake_recommended = True
                        else:
                            nkey = f"{ps_sid}:{ps_nonce}"
                            prev_nonce_used = self._used_nonces.get(nkey, 0.0) > now
                            if prev_nonce_used:
                                flag("REPEATER_NONCE_REPLAYED", 10, "Single-use nonce replayed")

                            seq_i = int(ps_seq) if _PS_SEQ_RE.fullmatch(ps_seq) else -1
                            if seq_i <= sess["last_seq"]:
                                flag("REPEATER_SEQ_REPLAY", 8, "Non-monotonic sequence")

                            ts_f = float("nan")
                            if _PS_TS_RE.fullmatch(ps_ts):
                                try:
                                    ts_f = float(ps_ts)
                                except ValueError:
                                    ts_f = float("nan")
                            age_ms = now - ts_f
                            stale_or_drift = not math.isfinite(ts_f) or age_ms > self.freshness_ms or age_ms < -self.max_future_skew_ms
                            if stale_or_drift:
                                flag("INTERCEPT_HOLD_OR_STALE_REPLAY", 6, "Freshness window exceeded")

                            canary_ok = hmac.compare_digest(ps_canary, sess["canary"])
                            if not canary_ok:
                                flag("REPEATER_STALE_CANARY", 8, "Stale honey-canary")

                            skip_sign_proof = (
                                self.mode != "monitor"
                                and len(body_b) > 4096
                                and upper_method not in ("GET", "HEAD")
                                and (prev_nonce_used or not canary_ok)
                            )
                            proof_ok = False
                            if not skip_sign_proof:
                                if not body_hash_hex:
                                    body_hash_hex = _sha256_hex(body_b)
                                safe_ctx = ps_ctx
                                canonical = (
                                    f"PS2|{upper_method}|{url_str}|{body_hash_hex}|{ps_seq}|{ps_ts}|{ps_nonce}|{ps_canary}|{safe_ctx}"
                                    if safe_ctx
                                    else f"PS1|{upper_method}|{url_str}|{body_hash_hex}|{ps_seq}|{ps_ts}|{ps_nonce}|{ps_canary}"
                                )
                                expected = _hmac_hex(sess["key"], canonical)
                                proof_ok = hmac.compare_digest(ps_proof, expected)
                            if not proof_ok and not skip_sign_proof:
                                flag("REPEATER_BODY_OR_PATH_TAMPERED", 10, "HMAC proof mismatch")

                            ug_ok = False
                            ga_val = 999_999
                            if not ps_ctx and self.require_signed_context:
                                flag("CONTEXT_HEADER_MISSING", 6, "Signed X-PS-Ctx header required")
                            elif cm_ctx:
                                ce = cm_ctx.group(1) == "1"
                                cdp = cm_ctx.group(2) == "1"
                                ug_ok = cm_ctx.group(3) == "1"
                                ga_val = int(cm_ctx.group(4))
                                ik = cm_ctx.group(5) == "1"
                                if ce:
                                    flag(
                                        "CONSOLE_EVAL_DETECTED",
                                        (10 if self.mode == "paranoid" else 8) if self.block_console_eval else 2,
                                        "Request originated from DevTools Console or CDP Runtime.evaluate",
                                    )
                                if cdp and (self.block_cdp_active or not self.allow_devtools):
                                    cdp_w = (4 if self.mode == "strict" else 6) if self.block_cdp_active else 1
                                    flag(
                                        "CDP_ACTIVE_DETECTED",
                                        cdp_w,
                                        "Active Chrome DevTools Protocol session detected",
                                    )
                                if ik:
                                    flag(
                                        "SYNTHETIC_INTERACTION",
                                        6,
                                        "Synthetic or teleported click kinematics detected",
                                    )
                            if gesture_applies and (not cm_ctx or not ug_ok or ga_val > self.user_gesture_window_ms):
                                flag(
                                    "MUTATION_WITHOUT_USER_GESTURE",
                                    6,
                                    f"State-changing {upper_method} lacked recent trusted user gesture",
                                )

                            ua_matches = (
                                (sess["ua"] == ua)
                                if isinstance(sess.get("ua"), str)
                                else hmac.compare_digest(sess["ua_hash"], _sha256_hex(ua))
                            )
                            if not ua_matches:
                                flag("REPEATER_UA_SESSION_MISMATCH", 6, "User-Agent mismatch")
                            ip_mismatch = bool(self.bind_ip and sess["ip"] and norm_ip and sess["ip"] != norm_ip)
                            if ip_mismatch:
                                flag("REPEATER_IP_SESSION_MISMATCH", 6, "Client IP mismatch")
                            if sess["origin"] and origin_hdr and sess["origin"] != origin_hdr:
                                flag("REPEATER_ORIGIN_MISMATCH", 6, "Origin mismatch")

                            if upper_method in ("GET", "HEAD") and not proof_ok and ua_matches and not ip_mismatch and seq_i > 0 and seq_i == sess["last_seq"]:
                                redirect_get_hint = True

                            if proof_ok and canary_ok and not prev_nonce_used and (ip_mismatch or stale_or_drift):
                                rehandshake_recommended = True

                            if proof_ok:
                                self._used_nonces.pop(nkey, None)
                                self._used_nonces[nkey] = now + float(self.nonce_ttl_ms)
                            valid_advance = proof_ok and seq_i > sess["last_seq"] and canary_ok
                            if valid_advance and (score < self.threshold or self.mode == "monitor"):
                                sess["last_seq"] = seq_i
                                sess["canary"] = secrets.token_hex(12)
                                next_canary = sess["canary"]
                                canary_ack = f"{ps_sid[:8]}:{seq_i}"

                # Signal 4: Per-IP Rapid Identical Unsigned Replay Burst (true LRU refresh)
                if burst_sig:
                    arr = [e for e in self._ip_bursts.pop(norm_ip, []) if now - e[0] <= 5000.0]
                    same_count = sum(1 for e in arr if e[1] == burst_sig)
                    arr.append((now, burst_sig))
                    self._ip_bursts[norm_ip] = arr[-30:]
                    if same_count >= 3:
                        flag("REPEATER_BURST_REPLAY", 5, f"Identical unsigned payload replayed {same_count + 1}x in 5s")

        blocked = self.mode != "monitor" and score >= self.threshold
        return InspectionResult(
            ok=not blocked,
            blocked=blocked,
            score=score,
            threshold=self.threshold,
            mode=self.mode,
            reasons=reasons,
            next_canary=next_canary,
            canary_ack=canary_ack,
            rehandshake_recommended=rehandshake_recommended,
            redirect_get_hint=redirect_get_hint,
        )
