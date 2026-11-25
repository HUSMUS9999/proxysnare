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
import math
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
    pt = (int.from_bytes(buf[1:33], "big"), int.from_bytes(buf[33:65], "big"))
    if not _p256_on_curve(pt):
        return None
    return pt, base64.b64encode(buf).decode("ascii")


def _p256_encode_uncompressed(pt: tuple[int, int]) -> str:
    raw = b"\x04" + pt[0].to_bytes(32, "big") + pt[1].to_bytes(32, "big")
    return base64.b64encode(raw).decode("ascii")


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


def is_cli_or_proxy_ua(ua: str, sec_ch_ua: str = "") -> bool:
    s = str(ua or "").strip()
    if not s:
        return True
    if _CLI_OR_PROXY_UA_RE.search(s):
        return True
    if re.search(r"HeadlessChrome", str(sec_ch_ua or ""), re.I):
        return True
    return False


def _normalize_ip(ip: str) -> str:
    s = str(ip or "").strip().lower()
    if s.startswith("::ffff:"):
        s = s[7:]
    return "127.0.0.1" if s == "::1" else s


_PCT_RUN_RE = re.compile(r"(?:%[0-9a-fA-F]{2})+")


def _decode_percent_lenient(s: str) -> str:
    def _repl(match: re.Match[str]) -> str:
        run = match.group(0)
        out: list[str] = []
        i = 0
        n_run = len(run)
        while i < n_run:
            b = int(run[i + 1 : i + 3], 16)
            if b == 0x00:
                out.append("\0")
                i += 3
                continue
            if 0x01 <= b <= 0x7F:
                out.append(chr(b))
                i += 3
                continue
            matched = False
            for seq_len in (2, 3, 4):
                if i + seq_len * 3 <= n_run:
                    raw_bytes = bytes(
                        int(run[i + k * 3 + 1 : i + k * 3 + 3], 16) for k in range(seq_len)
                    )
                    try:
                        out.append(raw_bytes.decode("utf-8", errors="strict"))
                        i += seq_len * 3
                        matched = True
                        break
                    except UnicodeDecodeError:
                        pass
            if not matched:
                out.append(run[i : i + 3])
                i += 3
        return "".join(out)

    return _PCT_RUN_RE.sub(_repl, s)


def _strip_scheme_and_authority(raw_url: str) -> str:
    s = str(raw_url or "/").lstrip()
    if not s:
        return "/"
    if re.match(r"^https?://", s, re.I):
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


def _trim_segment_noise(norm_path: str) -> str:
    s = "/".join(re.sub(r"[\s.]+$", "", seg) for seg in str(norm_path or "/").split("/"))
    s = re.sub(r"/+", "/", s)
    if not s.startswith("/"):
        s = "/" + s
    if len(s) > 1:
        s = s.rstrip("/")
    return s or "/"


def normalize_pathname(raw_url: str) -> str:
    s = _strip_scheme_and_authority(raw_url)
    q_idx = s.find("?")
    if q_idx >= 0:
        s = s[:q_idx]
    if not s:
        return "/"
    for _ in range(2):
        dec = _decode_percent_lenient(s)
        if dec == s:
            break
        s = dec
    s = s.replace("\0", "").replace("\\", "/")
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


def _expand_path_candidates(raw_url: str) -> list[str]:
    raw = _strip_scheme_and_authority(raw_url)
    q_idx = raw.find("?")
    raw_path = raw[:q_idx] if q_idx >= 0 else raw
    seen: list[str] = []

    def _add(val: str) -> None:
        n1 = normalize_pathname(val)
        n2 = _clean_path_no_collapse(val)
        for cand in (n1, n2, _trim_segment_noise(n1), _trim_segment_noise(n2)):
            if cand not in seen:
                seen.append(cand)

    _add(raw_path)
    raw_h = raw_path.find("#")
    if raw_h >= 0:
        _add(raw_path[:raw_h])

    dec = raw_path
    for _ in range(2):
        nxt = _decode_percent_lenient(dec)
        if nxt == dec:
            break
        dec = nxt
    _add(dec)
    null_idx = dec.find("\0")
    if null_idx >= 0:
        _add(dec[:null_idx])
    dec_q = dec.find("?")
    if dec_q >= 0:
        _add(dec[:dec_q])
    dec_h = dec.find("#")
    if dec_h >= 0:
        _add(dec[:dec_h])
    return seen


@dataclass
class InspectionResult:
    ok: bool
    blocked: bool
    score: int
    threshold: int
    mode: str
    reasons: list[dict] = field(default_factory=list)
    next_canary: str | None = None
    rehandshake_recommended: bool = False


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
        bind_ip: bool = True,
        protected_paths: list[str | re.Pattern] | None = None,
    ) -> None:
        m = str("strict" if mode is None else mode).strip().lower()
        if m not in ("off", "monitor", "observe", "balanced", "strict"):
            raise ValueError(f"Unsupported mode: {mode}")
        self.mode = "monitor" if m == "observe" else m
        if secret is None:
            self.secret = secrets.token_bytes(32)
        else:
            if not isinstance(secret, (bytes, bytearray, memoryview, str)):
                raise TypeError("secret must be bytes-like or str")
            sec_b = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
            if len(sec_b) < 16:
                raise ValueError("secret must be at least 16 bytes")
            self.secret = sec_b

        def _pos_finite(val: object, name: str) -> float | int:
            if not isinstance(val, (int, float)) or isinstance(val, bool) or not math.isfinite(val) or val <= 0:
                raise ValueError(f"{name} must be a positive finite number")
            return val

        def _pos_int(val: object, name: str) -> int:
            if not isinstance(val, int) or isinstance(val, bool) or val < 1:
                raise ValueError(f"{name} must be a positive integer")
            return val

        self.threshold = _pos_finite(threshold if threshold is not None else (4 if self.mode == "strict" else 6), "threshold")
        self.freshness_ms = _pos_finite(freshness_ms if freshness_ms is not None else (8000 if self.mode == "strict" else 15000), "freshness_ms")
        self.max_future_skew_ms = min(3000, self.freshness_ms)
        self.nonce_ttl_ms = _pos_finite(nonce_ttl_ms, "nonce_ttl_ms")
        self.session_ttl_ms = _pos_finite(session_ttl_ms, "session_ttl_ms")
        self.boot_token_ttl_ms = _pos_finite(boot_token_ttl_ms, "boot_token_ttl_ms")
        self.max_sessions = _pos_int(max_sessions, "max_sessions")
        self.max_nonces = _pos_int(max_nonces, "max_nonces")
        self.max_boot_tokens = _pos_int(max_boot_tokens, "max_boot_tokens")
        if handshake_pow_bits is None:
            self.handshake_pow_bits = 12 if self.mode == "strict" else (10 if self.mode == "balanced" else 0)
        else:
            if not isinstance(handshake_pow_bits, int) or isinstance(handshake_pow_bits, bool) or not (0 <= handshake_pow_bits <= 22):
                raise ValueError("handshake_pow_bits must be an integer in 0..22")
            self.handshake_pow_bits = handshake_pow_bits
        self.bind_ip = bool(bind_ip)
        raw_paths = protected_paths or ["/api"]
        self.protected_paths: list[str | re.Pattern] = [
            p
            if isinstance(p, re.Pattern)
            else ("*" if str(p).strip() == "*" else normalize_pathname(str(p)))
            for p in raw_paths
        ]
        self._sessions: dict[str, dict] = {}
        self._used_nonces: dict[str, float] = {}
        self._boot_tokens: dict[str, dict] = {}
        self._ip_bursts: dict[str, list[tuple[float, str]]] = {}
        self._inspect_counter = 0
        self._lock = threading.Lock()

    def _prune(self, now: float) -> None:
        if len(self._sessions) >= self.max_sessions:
            expired = [k for k, v in self._sessions.items() if v["exp"] <= now]
            for k in expired:
                self._sessions.pop(k, None)
        if len(self._boot_tokens) >= self.max_boot_tokens:
            expired_b = [k for k, v in self._boot_tokens.items() if v["exp"] <= now]
            for k in expired_b:
                self._boot_tokens.pop(k, None)
        if len(self._used_nonces) > self.max_nonces:
            expired_n = [k for k, exp in self._used_nonces.items() if exp <= now]
            for k in expired_n:
                self._used_nonces.pop(k, None)
            if len(self._used_nonces) > self.max_nonces:
                target = int(self.max_nonces * 0.85)
                for k in list(self._used_nonces.keys()):
                    self._used_nonces.pop(k, None)
                    if len(self._used_nonces) <= target:
                        break
        if len(self._ip_bursts) > 10_000:
            stale = [
                k for k, arr in self._ip_bursts.items() if not any(now - e[0] <= 5000.0 for e in arr)
            ]
            for k in stale:
                self._ip_bursts.pop(k, None)
            if len(self._ip_bursts) > 10_000:
                drop = len(self._ip_bursts) - 8_500
                for k in list(self._ip_bursts.keys())[:drop]:
                    self._ip_bursts.pop(k, None)

    def is_path_protected(self, raw_url: str) -> bool:
        for norm in _expand_path_candidates(raw_url):
            low = norm.lower()
            for rule in self.protected_paths:
                if isinstance(rule, re.Pattern):
                    if rule.search(norm):
                        return True
                else:
                    rl = rule.lower()
                    if rl in ("*", "/") or low == rl or low.startswith(rl if rl.endswith("/") else rl + "/"):
                        return True
        return False

    def serialize_protected_rules(self) -> list[str | dict]:
        rules: list[str | dict] = []
        for p in self.protected_paths:
            if isinstance(p, re.Pattern):
                flags = "i" if (p.flags & re.IGNORECASE) else ""
                rules.append({"regex": p.pattern, "flags": flags})
            else:
                rules.append(p)
        return rules

    def issue_boot_challenge(self, *, ip: str = "127.0.0.1", user_agent: str = "") -> dict | None:
        with self._lock:
            now = time.time() * 1000.0
            self._prune(now)
            if len(self._boot_tokens) >= self.max_boot_tokens:
                return None
            tid = secrets.token_hex(16)
            challenge = secrets.token_hex(16)
            norm_ip = _normalize_ip(ip)
            ua_hash = _sha256_hex(user_agent)
            exp = int(now + self.boot_token_ttl_ms)
            mac = _hmac_hex(
                self.secret,
                f"PS_BOOT_V2|{tid}|{norm_ip}|{ua_hash}|{challenge}|{self.handshake_pow_bits}|{exp}",
            )[:32]
            self._boot_tokens[tid] = {
                "ip": norm_ip,
                "ua_hash": ua_hash,
                "challenge": challenge,
                "difficulty": self.handshake_pow_bits,
                "exp": float(exp),
                "mac": mac,
            }
            return {
                "bootToken": f"{tid}.{mac}",
                "challenge": challenge,
                "difficulty": self.handshake_pow_bits,
                "exp": exp,
            }

    def consume_boot_challenge(
        self,
        *,
        boot_token: str,
        pow_nonce: str = "",
        ip: str = "127.0.0.1",
        user_agent: str = "",
    ) -> tuple[bool, str | None]:
        with self._lock:
            now = time.time() * 1000.0
            raw = str(boot_token or "").strip()
            if "." not in raw:
                return False, "BOOT_TOKEN_INVALID"
            tid, mac = raw.split(".", 1)
            if not re.fullmatch(r"[a-fA-F0-9]{32}", tid) or not re.fullmatch(r"[a-fA-F0-9]{32}", mac):
                return False, "BOOT_TOKEN_INVALID"
            rec = self._boot_tokens.pop(tid, None)
            if not rec:
                return False, "BOOT_TOKEN_REPLAYED_OR_INVALID"
            if rec["exp"] <= now:
                return False, "BOOT_TOKEN_EXPIRED"
            if not hmac.compare_digest(mac.lower(), rec["mac"].lower()):
                return False, "BOOT_TOKEN_INVALID"
            if self.bind_ip and rec["ip"] != _normalize_ip(ip):
                return False, "BOOT_TOKEN_IP_MISMATCH"
            if not hmac.compare_digest(rec["ua_hash"], _sha256_hex(user_agent)):
                return False, "BOOT_TOKEN_UA_MISMATCH"
            if not verify_pow_solution("PS_POW_V2", rec["challenge"], str(pow_nonce or ""), rec["difficulty"]):
                return False, "HANDSHAKE_POW_INVALID"
            return True, None

    def issue_session(
        self,
        *,
        ip: str = "127.0.0.1",
        user_agent: str = "",
        origin: str = "",
        client_pub_b64: str | None = None,
    ) -> dict | None:
        with self._lock:
            now = time.time() * 1000.0
            self._prune(now)
            if len(self._sessions) >= self.max_sessions:
                return None
            sid = secrets.token_hex(16)
            canary = _hmac_hex(self.secret, f"PS_CANARY|{sid}|0|{secrets.token_hex(8)}")[:24]
            ecdh_meta: dict[str, str] | None = None

            if client_pub_b64 is not None:
                parsed = _p256_decode_uncompressed(client_pub_b64)
                if parsed is None:
                    return {"error": "INVALID_CLIENT_ECDH_KEY"}
                client_pt, canonical_client_b64 = parsed
                priv = 1 + secrets.randbelow(_P256_N - 1)
                server_pt = _p256_scalar_mul(priv, _P256_G)
                shared_pt = _p256_scalar_mul(priv, client_pt)
                if server_pt is None or shared_pt is None:
                    return {"error": "INVALID_CLIENT_ECDH_KEY"}
                server_pub_b64 = _p256_encode_uncompressed(server_pt)
                shared_secret = shared_pt[0].to_bytes(32, "big")
                salt = secrets.token_bytes(16)
                salt_b64 = base64.b64encode(salt).decode("ascii")
                info = f"PS_ECDH_V2|{sid}|{canonical_client_b64}|{server_pub_b64}".encode("utf-8")
                key = _hkdf_sha256(shared_secret, salt, info, 32)
                ecdh_meta = {"serverPubB64": server_pub_b64, "saltB64": salt_b64}
            else:
                key = secrets.token_bytes(32)

            self._sessions[sid] = {
                "key": key,
                "key_hex": key.hex(),
                "last_seq": 0,
                "canary": canary,
                "ua_hash": _sha256_hex(user_agent),
                "ip": _normalize_ip(ip),
                "origin": str(origin or "").strip().lower(),
                "exp": now + float(self.session_ttl_ms),
            }
            base = {
                "sessionId": sid,
                "canary": canary,
                "freshnessMs": self.freshness_ms,
                "serverNowMs": int(now),
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
    ) -> str:
        body_hash = _sha256_hex(body)
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
        with self._lock:
            return self._inspect_request_unlocked(
                method=method,
                url=url,
                headers=headers,
                body=body,
                ip=ip,
                now_ms=now_ms,
                raw_header_lines=raw_header_lines,
                from_trusted_proxy=from_trusted_proxy,
            )

    def _inspect_request_unlocked(
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
        now = now_ms if now_ms is not None else time.time() * 1000.0
        self._inspect_counter += 1
        if (
            (self._inspect_counter & 255) == 0
            or len(self._used_nonces) > self.max_nonces
            or len(self._ip_bursts) > 10_000
        ):
            self._prune(now)

        upper_method = str(method or "GET").upper()
        body_b = body.encode("utf-8") if isinstance(body, str) else bytes(body or b"")
        norm_ip = _normalize_ip(ip)
        hdr: dict[str, str] = {}
        override_urls: list[str] = []
        for k, v in (headers or {}).items():
            kl = str(k).lower()
            if isinstance(v, (list, tuple)):
                hdr[kl] = ", ".join("" if x is None else str(x) for x in v)
                if kl in ("x-original-url", "x-rewrite-url"):
                    for item in v:
                        if isinstance(item, str) and item.strip():
                            override_urls.append(item)
            else:
                hdr[kl] = "" if v is None else str(v)
                if kl in ("x-original-url", "x-rewrite-url") and isinstance(v, str) and v.strip():
                    override_urls.append(v)

        reasons: list[dict] = []
        score = 0

        def flag(code: str, weight: int, detail: str) -> None:
            nonlocal score
            score += weight
            reasons.append({"code": code, "weight": weight, "detail": detail})

        override_prot = any(self.is_path_protected(u) for u in override_urls)
        is_prot = self.is_path_protected(url) or override_prot
        method_override = (
            hdr.get("x-http-method-override") or hdr.get("x-method-override") or hdr.get("x-http-method") or ""
        )

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
            host_count = 0
            cl_count = 0
            ps_counts: dict[str, int] = {}
            for ln in raw_header_lines:
                if ":" not in ln:
                    continue
                name = ln.split(":", 1)[0].strip().lower()
                if name == "host":
                    host_count += 1
                elif name == "content-length":
                    cl_count += 1
                elif name.startswith("x-ps-"):
                    ps_counts[name] = ps_counts.get(name, 0) + 1
            if host_count > 1:
                flag("DUPLICATE_HOST_HEADER", 8, f"Duplicate Host headers ({host_count})")
            if cl_count > 1:
                flag("DUPLICATE_CONTENT_LENGTH", 8, f"Duplicate Content-Length headers ({cl_count})")
            if any(c > 1 for c in ps_counts.values()):
                flag("REPEATER_BODY_OR_PATH_TAMPERED", 10, "Duplicate X-PS-* Proof-of-Freshness header")

        ua_pre = hdr.get("user-agent", "")
        sec_ch_pre = hdr.get("sec-ch-ua", "")
        host_pre = hdr.get("host", "").strip().lower()
        if host_pre.endswith(":80"):
            host_pre = host_pre[:-3]
        elif host_pre.endswith(":443"):
            host_pre = host_pre[:-4]
        orig_pre = hdr.get("origin", "").strip()
        orig_host = ""
        if orig_pre:
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
                    and re.fullmatch(r"[a-z0-9.\-:\[\]]+", u.netloc, re.I)
                ):
                    port = u.port
                    hn = u.hostname.lower()
                    if ":" in hn and not hn.startswith("["):
                        hn = f"[{hn}]"
                    if port is None or (u.scheme.lower() == "http" and port == 80) or (u.scheme.lower() == "https" and port == 443):
                        orig_host = hn
                    else:
                        orig_host = f"{hn}:{port}"
            except ValueError:
                orig_host = ""
        same_orig_pre = bool(orig_host and host_pre and orig_host == host_pre)
        cm_pre = re.search(r"Chrome/(\d+)", ua_pre, re.I)
        fm_pre = re.search(r"Firefox/(\d+)", ua_pre, re.I)
        modern_pre = (
            (cm_pre is not None and int(cm_pre.group(1)) >= 80)
            or (fm_pre is not None and int(fm_pre.group(1)) >= 90)
        ) and not is_cli_or_proxy_ua(ua_pre, sec_ch_pre)
        if (
            upper_method == "OPTIONS"
            and "access-control-request-method" in hdr
            and bool(orig_host)
            and not same_orig_pre
            and len(body_b) == 0
            and not method_override
            and not is_cli_or_proxy_ua(ua_pre, sec_ch_pre)
            and (
                not modern_pre
                or (hdr.get("sec-fetch-mode", "").lower() == "cors" and (from_trusted_proxy or hdr.get("connection", "").lower() != "close"))
            )
        ):
            blocked = self.mode != "monitor" and score >= self.threshold
            return InspectionResult(not blocked, blocked, score, self.threshold, self.mode, reasons)

        # Signal 2: Browser UA vs Repeater / CLI wire contradictions
        ua = hdr.get("user-agent", "")
        sec_ch_ua = hdr.get("sec-ch-ua", "")
        cm = re.search(r"Chrome/(\d+)", ua, re.I)
        fm = re.search(r"Firefox/(\d+)", ua, re.I)
        claims_modern = (
            (cm is not None and int(cm.group(1)) >= 80) or (fm is not None and int(fm.group(1)) >= 90)
        ) and not is_cli_or_proxy_ua(ua, sec_ch_ua)
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
            if "chunked" in te and 0 < len(body_b) < 512:
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
        elif is_prot and is_cli_or_proxy_ua(ua, sec_ch_ua):
            flag("NON_BROWSER_REPLAY_CLIENT", 6, "Direct replay/CLI/automation client User-Agent on protected route")

        # Signal 3: Proof-of-Freshness + Rotating Canary
        ps_sid = hdr.get("x-ps-session", "").strip()
        ps_seq = hdr.get("x-ps-seq", "").strip()
        ps_ts = hdr.get("x-ps-ts", "").strip()
        ps_nonce = hdr.get("x-ps-nonce", "").strip()
        ps_canary = hdr.get("x-ps-canary", "").strip()
        ps_proof = hdr.get("x-ps-proof", "").strip()
        has_any_ps = any((ps_sid, ps_seq, ps_ts, ps_nonce, ps_canary, ps_proof))
        next_canary = None
        rehandshake_recommended = False

        if is_prot or has_any_ps:
            if not all((ps_sid, ps_seq, ps_ts, ps_nonce, ps_canary, ps_proof)):
                if is_prot:
                    flag("REPEATER_PROOF_MISSING", 8 if self.mode == "strict" else 6, "Missing Proof-of-Freshness headers")
            elif (
                not re.fullmatch(r"[A-Za-z0-9_-]{8,64}", ps_nonce)
                or not re.fullmatch(r"[a-fA-F0-9]{16,64}", ps_sid)
                or not re.fullmatch(r"[a-fA-F0-9]{64}", ps_proof)
                or not re.fullmatch(r"[a-fA-F0-9]{16,64}", ps_canary)
                or "|" in ps_seq
                or "|" in ps_ts
                or "|" in upper_method
            ):
                flag("REPEATER_BODY_OR_PATH_TAMPERED", 10, "Malformed Proof-of-Freshness header syntax")
            else:
                sess = self._sessions.get(ps_sid)
                if not sess or sess["exp"] <= now:
                    flag("REPEATER_UNKNOWN_OR_EXPIRED_SESSION", 8, "Unknown or expired session")
                    rehandshake_recommended = True
                else:
                    nkey = f"{ps_sid}:{ps_nonce}"
                    if self._used_nonces.get(nkey, 0.0) > now:
                        flag("REPEATER_NONCE_REPLAYED", 10, "Single-use nonce replayed")

                    seq_i = int(ps_seq) if re.fullmatch(r"\d{1,15}", ps_seq) else -1
                    if seq_i <= sess["last_seq"]:
                        flag("REPEATER_SEQ_REPLAY", 8, "Non-monotonic sequence")

                    ts_f = float("nan")
                    if re.fullmatch(r"\d{1,15}(?:\.\d{1,4})?", ps_ts):
                        try:
                            ts_f = float(ps_ts)
                        except ValueError:
                            ts_f = float("nan")
                    age_ms = now - ts_f
                    if not math.isfinite(ts_f) or age_ms > self.freshness_ms or age_ms < -self.max_future_skew_ms:
                        flag("INTERCEPT_HOLD_OR_STALE_REPLAY", 6, "Freshness window exceeded")

                    canary_ok = hmac.compare_digest(ps_canary, sess["canary"])
                    if not canary_ok:
                        flag("REPEATER_STALE_CANARY", 8, "Stale honey-canary")

                    expected = self.sign_request(
                        session_key_hex=sess["key_hex"],
                        method=upper_method,
                        path_with_query=url,
                        body=body_b,
                        seq=ps_seq,
                        ts=ps_ts,
                        nonce=ps_nonce,
                        canary=ps_canary,
                    )
                    proof_ok = hmac.compare_digest(ps_proof, expected)
                    if not proof_ok:
                        flag("REPEATER_BODY_OR_PATH_TAMPERED", 10, "HMAC proof mismatch")

                    if not hmac.compare_digest(sess["ua_hash"], _sha256_hex(ua)):
                        flag("REPEATER_UA_SESSION_MISMATCH", 6, "User-Agent mismatch")
                    if self.bind_ip and sess["ip"] and norm_ip and sess["ip"] != norm_ip:
                        flag("REPEATER_IP_SESSION_MISMATCH", 6, "Client IP mismatch")
                    if sess["origin"] and origin_hdr and sess["origin"] != origin_hdr:
                        flag("REPEATER_ORIGIN_MISMATCH", 6, "Origin mismatch")

                    if proof_ok:
                        self._used_nonces[nkey] = now + float(self.nonce_ttl_ms)
                    valid_advance = proof_ok and seq_i > sess["last_seq"] and canary_ok
                    if valid_advance and (score < self.threshold or self.mode == "monitor"):
                        sess["last_seq"] = seq_i
                        sess["canary"] = _hmac_hex(self.secret, f"PS_CANARY|{ps_sid}|{seq_i}|{secrets.token_hex(8)}")[:24]
                        next_canary = sess["canary"]

        # Signal 4: Per-IP Rapid Identical Unsigned Replay Burst (true LRU refresh)
        if is_prot and len(body_b) > 0 and not has_any_ps:
            sig = _sha256_hex(f"{upper_method}|{url}|{_sha256_hex(body_b)}")
            arr = [e for e in self._ip_bursts.pop(norm_ip, []) if now - e[0] <= 5000.0]
            same_count = sum(1 for e in arr if e[1] == sig)
            arr.append((now, sig))
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
            rehandshake_recommended=rehandshake_recommended,
        )
