"""
ProxySnare Python Verifier (Zero Dependencies, Python >= 3.10).
Wire- and scoring-compatible with the Node.js `proxysnare` engine and browser guard
(`PS1|` Proof-of-Freshness + Rotating Honey-Canary).
"""

from __future__ import annotations

import hashlib
import hmac
import math
import posixpath
import re
import secrets
import time
from dataclasses import dataclass, field


def _sha256_hex(data: bytes | str) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def _hmac_hex(key: bytes, msg: str) -> str:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).hexdigest()


_PCT_RUN_RE = re.compile(r"(?:%[0-9a-fA-F]{2})+")


def _decode_percent_lenient(s: str) -> str:
    """Decode valid ASCII/UTF-8 percent escapes without letting invalid %ff poison adjacent runs."""
    def _repl(match: re.Match[str]) -> str:
        run = match.group(0)
        out: list[str] = []
        i = 0
        n_run = len(run)
        while i < n_run:
            b = int(run[i + 1 : i + 3], 16)
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
    s = str(raw_url or "/").strip()
    if re.match(r"^https?://", s, re.I):
        after = s.find("://") + 3
        cuts = [idx for idx in (s.find("/", after), s.find("?", after), s.find("#", after)) if idx >= 0]
        if not cuts:
            return "/"
        first = min(cuts)
        s = s[first:] if s[first] == "/" else "/" + s[first:]
    return s


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
    s = s.replace("\\", "/")
    if not s.startswith("/"):
        s = "/" + s
    s = "/".join(seg.split(";", 1)[0] for seg in s.split("/"))
    s = posixpath.normpath(s)
    # POSIX normpath preserves leading '//' — collapse to single '/' (Loop 3 CRIT-4!)
    s = re.sub(r"^/+", "/", s)
    if not s.startswith("/"):
        s = "/" + s
    return s


def _expand_path_candidates(raw_url: str) -> list[str]:
    raw = _strip_scheme_and_authority(raw_url)
    q_idx = raw.find("?")
    raw_path = raw[:q_idx] if q_idx >= 0 else raw
    seen: list[str] = []

    def _add(val: str) -> None:
        n = normalize_pathname(val)
        if n not in seen:
            seen.append(n)

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
        max_sessions: int = 20_000,
        max_nonces: int = 50_000,
        protected_paths: list[str | re.Pattern] | None = None,
    ) -> None:
        m = str("strict" if mode is None else mode).strip().lower()
        if m not in ("off", "monitor", "observe", "balanced", "strict"):
            raise ValueError(f"Unsupported mode: {mode}")
        self.mode = "monitor" if m == "observe" else m
        if secret is None:
            self.secret = secrets.token_bytes(32)
        else:
            sec_b = secret.encode("utf-8") if isinstance(secret, str) else bytes(secret)
            if len(sec_b) < 16:
                raise ValueError("secret must be at least 16 bytes")
            self.secret = sec_b

        self.threshold = threshold if threshold is not None else (4 if self.mode == "strict" else 6)
        self.freshness_ms = freshness_ms if freshness_ms is not None else (8000 if self.mode == "strict" else 15000)
        if self.threshold <= 0 or self.freshness_ms <= 0:
            raise ValueError("threshold and freshness_ms must be positive")
        self.max_future_skew_ms = min(3000, self.freshness_ms)
        self.nonce_ttl_ms = nonce_ttl_ms
        self.session_ttl_ms = session_ttl_ms
        self.max_sessions = max(1, int(max_sessions))
        self.max_nonces = max(1, int(max_nonces))
        raw_paths = protected_paths or ["/api"]
        self.protected_paths: list[str | re.Pattern] = [
            p
            if isinstance(p, re.Pattern)
            else ("*" if str(p).strip() == "*" else normalize_pathname(str(p)))
            for p in raw_paths
        ]
        self._sessions: dict[str, dict] = {}
        self._used_nonces: dict[str, float] = {}
        self._ip_bursts: dict[str, list[tuple[float, str]]] = {}
        self._inspect_counter = 0

    def _prune(self, now: float) -> None:
        if len(self._sessions) >= self.max_sessions:
            expired = [k for k, v in self._sessions.items() if v["exp"] <= now]
            for k in expired:
                self._sessions.pop(k, None)
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
        # Bounded expired-first LRU cleanup on _ip_bursts — never wipe active buckets with .clear() (HIGH-10)
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

    def issue_session(
        self, *, ip: str = "127.0.0.1", user_agent: str = "", origin: str = ""
    ) -> dict | None:
        now = time.time() * 1000.0
        self._prune(now)
        # Refuse new sessions at capacity instead of evicting active unexpired users (HIGH-10)
        if len(self._sessions) >= self.max_sessions:
            return None
        sid = secrets.token_hex(16)
        key = secrets.token_bytes(32)
        canary = _hmac_hex(self.secret, f"PS_CANARY|{sid}|0|{secrets.token_hex(8)}")[:24]
        self._sessions[sid] = {
            "key": key,
            "key_hex": key.hex(),
            "last_seq": 0,
            "canary": canary,
            "ua_hash": _sha256_hex(user_agent),
            "ip": ip,
            "origin": str(origin or "").strip().lower(),
            "exp": now + float(self.session_ttl_ms),
        }
        return {
            "sessionId": sid,
            "sessionKeyHex": key.hex(),
            "canary": canary,
            "freshnessMs": self.freshness_ms,
            "serverNowMs": int(now),
            "protectedPaths": [p for p in self.protected_paths if isinstance(p, str)],
            "protectedRules": self.serialize_protected_rules(),
        }

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
        hdr: dict[str, str] = {}
        for k, v in (headers or {}).items():
            kl = str(k).lower()
            if isinstance(v, (list, tuple)):
                hdr[kl] = ", ".join("" if x is None else str(x) for x in v)
            else:
                hdr[kl] = "" if v is None else str(v)

        reasons: list[dict] = []
        score = 0

        def flag(code: str, weight: int, detail: str) -> None:
            nonlocal score
            score += weight
            reasons.append({"code": code, "weight": weight, "detail": detail})

        is_prot = self.is_path_protected(url)

        # Signal 1: Smuggling & proxy header leaks (ALWAYS runs even on CORS OPTIONS — MED-23!)
        if hdr.get("content-length") and hdr.get("transfer-encoding"):
            flag("CL_TE_SMUGGLING", 10, "Both Content-Length and Transfer-Encoding present")
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
            host_count = sum(1 for ln in raw_header_lines if re.match(r"^host\s*:", ln, re.I))
            if host_count > 1:
                flag("DUPLICATE_HOST_HEADER", 8, f"Duplicate Host headers ({host_count})")

        if upper_method == "OPTIONS" and "access-control-request-method" in hdr:
            blocked = self.mode != "monitor" and score >= self.threshold
            return InspectionResult(not blocked, blocked, score, self.threshold, self.mode, reasons)

        # Signal 2: Browser UA vs Repeater wire contradictions
        ua = hdr.get("user-agent", "")
        cm = re.search(r"Chrome/(\d+)", ua, re.I)
        fm = re.search(r"Firefox/(\d+)", ua, re.I)
        claims_modern = (cm is not None and int(cm.group(1)) >= 80) or (fm is not None and int(fm.group(1)) >= 90)
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
            if hdr.get("connection", "").lower() == "close" and (is_prot or has_proxy_leak):
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
        elif is_prot and re.search(
            r"burp|caido|mitmproxy|sqlmap|ffuf|nuclei|curl/|python-requests|go-http-client|insomnia|postman",
            ua,
            re.I,
        ):
            flag("NON_BROWSER_REPLAY_CLIENT", 4, "Direct replay/CLI client User-Agent on protected route")

        # Signal 3: Proof-of-Freshness + Rotating Canary
        ps_sid = hdr.get("x-ps-session", "").strip()
        ps_seq = hdr.get("x-ps-seq", "").strip()
        ps_ts = hdr.get("x-ps-ts", "").strip()
        ps_nonce = hdr.get("x-ps-nonce", "").strip()
        ps_canary = hdr.get("x-ps-canary", "").strip()
        ps_proof = hdr.get("x-ps-proof", "").strip()
        has_any_ps = any((ps_sid, ps_seq, ps_ts, ps_nonce, ps_canary, ps_proof))
        next_canary = None

        if is_prot or has_any_ps:
            if not all((ps_sid, ps_seq, ps_ts, ps_nonce, ps_canary, ps_proof)):
                if is_prot:
                    flag("REPEATER_PROOF_MISSING", 8 if self.mode == "strict" else 6, "Missing Proof-of-Freshness headers")
            elif (
                not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", ps_nonce)
                or not re.fullmatch(r"[a-fA-F0-9]{16,64}", ps_sid)
                or not re.fullmatch(r"[a-fA-F0-9]{64}", ps_proof)
                or not re.fullmatch(r"[a-fA-F0-9]{16,64}", ps_canary)
                or "|" in ps_seq
                or "|" in ps_ts
                or "|" in upper_method
            ):
                # Strict delimiter-free validation eliminates HMAC '|' canonicalization injection (CRIT-5)
                flag("REPEATER_BODY_OR_PATH_TAMPERED", 10, "Malformed Proof-of-Freshness header syntax")
            else:
                sess = self._sessions.get(ps_sid)
                if not sess or sess["exp"] <= now:
                    flag("REPEATER_UNKNOWN_OR_EXPIRED_SESSION", 8, "Unknown or expired session")
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
                    if sess["origin"] and origin_hdr and sess["origin"] != origin_hdr:
                        flag("REPEATER_ORIGIN_MISMATCH", 6, "Origin mismatch")

                    if proof_ok:
                        self._used_nonces[nkey] = now + float(self.nonce_ttl_ms)
                    # Require authentic proof, monotonic seq, and valid canary BEFORE advancing seq/canary (MED-19)
                    valid_advance = proof_ok and seq_i > sess["last_seq"] and canary_ok
                    if valid_advance and (score < self.threshold or self.mode == "monitor"):
                        sess["last_seq"] = seq_i
                        sess["canary"] = _hmac_hex(self.secret, f"PS_CANARY|{ps_sid}|{seq_i}|{secrets.token_hex(8)}")[:24]
                        next_canary = sess["canary"]

        # Signal 4: Per-IP Rapid Identical Unsigned Replay Burst (true LRU refresh)
        if is_prot and len(body_b) > 0 and not has_any_ps:
            sig = _sha256_hex(f"{upper_method}|{url}|{_sha256_hex(body_b)}")
            arr = [e for e in self._ip_bursts.pop(ip, []) if now - e[0] <= 5000.0]
            same_count = sum(1 for e in arr if e[1] == sig)
            arr.append((now, sig))
            self._ip_bursts[ip] = arr[-30:]
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
        )
