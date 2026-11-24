"""
ProxySnare Python Verifier (Zero Dependencies, Python >= 3.10).
Wire-compatible with the Node.js `proxysnare` browser guard (`PS1|` Proof-of-Freshness + Rotating Canary).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
import time
from dataclasses import dataclass, field


def _sha256_hex(data: bytes | str) -> str:
    raw = data.encode("utf-8") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def _hmac_hex(key: bytes, msg: str) -> str:
    return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).hexdigest()


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
        mode: str = "strict",
        secret: bytes | None = None,
        freshness_ms: int | None = None,
        protected_paths: list[str] | None = None,
    ) -> None:
        m = mode.strip().lower()
        if m not in ("off", "monitor", "balanced", "strict"):
            raise ValueError(f"Unsupported mode: {mode}")
        self.mode = m
        self.secret = secret or secrets.token_bytes(32)
        self.threshold = 4 if m == "strict" else 6
        self.freshness_ms = freshness_ms if freshness_ms is not None else (8000 if m == "strict" else 15000)
        self.protected_paths = protected_paths or ["/api"]
        self._sessions: dict[str, dict] = {}
        self._used_nonces: dict[str, float] = {}

    def issue_session(self, *, ip: str = "127.0.0.1", user_agent: str = "") -> dict:
        now = time.time() * 1000.0
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
            "exp": now + 1_800_000.0,
        }
        return {
            "sessionId": sid,
            "sessionKeyHex": key.hex(),
            "canary": canary,
            "freshnessMs": self.freshness_ms,
            "serverNowMs": int(now),
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
        headers: dict[str, str],
        body: bytes = b"",
        now_ms: float | None = None,
    ) -> InspectionResult:
        if self.mode == "off":
            return InspectionResult(True, False, 0, self.threshold, self.mode)
        now = now_ms if now_ms is not None else time.time() * 1000.0
        hdr = {k.lower(): v for k, v in headers.items()}
        reasons: list[dict] = []
        score = 0

        def flag(code: str, weight: int, detail: str) -> None:
            nonlocal score
            score += weight
            reasons.append({"code": code, "weight": weight, "detail": detail})

        if hdr.get("content-length") and hdr.get("transfer-encoding"):
            flag("CL_TE_SMUGGLING", 10, "Both Content-Length and Transfer-Encoding present")
        for ph in ("proxy-connection", "x-burp-header", "x-caido-id", "x-caido-replay", "x-mitmproxy"):
            if ph in hdr:
                flag("PROXY_HEADER_LEAK", 5, f"Proxy artifact header '{ph}'")

        ua = hdr.get("user-agent", "")
        if "Chrome/" in ua or "Firefox/" in ua:
            if not hdr.get("sec-fetch-site") and not hdr.get("sec-fetch-mode"):
                flag("FETCH_METADATA_MISSING", 4, "Modern browser UA missing Sec-Fetch metadata")
            if hdr.get("connection", "").lower() == "close":
                flag("REPEATER_CONNECTION_CLOSE", 3, "Modern browser UA sent Connection: close")

        pathname = url.split("?")[0]
        is_prot = any(p == "*" or pathname == p or pathname.startswith(p.rstrip("/") + "/") for p in self.protected_paths)
        ps_sid = hdr.get("x-ps-session", "")
        ps_seq = hdr.get("x-ps-seq", "")
        ps_ts = hdr.get("x-ps-ts", "")
        ps_nonce = hdr.get("x-ps-nonce", "")
        ps_canary = hdr.get("x-ps-canary", "")
        ps_proof = hdr.get("x-ps-proof", "")
        next_canary = None

        if is_prot or any((ps_sid, ps_seq, ps_ts, ps_nonce, ps_canary, ps_proof)):
            if not all((ps_sid, ps_seq, ps_ts, ps_nonce, ps_canary, ps_proof)):
                flag("REPEATER_PROOF_MISSING", 8 if self.mode == "strict" else 5, "Missing Proof-of-Freshness headers")
            else:
                sess = self._sessions.get(ps_sid)
                if not sess or sess["exp"] <= now:
                    flag("REPEATER_UNKNOWN_OR_EXPIRED_SESSION", 8, "Unknown or expired session")
                else:
                    nkey = f"{ps_sid}:{ps_nonce}"
                    if self._used_nonces.get(nkey, 0.0) > now:
                        flag("REPEATER_NONCE_REPLAYED", 10, "Single-use nonce replayed")
                    try:
                        seq_i = int(ps_seq)
                        ts_f = float(ps_ts)
                    except ValueError:
                        seq_i, ts_f = -1, -1.0
                    if seq_i <= sess["last_seq"]:
                        flag("REPEATER_SEQ_REPLAY", 8, "Non-monotonic sequence")
                    if abs(now - ts_f) > self.freshness_ms:
                        flag("INTERCEPT_HOLD_OR_STALE_REPLAY", 6, "Freshness window exceeded")
                    if not hmac.compare_digest(ps_canary, sess["canary"]):
                        flag("REPEATER_STALE_CANARY", 8, "Stale honey-canary")
                    expected = self.sign_request(
                        session_key_hex=sess["key_hex"],
                        method=method,
                        path_with_query=url,
                        body=body,
                        seq=ps_seq,
                        ts=ps_ts,
                        nonce=ps_nonce,
                        canary=ps_canary,
                    )
                    if not hmac.compare_digest(ps_proof, expected):
                        flag("REPEATER_BODY_OR_PATH_TAMPERED", 10, "HMAC proof mismatch")
                    if sess["ua_hash"] != _sha256_hex(ua):
                        flag("REPEATER_UA_SESSION_MISMATCH", 6, "User-Agent mismatch")
                    self._used_nonces[nkey] = now + 300_000.0
                    if score < self.threshold:
                        sess["last_seq"] = seq_i
                        sess["canary"] = _hmac_hex(self.secret, f"PS_CANARY|{ps_sid}|{seq_i}|{secrets.token_hex(8)}")[:24]
                        next_canary = sess["canary"]

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
