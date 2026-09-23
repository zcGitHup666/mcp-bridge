"""PKCE (RFC 7636) — S256 校验。

按接入方案 §A7: PKCE S256 必须强制校验, code_verifier 不对 → 400 invalid_grant。

按 CLAUDE §6.3.2: 不记录明文 code_verifier (只在内存瞬时存在, 不落库)。
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import secrets


def generate_code_verifier(length: int = 64) -> str:
    """生成 PKCE code_verifier (RFC 7636 §4.1)。

    length: 43-128 字符 (RFC 推荐 64+)。这里默认 64。
    字符集: [A-Z][a-z][0-9]-._~ (unreserved characters)
    """
    if not 43 <= length <= 128:
        raise ValueError(f"code_verifier length 必须在 43-128 之间, 当前 {length}")
    # secrets.token_urlsafe 生成 base64url-safe 字符串
    # 长度 = n 字节 -> ~1.33n 字符, 这里取 length 字节 ≈ 1.5n 字符 (足够)
    raw = secrets.token_bytes(length)
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")[:length]


def derive_code_challenge(code_verifier: str, method: str = "S256") -> str:
    """从 code_verifier 派生 code_challenge (RFC 7636 §4.2)。

    method: 'S256' (推荐) 或 'plain' (不推荐, 接入方案强制 S256)。
    """
    if method == "S256":
        digest = hashlib.sha256(code_verifier.encode("ascii")).digest()
        return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    if method == "plain":
        return code_verifier
    raise ValueError(f"不支持的 code_challenge_method: {method}")


def verify_pkce(
    code_verifier: str,
    code_challenge: str,
    code_challenge_method: str = "S256",
) -> bool:
    """校验 PKCE: derived(code_verifier) == code_challenge。

    按接入方案 §A7 + RFC 7636 §4.6: 用**恒定时间比较**避免 timing attack。
    返回 bool (不是抛异常): 由 controller 决定返回 invalid_grant 错误。
    """
    try:
        derived = derive_code_challenge(code_verifier, code_challenge_method)
    except ValueError:
        return False
    # hmac.compare_digest: 恒定时间字符串比较, 避免 timing attack
    return hmac.compare_digest(derived, code_challenge)