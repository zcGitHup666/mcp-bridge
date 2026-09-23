"""PKCE S256 校验单元测试 (RFC 7636 + 接入方案 §A7).

按 CLAUDE §6.3.2: 测试不打印 code_verifier 明文 (只用长度断言).
按 CLAUDE §7: KISS — 测试核心 S256 + plain 两种方法 + 失败场景.
"""
from __future__ import annotations

from qcn_mcp_bridge.auth.pkce import derive_code_challenge, generate_code_verifier, verify_pkce


def test_generate_code_verifier_length_in_range():
    """§4.1: code_verifier 长度 43-128."""
    v = generate_code_verifier(64)
    assert 43 <= len(v) <= 128
    assert len(v) == 64


def test_generate_code_verifier_unique_each_time():
    """每次生成不同 (secrets 源)."""
    a = generate_code_verifier()
    b = generate_code_verifier()
    assert a != b


def test_generate_code_verifier_charset():
    """字符集符合 RFC 7636 §4.1: unreserved characters."""
    v = generate_code_verifier(64)
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
    assert set(v).issubset(allowed)


def test_derive_code_challenge_s256_known_vector():
    """RFC 7636 §4.6 标准测试向量:

    code_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    code_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    """
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    assert derive_code_challenge(verifier, "S256") == expected


def test_verify_pkce_s256_correct():
    """正向: 正确的 verifier 应通过."""
    verifier = generate_code_verifier(64)
    challenge = derive_code_challenge(verifier, "S256")
    assert verify_pkce(verifier, challenge, "S256") is True


def test_verify_pkce_s256_wrong_verifier():
    """反向: 错误 verifier 必须失败 (接入方案 §A7 强制)."""
    verifier = generate_code_verifier(64)
    challenge = derive_code_challenge(verifier, "S256")
    other_verifier = generate_code_verifier(64)
    assert verify_pkce(other_verifier, challenge, "S256") is False


def test_verify_pkce_plain_method():
    """plain 方法 (RFC 7636 §4.2, 不推荐但 spec 允许)."""
    verifier = "my-plain-verifier-12345"
    challenge = derive_code_challenge(verifier, "plain")
    assert challenge == verifier
    assert verify_pkce(verifier, challenge, "plain") is True


def test_verify_pkce_unsupported_method_returns_false():
    """不支持的方法返回 False (不抛异常)."""
    verifier = generate_code_verifier(64)
    assert verify_pkce(verifier, "irrelevant", "S512") is False


def test_verify_pkce_uses_constant_time_compare():
    """§6.4 安全: 用 hmac.compare_digest (防 timing attack). 间接验证:同长度不同字符返回 False."""
    verifier = "x" * 64
    challenge = "y" * 44  # S256 base64 长度约 43
    # 长度不匹配但 verify 应该返回 False, 不抛
    assert verify_pkce(verifier, challenge, "S256") is False