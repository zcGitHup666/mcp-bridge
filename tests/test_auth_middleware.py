"""Phase 1B: Bearer 校验 middleware 测试 (RFC 6750 + 接入方案 §A1/A7/A8).

按 CLAUDE §6.3.2: 不打印 token 明文 (测试里只用长度断言).
按 CLAUDE §7: KISS — 5 个 case 覆盖核心路径.
"""
from __future__ import annotations

import time

import jwt
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.routing import Route
from starlette.testclient import TestClient

from qcn_mcp_bridge.auth.jwt_signer import JWTSigner
from qcn_mcp_bridge.auth.middleware import BearerAuthMiddleware
from qcn_mcp_bridge.auth.storage import init_engine, save_token


# 共享 fixture: 简单 protected app, 通过后返回 200 + request.state.user
def _make_protected_app(
    *, jwt_signer: JWTSigner, session_factory
) -> Starlette:
    def _echo(request: Request):
        # 200, 返回 request.state.user (验证注入)
        from starlette.responses import JSONResponse
        return JSONResponse({"user": request.state.user})

    inner = Starlette(routes=[Route("/protected", _echo)])
    return BearerAuthMiddleware(
        inner,
        jwt_signer=jwt_signer,
        session_factory=session_factory,
        resource_metadata_url="https://test.bridge/.well-known/oauth-protected-resource",
    )


def _seed_token(SessionLocal, *, jwt_signer, scope: str = "read:demand") -> str:
    """写一个有效 token 到 oauth_tokens 表, 返回明文 token."""
    session = SessionLocal()
    try:
        token = jwt_signer.sign(sub=5083, scope=scope, ttl_seconds=3600)
        save_token(
            session,
            access_token=token,
            refresh_token=None,
            client_id="test-client",
            user_id=5083,
            tenant_id=42,
            product="qcn",
            scope=scope,
            access_ttl_seconds=3600,
            refresh_ttl_seconds=None,
        )
        return token
    finally:
        session.close()


def test_no_authorization_returns_401_with_www_authenticate(tmp_db, jwt_signer):
    """§A1: 无 Authorization → 401 + WWW-Authenticate 触发 client OAuth 流程."""
    _, SessionLocal = tmp_db
    app = _make_protected_app(jwt_signer=jwt_signer, session_factory=SessionLocal)
    client = TestClient(app)
    r = client.get("/protected")
    assert r.status_code == 401
    # WWW-Authenticate 头必须含 Bearer + resource_metadata (RFC 6750)
    www_auth = r.headers["www-authenticate"]
    assert "Bearer" in www_auth
    assert 'resource_metadata="https://test.bridge/.well-known/oauth-protected-resource"' in www_auth
    # body 也带 error
    body = r.json()
    assert body["error"] == "invalid_request"


def test_authorization_without_bearer_prefix_returns_401(tmp_db, jwt_signer):
    """Authorization 不是 Bearer 前缀 → 401."""
    _, SessionLocal = tmp_db
    app = _make_protected_app(jwt_signer=jwt_signer, session_factory=SessionLocal)
    client = TestClient(app)
    r = client.get("/protected", headers={"Authorization": "Basic dXNlcjpwYXNz"})
    assert r.status_code == 401
    assert r.json()["error"] == "invalid_request"


def test_bearer_with_invalid_signature_returns_401(tmp_db, jwt_signer):
    """Bearer 但 JWT 签名错 → invalid_token."""
    _, SessionLocal = tmp_db
    app = _make_protected_app(jwt_signer=jwt_signer, session_factory=SessionLocal)
    client = TestClient(app)
    # 用别的密钥签一个 token, signer.verify 验签失败
    fake_signer = JWTSigner.__new__(JWTSigner)
    fake_signer._private_key_pem = _gen_fake_key()
    fake_signer._public_key = _load_pub(_gen_fake_key())
    fake_signer._key_id = "fake"
    fake_signer._issuer = "https://test.bridge"
    fake_signer._audience = "https://test.bridge/mcp"
    fake_signer._algorithm = "RS256"
    fake_token = fake_signer.sign(sub=1, scope="read:demand")
    r = client.get("/protected", headers={"Authorization": f"Bearer {fake_token}"})
    assert r.status_code == 401
    assert r.json()["error"] == "invalid_token"


def test_bearer_with_aud_mismatch_returns_401(tmp_db, jwt_signer):
    """Bearer JWT 验签 OK 但 aud 不匹配 → invalid_token (§A8)."""
    _, SessionLocal = tmp_db
    app = _make_protected_app(jwt_signer=jwt_signer, session_factory=SessionLocal)
    client = TestClient(app)
    # 用错误的 audience 签 token (但 secret 跟 jwt_signer 一样)
    expired_signer = JWTSigner.__new__(JWTSigner)
    expired_signer._private_key_pem = jwt_signer._private_key_pem
    expired_signer._public_key = jwt_signer._public_key
    expired_signer._key_id = jwt_signer._key_id
    expired_signer._issuer = jwt_signer._issuer
    expired_signer._audience = "https://wrong.audience"  # 错!
    expired_signer._algorithm = "RS256"
    expired_token = expired_signer.sign(sub=1, scope="read:demand", ttl_seconds=3600)
    r = client.get("/protected", headers={"Authorization": f"Bearer {expired_token}"})
    assert r.status_code == 401


def test_bearer_valid_token_in_db_passes(tmp_db, jwt_signer):
    """正向: Bearer JWT OK + token 表里存在 → 200, request.state.user 注入."""
    _, SessionLocal = tmp_db
    token = _seed_token(SessionLocal, jwt_signer=jwt_signer, scope="read:demand")
    app = _make_protected_app(jwt_signer=jwt_signer, session_factory=SessionLocal)
    client = TestClient(app)
    r = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 200
    body = r.json()
    # current_user 注入校验
    user = body["user"]
    assert user["sub"] == "5083"
    assert user["user_id"] == 5083
    assert user["scope"] == "read:demand"
    assert user["tenant_id"] == 42


def test_bearer_valid_jwt_but_not_in_db_returns_401(tmp_db, jwt_signer):
    """Bearer JWT 验签 OK 但 token 表里没存 → 401 (replay/伪造)."""
    _, SessionLocal = tmp_db
    # 不调 _seed_token, 只签 JWT
    fake_token = jwt_signer.sign(sub=999, scope="read:demand")
    app = _make_protected_app(jwt_signer=jwt_signer, session_factory=SessionLocal)
    client = TestClient(app)
    r = client.get("/protected", headers={"Authorization": f"Bearer {fake_token}"})
    assert r.status_code == 401
    assert r.json()["error"] == "invalid_token"


def test_required_scope_enforced(tmp_db, jwt_signer):
    """§A12: token scope 不足 → insufficient_scope."""
    _, SessionLocal = tmp_db
    # token scope = "read:supply", middleware 要求 "read:demand"
    token = _seed_token(SessionLocal, jwt_signer=jwt_signer, scope="read:supply")
    from starlette.applications import Starlette
    from starlette.requests import Request
    from starlette.responses import JSONResponse
    from starlette.routing import Route
    from qcn_mcp_bridge.auth.middleware import BearerAuthMiddleware

    def _echo(req: Request):
        return JSONResponse({"user": req.state.user})
    inner = Starlette(routes=[Route("/protected", _echo)])
    protected = BearerAuthMiddleware(
        inner,
        jwt_signer=jwt_signer,
        session_factory=SessionLocal,
        resource_metadata_url="https://test.bridge/.well-known/oauth-protected-resource",
        required_scope="read:demand",  # 要求 read:demand
    )
    client = TestClient(protected)
    r = client.get("/protected", headers={"Authorization": f"Bearer {token}"})
    assert r.status_code == 401
    assert r.json()["error"] == "insufficient_scope"


def _gen_fake_key() -> str:
    """生成一个临时 RSA 私钥 (用于伪造 token)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from pathlib import Path
    import tempfile

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    p = Path(tempfile.gettempdir()) / "fake_key.pem"
    p.write_bytes(pem)
    return pem.decode("utf-8")


def _load_pub(pem_str: str):
    """从 PEM 私钥字符串加载 RSAPublicKey 对象 (绕过 __init__ 复用 signer)."""
    from cryptography.hazmat.primitives.serialization import load_pem_private_key
    return load_pem_private_key(pem_str.encode("utf-8"), password=None).public_key()