"""/oauth/token 单元测试 (RFC 6749 §4.1.3 / §6, 接入方案 §A6/A7/A10).

覆盖:
- authorization_code grant + PKCE S256 校验
- 错误 code_verifier → invalid_grant (强制)
- refresh_token grant + token rotation (RFC 6819 §5.2.2.1)
"""
from __future__ import annotations

import json
from sqlalchemy.orm import Session

from qcn_mcp_bridge.auth.authorize import handle_authorize
from qcn_mcp_bridge.auth.dynamic_client import register_client
from qcn_mcp_bridge.auth.jwt_signer import JWTSigner
from qcn_mcp_bridge.auth.pkce import derive_code_challenge, generate_code_verifier
from qcn_mcp_bridge.auth.storage import consume_auth_code, find_token_by_access
from qcn_mcp_bridge.auth.token import handle_token


# --------- 测试工具函数 ---------

def _register_client(SessionLocal) -> dict:
    session: Session = SessionLocal()
    try:
        resp, _ = register_client(
            session,
            body={
                "client_name": "Test",
                "redirect_uris": ["https://app/cb"],
            },
            default_scopes=["read:demand", "read:supply"],
        )
        return resp
    finally:
        session.close()


def _authorize_code(SessionLocal, client_id: str) -> tuple[str, str]:
    """走 authorize 端点拿到 code + code_verifier."""
    verifier = generate_code_verifier(64)
    challenge = derive_code_challenge(verifier, "S256")
    session: Session = SessionLocal()
    try:
        redirect, err = handle_authorize(
            session,
            query={
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": "https://app/cb",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "scope": "read:demand",
            },
        )
        # 提取 code from Location header
        loc = redirect.headers["location"]
        # Location: https://app/cb?code=xxx&state=...
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(loc).query)
        return qs["code"][0], verifier
    finally:
        session.close()


# --------- authorization_code 测试 ---------

def test_token_authorization_code_success(tmp_db, jwt_signer):
    """正向: 正确 PKCE → 200 + access_token + refresh_token."""
    _, SessionLocal = tmp_db
    client = _register_client(SessionLocal)
    code, verifier = _authorize_code(SessionLocal, client["client_id"])

    session: Session = SessionLocal()
    try:
        response, err = handle_token(
            session,
            form={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app/cb",
                "client_id": client["client_id"],
                "code_verifier": verifier,
            },
            jwt_signer=jwt_signer,
        )
        assert err is None
        assert response is not None
        assert response["token_type"] == "Bearer"
        assert response["scope"] == "read:demand"
        assert "access_token" in response
        assert "refresh_token" in response
        assert response["expires_in"] > 0
    finally:
        session.close()


def test_token_authorization_code_wrong_verifier_returns_invalid_grant(tmp_db, jwt_signer):
    """反向: 错误 code_verifier → invalid_grant (接入方案 §A7 强制)."""
    _, SessionLocal = tmp_db
    client = _register_client(SessionLocal)
    code, _ = _authorize_code(SessionLocal, client["client_id"])

    session: Session = SessionLocal()
    try:
        response, err = handle_token(
            session,
            form={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app/cb",
                "client_id": client["client_id"],
                "code_verifier": "totally-wrong-verifier-but-43-chars-aaaaa",
            },
            jwt_signer=jwt_signer,
        )
        assert response is None
        body = json.loads(bytes(err.body).decode("utf-8"))
        assert body["error"] == "invalid_grant"
    finally:
        session.close()


def test_token_code_is_single_use(tmp_db, jwt_signer):
    """§B2 一次性: 同一个 code 第二次换 token 失败."""
    _, SessionLocal = tmp_db
    client = _register_client(SessionLocal)
    code, verifier = _authorize_code(SessionLocal, client["client_id"])

    # 第一次成功
    session: Session = SessionLocal()
    try:
        r1, _ = handle_token(
            session,
            form={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app/cb",
                "client_id": client["client_id"],
                "code_verifier": verifier,
            },
            jwt_signer=jwt_signer,
        )
        assert r1 is not None
    finally:
        session.close()

    # 第二次同样 code → 失败
    session: Session = SessionLocal()
    try:
        r2, err = handle_token(
            session,
            form={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app/cb",
                "client_id": client["client_id"],
                "code_verifier": verifier,
            },
            jwt_signer=jwt_signer,
        )
        assert r2 is None
        body = json.loads(bytes(err.body).decode("utf-8"))
        assert body["error"] == "invalid_grant"
    finally:
        session.close()


def test_token_wrong_client_id_returns_invalid_grant(tmp_db, jwt_signer):
    """client_id 不匹配 → invalid_grant."""
    _, SessionLocal = tmp_db
    client = _register_client(SessionLocal)
    code, verifier = _authorize_code(SessionLocal, client["client_id"])

    session: Session = SessionLocal()
    try:
        response, err = handle_token(
            session,
            form={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app/cb",
                "client_id": "wrong-client",
                "code_verifier": verifier,
            },
            jwt_signer=jwt_signer,
        )
        assert response is None
        body = json.loads(bytes(err.body).decode("utf-8"))
        assert body["error"] in ("invalid_grant", "invalid_client")
    finally:
        session.close()


def test_token_unsupported_grant_type(tmp_db, jwt_signer):
    """grant_type 不支持 → unsupported_grant_type."""
    _, SessionLocal = tmp_db
    session: Session = SessionLocal()
    try:
        response, err = handle_token(
            session,
            form={"grant_type": "client_credentials", "client_id": "x"},
            jwt_signer=jwt_signer,
        )
        assert response is None
        body = json.loads(bytes(err.body).decode("utf-8"))
        assert body["error"] == "unsupported_grant_type"
    finally:
        session.close()


# --------- refresh_token 测试 ---------

def test_token_refresh_rotation(tmp_db, jwt_signer):
    """§A10: refresh_token grant + token rotation (旧 refresh 撤销, 新 refresh 签发)."""
    _, SessionLocal = tmp_db
    client = _register_client(SessionLocal)
    code, verifier = _authorize_code(SessionLocal, client["client_id"])

    session: Session = SessionLocal()
    try:
        # 第一次拿 token
        r1, _ = handle_token(
            session,
            form={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": "https://app/cb",
                "client_id": client["client_id"],
                "code_verifier": verifier,
            },
            jwt_signer=jwt_signer,
        )
        assert r1 is not None
        refresh_1 = r1["refresh_token"]
    finally:
        session.close()

    # 用 refresh_token 换新
    session: Session = SessionLocal()
    try:
        r2, err = handle_token(
            session,
            form={
                "grant_type": "refresh_token",
                "client_id": client["client_id"],
                "refresh_token": refresh_1,
            },
            jwt_signer=jwt_signer,
        )
        assert err is None
        assert r2 is not None
        assert "access_token" in r2
        assert r2["refresh_token"] != refresh_1  # rotation: 新 refresh_token
    finally:
        session.close()

    # 旧 refresh_token 再用 → 失败
    session: Session = SessionLocal()
    try:
        r3, err = handle_token(
            session,
            form={
                "grant_type": "refresh_token",
                "client_id": client["client_id"],
                "refresh_token": refresh_1,  # 旧 refresh
            },
            jwt_signer=jwt_signer,
        )
        assert r3 is None
        body = json.loads(bytes(err.body).decode("utf-8"))
        assert body["error"] == "invalid_grant"
    finally:
        session.close()