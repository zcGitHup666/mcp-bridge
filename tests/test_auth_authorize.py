"""/oauth/authorize 单元测试 (RFC 6749 §4.1, 接入方案 §A5/A7).

Phase 1A: authorize 端点直接生成 code → 302 redirect (登录页 Phase 2 加).
"""
from __future__ import annotations

import json
from sqlalchemy.orm import Session

from qcn_mcp_bridge.auth.authorize import handle_authorize
from qcn_mcp_bridge.auth.dynamic_client import register_client
from qcn_mcp_bridge.auth.pkce import generate_code_verifier, derive_code_challenge


def _client(SessionLocal) -> dict:
    """注册一个测试 client, 返回 client_id."""
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


def _query(**overrides) -> dict[str, str]:
    """构造有效 query (按 RFC 7636 §4.4 + 接入方案 §A7)."""
    verifier = generate_code_verifier(64)
    q = {
        "response_type": "code",
        "client_id": "test-client",  # 测试时会被替换
        "redirect_uri": "https://app/cb",
        "code_challenge": derive_code_challenge(verifier, "S256"),
        "code_challenge_method": "S256",
        "state": "csrf-token-123",
        "scope": "read:demand",
    }
    q.update(overrides)
    return q


def test_authorize_success_redirect_302(tmp_db):
    """成功路径: 生成 code → 302 redirect."""
    _, SessionLocal = tmp_db
    client = _client(SessionLocal)
    session: Session = SessionLocal()
    try:
        q = _query(client_id=client["client_id"])
        redirect, err = handle_authorize(session, query=q)
        assert err is None
        # RedirectResponse (status 302)
        assert redirect.status_code == 302
        # Location: https://app/cb?code=xxx&state=csrf-token-123
        loc = redirect.headers["location"]
        assert loc.startswith("https://app/cb?")
        assert "code=" in loc
        assert "&state=csrf-token-123" in loc
    finally:
        session.close()


def test_authorize_missing_code_challenge(tmp_db):
    """缺失 code_challenge → invalid_request (§A7 PKCE 强制)."""
    _, SessionLocal = tmp_db
    client = _client(SessionLocal)
    session: Session = SessionLocal()
    try:
        q = _query(client_id=client["client_id"])
        del q["code_challenge"]
        redirect, err = handle_authorize(session, query=q)
        assert redirect is None
        body = json.loads(bytes(err.body).decode("utf-8"))
        assert body["error"] == "invalid_request"
        assert "code_challenge" in body["error_description"]
    finally:
        session.close()


def test_authorize_wrong_code_challenge_method(tmp_db):
    """code_challenge_method != S256 → unsupported_code_challenge_method (§A7)."""
    _, SessionLocal = tmp_db
    client = _client(SessionLocal)
    session: Session = SessionLocal()
    try:
        q = _query(
            client_id=client["client_id"],
            code_challenge_method="plain",  # 不允许
        )
        redirect, err = handle_authorize(session, query=q)
        assert redirect is None
        body = json.loads(bytes(err.body).decode("utf-8"))
        assert body["error"] == "unsupported_code_challenge_method"
    finally:
        session.close()


def test_authorize_unknown_client_id(tmp_db):
    """未知 client_id → invalid_client."""
    _, SessionLocal = tmp_db
    session: Session = SessionLocal()
    try:
        q = _query(client_id="ghost-client")
        redirect, err = handle_authorize(session, query=q)
        assert redirect is None
        body = json.loads(bytes(err.body).decode("utf-8"))
        assert body["error"] == "invalid_client"
    finally:
        session.close()


def test_authorize_unregistered_redirect_uri(tmp_db):
    """redirect_uri 不在 client 白名单 → invalid_request (§B5)."""
    _, SessionLocal = tmp_db
    client = _client(SessionLocal)
    session: Session = SessionLocal()
    try:
        q = _query(
            client_id=client["client_id"],
            redirect_uri="https://evil.com/cb",  # 不在白名单
        )
        redirect, err = handle_authorize(session, query=q)
        assert redirect is None
        body = json.loads(bytes(err.body).decode("utf-8"))
        assert body["error"] == "invalid_request"
    finally:
        session.close()


def test_authorize_wrong_response_type(tmp_db):
    """response_type != 'code' → unsupported_response_type."""
    _, SessionLocal = tmp_db
    client = _client(SessionLocal)
    session: Session = SessionLocal()
    try:
        q = _query(client_id=client["client_id"], response_type="token")
        redirect, err = handle_authorize(session, query=q)
        assert redirect is None
        body = json.loads(bytes(err.body).decode("utf-8"))
        assert body["error"] == "unsupported_response_type"
    finally:
        session.close()