"""/oauth/revoke 单元测试 (RFC 7009).

按 CLAUDE §6.3.2: 不打印 token 明文.
按 CLAUDE §7: KISS — 5 个核心 case 覆盖 RFC 7009 §2 关键路径.
"""
from __future__ import annotations

import json
import secrets

from sqlalchemy.orm import Session

from qcn_mcp_bridge.auth.revoke import handle_revoke
from qcn_mcp_bridge.auth.storage import (
    find_token_by_access,
    find_token_by_refresh,
    save_token,
)


def _save_test_token(SessionLocal, *, user_id: int = 1234, tenant_id: int = 42):
    """保存一对测试 access + refresh token 到 oauth_tokens 表. 返回 (access, refresh) 明文."""
    access = secrets.token_urlsafe(32)
    refresh = secrets.token_urlsafe(32)
    session = SessionLocal()
    try:
        save_token(
            session,
            access_token=access,
            refresh_token=refresh,
            client_id="test-client",
            user_id=user_id,
            tenant_id=tenant_id,
            product="qcn",
            scope="read:demand",
            access_ttl_seconds=3600,
            refresh_ttl_seconds=86400,
        )
    finally:
        session.close()
    return access, refresh


def test_revoke_missing_token_returns_400(tmp_db):
    """body 无 token → 400 invalid_request (RFC 7009 §2.2.1)."""
    _, SessionLocal = tmp_db
    session: Session = SessionLocal()
    try:
        resp = handle_revoke(session, form={})
        assert resp.status_code == 400
        body = json.loads(bytes(resp.body).decode("utf-8"))
        assert body["error"] == "invalid_request"
        assert "token" in body.get("error_description", "")
    finally:
        session.close()


def test_revoke_access_token_marks_revoked_and_blocks_lookup(tmp_db):
    """access_token 撤销 → DB revoked=True + find_token_by_access 返 None."""
    _, SessionLocal = tmp_db
    access, _ = _save_test_token(SessionLocal)
    session: Session = SessionLocal()
    try:
        resp = handle_revoke(
            session, form={"token": access, "token_type_hint": "access_token"}
        )
        assert resp.status_code == 200
        # 再查应返 None (revoked=True 让 find 视为不存在)
        s2: Session = SessionLocal()
        try:
            assert find_token_by_access(s2, access_token=access) is None
        finally:
            s2.close()
    finally:
        session.close()


def test_revoke_refresh_token_marks_revoked(tmp_db):
    """refresh_token 撤销 → DB revoked=True + find_token_by_refresh 返 None."""
    _, SessionLocal = tmp_db
    _, refresh = _save_test_token(SessionLocal)
    session: Session = SessionLocal()
    try:
        resp = handle_revoke(
            session, form={"token": refresh, "token_type_hint": "refresh_token"}
        )
        assert resp.status_code == 200
        s2: Session = SessionLocal()
        try:
            assert find_token_by_refresh(s2, refresh_token=refresh) is None
        finally:
            s2.close()
    finally:
        session.close()


def test_revoke_unknown_token_returns_200(tmp_db):
    """RFC 7009 §2.2: 未知 token 一律返 200 (不泄露存在性)."""
    _, SessionLocal = tmp_db
    session: Session = SessionLocal()
    try:
        resp = handle_revoke(session, form={"token": "never-issued-token-xyz"})
        assert resp.status_code == 200
    finally:
        session.close()


def test_revoke_without_hint_still_revokes_both_columns(tmp_db):
    """无 token_type_hint 也兜底尝试 access + refresh 双 revoke (RFC 7009 §2.1 hint 可选)."""
    _, SessionLocal = tmp_db
    access, refresh = _save_test_token(SessionLocal)
    session: Session = SessionLocal()
    try:
        resp = handle_revoke(session, form={"token": access})  # 不传 hint
        assert resp.status_code == 200
        # 同一 token 行的 refresh 也应被废 (兜底)
        s2: Session = SessionLocal()
        try:
            assert find_token_by_refresh(s2, refresh_token=refresh) is None
        finally:
            s2.close()
    finally:
        session.close()
