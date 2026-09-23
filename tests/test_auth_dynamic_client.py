"""RFC 7591 OAuth Dynamic Client Registration 单元测试 (接入方案 §A4).

按 CLAUDE §6.3.2: 不打印 client_id 明文 (测试里只用长度断言).
"""
from __future__ import annotations

from sqlalchemy.orm import Session

from qcn_mcp_bridge.auth.dynamic_client import register_client
from qcn_mcp_bridge.auth.errors import OAuthErrorCode


def _session(SessionLocal) -> Session:
    return SessionLocal()


def test_register_minimal_success(tmp_db):
    """最小字段 (client_name + redirect_uris) 注册成功."""
    _, SessionLocal = tmp_db
    session = _session(SessionLocal)
    body = {
        "client_name": "WorkBuddy",
        "redirect_uris": ["https://app.workbuddy.com/callback"],
    }
    response, err = register_client(
        session, body=body, default_scopes=["read:demand"]
    )
    assert err is None
    assert response is not None
    assert response["client_name"] == "WorkBuddy"
    assert response["redirect_uris"] == ["https://app.workbuddy.com/callback"]
    # public client: 不返回 client_secret
    assert "client_secret" not in response
    # client_id 是 qcn_mcp_ 前缀 (MCP Bridge 唯一命名空间)
    assert response["client_id"].startswith("qcn_mcp_")
    # 申请了默认 scope
    assert "read:demand" in response["scope"]


def test_register_with_requested_scopes_filtered_to_allowed(tmp_db):
    """客户端申请超过 default_scopes 的 scope 时, 取交集 (§B6 scope 严格)."""
    _, SessionLocal = tmp_db
    session = _session(SessionLocal)
    body = {
        "client_name": "Test",
        "redirect_uris": ["https://test/cb"],
        "scope": "read:demand read:supply write:admin",  # write:admin 不在默认
    }
    response, err = register_client(
        session, body=body, default_scopes=["read:demand", "read:supply"]
    )
    assert err is None
    scopes = response["scope"].split()
    assert "read:demand" in scopes
    assert "read:supply" in scopes
    # write:admin 不在 default_scopes, 应被过滤掉
    assert "write:admin" not in scopes


def test_register_missing_client_name(tmp_db):
    """client_name 缺失 → invalid_request."""
    _, SessionLocal = tmp_db
    session = _session(SessionLocal)
    body = {"redirect_uris": ["https://x/cb"]}
    response, err = register_client(session, body=body, default_scopes=["read:foo"])
    assert response is None
    assert err is not None
    assert err.status_code == 400
    # 提取 body 看 error code
    import json
    body_dict = json.loads(bytes(err.body).decode("utf-8"))
    assert body_dict["error"] == "invalid_request"
    assert "client_name" in body_dict["error_description"]


def test_register_missing_redirect_uris(tmp_db):
    """redirect_uris 缺失 → invalid_request."""
    _, SessionLocal = tmp_db
    session = _session(SessionLocal)
    body = {"client_name": "Test"}
    response, err = register_client(session, body=body, default_scopes=["read:foo"])
    assert response is None
    assert err.status_code == 400
    import json
    body_dict = json.loads(bytes(err.body).decode("utf-8"))
    assert body_dict["error"] == "invalid_request"
    assert "redirect_uris" in body_dict["error_description"]


def test_register_redirect_uris_empty_list(tmp_db):
    """redirect_uris 是空 list → invalid_request."""
    _, SessionLocal = tmp_db
    session = _session(SessionLocal)
    body = {"client_name": "T", "redirect_uris": []}
    response, err = register_client(session, body=body, default_scopes=["r"])
    assert response is None
    assert err.status_code == 400


def test_register_idempotency_returns_different_client_id(tmp_db):
    """DCR 重复注册返回不同 client_id (按 §A4 验收判据: '重复注册返回不同 client_id')."""
    _, SessionLocal = tmp_db
    session = _session(SessionLocal)
    body = {
        "client_name": "WorkBuddy",
        "redirect_uris": ["https://x/cb"],
    }
    r1, _ = register_client(session, body=body, default_scopes=["r"])
    r2, _ = register_client(session, body=body, default_scopes=["r"])
    assert r1["client_id"] != r2["client_id"]