"""Phase 2B1: 登录页 3 状态 UI + form submit e2e 测试.

按 CLAUDE §6.3.2: 不打印 token / session cookie / 手机号验证码明文.
按 CLAUDE §7: KISS — 5 个 e2e 测试覆盖核心流程.

测试场景:
1. GET /authorize 无 cookie → 渲染 login.html
2. GET /authorize 有 cookie → 渲染 consent.html (client_name + scope)
3. POST /oauth/send-code 手机号无效 → 400
4. POST /oauth/login-form → 设 cookie + 303
5. 完整流程: 无 cookie → login → 同意 → 302 with code
"""
from __future__ import annotations

import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from starlette.testclient import TestClient

from qcn_mcp_bridge.auth.asgi import build_oauth_asgi
from qcn_mcp_bridge.auth.dynamic_client import register_client
from qcn_mcp_bridge.auth.qcn_dev_client import QcnDevClient


def _mock_qcn_dev():
    """Phase 2B1 Step 2: mock qcn-dev client (AsyncMock + 配置 send_code/login/register 返值).

    login 返 (handler 期望): auth_token / user_id / tenant_id / eim_name / phone / all_users.
    register/send_code 返 None (handler 不期待返值).
    """
    from unittest.mock import AsyncMock
    mock = AsyncMock(spec=QcnDevClient)
    mock.login.return_value = {
        "auth_token": "mock-qcn-dev-jwt-token",
        "user_id": 5083,
        "tenant_id": 42,
        "eim_name": "测试公司",
        "phone": "13800000000",
        "all_users": [],
    }
    mock.register.return_value = None
    mock.send_code.return_value = None
    return mock


def _build_app_with_real_key(tmp_db, qcn_dev_client=None):
    """构造一个真 RSA 私钥的 oauth_asgi app (生产部署也是真密钥).

    关键: 用 tmp_db 的 db_path (不是 tempfile.gettempdir()), 保证 OAuth app 跟
    tmp_db fixture 用同一个 SQLite 文件 — 否则注册跟 authorize 跨库, client 找不到.

    qcn_dev_client: Phase 2B1 Step 2 真实调 (server.py 注入).
                  测试传 _mock_qcn_dev() 避免真打 qcn-dev.
    """
    db_path, SessionLocal = tmp_db
    key_path = Path(tempfile.gettempdir()) / f"login_key_{id(tmp_db)}.pem"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    key_path.write_bytes(pem)
    return build_oauth_asgi(
        issuer="https://test.bridge",
        resource="https://test.bridge/mcp",
        db_path=db_path,
        jwt_key_path=key_path,
        qcn_dev_client=qcn_dev_client if qcn_dev_client is not None else _mock_qcn_dev(),
    )


def _register_one(SL):
    """注册一个测试 client, 返回 client_id."""
    reg, _ = register_client(
        SL(),
        body={
            "client_name": "Phase2B1-Test",
            "redirect_uris": ["https://app/cb"],
        },
        default_scopes=["read:demand", "read:supply"],
    )
    return reg


def _authorize_url(client_id: str) -> str:
    """构造 /authorize URL (PKCE + state 都用 mock)."""
    return (
        f"/authorize?response_type=code&client_id={client_id}"
        f"&redirect_uri=https://app/cb&code_challenge=mock-challenge"
        f"&code_challenge_method=S256&state=mock-state&scope=read:demand"
    )


def test_authorize_without_cookie_renders_login_page(tmp_db):
    """§5.2: 未登录 → 渲染 login.html, 含 PKCE state 透传 hidden field."""
    app = _build_app_with_real_key(tmp_db)
    _, SL = tmp_db
    client_id = _register_one(SL)["client_id"]
    client = TestClient(app)
    r = client.get(_authorize_url(client_id))
    assert r.status_code == 200
    body = r.text
    assert "账号登录" in body
    assert "企采牛 MCP Bridge" in body  # 模板标题/副标题里出现
    # PKCE + state 透传 (RFC 6749 §B5 防篡改)
    assert 'value="mock-state"' in body
    assert 'value="mock-challenge"' in body
    assert 'value="S256"' in body
    assert 'value="' + client_id + '"' in body
    assert 'value="https://app/cb"' in body
    # 倒计时脚本
    assert "send-code-btn" in body


def test_authorize_with_cookie_renders_consent_page(tmp_db):
    """§5.2: 已登录 (cookie 有 user_id) → 渲染 consent.html, 含 client_name + scope."""
    app = _build_app_with_real_key(tmp_db)
    _, SL = tmp_db
    client_id = _register_one(SL)["client_id"]
    client = TestClient(app)
    r = client.get(
        _authorize_url(client_id),
        cookies={"qcn_bridge_session": "user_id=5083"},
    )
    assert r.status_code == 200
    body = r.text
    assert "授权请求" in body
    assert "Phase2B1-Test" in body   # client_name
    assert "read:demand" in body      # scope
    # 同意 / 拒绝 两个 form
    assert 'value="approve"' in body
    assert 'value="deny"' in body


def test_send_code_calls_qcn_dev(tmp_db):
    """POST /oauth/send-code → 调 qcn-dev.send_code(phone) (Phase 2B1 Step 2 真实调)."""
    from unittest.mock import AsyncMock
    mock_qcn = _mock_qcn_dev()
    # 让 mock send_code 抛错模拟 qcn-dev 业务错 (手机号无效)
    from qcn_mcp_bridge.auth.qcn_dev_client import QcnDevBusinessError
    mock_qcn.send_code.side_effect = QcnDevBusinessError(code=0, message="手机号格式错误")
    app = _build_app_with_real_key(tmp_db, mock_qcn)
    client = TestClient(app)
    # qcn-dev 返 business_error → Bridge 返 400
    r = client.post("/send-code", json={"phone": "123"})
    assert r.status_code == 400
    assert r.json()["ok"] is False
    # qcn-dev OK (默认 mock 返 None)
    mock_qcn2 = _mock_qcn_dev()
    app2 = _build_app_with_real_key(tmp_db, mock_qcn2)
    client2 = TestClient(app2)
    r = client2.post("/send-code", json={"phone": "13800000000"})
    assert r.status_code == 200
    assert r.json()["ok"] is True
    # 验证 qcn-dev 真被调了
    mock_qcn2.send_code.assert_awaited_once_with("13800000000")


def test_login_form_post_sets_cookie_and_redirects(tmp_db):
    """POST /oauth/login-form → 设 session cookie + 303 → /oauth/authorize."""
    app = _build_app_with_real_key(tmp_db)
    _, SL = tmp_db
    client_id = _register_one(SL)["client_id"]
    client = TestClient(app)
    r = client.post(
        "/login-form",
        data={
            "phone": "13800000000",
            "code": "123456",
            "state": "mock-state",
            "code_challenge": "mock-challenge",
            "code_challenge_method": "S256",
            "redirect_uri": "https://app/cb",
            "client_id": client_id,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    # 设了 session cookie
    assert "qcn_bridge_session" in r.cookies
    # 重定向到 /authorize
    assert r.headers["location"].startswith("/oauth/authorize")
    # PKCE state 透传
    assert "state=mock-state" in r.headers["location"]
    assert "code_challenge=mock-challenge" in r.headers["location"]


def test_full_flow_no_cookie_to_code_redirect(tmp_db):
    """完整流程: GET authorize (无 cookie) → login-form POST → consent → approve → 302 code."""
    import base64
    import hashlib

    # Phase 2B1 Step 1 mock: 真实 PKCE 校验需要 verifier 能解 challenge
    challenge = base64.urlsafe_b64encode(hashlib.sha256(b"test-verifier").digest()).rstrip(b"=").decode()

    app = _build_app_with_real_key(tmp_db)
    _, SL = tmp_db
    client_id = _register_one(SL)["client_id"]
    client = TestClient(app)

    # 1) GET authorize (无 cookie) → 渲染 login.html
    url = (
        f"/authorize?response_type=code&client_id={client_id}"
        f"&redirect_uri=https://app/cb&code_challenge={challenge}"
        f"&code_challenge_method=S256&state=mock-state&scope=read:demand"
    )
    r = client.get(url)
    assert r.status_code == 200
    assert "账号登录" in r.text

    # 2) POST login-form → cookie + 303
    r = client.post(
        "/login-form",
        data={
            "phone": "13800000000",
            "code": "123456",
            "state": "mock-state",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "redirect_uri": "https://app/cb",
            "client_id": client_id,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    session_cookie = r.cookies["qcn_bridge_session"]

    # 3) GET authorize (带 cookie) → 渲染 consent.html
    r = client.get(url, cookies={"qcn_bridge_session": session_cookie})
    assert r.status_code == 200
    assert "授权请求" in r.text

    # 4) POST authorize approve → 302 with code
    r = client.post(
        "/authorize",
        data={
            "decision": "approve",
            "state": "mock-state",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "redirect_uri": "https://app/cb",
            "client_id": client_id,
            "scope": "read:demand",
        },
        cookies={"qcn_bridge_session": session_cookie},
        follow_redirects=False,
    )
    assert r.status_code == 302
    loc = r.headers["location"]
    assert loc.startswith("https://app/cb")
    assert "code=" in loc
    assert "state=mock-state" in loc


def test_register_form_validation_errors(tmp_db):
    """POST /oauth/register-form 校验: 空字段 / 密码不一致 / 未同意协议 (Phase 2B1 Step 2 改为 303 redirect with error query)."""
    from urllib.parse import unquote

    app = _build_app_with_real_key(tmp_db)
    _, SL = tmp_db
    client_id = _register_one(SL)["client_id"]
    client = TestClient(app)

    # 空字段 → 303 redirect with error=不能为空
    r = client.post(
        "/register-form",
        data={
            "phone": "",
            "code": "123456",
            "company_select": "__new__",
            "company_new": "新公司",
            "password": "abc123",
            "password_confirm": "abc123",
            "agree": "on",
            "state": "s", "code_challenge": "c", "code_challenge_method": "S256",
            "redirect_uri": "https://app/cb", "client_id": client_id,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "不能为空" in unquote(r.headers["location"])

    # 密码不一致
    r = client.post(
        "/register-form",
        data={
            "phone": "13800000000",
            "code": "123456",
            "company_select": "__new__",
            "company_new": "新公司",
            "password": "abc123",
            "password_confirm": "abc456",
            "agree": "on",
            "state": "s", "code_challenge": "c", "code_challenge_method": "S256",
            "redirect_uri": "https://app/cb", "client_id": client_id,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "两次密码不一致" in unquote(r.headers["location"])

    # 未勾选同意
    r = client.post(
        "/register-form",
        data={
            "phone": "13800000000",
            "code": "123456",
            "company_select": "__new__",
            "company_new": "新公司",
            "password": "abc123",
            "password_confirm": "abc123",
            "agree": "",
            "state": "s", "code_challenge": "c", "code_challenge_method": "S256",
            "redirect_uri": "https://app/cb", "client_id": client_id,
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    assert "协议" in unquote(r.headers["location"])


def test_authorize_deny_returns_error_redirect(tmp_db):
    """POST /authorize decision=deny → 302 redirect_uri?error=access_denied&state=xxx."""
    app = _build_app_with_real_key(tmp_db)
    _, SL = tmp_db
    client_id = _register_one(SL)["client_id"]
    client = TestClient(app)
    r = client.post(
        "/authorize",
        data={
            "decision": "deny",
            "state": "mock-state",
            "code_challenge": "c",
            "code_challenge_method": "S256",
            "redirect_uri": "https://app/cb",
            "client_id": client_id,
        },
        cookies={"qcn_bridge_session": "user_id=5083"},
        follow_redirects=False,
    )
    assert r.status_code == 302
    loc = r.headers["location"]
    assert loc.startswith("https://app/cb")
    assert "error=access_denied" in loc
    assert "state=mock-state" in loc