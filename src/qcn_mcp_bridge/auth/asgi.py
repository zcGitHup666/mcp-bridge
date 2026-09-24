"""OAuth ASGI sub-app — 5 OAuth 端点 + 2 discovery + 4 form handler (Phase 2B1).

挂载方式 (server.py):
    main_app = Starlette(routes=[
        Mount("/.well-known", oauth_asgi),
        Mount("/oauth", oauth_asgi),
        Mount("/mcp", mcp.streamable_http_app()),
    ])

按 CLAUDE §4.5: 出参类型 JSONResponse / RedirectResponse / TemplateResponse.
按 CLAUDE §6.3.2: 不打印 form body / query params / token / 验证码.

Phase 2B1 Step 2: 4 个 form handler (login / register / send-code / authorize-post)
从 Step 1 mock 改为真实调 qcn-dev (QcnDevClient) + AES-GCM 加密 session 写 bindings.

Phase 2B2 Step 1: 新增 POST /oauth/revoke (RFC 7009) + 元数据声明 revocation_endpoint.
"""
from __future__ import annotations

from urllib.parse import parse_qs

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.templating import Jinja2Templates
from pathlib import Path

from qcn_mcp_bridge.auth.authorize import DEFAULT_SCOPES
from qcn_mcp_bridge.auth.dynamic_client import (
    find_client,
    register_client,
    verify_client_redirect,
)
from qcn_mcp_bridge.auth.handlers_login import (
    SESSION_COOKIE_NAME,
    make_authorize_post_handler,
    make_login_form_handler,
    make_register_form_handler,
    make_send_code_handler,
)
from qcn_mcp_bridge.auth.jwt_signer import JWTSigner
from qcn_mcp_bridge.auth.metadata import (
    authorization_server_metadata,
    protected_resource_metadata,
)
from qcn_mcp_bridge.auth.qcn_dev_client import QcnDevClient
from qcn_mcp_bridge.auth.revoke import handle_revoke   # Phase 2B2 Step 1
from qcn_mcp_bridge.auth.storage import init_engine
from qcn_mcp_bridge.auth.token import handle_token


# Jinja2 templates (templates/*.html)
_TEMPLATES_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(_TEMPLATES_DIR))


def _get_session_user_id(request: Request) -> int | None:
    """从 Bridge session cookie 解 user_id."""
    cookie = request.cookies.get(SESSION_COOKIE_NAME)
    if not cookie:
        return None
    try:
        return int(cookie.split("=", 1)[1]) if "=" in cookie else None
    except (ValueError, IndexError):
        return None


def build_oauth_asgi(
    *,
    issuer: str,
    resource: str,
    db_path: str,
    jwt_key_path: Path,
    qcn_dev_client: QcnDevClient | None = None,
    dev_mode: bool = False,                                 # Phase 2B2 Step 1
) -> Starlette:
    """构造 OAuth ASGI sub-app.

    qcn_dev_client: Phase 2B1 Step 2 真实调 qcn-dev (server.py 注入).
                    测试传 None 用 mock (Step 1 兼容, Phase 2B1 Step 1 测试用).
    dev_mode:        dev backdoor (QCN_BRIDGE_DEV_LOGIN=true 时打开), 短路
                    /oauth/send-code + /oauth/login-form, 不真打 qcn-dev.
                    仅本地 / CI 测试用, 生产必须 false.
    """
    engine, SessionLocal = init_engine(db_path)
    jwt_signer = JWTSigner(jwt_key_path, issuer=issuer, audience=resource)

    # ===== 2 个 discovery 端点 =====
    async def prm_endpoint(request: Request):
        return JSONResponse(protected_resource_metadata(
            resource=resource, authorization_servers=[issuer]
        ))

    async def as_metadata_endpoint(request: Request):
        return JSONResponse(authorization_server_metadata(
            issuer=issuer,
            authorization_endpoint=f"{issuer}/oauth/authorize",
            token_endpoint=f"{issuer}/oauth/token",
            registration_endpoint=f"{issuer}/oauth/register",
            revocation_endpoint=f"{issuer}/oauth/revoke",   # Phase 2B2 Step 1
            scopes_supported=DEFAULT_SCOPES,
        ))

    # ===== DCR =====
    async def register_endpoint(request: Request):
        body = await request.json()
        session = SessionLocal()
        try:
            response, err = register_client(
                session, body=body, default_scopes=DEFAULT_SCOPES
            )
            if err is not None:
                return err
            return JSONResponse(response, status_code=201)
        finally:
            session.close()

    # ===== /oauth/token =====
    async def token_endpoint(request: Request):
        form: dict[str, str] = {}
        content_type = request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in content_type:
            body_bytes = await request.body()
            if body_bytes:
                parsed = parse_qs(body_bytes.decode("utf-8"))
                form = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
        elif "application/json" in content_type:
            form = await request.json()
        else:
            body_bytes = await request.body()
            if body_bytes:
                parsed = parse_qs(body_bytes.decode("utf-8"))
                form = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
        session = SessionLocal()
        try:
            response, err = handle_token(session, form=form, jwt_signer=jwt_signer)
            if err is not None:
                return err
            return JSONResponse(response)
        finally:
            session.close()

    # ===== /oauth/logout (OIDC RP-Initiated Logout, Phase 2B2 Step 2) =====
    # POST /oauth/logout → 清 qcn_bridge_session cookie (user 切账号前置)
    async def logout_endpoint(request: Request):
        response = JSONResponse({"ok": True})
        # delete_cookie 走默认 path=/, 不指定 domain 让浏览器按当前 host 匹配
        response.delete_cookie(SESSION_COOKIE_NAME)
        return response

    # ===== /oauth/revoke (RFC 7009, Phase 2B2 Step 1) =====
    async def revoke_endpoint(request: Request):
        form: dict[str, str] = {}
        content_type = request.headers.get("content-type", "")
        if "application/x-www-form-urlencoded" in content_type:
            body_bytes = await request.body()
            if body_bytes:
                parsed = parse_qs(body_bytes.decode("utf-8"))
                form = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
        elif "application/json" in content_type:
            form = await request.json()
        else:
            body_bytes = await request.body()
            if body_bytes:
                parsed = parse_qs(body_bytes.decode("utf-8"))
                form = {k: v[0] if len(v) == 1 else v for k, v in parsed.items()}
        session = SessionLocal()
        try:
            return handle_revoke(session, form=form)
        finally:
            session.close()

    # ===== /oauth/authorize GET (3 状态分支) =====
    async def authorize_get(request: Request):
        """§5.2: 未登录→login.html / 已登录→consent.html / 已授权→302 code (Phase 2B2)."""
        query = dict(request.query_params)
        state = query.get("state", "")
        code_challenge = query.get("code_challenge", "")
        code_challenge_method = query.get("code_challenge_method", "")
        redirect_uri = query.get("redirect_uri", "")
        client_id = query.get("client_id", "")
        scope = query.get("scope", "")
        error_msg = query.get("error", "") or None

        # 校验 client_id + redirect_uri (RFC 6749 §B5)
        session = SessionLocal()
        try:
            client, err = verify_client_redirect(
                session, client_id=client_id, redirect_uri=redirect_uri
            )
        finally:
            session.close()
        if err is not None:
            return err

        # Phase 2B2 Step 2: force_login=true query param 跳过 session cookie,
        #           强制渲染 login.html (OIDC prompt=login 的 Bridge 等价物,
        #           用于切换账号场景)
        force_login = query.get("force_login", "").lower() in ("true", "1")
        user_id = _get_session_user_id(request)
        if force_login:
            user_id = None

        if user_id is None:
            # 1) 未登录 → render login.html
            return templates.TemplateResponse(
                request, "login.html",
                {
                    "state": state,
                    "code_challenge": code_challenge,
                    "code_challenge_method": code_challenge_method,
                    "redirect_uri": redirect_uri,
                    "client_id": client_id,
                    "error": error_msg,
                },
            )

        # 2) 已登录 → consent 页 (Phase 2B2 加 bindings 状态机后直签 code)
        client_name = client["client_name"]
        scopes_list = scope.split() if scope else client["scopes"]
        return templates.TemplateResponse(
            request, "consent.html",
            {
                "client_name": client_name,
                "scopes": scopes_list,
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": code_challenge_method,
                "redirect_uri": redirect_uri,
                "client_id": client_id,
            },
        )

    # ===== 4 个 form POST handler (Phase 2B1 Step 2) =====
    # Step 1 测试兼容: qcn_dev_client=None 时用 mock fallback
    if qcn_dev_client is None:
        # Mock: 登录/注册直接 set user_id = 5083, 不真调 qcn-dev
        # 用 handlers_login factory 但传 None QcnDevClient 会 raise)
        # Phase 2B1 Step 1 测试传 mock QcnDevClient 用 `MagicMock`
        from unittest.mock import MagicMock
        qcn_dev_client = MagicMock()

    login_form = make_login_form_handler(
        qcn_dev=qcn_dev_client, SessionLocal=SessionLocal, dev_mode=dev_mode,  # Phase 2B2 Step 1
    )
    register_form_post = make_register_form_handler(qcn_dev=qcn_dev_client, SessionLocal=SessionLocal)
    # Phase 2B2 Step 2: GET 请求渲染 register.html (UI 自注册入口).
    # POST 部分委托给原 register_form_post 工厂(调 qcn-dev register API).
    async def register_form_endpoint(request: Request):
        if request.method == "GET":
            return templates.TemplateResponse(
                request, "register.html",
                {
                    "state": request.query_params.get("state", ""),
                    "code_challenge": request.query_params.get("code_challenge", ""),
                    "code_challenge_method": request.query_params.get("code_challenge_method", ""),
                    "redirect_uri": request.query_params.get("redirect_uri", ""),
                    "client_id": request.query_params.get("client_id", ""),
                    "phone": "",
                    "company_new": "",
                    "error": None,
                },
            )
        # POST: 委托给原 POST 工厂
        return await register_form_post(request)

    send_code = make_send_code_handler(
        qcn_dev=qcn_dev_client, dev_mode=dev_mode,   # Phase 2B2 Step 1
    )
    authorize_post = make_authorize_post_handler(SessionLocal=SessionLocal)

    return Starlette(routes=[
        Route("/oauth-protected-resource", prm_endpoint, methods=["GET"]),
        Route("/oauth-authorization-server", as_metadata_endpoint, methods=["GET"]),
        Route("/register", register_endpoint, methods=["POST"]),
        Route("/token", token_endpoint, methods=["POST"]),
        Route("/revoke", revoke_endpoint, methods=["POST"]),   # Phase 2B2 Step 1
        Route("/logout", logout_endpoint, methods=["POST"]),    # Phase 2B2 Step 2
        Route("/authorize", authorize_get, methods=["GET"]),
        Route("/authorize", authorize_post, methods=["POST"]),
        Route("/login-form", login_form, methods=["POST"]),
        Route("/register-form", register_form_endpoint, methods=["GET", "POST"]),  # Phase 2B2 Step 2
        Route("/send-code", send_code, methods=["POST"]),
    ])
