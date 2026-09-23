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
"""
from __future__ import annotations

from urllib.parse import parse_qs

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.templating import Jinja2Templates

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
from qcn_mcp_bridge.auth.storage import init_engine
from qcn_mcp_bridge.auth.token import handle_token
from pathlib import Path


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
) -> Starlette:
    """构造 OAuth ASGI sub-app.

    qcn_dev_client: Phase 2B1 Step 2 真实调 qcn-dev (server.py 注入).
    测试传 None 用 mock (Step 1 兼容, Phase 2B1 Step 1 测试用).
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

        user_id = _get_session_user_id(request)

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

    login_form = make_login_form_handler(qcn_dev=qcn_dev_client, SessionLocal=SessionLocal)
    register_form = make_register_form_handler(qcn_dev=qcn_dev_client, SessionLocal=SessionLocal)
    send_code = make_send_code_handler(qcn_dev=qcn_dev_client)
    authorize_post = make_authorize_post_handler(SessionLocal=SessionLocal)

    return Starlette(routes=[
        Route("/oauth-protected-resource", prm_endpoint, methods=["GET"]),
        Route("/oauth-authorization-server", as_metadata_endpoint, methods=["GET"]),
        Route("/register", register_endpoint, methods=["POST"]),
        Route("/token", token_endpoint, methods=["POST"]),
        Route("/authorize", authorize_get, methods=["GET"]),
        Route("/authorize", authorize_post, methods=["POST"]),
        Route("/login-form", login_form, methods=["POST"]),
        Route("/register-form", register_form, methods=["POST"]),
        Route("/send-code", send_code, methods=["POST"]),
    ])