"""RFC 6749 §4.1 Authorization Endpoint — /oauth/authorize.

Phase 1A: 直接生成 auth code → 302 到 redirect_uri (Phase 2 才加登录页).
Phase 2:  插入渲染登录页 (未注册/未登录/未授权 三态分支).

按 CLAUDE §4.5: 出参类型 dict / Response.
按 CLAUDE §6.3.2: 不打印 query params 明文 (code_challenge / state / redirect_uri).
按接入方案 §A7: PKCE S256 强制.
"""
from __future__ import annotations

import secrets
from typing import Any
from urllib.parse import urlencode

from sqlalchemy.orm import Session

from qcn_mcp_bridge.auth.dynamic_client import verify_client_redirect
from qcn_mcp_bridge.auth.storage import save_auth_code
from qcn_mcp_bridge.auth.errors import oauth_error


DEFAULT_SCOPES = ["read:demand", "read:supply", "write:demand", "write:supply"]
DEFAULT_CODE_TTL_SECONDS = 600  # 接入方案 §B3: 10 分钟


def handle_authorize(
    session: Session,
    *,
    query: dict[str, str],
) -> tuple[Any | None, Any]:
    """处理 /oauth/authorize GET 请求.

    返回 (redirect_response, None) 或 (None, error_response).
    二选一非 None.

    query 字段 (RFC 6749 §4.1.1):
      - response_type: 必须 "code"
      - client_id: 必填
      - redirect_uri: 必填
      - scope: 空格分隔 (可选, 缺省用 default_scopes)
      - state: 推荐 (CSRF 防伪)
      - code_challenge: PKCE S256 必填 (接入方案 §A7)
      - code_challenge_method: 必须 "S256"
    """
    response_type = query.get("response_type", "")
    client_id = query.get("client_id", "")
    redirect_uri = query.get("redirect_uri", "")
    scope_str = query.get("scope", "")
    state = query.get("state", "")
    code_challenge = query.get("code_challenge", "")
    code_challenge_method = query.get("code_challenge_method", "")

    # 必填校验
    if response_type != "code":
        return None, oauth_error(
            "unsupported_response_type",
            f"response_type must be 'code', got '{response_type}'",
        )
    if not client_id:
        return None, oauth_error("invalid_request", "client_id is required")
    if not redirect_uri:
        return None, oauth_error("invalid_request", "redirect_uri is required")
    if not code_challenge:
        return None, oauth_error(
            "invalid_request",
            "code_challenge is required (PKCE S256)",
        )
    if code_challenge_method != "S256":
        return None, oauth_error(
            "unsupported_code_challenge_method",
            f"code_challenge_method must be 'S256', got '{code_challenge_method}'",
        )

    # client_id + redirect_uri 校验 (§B5)
    client, err = verify_client_redirect(
        session, client_id=client_id, redirect_uri=redirect_uri
    )
    if err is not None:
        return None, err

    # scope 处理: 客户端申请的 scope 与 client 注册时的 scope 求交集
    requested = set(scope_str.split()) if scope_str else set()
    granted = list(requested & set(client["scopes"])) if requested else list(client["scopes"])

    # 生成 auth code
    code = save_auth_code(
        session,
        client_id=client_id,
        redirect_uri=redirect_uri,
        code_challenge=code_challenge,
        code_challenge_method=code_challenge_method,
        scope=" ".join(granted),
        resource=None,  # Phase 2 加
        state=state if state else None,
        ttl_seconds=DEFAULT_CODE_TTL_SECONDS,
    )

    # 302 redirect to client redirect_uri
    from starlette.responses import RedirectResponse

    qs = urlencode({"code": code})
    if state:
        qs += "&" + urlencode({"state": state})
    target = f"{redirect_uri}?{qs}"
    return RedirectResponse(url=target, status_code=302), None