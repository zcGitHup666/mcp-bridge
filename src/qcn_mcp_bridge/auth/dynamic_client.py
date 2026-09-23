"""RFC 7591 OAuth 2.0 Dynamic Client Registration.

接入方案 §A4: POST /oauth/register.

按 CLAUDE §6.3.2: 响应不含 client_secret 明文 (public client 不需要 secret).
按 CLAUDE §4.5: 出参类型 dict.
"""
from __future__ import annotations

from typing import Any

from sqlalchemy.orm import Session

from qcn_mcp_bridge.auth.storage import create_client, find_client
from qcn_mcp_bridge.auth.errors import oauth_error, OAuthErrorCode


def register_client(
    session: Session,
    *,
    body: dict[str, Any],
    default_scopes: list[str],
) -> tuple[dict[str, Any] | None, Any]:
    """处理 RFC 7591 动态客户端注册请求.

    返回 (response_dict, error_response). 二选一非 None:
      - 成功: ({"client_id": ..., ...}, None)
      - 失败: (None, oauth_error(...))

    body 字段 (RFC 7591 §2):
      - client_name: str  (推荐)
      - redirect_uris: list[str]  (必填, 多个 URI)
      - scope: str (空格分隔; 缺省用 default_scopes)
      - 其他字段忽略
    """
    client_name = body.get("client_name")
    redirect_uris = body.get("redirect_uris")
    scope_str = body.get("scope")

    # RFC 7591 §3.2.2: invalid_request 校验
    if not client_name or not isinstance(client_name, str):
        return None, oauth_error(
            "invalid_request",
            "client_name is required and must be a string",
        )
    if not redirect_uris or not isinstance(redirect_uris, list) or not redirect_uris:
        return None, oauth_error(
            "invalid_request",
            "redirect_uris is required and must be a non-empty list",
        )
    if not all(isinstance(u, str) and u for u in redirect_uris):
        return None, oauth_error(
            "invalid_request",
            "each redirect_uri must be a non-empty string",
        )

    # scope 处理: 客户端申请 + 服务端默认求交集
    requested_scopes = (
        set(scope_str.split()) if isinstance(scope_str, str) and scope_str else set()
    )
    granted_scopes = list(
        requested_scopes & set(default_scopes) if requested_scopes else default_scopes
    )

    # 调用存储层
    client = create_client(
        session,
        client_name=client_name,
        redirect_uris=redirect_uris,
        scopes=granted_scopes,
        client_secret=None,  # public client (MCP WorkBuddy), 不需要 secret
    )
    return {
        "client_id": client["client_id"],
        "client_id_issued_at": int(__import__("time").time()),
        "client_name": client["client_name"],
        "redirect_uris": client["redirect_uris"],
        "scope": " ".join(client["scopes"]),
    }, None


def verify_client_redirect(
    session: Session,
    *,
    client_id: str,
    redirect_uri: str,
) -> tuple[dict[str, Any] | None, Any]:
    """校验 client_id 存在 + redirect_uri 在白名单 (§B5).

    返回 (client_dict, None) 或 (None, oauth_error).
    """
    client = find_client(session, client_id)
    if client is None:
        return None, oauth_error(
            "invalid_client",
            "unknown client_id",
        )
    if redirect_uri not in client["redirect_uris"]:
        return None, oauth_error(
            "invalid_request",
            "redirect_uri not registered for this client",
        )
    return client, None