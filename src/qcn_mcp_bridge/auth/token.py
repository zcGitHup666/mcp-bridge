"""RFC 6749 §4.1.3 Token Endpoint — /oauth/token.

支持 grant_type:
  - authorization_code (Phase 1A 完整实现, 含 PKCE S256 校验)
  - refresh_token     (Phase 1A 完整实现, 含 rotation)

按 CLAUDE §4.5: 出参类型 dict.
按 CLAUDE §6.3.2: 不打印 code_verifier / refresh_token 明文.
按接入方案 §A7: PKCE S256 强制.
按接入方案 §A8: token aud 校验在 jwt_signer.verify() 强制.
"""
from __future__ import annotations

import secrets
from typing import Any

from sqlalchemy.orm import Session

from qcn_mcp_bridge.auth.dynamic_client import verify_client_redirect
from qcn_mcp_bridge.auth.errors import oauth_error
from qcn_mcp_bridge.auth.jwt_signer import JWTSigner
from qcn_mcp_bridge.auth.pkce import verify_pkce
from qcn_mcp_bridge.auth.storage import (
    consume_auth_code,
    find_token_by_refresh,
    revoke_by_refresh_token,
    save_token,
)


DEFAULT_ACCESS_TTL_SECONDS = 3600                  # 1 小时
DEFAULT_REFRESH_TTL_SECONDS = 30 * 24 * 3600      # 30 天


def _token_response(
    *,
    access_token: str,
    refresh_token: str | None,
    scope: str,
    ttl_seconds: int,
) -> dict[str, Any]:
    """RFC 6749 §5.1 标准 token 响应."""
    body: dict[str, Any] = {
        "access_token": access_token,
        "token_type": "Bearer",
        "expires_in": ttl_seconds,
        "scope": scope,
    }
    if refresh_token:
        body["refresh_token"] = refresh_token
    return body


def handle_token(
    session: Session,
    *,
    form: dict[str, str],
    jwt_signer: JWTSigner,
) -> tuple[dict[str, Any] | None, Any]:
    """处理 /oauth/token POST 请求.

    返回 (token_response_dict, None) 或 (None, error_response).
    """
    grant_type = form.get("grant_type", "")
    client_id = form.get("client_id", "")

    if not client_id:
        return None, oauth_error("invalid_request", "client_id is required")

    if grant_type == "authorization_code":
        return _handle_authorization_code(session, form=form, client_id=client_id, jwt_signer=jwt_signer)
    if grant_type == "refresh_token":
        return _handle_refresh_token(session, form=form, client_id=client_id, jwt_signer=jwt_signer)
    return None, oauth_error(
        "unsupported_grant_type",
        f"grant_type '{grant_type}' is not supported",
    )


def _handle_authorization_code(
    session: Session,
    *,
    form: dict[str, str],
    client_id: str,
    jwt_signer: JWTSigner,
) -> tuple[dict[str, Any] | None, Any]:
    """authorization_code grant (§4.1.3) — 含 PKCE S256 强制校验 (§A7)."""
    code = form.get("code", "")
    redirect_uri = form.get("redirect_uri", "")
    code_verifier = form.get("code_verifier", "")

    if not code:
        return None, oauth_error("invalid_grant", "code is required")
    if not redirect_uri:
        return None, oauth_error("invalid_grant", "redirect_uri is required")
    if not code_verifier:
        return None, oauth_error("invalid_grant", "code_verifier is required")

    # 校验 client_id + redirect_uri (§B5)
    client, err = verify_client_redirect(
        session, client_id=client_id, redirect_uri=redirect_uri
    )
    if err is not None:
        return None, err

    # 消费 code (§B2 一次性): 找到 + 删除
    consumed = consume_auth_code(
        session,
        code=code,
        client_id=client_id,
        redirect_uri=redirect_uri,
    )
    if consumed is None:
        return None, oauth_error(
            "invalid_grant",
            "code is invalid, expired, or already used",
        )

    # PKCE S256 强制校验 (§A7, RFC 7636 §4.6)
    if not verify_pkce(
        code_verifier=code_verifier,
        code_challenge=consumed["code_challenge"],
        code_challenge_method=consumed["code_challenge_method"],
    ):
        return None, oauth_error(
            "invalid_grant",
            "code_verifier does not match code_challenge",
        )

    # 签发 access_token (Phase 1A: user_id=0, Phase 2 接入 qcn-dev 登录后填)
    sub = consumed.get("user_id") or 0
    access_token = jwt_signer.sign(
        sub=sub,
        scope=consumed["scope"],
        ttl_seconds=DEFAULT_ACCESS_TTL_SECONDS,
    )
    refresh_token = secrets.token_urlsafe(32)
    save_token(
        session,
        access_token=access_token,
        refresh_token=refresh_token,
        client_id=client_id,
        user_id=sub,
        tenant_id=consumed.get("tenant_id"),
        product=consumed.get("product") or "qcn",
        scope=consumed["scope"],
        access_ttl_seconds=DEFAULT_ACCESS_TTL_SECONDS,
        refresh_ttl_seconds=DEFAULT_REFRESH_TTL_SECONDS,
    )
    return _token_response(
        access_token=access_token,
        refresh_token=refresh_token,
        scope=consumed["scope"],
        ttl_seconds=DEFAULT_ACCESS_TTL_SECONDS,
    ), None


def _handle_refresh_token(
    session: Session,
    *,
    form: dict[str, str],
    client_id: str,
    jwt_signer: JWTSigner,
) -> tuple[dict[str, Any] | None, Any]:
    """refresh_token grant (§6) — 含 token rotation (RFC 6819 §5.2.2.1)."""
    refresh_token = form.get("refresh_token", "")
    if not refresh_token:
        return None, oauth_error("invalid_grant", "refresh_token is required")

    old = find_token_by_refresh(session, refresh_token=refresh_token)
    if old is None:
        return None, oauth_error(
            "invalid_grant",
            "refresh_token is invalid, expired, or revoked",
        )
    if old["client_id"] != client_id:
        return None, oauth_error("invalid_grant", "client_id mismatch")

    # 撤销旧 token (rotation)
    revoke_by_refresh_token(session, refresh_token=refresh_token)

    # 签发新 token
    access_token = jwt_signer.sign(
        sub=old["user_id"],
        scope=old["scope"],
        ttl_seconds=DEFAULT_ACCESS_TTL_SECONDS,
    )
    new_refresh = secrets.token_urlsafe(32)
    save_token(
        session,
        access_token=access_token,
        refresh_token=new_refresh,
        client_id=client_id,
        user_id=old["user_id"],
        tenant_id=old.get("tenant_id"),
        product=old["product"],
        scope=old["scope"],
        access_ttl_seconds=DEFAULT_ACCESS_TTL_SECONDS,
        refresh_ttl_seconds=DEFAULT_REFRESH_TTL_SECONDS,
    )
    return _token_response(
        access_token=access_token,
        refresh_token=new_refresh,
        scope=old["scope"],
        ttl_seconds=DEFAULT_ACCESS_TTL_SECONDS,
    ), None