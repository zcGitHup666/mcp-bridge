"""Bearer 校验中间件 (Phase 1B, 纯 ASGI 实现).

按接入方案 §A1/A7/A8/A12:
- 无凭证 / 错误凭证 → 401 + WWW-Authenticate (RFC 6750)
- JWT 签名 + aud + exp 校验 (jwt_signer.verify 强制 aud)
- 查 token 表看是否 revoked (§B4 token 哈希存)
- scope 校验: token.scope 必需含 required_scope

实现: 纯 ASGI middleware (不用 Starlette BaseHTTPMiddleware, 因后者对 redirect 处理有 bug:
内层 FastMCP streamable_http_app 在 /mcp 不带 / 时会 307 redirect 到 /mcp/, redirect 会绕过
BaseHTTPMiddleware, 导致 401 不生效)。

按 CLAUDE §6.3.2: 不打印 token 明文 / 不打日志.
按 CLAUDE §4.5: 出参类型 dict, 不暴露 ORM Entity.
"""
from __future__ import annotations

import json
from typing import Any, Awaitable, Callable, MutableMapping

from sqlalchemy.orm import sessionmaker

from qcn_mcp_bridge.auth.jwt_signer import JWTSigner
from qcn_mcp_bridge.auth.storage import find_token_by_access


def _build_www_authenticate(resource_metadata_url: str, scope: str | None, error: str) -> str:
    """RFC 6750 §3 WWW-Authenticate: Bearer realm + resource_metadata + error.

    按接入方案 §A1: 必须含 resource_metadata 触发 client 自动 OAuth.
    """
    parts = [
        'Bearer realm="qcn-mcp-bridge"',
        f'resource_metadata="{resource_metadata_url}"',
        f'error="{error}"',
    ]
    if scope:
        parts.append(f'scope="{scope}"')
    return ", ".join(parts)


def _unauthorized(
    *,
    error: str,
    description: str,
    resource_metadata_url: str,
    scope: str | None = None,
) -> dict[str, Any]:
    """构造 401 响应 payload (由 _send_401 包装成 ASGI 事件)."""
    body = {"error": error, "error_description": description}
    return {
        "status": 401,
        "headers": [
            (b"content-type", b"application/json"),
            (
                b"www-authenticate",
                _build_www_authenticate(resource_metadata_url, scope, error).encode("utf-8"),
            ),
        ],
        "body": json.dumps(body).encode("utf-8"),
    }


async def _send_401(send: Callable[[Any], Awaitable[None]], payload: dict[str, Any]) -> None:
    """发送 401 ASGI 响应 (send start + body)."""
    await send({
        "type": "http.response.start",
        "status": payload["status"],
        "headers": payload["headers"],
    })
    await send({
        "type": "http.response.body",
        "body": payload["body"],
    })


class BearerAuthMiddleware:
    """纯 ASGI middleware: 校验 Authorization: Bearer <token>.

    校验链 (任一失败 → 401):
      1. Bearer 前缀
      2. JWT 签名 + aud + exp (jwt_signer.verify 强制)
      3. token 在 oauth_tokens 表 (查 hash, 查 revoked, 查过期)
      4. scope 含 required_scope (可选)

    注入: scope["state"]["user"] = current_user dict (Starlette request.state.user
    和 FastMCP Request.state.user 都从这取).
    """

    def __init__(
        self,
        app: Callable,
        *,
        jwt_signer: JWTSigner,
        session_factory: sessionmaker,
        resource_metadata_url: str,
        required_scope: str | None = None,
    ) -> None:
        self.app = app
        self._jwt_signer = jwt_signer
        self._session_factory = session_factory
        self._resource_metadata_url = resource_metadata_url
        self._required_scope = required_scope

    async def __call__(
        self,
        scope: MutableMapping[str, Any],
        receive: Callable[[Any], Awaitable[None]],
        send: Callable[[Any], Awaitable[None]],
    ) -> None:
        # 非 HTTP scope (lifespan / websocket) 直接透传
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        # 读 Authorization header (ASGI headers = list of (bytes, bytes))
        auth_value = ""
        for name, value in scope.get("headers", []):
            if name == b"authorization":
                auth_value = value.decode("latin-1", errors="replace")
                break

        # 1. 校验 Bearer 前缀
        if not auth_value.startswith("Bearer "):
            await _send_401(send, _unauthorized(
                error="invalid_request",
                description="missing or invalid Authorization header",
                resource_metadata_url=self._resource_metadata_url,
                scope=self._required_scope,
            ))
            return

        token = auth_value[7:].strip()
        if not token:
            await _send_401(send, _unauthorized(
                error="invalid_request",
                description="empty bearer token",
                resource_metadata_url=self._resource_metadata_url,
            ))
            return

        # 2. JWT 验签 (jwt_signer.verify 强制 aud)
        claims = self._jwt_signer.verify(token)
        if claims is None:
            await _send_401(send, _unauthorized(
                error="invalid_token",
                description="token signature/aud/exp invalid",
                resource_metadata_url=self._resource_metadata_url,
            ))
            return

        # 3. 查 token 表 (§B4 token 只存 hash)
        session = self._session_factory()
        try:
            token_row = find_token_by_access(session, access_token=token)
        finally:
            session.close()
        if token_row is None:
            await _send_401(send, _unauthorized(
                error="invalid_token",
                description="token not in DB, revoked, or expired",
                resource_metadata_url=self._resource_metadata_url,
            ))
            return

        # 4. scope 校验 (§A12)
        if self._required_scope:
            token_scopes = set(token_row.get("scope", "").split())
            if self._required_scope not in token_scopes:
                await _send_401(send, _unauthorized(
                    error="insufficient_scope",
                    description=f"token scope does not contain required '{self._required_scope}'",
                    resource_metadata_url=self._resource_metadata_url,
                    scope=self._required_scope,
                ))
                return

        # 5. 注入 current_user 到 scope (Starlette request.state.user + FastMCP Request.state
        #    都从 scope["state"] 取)
        state = scope.setdefault("state", {})
        if not isinstance(state, dict):
            state = {}
            scope["state"] = state
        state["user"] = {
            "sub": claims.get("sub"),
            "scope": token_row.get("scope", ""),
            "user_id": token_row.get("user_id"),
            "tenant_id": token_row.get("tenant_id"),
            "product": token_row.get("product"),
            "client_id": token_row.get("client_id"),
        }

        # 通过校验, 继续内层 app
        await self.app(scope, receive, send)