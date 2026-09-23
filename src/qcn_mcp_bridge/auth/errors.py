"""OAuth 2.1 / RFC 6749 §5.2 错误响应。

按 CLAUDE §4.5: 出参类型 DTO, 不返回 Entity。
按 CLAUDE §6.3.2: 错误响应不含明文凭证。
"""
from __future__ import annotations

from typing import Literal

from starlette.responses import JSONResponse

# RFC 6749 §5.2 + RFC 7009 (revocation) + RFC 7591 §3.2.2 (DCR)
OAuthErrorCode = Literal[
    "invalid_request",          # 参数缺失 / 无效
    "invalid_client",           # client_id 无效 / client auth 失败
    "invalid_grant",            # code / refresh_token 无效
    "invalid_scope",            # scope 无效
    "unauthorized_client",      # client 无权用此 grant type
    "unsupported_grant_type",   # 不支持的 grant_type
    "unsupported_response_type", # 不支持的 response_type
    "invalid_token",            # access_token 无效 (RFC 7009)
    "server_error",             # 服务器内部错
    "temporarily_unavailable",  # 服务暂时不可用
    "access_denied",           # 用户拒绝授权
    "unsupported_code_challenge_method",  # 不支持 PKCE 方法 (RFC 7636)
    "invalid_code_challenge",   # PKCE challenge 无效
    "invalid_grant_type",        # grant type 错
]


def oauth_error(
    error: OAuthErrorCode,
    description: str = "",
    status_code: int = 400,
    error_uri: str | None = None,
) -> JSONResponse:
    """RFC 6749 §5.2 标准 OAuth 错误响应。

    返回 JSONResponse (而不是 raise), 让 controller 决定 return 流程。
    description 不含明文凭证 (按 §6.3.2)。
    """
    body: dict[str, str] = {"error": error}
    if description:
        body["error_description"] = description
    if error_uri:
        body["error_uri"] = error_uri
    return JSONResponse(body, status_code=status_code)