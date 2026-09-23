"""OAuth / MCP discovery 元数据端点。

- /.well-known/oauth-protected-resource  (RFC 9728 PRM, 接入方案 §A2)
- /.well-known/oauth-authorization-server (RFC 8414, 接入方案 §A3)

按 CLAUDE §4.5: 出参类型 dict, 字段名按 RFC 原文 (resource / authorization_servers / etc).
"""
from __future__ import annotations

from typing import Any


def protected_resource_metadata(
    *,
    resource: str,
    authorization_servers: list[str],
    bearer_methods: list[str] | None = None,
    signing_algs: list[str] | None = None,
) -> dict[str, Any]:
    """RFC 9728 Protected Resource Metadata.

    接入方案 §A2: client 401 后从这里找 authorization_servers.
    """
    return {
        "resource": resource,
        "authorization_servers": authorization_servers,
        "bearer_methods_supported": bearer_methods or ["header"],
        "resource_signing_alg_values_supported": signing_algs or ["RS256"],
    }


def authorization_server_metadata(
    *,
    issuer: str,
    authorization_endpoint: str,
    token_endpoint: str,
    registration_endpoint: str,
    scopes_supported: list[str],
    code_challenge_methods: list[str] | None = None,
) -> dict[str, Any]:
    """RFC 8414 Authorization Server Metadata.

    接入方案 §A3: 必须含 code_challenge_methods_supported: ["S256"].
    """
    return {
        "issuer": issuer,
        "authorization_endpoint": authorization_endpoint,
        "token_endpoint": token_endpoint,
        "registration_endpoint": registration_endpoint,
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": code_challenge_methods or ["S256"],
        "token_endpoint_auth_methods_supported": ["none"],  # public client, no secret
        "scopes_supported": scopes_supported,
    }