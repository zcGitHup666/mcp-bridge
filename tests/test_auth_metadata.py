"""OAuth discovery 元数据单元测试 (RFC 9728 + RFC 8414).

- /.well-known/oauth-protected-resource (接入方案 §A2)
- /.well-known/oauth-authorization-server (接入方案 §A3)
"""
from __future__ import annotations

from qcn_mcp_bridge.auth.metadata import (
    authorization_server_metadata,
    protected_resource_metadata,
)


def test_prm_required_fields():
    """RFC 9728: 必须含 resource + authorization_servers."""
    meta = protected_resource_metadata(
        resource="https://cc.qicainiu.com/mcp",
        authorization_servers=["https://cc.qicainiu.com"],
    )
    assert meta["resource"] == "https://cc.qicainiu.com/mcp"
    assert meta["authorization_servers"] == ["https://cc.qicainiu.com"]
    assert "bearer_methods_supported" in meta
    assert "header" in meta["bearer_methods_supported"]


def test_prm_default_signing_algs():
    """默认支持 RS256."""
    meta = protected_resource_metadata(
        resource="r", authorization_servers=["s"]
    )
    assert "RS256" in meta["resource_signing_alg_values_supported"]


def test_as_metadata_required_fields():
    """RFC 8414: 必须含 issuer + endpoints + code_challenge_methods_supported."""
    meta = authorization_server_metadata(
        issuer="https://cc.qicainiu.com",
        authorization_endpoint="https://cc.qicainiu.com/oauth/authorize",
        token_endpoint="https://cc.qicainiu.com/oauth/token",
        registration_endpoint="https://cc.qicainiu.com/oauth/register",
        scopes_supported=["read:demand", "read:supply"],
    )
    assert meta["issuer"] == "https://cc.qicainiu.com"
    assert meta["authorization_endpoint"].endswith("/oauth/authorize")
    assert meta["token_endpoint"].endswith("/oauth/token")
    assert meta["registration_endpoint"].endswith("/oauth/register")
    # §A3 强制 S256
    assert "S256" in meta["code_challenge_methods_supported"]
    # 响应类型必须含 code
    assert "code" in meta["response_types_supported"]
    # grant_type 含 authorization_code + refresh_token (M1A)
    assert "authorization_code" in meta["grant_types_supported"]
    assert "refresh_token" in meta["grant_types_supported"]
    # 公共客户端 (MCP WorkBuddy) 不需要 client_secret
    assert "none" in meta["token_endpoint_auth_methods_supported"]


def test_as_metadata_default_scopes():
    """默认 scope 列表."""
    meta = authorization_server_metadata(
        issuer="x",
        authorization_endpoint="a",
        token_endpoint="t",
        registration_endpoint="r",
        scopes_supported=["read:foo"],
    )
    assert meta["scopes_supported"] == ["read:foo"]