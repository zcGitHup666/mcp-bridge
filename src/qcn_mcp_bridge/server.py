"""MCP server 入口: 构造 FastMCP 实例 + 注册 4 个 tool + 挂载 OAuth sub-app.

启动方式:
- stdio:           ``python -m qcn_mcp_bridge`` (默认, 只跑 MCP, 不带 OAuth)
- streamable-http: ``MCP_TRANSPORT=streamable-http python -m qcn_mcp_bridge``
                  (Phase 1A 改造: uvicorn 直接 run 顶层 Starlette, 挂 3 个 sub-app:
                   /mcp → FastMCP, /.well-known → OAuth discovery, /oauth → OAuth 5 端点)

按 CLAUDE §4.5: 顶层不暴露 ORM Entity / 内部类.
按 CLAUDE §6.3.2: 启动日志不回显 JWT / RSA 私钥.
"""
from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

import uvicorn
from mcp.server.fastmcp import FastMCP
from starlette.applications import Starlette
from starlette.routing import Mount

from qcn_mcp_bridge.auth.asgi import build_oauth_asgi
from qcn_mcp_bridge.client import QcnClient
from qcn_mcp_bridge.config import Settings, load_settings
from qcn_mcp_bridge.tools import demand as demand_tools
from qcn_mcp_bridge.tools import supply as supply_tools

log = logging.getLogger(__name__)

_SERVER_ATTR_CLIENT = "_qcn_client"


def build_server(
    settings: Optional[Settings] = None,
    client: Optional[QcnClient] = None,
) -> FastMCP:
    """构造 FastMCP 实例并注册 4 个 tool。

    提供 ``settings`` / ``client`` 参数用于测试注入; 默认从环境变量加载。
    """
    if settings is None:
        settings = load_settings()
    if client is None:
        client = QcnClient(settings)

    mcp = FastMCP(
        name="qcn-mcp-bridge",
        host=settings.mcp_http_host,
        port=settings.mcp_http_port,
    )

    demand_tools.register(mcp, client)
    supply_tools.register(mcp, client)

    # 用 object.__setattr__ 避开 FastMCP 的 __slots__ 检查 (如有)
    setattr(mcp, _SERVER_ATTR_CLIENT, client)
    log.info("MCP server 构造完成, transport=%s", settings.mcp_transport)
    return mcp


async def _shutdown(mcp: FastMCP) -> None:
    client = getattr(mcp, _SERVER_ATTR_CLIENT, None)
    if client is not None:
        await client.aclose()


def _build_main_app(
    mcp: FastMCP, settings: Settings
) -> Starlette:
    """构造顶层 Starlette: 挂载 /mcp (FastMCP, Bearer 校验) + /.well-known + /oauth.

    Phase 1B: /mcp 套一层 BearerAuthMiddleware:
      - 无 Bearer → 401 + WWW-Authenticate (RFC 6750) → MCP client 自动走 OAuth
      - Bearer 但 JWT 签名/aud/exp 错 → 401
      - 查 token 表 (按 SHA256 哈希) 看是否 revoked
      - 注入 current_user 到 request.state, tool handler 通过 Context 拿

    Phase 2B1: 真接 qcn-dev (QcnDevClient). settings.qcn_base_url 是公网 qcniu.cn/
    """
    # Phase 2B1: 真接 qcn-dev (按 CLAUDE §6.3.2 不展示 JWT, 但 URL 是公开 §6.4)
    from qcn_mcp_bridge.auth.qcn_dev_client import QcnDevClient
    qcn_dev_client = QcnDevClient(settings)

    # OAuth sub-app (Phase 1A + 注入 qcn-dev 客户端)
    oauth_asgi = build_oauth_asgi(
        issuer=settings.qcn_bridge_issuer,
        resource=settings.qcn_bridge_resource,
        db_path=settings.qcn_bridge_db_path,
        jwt_key_path=Path(settings.qcn_bridge_jwt_key_path),
        qcn_dev_client=qcn_dev_client,
    )

    # Phase 1B: Bearer 校验中间件
    # 共享 OAuth 用的 RSA 私钥 + SessionLocal (JWT 验签 + 查 token 表)
    from qcn_mcp_bridge.auth.jwt_signer import JWTSigner
    from qcn_mcp_bridge.auth.middleware import BearerAuthMiddleware
    from qcn_mcp_bridge.auth.storage import init_engine

    engine, SessionLocal = init_engine(settings.qcn_bridge_db_path)
    bridge_jwt_signer = JWTSigner(
        Path(settings.qcn_bridge_jwt_key_path),
        issuer=settings.qcn_bridge_issuer,
        audience=settings.qcn_bridge_resource,
    )
    protected_mcp = BearerAuthMiddleware(
        mcp.streamable_http_app(),
        jwt_signer=bridge_jwt_signer,
        session_factory=SessionLocal,
        resource_metadata_url=f"{settings.qcn_bridge_issuer}/.well-known/oauth-protected-resource",
        # Phase 1B: 先不强求 scope (Phase 2 加 tool-level scope)
        required_scope=None,
    )

    log.info("qcn-dev client ready: base_url=%s (真接公网 qcniu.cn)", settings.qcn_base_url)
    return Starlette(
        routes=[
            # /.well-known/oauth-protected-resource + /.well-known/oauth-authorization-server
            Mount("/.well-known", oauth_asgi),
            # /oauth/register + /oauth/authorize + /oauth/token
            Mount("/oauth", oauth_asgi),
            # MCP 主端点 (Phase 1B: Bearer 校验套中间件)
            Mount("/mcp", protected_mcp),
        ],
    )


def main() -> None:
    settings = load_settings()
    logging.basicConfig(
        level=settings.log_level,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )

    mcp = build_server(settings)

    if settings.mcp_transport == "stdio":
        log.info("starting MCP server via stdio (Phase 1A: OAuth 不暴露, stdio 不走公网)")
        try:
            mcp.run(transport="stdio")
        finally:
            asyncio.run(_shutdown(mcp))
    else:
        log.info(
            "starting MCP + OAuth via streamable-http at %s:%s",
            settings.mcp_http_host,
            settings.mcp_http_port,
        )
        # Phase 1A: uvicorn 直接 run 顶层 Starlette (挂 /mcp + /oauth + /.well-known)
        main_app = _build_main_app(mcp, settings)
        uvicorn_config = uvicorn.Config(
            main_app,
            host=settings.mcp_http_host,
            port=settings.mcp_http_port,
            log_level=settings.log_level.lower(),
        )
        server = uvicorn.Server(uvicorn_config)
        try:
            server.run()
        finally:
            asyncio.run(_shutdown(mcp))


if __name__ == "__main__":
    main()