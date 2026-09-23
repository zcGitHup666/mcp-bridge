"""配置加载: 环境变量 + .env 文件。

设计要点:
- 所有配置从 os.environ 读取, 通过 python-dotenv 把 .env 注入 (但 .env 已 gitignore)
- 不引入 pydantic-settings / dataclass: 配置就是个 socket, 不需要类型校验
- 任何缺失必填项直接抛 ConfigError, 让上层在启动期就崩, 不要到请求期才报错
"""
from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from dotenv import load_dotenv

# .env 位于仓库根目录 C:\whg\mcp-bridge\.env
# 不强制存在: 生产环境用 K8s ConfigMap / Vault 注入, 不依赖文件
_REPO_ROOT = Path(__file__).resolve().parents[2]
_DOTENV_PATH = _REPO_ROOT / ".env"
load_dotenv(dotenv_path=_DOTENV_PATH, override=False)

log = logging.getLogger(__name__)

Transport = Literal["stdio", "streamable-http"]


class ConfigError(RuntimeError):
    """配置缺失或非法。启动期抛错, 避免请求期才发现。"""


@dataclass(frozen=True)
class Settings:
    qcn_base_url: str
    qcn_jwt: str
    qcn_http_timeout: float
    mcp_transport: Transport
    mcp_http_host: str
    mcp_http_port: int
    mcp_http_path: str
    log_level: str
    # Phase 1A (OAuth 2.1 + PKCE)
    qcn_bridge_issuer: str
    qcn_bridge_resource: str
    qcn_bridge_db_path: str
    qcn_bridge_jwt_key_path: str
    qcn_bridge_access_ttl: int
    qcn_bridge_refresh_ttl: int
    # Phase 2B1: 7 项业务参数 (按接入清单 §6.3 + 用户已确认)
    qcn_dev_session_ttl_seconds: int   # 业务凭证有效期 (60min=3600, §7.1)
    qcn_dev_kick_concurrent: bool        # 并发登录踢下线 (§7.3)
    qcn_dev_rate_limit_per_minute: int   # 接口调用限额 (0=无限, §7.4)


def _require(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise ConfigError(
            f"环境变量 {name} 未设置。复制 .env.example 为 .env 并填值, "
            f"或通过 K8s ConfigMap / Vault 注入。"
        )
    return value


def load_settings() -> Settings:
    """从环境变量读取所有配置; 必填项缺失抛 ConfigError。"""
    transport_raw = os.environ.get("MCP_TRANSPORT", "stdio").strip().lower()
    if transport_raw not in ("stdio", "streamable-http"):
        raise ConfigError(
            f"MCP_TRANSPORT 必须为 stdio 或 streamable-http, 当前: {transport_raw!r}"
        )

    timeout_raw = os.environ.get("QCN_HTTP_TIMEOUT", "30.0").strip()
    try:
        timeout = float(timeout_raw)
    except ValueError as exc:
        raise ConfigError(f"QCN_HTTP_TIMEOUT 非数字: {timeout_raw!r}") from exc

    port_raw = os.environ.get("MCP_HTTP_PORT", "8765").strip()
    try:
        port = int(port_raw)
    except ValueError as exc:
        raise ConfigError(f"MCP_HTTP_PORT 非整数: {port_raw!r}") from exc

    settings = Settings(
        qcn_base_url=os.environ.get("QCN_BASE_URL", "https://www.qcniu.cn/").rstrip("/"),
        qcn_jwt=_require("QCN_JWT"),
        qcn_http_timeout=timeout,
        mcp_transport=transport_raw,  # type: ignore[arg-type]
        mcp_http_host=os.environ.get("MCP_HTTP_HOST", "127.0.0.1"),
        mcp_http_port=port,
        mcp_http_path=os.environ.get("MCP_HTTP_PATH", "/mcp"),
        log_level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        # Phase 1A OAuth 配置
        qcn_bridge_issuer=os.environ.get("QCN_BRIDGE_ISSUER", "https://cc.qicainiu.com").rstrip("/"),
        qcn_bridge_resource=os.environ.get("QCN_BRIDGE_RESOURCE", "https://cc.qicainiu.com/mcp"),
        qcn_bridge_db_path=os.environ.get(
            "QCN_BRIDGE_DB_PATH",
            str(Path.home() / ".qcn-mcp-bridge" / "db.sqlite3"),
        ),
        qcn_bridge_jwt_key_path=os.environ.get(
            "QCN_BRIDGE_JWT_KEY_PATH",
            str(Path.home() / ".qcn-mcp-bridge" / "jwt-signing.pem"),
        ),
        qcn_bridge_access_ttl=int(os.environ.get("QCN_BRIDGE_ACCESS_TTL", "3600")),
        qcn_bridge_refresh_ttl=int(os.environ.get("QCN_BRIDGE_REFRESH_TTL", str(30 * 24 * 3600))),
        # Phase 2B1: 7 项业务参数 (按接入清单 §6.3, 用户已确认 dev 值)
        qcn_dev_session_ttl_seconds=int(os.environ.get("QCN_DEV_SESSION_TTL_SECONDS", "3600")),  # 60min(§7.1)
        qcn_dev_kick_concurrent=os.environ.get("QCN_DEV_KICK_CONCURRENT", "true").lower() in ("true", "1", "yes"),  # 是(§7.3)
        qcn_dev_rate_limit_per_minute=int(os.environ.get("QCN_DEV_RATE_LIMIT_PER_MINUTE", "0")),  # 无限(§7.4)
    )

    # 显式回显非敏感字段, 凭证一律 <REDACTED> (CLAUDE.md §6.3.2)
    log.info(
        "bridge config: base_url=%s timeout=%ss transport=%s http=%s:%s%s log=%s jwt=<REDACTED>",
        settings.qcn_base_url,
        settings.qcn_http_timeout,
        settings.mcp_transport,
        settings.mcp_http_host,
        settings.mcp_http_port,
        settings.mcp_http_path,
        settings.log_level,
    )
    return settings