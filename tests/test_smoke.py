"""Smoke 测试: 不依赖真实 qcn-dev, 用 httpx MockTransport 验证 client + tool 行为。

跑法:
    cd C:\\whg\\mcp-bridge
    python -m pytest tests/ -v
"""
from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from qcn_mcp_bridge.client import QcnClient
from qcn_mcp_bridge.config import Settings
from qcn_mcp_bridge.errors import QcnBusinessError, QcnTransportError
from qcn_mcp_bridge.tools import demand as demand_tools


def _settings() -> Settings:
    return Settings(
        qcn_base_url="http://qcn.test",
        qcn_jwt="dummy-jwt",
        qcn_http_timeout=5.0,
        mcp_transport="stdio",
        mcp_http_host="127.0.0.1",
        mcp_http_port=8765,
        mcp_http_path="/mcp",
        log_level="WARNING",
        # Phase 1A OAuth 字段
        qcn_bridge_issuer="https://test.bridge",
        qcn_bridge_resource="https://test.bridge/mcp",
        qcn_bridge_db_path=":memory:",
        qcn_bridge_jwt_key_path=":memory:",
        qcn_bridge_access_ttl=3600,
        qcn_bridge_refresh_ttl=2592000,
        # Phase 2B1 业务参数 (按 §6.3 + 用户已确认 dev 值)
        qcn_dev_session_ttl_seconds=3600,    # 60min (§7.1)
        qcn_dev_kick_concurrent=True,        # 是 (§7.3)
        qcn_dev_rate_limit_per_minute=0,     # 无限 (§7.4)
    )


def _mock_transport(handler):
    return httpx.MockTransport(handler)


def test_post_json_unwraps_syresult_data() -> None:
    """成功响应 (code=1) 应该返回 data 字段原值。"""
    captured: dict[str, Any] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.content.decode("utf-8"))
        return httpx.Response(
            200,
            json={"code": 1, "message": "ok", "data": {"list": [1, 2, 3]}},
        )

    settings = _settings()
    transport = _mock_transport(handler)
    client = QcnClient(settings)
    # 替换内部 httpx client 的 transport
    client._client._transport = transport  # type: ignore[attr-defined]

    import asyncio

    data = asyncio.run(client.post_json("/user/demand/getNewest", {"pageNum": 1}))

    assert data == {"list": [1, 2, 3]}
    assert captured["url"].endswith("/user/demand/getNewest")
    assert captured["headers"]["authorization"] == "Bearer dummy-jwt"
    assert captured["body"] == {"pageNum": 1}


def test_post_json_business_error() -> None:
    """code != 1 应该抛 QcnBusinessError, 含 code / message / data。"""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"code": 0, "message": "参数错误", "data": {"field": "userId"}},
        )

    settings = _settings()
    transport = _mock_transport(handler)
    client = QcnClient(settings)
    client._client._transport = transport  # type: ignore[attr-defined]

    import asyncio

    with pytest.raises(QcnBusinessError) as exc_info:
        asyncio.run(client.post_json("/x", {}))
    err = exc_info.value
    assert err.code == 0
    assert err.message == "参数错误"
    assert err.data == {"field": "userId"}


def test_post_json_5xx_is_transport_error() -> None:
    """5xx 应该走 QcnTransportError, 不当业务错误。"""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(502, text="Bad Gateway")

    settings = _settings()
    transport = _mock_transport(handler)
    client = QcnClient(settings)
    client._client._transport = transport  # type: ignore[attr-defined]

    import asyncio

    with pytest.raises(QcnTransportError):
        asyncio.run(client.post_json("/x", {}))


def test_demand_get_newest_tool_returns_ok_true() -> None:
    """tool 函数成功路径应该返回 {"ok": true, ...} 结构。"""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"code": 1, "message": "ok", "data": {"rows": [], "total": 0}},
        )

    settings = _settings()
    transport = _mock_transport(handler)
    client = QcnClient(settings)
    client._client._transport = transport  # type: ignore[attr-defined]

    # 直接调 inner 函数
    # demand_tools.register() 是 FastMCP 装饰器闭包, 没法直接 import,
    # 这里走一条端到端: 构造一个 dummy FastMCP, 让 register 把真实函数挂上,
    # 再通过属性访问拿出来。
    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP(name="test")
    demand_tools.register(mcp, client)
    # FastMCP 内部把 tool 存到 _tool_manager._tools (dict[str, Tool])
    tool = mcp._tool_manager._tools["qcn_demand_get_newest"]  # type: ignore[attr-defined]

    import asyncio

    raw = asyncio.run(tool.fn(pageNum=1, pageSize=10))
    payload = json.loads(raw)
    assert payload["ok"] is True
    assert payload["endpoint"] == "/user/demand/getNewest"
    assert payload["data"] == {"rows": [], "total": 0}


def test_demand_tool_returns_business_error_json() -> None:
    """tool 业务错误应该返回 {"ok": false, "kind": "business_error", ...}。"""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(
            200,
            json={"code": 401, "message": "未登录", "data": None},
        )

    settings = _settings()
    transport = _mock_transport(handler)
    client = QcnClient(settings)
    client._client._transport = transport  # type: ignore[attr-defined]

    from mcp.server.fastmcp import FastMCP

    mcp = FastMCP(name="test")
    demand_tools.register(mcp, client)
    tool = mcp._tool_manager._tools["qcn_demand_get_newest"]  # type: ignore[attr-defined]

    import asyncio

    raw = asyncio.run(tool.fn(pageNum=1))
    payload = json.loads(raw)
    assert payload["ok"] is False
    assert payload["kind"] == "business_error"
    assert payload["code"] == 401
    assert payload["message"] == "未登录"
    assert payload["endpoint"] == "/user/demand/getNewest"