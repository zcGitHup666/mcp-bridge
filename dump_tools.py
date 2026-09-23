"""Dump 4 个 MCP tool 的 JSON Schema, 用于人工对照 qcn-dev DTO 字段。

跑法:
    cd C:\\whg\\mcp-bridge
    py -3.11 dump_tools.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

# 让脚本可以直接 python dump_tools.py 而不依赖 PYTHONPATH
_ROOT = Path(__file__).resolve().parent
_SRC = _ROOT / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

from mcp.server.fastmcp import FastMCP  # noqa: E402

from qcn_mcp_bridge.client import QcnClient  # noqa: E402
from qcn_mcp_bridge.config import Settings  # noqa: E402
from qcn_mcp_bridge.tools import demand, supply  # noqa: E402


def main() -> None:
    # dummy 设置, 只为构造 FastMCP 实例拿 schema, 不会真的发请求
    settings = Settings(
        qcn_base_url="http://qcn.test",
        qcn_jwt="dummy",
        qcn_http_timeout=5.0,
        mcp_transport="stdio",
        mcp_http_host="127.0.0.1",
        mcp_http_port=8765,
        mcp_http_path="/mcp",
        log_level="WARNING",
    )
    client = QcnClient(settings)
    mcp = FastMCP(name="dump")
    demand.register(mcp, client)
    supply.register(mcp, client)

    tools = mcp._tool_manager._tools  # type: ignore[attr-defined]

    # 跟 qcn-dev 端点对齐, 方便对照
    endpoint_map = {
        "qcn_demand_get_newest": "/user/demand/getNewest (POST JSON, body=RequirementPoolVo)",
        "qcn_supply_get_newest": "/user/supply/getNewest (POST JSON, body=SearchSupply)",
        "qcn_supply_get_list": "/user/supply/getSupplyList (POST JSON, body=SearchSupply; recommendType 默认 0)",
    }

    dump = {}
    for name, tool in tools.items():
        dump[name] = {
            "endpoint": endpoint_map.get(name, "?"),
            "description": tool.description,
            "parameters_schema": tool.parameters,
        }
    # 写到文件而不是 stdout, 避免 Windows GBK terminal 编码问题
    out = _ROOT / "tool_schemas.json"
    out.write_text(
        json.dumps(dump, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    print(f"schema dumped to {out}", flush=True)


if __name__ == "__main__":
    main()