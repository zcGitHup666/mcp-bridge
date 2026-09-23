"""需求侧 tool — 对应 qcn-dev /user/demand/getNewest。

每个 tool 返回结构化 JSON 字符串:
- 成功:    ``{"ok": true,  "endpoint": ..., "data": <SysResult.data>}``
- 业务错:    ``{"ok": false, "kind": "business_error",  "code": ..., "message": ..., "data": ...}``
- 传输错:    ``{"ok": false, "kind": "transport_error", "message": ...}``

调用方 (WorkBuddy / Claude) 解析 ``ok`` 字段判断是否成功。
"""
from __future__ import annotations

import json
from typing import Any, List, Optional

from mcp.server.fastmcp import FastMCP

from qcn_mcp_bridge.client import QcnClient
from qcn_mcp_bridge.errors import QcnError, to_error_json


def register(mcp: FastMCP, client: QcnClient) -> None:
    """把 1 个需求侧 tool 挂到 mcp 实例; 通过闭包捕获 client。"""

    @mcp.tool()
    async def qcn_demand_get_newest(
        pageNum: int = 1,
        pageSize: int = 20,
        status: Optional[int] = None,
        userId: Optional[int] = None,
        condition: Optional[str] = None,
        eimId: Optional[int] = None,
    ) -> str:
        """拉取最新需求列表（分页）。对应 qcn-dev UserDemandController.getNewest。

        qcn-dev controller 会按 PageHelper 自动 LIMIT, 必须传 pageNum / pageSize。
        透传给 SysResult.data (PageInfo<RequirementPoolVo>)。
        """
        body = {
            "pageNum": pageNum,
            "pageSize": pageSize,
            "status": status,
            "userId": userId,
            "condition": condition,
            "eimId": eimId,
        }
        # 去掉 None, 避免覆盖 qcn-dev 端默认值
        body = {k: v for k, v in body.items() if v is not None}
        endpoint = "/user/demand/getNewest"
        try:
            data = await client.post_json(endpoint, body)
            payload: dict[str, Any] = {"ok": True, "endpoint": endpoint, "data": data}
        except QcnError as exc:
            payload = to_error_json(exc, endpoint)
        return json.dumps(payload, ensure_ascii=False, default=str)