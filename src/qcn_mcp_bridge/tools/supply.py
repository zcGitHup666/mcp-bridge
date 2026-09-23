"""供应侧 tool — 对应 qcn-dev /user/supply/* 的 2 个高频查询接口。

入参是 SearchSupply DTO, 共 30+ 字段; 这里只暴露高频字段, 其它保持默认。
"""
from __future__ import annotations

import json
from typing import Any, List, Optional

from mcp.server.fastmcp import FastMCP

from qcn_mcp_bridge.client import QcnClient
from qcn_mcp_bridge.errors import QcnError, to_error_json


def register(mcp: FastMCP, client: QcnClient) -> None:
    """把 2 个供应侧 tool 挂到 mcp 实例; 通过闭包捕获 client。"""

    @mcp.tool()
    async def qcn_supply_get_newest(
        pageNum: int = 1,
        pageSize: int = 20,
        status: Optional[int] = None,
        userId: Optional[int] = None,
        condition: Optional[str] = None,
        eimId: Optional[int] = None,
        material: Optional[str] = None,
        sortType: Optional[int] = None,
        sortOrder: Optional[int] = None,
    ) -> str:
        """拉取最新供应列表（分页）。对应 qcn-dev UserSupplyController.getNewest。"""
        body = {
            "pageNum": pageNum,
            "pageSize": pageSize,
            "status": status,
            "userId": userId,
            "condition": condition,
            "eimId": eimId,
            "material": material,
            "sortType": sortType,
            "sortOrder": sortOrder,
        }
        body = {k: v for k, v in body.items() if v is not None}
        endpoint = "/user/supply/getNewest"
        try:
            data = await client.post_json(endpoint, body)
            payload: dict[str, Any] = {"ok": True, "endpoint": endpoint, "data": data}
        except QcnError as exc:
            payload = to_error_json(exc, endpoint)
        return json.dumps(payload, ensure_ascii=False, default=str)

    @mcp.tool()
    async def qcn_supply_get_list(
        pageNum: int = 1,
        pageSize: int = 20,
        status: Optional[int] = None,
        supplyType: Optional[int] = None,
        eimsContractId: Optional[int] = None,
        lineId: Optional[int] = None,
        categoryId: Optional[int] = None,
        catenameId: Optional[int] = None,
        spe: Optional[str] = None,
        beginTime: Optional[str] = None,
        endTime: Optional[str] = None,
        provinceId: Optional[str] = None,
        cityId: Optional[str] = None,
        userId: Optional[int] = None,
        newFlag: Optional[int] = None,
        minNum: Optional[float] = None,
        maxNum: Optional[float] = None,
        removalStartTime: Optional[str] = None,
        removalEndTime: Optional[str] = None,
        specialType: Optional[int] = None,
        recommendType: Optional[int] = 0,
        material: Optional[str] = None,
        brandList: Optional[List[int]] = None,
        levelList: Optional[List[int]] = None,
        condition: Optional[str] = None,
        eimId: Optional[int] = None,
        sortType: Optional[int] = None,
        sortOrder: Optional[int] = None,
        eimType: Optional[int] = None,
    ) -> str:
        """供应列表综合查询（带多维过滤 + 分页）。对应 qcn-dev UserSupplyController.getSupplyList。"""
        body = {
            "pageNum": pageNum,
            "pageSize": pageSize,
            "status": status,
            "supplyType": supplyType,
            "eimsContractId": eimsContractId,
            "lineId": lineId,
            "categoryId": categoryId,
            "catenameId": catenameId,
            "spe": spe,
            "beginTime": beginTime,
            "endTime": endTime,
            "provinceId": provinceId,
            "cityId": cityId,
            "userId": userId,
            "newFlag": newFlag,
            "minNum": minNum,
            "maxNum": maxNum,
            "removalStartTime": removalStartTime,
            "removalEndTime": removalEndTime,
            "specialType": specialType,
            "recommendType": recommendType,
            "material": material,
            "brandList": brandList,
            "levelList": levelList,
            "condition": condition,
            "eimId": eimId,
            "sortType": sortType,
            "sortOrder": sortOrder,
            "eimType": eimType,
        }
        body = {k: v for k, v in body.items() if v is not None}
        endpoint = "/user/supply/getSupplyList"
        try:
            data = await client.post_json(endpoint, body)
            payload = {"ok": True, "endpoint": endpoint, "data": data}
        except QcnError as exc:
            payload = to_error_json(exc, endpoint)
        return json.dumps(payload, ensure_ascii=False, default=str)