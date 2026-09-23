"""qcn-dev HTTP 客户端 + SysResult 解析。

为什么不直接调 Spring 接口: qcn-dev 所有响应都包成 SysResult { code, message, data },
需要先按 code 翻译, 再把内容交给 MCP 层。
"""
from __future__ import annotations

import logging
from typing import Any, Mapping

import httpx

from qcn_mcp_bridge.config import Settings
from qcn_mcp_bridge.errors import QcnBusinessError, QcnTransportError

log = logging.getLogger(__name__)

# qcn-dev SysConstant.SUCCESS_CODE = 1 (see html-doc-response-code.md memory)
_SUCCESS_CODE = 1


class QcnClient:
    """qcn-dev HTTP 客户端。

    - 每次请求自动注入 ``Authorization: Bearer <jwt>`` header
    - 响应统一按 SysResult 解析; ``code != 1`` 抛 ``QcnBusinessError``
    - 网络层异常 (connect timeout / 5xx / JSON 解析失败) 抛 ``QcnTransportError``
    """

    def __init__(self, settings: Settings) -> None:
        self._settings = settings
        self._client = httpx.AsyncClient(
            base_url=settings.qcn_base_url,
            timeout=httpx.Timeout(settings.qcn_http_timeout),
            headers={
                "Authorization": f"Bearer {settings.qcn_jwt}",
                "Content-Type": "application/json",
                "Accept": "application/json",
            },
            # qcn-dev 内网调用, 关掉 SSL verify 默认值不安全; 显式按 settings 走
            verify=True,
        )

    async def aclose(self) -> None:
        await self._client.aclose()

    async def post_json(self, path: str, body: Mapping[str, Any]) -> Any:
        """POST application/json。返回 SysResult.data 字段。

        业务错误 (code != 1) → QcnBusinessError
        网络 / 5xx / 非 JSON → QcnTransportError
        """
        try:
            response = await self._client.post(path, json=dict(body))
        except httpx.HTTPError as exc:
            raise QcnTransportError(f"qcn-dev 请求失败: {path}: {exc!r}") from exc

        # 5xx 一律按 transport 错误处理, 不当业务错误
        if response.status_code >= 500:
            raise QcnTransportError(
                f"qcn-dev 服务端错误: {path} → HTTP {response.status_code}"
            )

        # 4xx 可能是权限 / 参数错误, 走业务错误路径
        try:
            payload = response.json()
        except ValueError as exc:
            raise QcnTransportError(
                f"qcn-dev 响应非 JSON: {path} → HTTP {response.status_code}"
            ) from exc

        return _unwrap_sysresult(path, payload)

    async def post_form(self, path: str, form: Mapping[str, Any]) -> Any:
        """POST application/x-www-form-urlencoded (searchDemandPool 用)。"""
        try:
            response = await self._client.post(path, data=dict(form))
        except httpx.HTTPError as exc:
            raise QcnTransportError(f"qcn-dev 请求失败: {path}: {exc!r}") from exc

        if response.status_code >= 500:
            raise QcnTransportError(
                f"qcn-dev 服务端错误: {path} → HTTP {response.status_code}"
            )

        try:
            payload = response.json()
        except ValueError as exc:
            raise QcnTransportError(
                f"qcn-dev 响应非 JSON: {path} → HTTP {response.status_code}"
            ) from exc

        return _unwrap_sysresult(path, payload)


def _unwrap_sysresult(path: str, payload: Any) -> Any:
    """拆 SysResult {code, message, data}; 失败抛业务错误。"""
    if not isinstance(payload, dict):
        raise QcnTransportError(f"qcn-dev 响应非对象: {path} → {type(payload).__name__}")

    code = payload.get("code")
    if code != _SUCCESS_CODE:
        # 包含原始 data 字段方便上层排查 (e.g. validation error 详情)
        raise QcnBusinessError(
            code=code,
            message=str(payload.get("message", "")),
            data=payload.get("data"),
        )

    return payload.get("data")