"""错误类型 + JSON 翻译。

参考:
- html-doc-response-code.md: SysConstant.SUCCESS_CODE = 1
- SysConstant.FLOW_CONTROL_CODE = 999 (流控拦截)

tool 层捕获 QcnError 后, 把错误包成结构化 JSON 返回;
不在 MCP 协议层做 isError, 因为 FastMCP 的 @tool 装饰器不暴露 isError 字段。
调用方 (WorkBuddy / Claude) 解析返回 JSON 的 ``ok`` 字段判断成败。
"""
from __future__ import annotations

from typing import Any


class QcnError(Exception):
    """所有 qcn-mcp-bridge 异常的基类。"""


class QcnTransportError(QcnError):
    """网络层 / 5xx / 响应解析失败 — 走 transport_error JSON, 视为系统故障。"""


class QcnBusinessError(QcnError):
    """qcn-dev 业务错误 (code != 1)。data 字段保留原始 payload 便于排查。"""

    def __init__(self, code: Any, message: str, data: Any) -> None:
        super().__init__(f"qcn-dev 业务错误 code={code}: {message}")
        self.code = code
        self.message = message
        self.data = data


def to_error_json(err: QcnError, endpoint: str) -> dict[str, Any]:
    """把 QcnError 翻译成结构化 dict, 由 tool 层 json.dumps 返回。"""
    if isinstance(err, QcnBusinessError):
        return {
            "ok": False,
            "kind": "business_error",
            "endpoint": endpoint,
            "code": err.code,
            "message": err.message,
            "data": err.data,
        }
    if isinstance(err, QcnTransportError):
        return {
            "ok": False,
            "kind": "transport_error",
            "endpoint": endpoint,
            "message": str(err),
        }
    return {
        "ok": False,
        "kind": "unexpected_error",
        "endpoint": endpoint,
        "message": str(err),
    }


__all__ = ["QcnError", "QcnTransportError", "QcnBusinessError", "to_error_json"]