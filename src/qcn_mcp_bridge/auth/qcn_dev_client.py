"""qcn-dev HTTP 客户端 (Phase 2B1 Step 2).

按接入方案 §四 + CLAUDE §6.3.2:
- httpx AsyncClient 调 qcn-dev 5 个 endpoint
- 不打印 authToken / cookie / phone 明文
- 任何 5xx / 网络异常 → raise QcnDevTransportError
- qcn-dev code != 1 → raise QcnDevBusinessError

按 CLAUDE §4.5: 出参类型 dict, 不暴露 qcn-dev 内部类名.
按 CLAUDE §4.1: 单文件 ≤ 300 行.
"""
from __future__ import annotations

import logging
from typing import Any

import httpx

from qcn_mcp_bridge.config import Settings

log = logging.getLogger(__name__)


class QcnDevError(Exception):
    """所有 qcn-dev 调用异常的基类."""


class QcnDevTransportError(QcnDevError):
    """网络层 / 5xx / 响应解析失败."""


class QcnDevBusinessError(QcnDevError):
    """qcn-dev 业务错误 (code != 1).

    不展示原始 payload 明文凭证, 只保留 code/message.
    """

    def __init__(self, code: int, message: str, code_value: int | None = None) -> None:
        super().__init__(f"qcn-dev code={code}: {message}")
        self.code = code
        self.message = message
        self.code_value = code_value  # qcn-dev 业务码 (1=成功, 0=业务错, etc.)


def _unwrap(response_body: dict[str, Any], *, endpoint: str) -> dict[str, Any]:
    """检查 qcn-dev 响应 {code, message, data}, code != 1 抛业务错."""
    code = response_body.get("code")
    message = response_body.get("message", "")
    data = response_body.get("data")
    if code != 1:
        # 业务错 (按 qcn-dev 业务码)
        raise QcnDevBusinessError(code=code or 0, message=message, code_value=code)
    return data if data is not None else {}


class QcnDevClient:
    """qcn-dev HTTP 客户端 (Phase 2B1 Step 2).

    每个请求新开 httpx.AsyncClient (短连接, 不需要连接池).
    按 CLAUDE §6.3.2: 不打印 request/response body 明文.
    """

    def __init__(self, settings: Settings) -> None:
        self._base_url = settings.qcn_base_url.rstrip("/")
        self._timeout = httpx.Timeout(settings.qcn_http_timeout)
        # 按 §6.3.2: 不把 qcn_jwt 塞进 headers (Phase 2B1 是用户登录拿自己的 session, 不是 service-account)

    async def _post_form(self, endpoint: str, data: dict[str, str]) -> dict[str, Any]:
        """POST form-urlencoded 到 qcn-dev, unwrap SysResult.

        接入方案 §四: qcn-dev 业务接口默认 register 走浏览器 form, Bridge 模拟表单请求.
        """
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            try:
                resp = await client.post(
                    f"{self._base_url}{endpoint}",
                    data=data,
                    headers={
                        "User-Agent": "qcn-mcp-bridge/1.0",
                        "Accept": "application/json, text/plain",
                    },
                )
            except httpx.HTTPError as exc:
                raise QcnDevTransportError(
                    f"qcn-dev POST {endpoint}: {exc}"
                ) from exc
        if resp.status_code >= 500:
            raise QcnDevTransportError(
                f"qcn-dev POST {endpoint}: HTTP {resp.status_code}"
            )
        try:
            body = resp.json()
        except ValueError as exc:
            raise QcnDevTransportError(
                f"qcn-dev POST {endpoint}: non-JSON response"
            ) from exc
        return _unwrap(body, endpoint=endpoint)

    async def _get(self, endpoint: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        """GET 到 qcn-dev (no-autho-path 接口用, 例如 /eims/info/listAll)."""
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            try:
                resp = await client.get(
                    f"{self._base_url}{endpoint}",
                    params=params,
                    headers={"User-Agent": "qcn-mcp-bridge/1.0"},
                )
            except httpx.HTTPError as exc:
                raise QcnDevTransportError(
                    f"qcn-dev GET {endpoint}: {exc}"
                ) from exc
        if resp.status_code >= 500:
            raise QcnDevTransportError(
                f"qcn-dev GET {endpoint}: HTTP {resp.status_code}"
            )
        try:
            body = resp.json()
        except ValueError as exc:
            raise QcnDevTransportError(
                f"qcn-dev GET {endpoint}: non-JSON response"
            ) from exc
        return _unwrap(body, endpoint=endpoint)

    # ===== 5 个接口 (Phase 2B1 Step 2) =====

    async def send_code(self, phone: str) -> None:
        """POST /getMessageCode - 发短信验证码.

        qcn-dev 返回 {code: 1, message: "..."} (无 data).
        限流在 qcn-dev 端 (同 IP 100/天, 同手机 10/天).
        """
        await self._post_form("/getMessageCode", {"phone": phone})

    async def login(self, phone: str, code: str) -> dict[str, Any]:
        """POST /login - 手机号 + 短信验证码登录.

        返回:
          {
            "auth_token": str,        # qcn-dev JWT (HS256, qcn-dev secret)
            "user_id": int,           # data.user[0].id
            "tenant_id": int | None,  # data.user[0].eimsId
            "eim_name": str,          # data.user[0].name
            "phone": str,
            "all_users": list[dict],  # 多公司用户的所有候选 (Phase 2B2 选公司用)
          }

        接入方案 §F2: 多公司用户 size > 1, JWT 只有 5 分钟预登录有效期, 需 select().
        Phase 2B1 Step 2 暂存 all_users, Phase 2B2 在 consent 之前加 select step.
        """
        data = await self._post_form("/login", {"phone": phone, "code": code})
        user_list = data.get("user") or []
        if not user_list:
            raise QcnDevBusinessError(
                code=0, message="qcn-dev /login 返回 user 列表为空"
            )
        primary = user_list[0]
        return {
            "auth_token": data.get("authToken"),
            "user_id": int(primary.get("id", 0)),
            "tenant_id": primary.get("eimsId"),
            "eim_name": primary.get("name"),
            "phone": primary.get("phone"),
            "all_users": user_list,
        }

    async def register(
        self,
        *,
        phone: str,
        eim_name: str,
        password: str,
        invite_code: str = "",
    ) -> None:
        """POST /regist - 注册.

        字段 (按 qcn-dev /regist Controller line 633):
          phone, eimName, pass, inviteCode

        接入方案 §F2: eim_name 已存在必须有 inviteCode, 新公司不用. Bridge 不强制, 让 qcn-dev 报业务错.
        """
        await self._post_form(
            "/regist",
            {"phone": phone, "eimName": eim_name, "pass": password, "inviteCode": invite_code},
        )

    async def login_by_password(
        self, *, eim_code: str, name: str, password: str
    ) -> dict[str, Any]:
        """POST /passLogin - 公司码 + 用户名 + 密码登录.

        eimCode 解码: parseInt(eimCode.substring(1)) ^ EIM_CODE_MASK
        (qcn-dev LoginController line 580). 假设 client 直接传 eim_code 字符串, 跳过解码让 qcn-dev 处理.
        """
        data = await self._post_form(
            "/passLogin", {"eimCode": eim_code, "name": name, "pass": password}
        )
        user_list = data.get("user") or []
        if not user_list:
            raise QcnDevBusinessError(code=0, message="/passLogin 返回 user 列表为空")
        primary = user_list[0]
        return {
            "auth_token": data.get("authToken"),
            "user_id": int(primary.get("id", 0)),
            "tenant_id": primary.get("eimsId"),
            "eim_name": primary.get("name"),
            "phone": primary.get("phone"),
            "all_users": user_list,
        }

    async def list_companies(self, name: str = "") -> list[dict[str, Any]]:
        """GET /eims/info/listAll - 公司列表 (注册页下拉).

        接入方案 §B1 (B7): 注册时选/新增公司, 这里拿已有公司列表给前端下拉.
        返回 [{id, name, ...}, ...]
        """
        data = await self._get("/eims/info/listAll", params={"name": name} if name else None)
        # qcn-dev 返回 PageInfo, list 在 data.list
        if isinstance(data, dict):
            return data.get("list") or []
        return []